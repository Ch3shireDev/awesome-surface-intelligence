# Attack Surface Intelligence - HackNation 2026
#
# Standardowe reguly make: linie recept zaczynaja sie od tabulatora (wymog
# make). Jesli po skopiowaniu/wklejeniu dostaniesz "missing separator",
# edytor prawdopodobnie zamienil tabulatory na spacje - popraw wciecia.

SHELL := /bin/bash

# --- konfiguracja ---
# UWAGA: TARGETS musi byc potwierdzony z mentorami CBI AGH przed pierwszym
# skanem - patrz docs/DECISIONS.md, sekcja "Otwarte pytania".
TARGETS ?= scans/targets.txt
OUT_DIR := scans/results
STAMP   := $(shell date +%Y%m%d-%H%M%S)

.PHONY: help up down logs nmap-shell \
        scan-discover scan-fast scan-full scan-service scan-udp \
        import-defectdojo clean

help:
	@echo "Cele:"
	@echo "  make up               - odpal caly stack (DefectDojo + scanner)"
	@echo "  make down             - zatrzymaj stack"
	@echo "  make logs             - sledz logi DefectDojo (uwsgi)"
	@echo "  make nmap-shell       - wejdz do kontenera skanera"
	@echo "  make scan-discover    - ping sweep (-sn) po TARGETS"
	@echo "  make scan-fast        - szybki skan top-portow (-T4 -F)"
	@echo "  make scan-full        - pelny skan TCP (-p-), wolny"
	@echo "  make scan-service     - wykrywanie wersji/uslug (-sV -sC) na top-portach"
	@echo "  make scan-udp         - top porty UDP (bardzo wolne)"
	@echo "  make import-defectdojo FILE=scans/results/xxx.xml  - import XML do DefectDojo"
	@echo "  make clean            - usun lokalne wyniki skanow"

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f uwsgi

nmap-shell:
	docker compose exec nmap-scanner bash

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# --- skany ---
# Kazdy cel uzywa -oA (zamiast samego -oX), wiec jednym przebiegiem nmapa
# dostajemy TRZY pliki w /scans/results (zamontowane jako ./scans w repo):
#   <nazwa>.nmap  - czytelny dla czlowieka (szybki podglad bez DefectDojo)
#   <nazwa>.gnmap - grepowalny (np. `grep open *.gnmap` do szybkich zestawien)
#   <nazwa>.xml   - do importu w DefectDojo (scan_type=Nmap Scan)
# Nmap nie ma natywnego eksportu JSON - jesli zajdzie potrzeba JSON-a (np. pod
# inny dashboard niz DefectDojo), dopisz osobny cel konwertujacy .xml (patrz
# komentarz przy import-defectdojo nizej).

scan-discover: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -sn -iL /scans/$(notdir $(TARGETS)) \
		-oA /scans/results/discover-$(STAMP)

scan-fast: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -T4 -F -iL /scans/$(notdir $(TARGETS)) \
		-oA /scans/results/fast-$(STAMP)

scan-full: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -T4 -p- -iL /scans/$(notdir $(TARGETS)) \
		-oA /scans/results/full-$(STAMP)

scan-service: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -T4 -sV -sC --top-ports 1000 -iL /scans/$(notdir $(TARGETS)) \
		-oA /scans/results/service-$(STAMP)

scan-udp: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -sU --top-ports 100 -iL /scans/$(notdir $(TARGETS)) \
		-oA /scans/results/udp-$(STAMP)

# --- import do DefectDojo ---
# Wymaga DD_API_KEY i DD_ENGAGEMENT_ID w .env (patrz .env.example: uzupelnij
# PO pierwszym zalogowaniu sie do UI DefectDojo -> Configuration -> API key).
# Uzycie: make import-defectdojo FILE=scans/results/fast-20261121-120000.xml
import-defectdojo:
	@if [ -z "$(FILE)" ]; then echo "Podaj FILE=sciezka/do/wyniku.xml"; exit 1; fi
	source .env && curl -sS \
		-H "Authorization: Token $$DD_API_KEY" \
		-F "scan_type=Nmap Scan" \
		-F "engagement=$$DD_ENGAGEMENT_ID" \
		-F "file=@$(FILE)" \
		http://localhost:8080/api/v2/import-scan/

clean:
	rm -f $(OUT_DIR)/*.xml $(OUT_DIR)/*.nmap $(OUT_DIR)/*.gnmap
