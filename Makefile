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
# Kazdy cel pisze XML do /scans/results (zamontowane jako ./scans w repo),
# zeby mozna bylo od razu zaimportowac go do DefectDojo (scan_type=Nmap Scan).

scan-discover: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -sn -iL /scans/$(notdir $(TARGETS)) \
		-oX /scans/results/discover-$(STAMP).xml

scan-fast: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -T4 -F -iL /scans/$(notdir $(TARGETS)) \
		-oX /scans/results/fast-$(STAMP).xml

scan-full: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -T4 -p- -iL /scans/$(notdir $(TARGETS)) \
		-oX /scans/results/full-$(STAMP).xml

scan-service: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -T4 -sV -sC --top-ports 1000 -iL /scans/$(notdir $(TARGETS)) \
		-oX /scans/results/service-$(STAMP).xml

scan-udp: $(OUT_DIR)
	docker compose exec -T nmap-scanner \
		nmap -sU --top-ports 100 -iL /scans/$(notdir $(TARGETS)) \
		-oX /scans/results/udp-$(STAMP).xml

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
	rm -f $(OUT_DIR)/*.xml
