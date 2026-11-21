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

.PHONY: help env env-sync up down nuke ps logs nmap-shell \
        scan-discover scan-fast scan-full scan-service scan-udp \
        import-defectdojo import-latest poc clean \
        build test asi asi-scan asi-serve docs sync \
        lab-up lab-down lab-ps demo env-keys crypto-check

help:
	@echo "Cele:"
	@echo "  make env-sync         - dopisz do istniejacego .env brakujace klucze z .env.example (robi to tez make up)"
	@echo "  make env              - utworz .env z .env.example z wygenerowanymi sekretami"
	@echo "  make up               - odpal caly stack (DefectDojo + scanner)"
	@echo "  make down             - zatrzymaj stack"
	@echo "  make nuke             - zatrzymaj stack i USUN dane (wolumeny postgres/valkey/media)"
	@echo "  make ps               - status kontenerow"
	@echo "  make logs             - sledz logi DefectDojo (uwsgi)"
	@echo "  make nmap-shell       - wejdz do kontenera skanera"
	@echo "  make scan-discover    - ping sweep (-sn) po TARGETS"
	@echo "  make scan-fast        - szybki skan top-portow (-T4 -F)"
	@echo "  make scan-full        - pelny skan TCP (-p-), wolny"
	@echo "  make scan-service     - wykrywanie wersji/uslug (-sV -sC) na top-portach"
	@echo "  make scan-udp         - top porty UDP (bardzo wolne)"
	@echo "  make import-defectdojo FILE=scans/results/xxx.xml  - import XML do DefectDojo"
	@echo "  make env-keys         - dopisz klucze szyfrowania (SEC-6) do istniejacego .env"
	@echo "  make crypto-check     - dowod szyfrowania at rest asi-db (TDE + pola AES-GCM)"
	@echo "  make import-latest    - import najnowszego scans/results/*.xml"
	@echo "  make poc              - jeden przebieg PoC: discover + fast + import obu do DD"
	@echo "  make clean            - usun lokalne wyniki skanow"
	@echo ""
	@echo "Silnik asi (Go):"
	@echo "  make up               - panel web ASI na http://127.0.0.1:8090 (login: ASI_ADMIN_USER/ASI_ADMIN_PASSWORD z .env)"
	@echo "  make asi ARGS='plan'  - dowolna komenda asi w kontenerze skanera (cele: targets/, wyniki: results/)"
	@echo "  make asi-scan         - skan targets/targets.csv: panel CLI :8094, upload live do DefectDojo"
	@echo "  make asi-serve        - stary panel plikowy z historia/diffem (:8095)"
	@echo "  make build            - lokalny build ./asi (wymaga Go na hoscie - dev)"
	@echo "  make test             - go vet + go test (wymaga Go na hoscie - dev)"
	@echo "  make docs             - dokumentacja VitePress na :4173 (wymaga pnpm - dev)"
	@echo "  make sync             - git pull --rebase + push do origin (repo blackarch przez ssh)"
	@echo ""
	@echo "Lab i demo (docker/lab, siec 192.0.2.0/24, cele targets/lab.csv):"
	@echo "  make lab-up           - postaw lab w stanie przebiegu 1"
	@echo "  make lab-down         - usun lab (wszystkie profile)"
	@echo "  make demo             - lab od zera -> skan 1 -> zmiany w labie -> skan 2 -> diff (+ upload do DD)"

# Tworzy .env tylko jesli nie istnieje (nie nadpisuje istniejacego).
env:
	@if [ -f .env ]; then echo ".env juz istnieje - nie nadpisuje"; exit 0; fi; \
	ASI_DBP=$$(openssl rand -hex 16); \
	sed -e "s|^DD_SECRET_KEY=.*|DD_SECRET_KEY=$$(openssl rand -hex 32)|" \
	    -e "s|^DD_CREDENTIAL_AES_256_KEY=.*|DD_CREDENTIAL_AES_256_KEY=$$(openssl rand -hex 16)|" \
	    -e "s|^DD_ADMIN_PASSWORD=.*|DD_ADMIN_PASSWORD=$$(openssl rand -hex 12)|" \
	    -e "s|CHANGE_ME_ASI_DB|$$ASI_DBP|g" \
	    -e "s|CHANGE_ME_ASI_ADMIN|$$(openssl rand -hex 12)|" \
	    -e "s|^ASI_ENCRYPTION_KEYS=.*|ASI_ENCRYPTION_KEYS=k1:$$(openssl rand -base64 32)|" \
	    .env.example > .env && chmod 600 .env && \
	echo "Utworzono .env (hasla adminow: grep -E 'DD_ADMIN_PASSWORD|ASI_ADMIN_PASSWORD' .env)"

# Dopisuje do ISTNIEJACEGO .env klucze szyfrowania (SEC-6), jesli ich brak.
# Nie rusza istniejacych wartosci. Po tym: make up (nowa baza z TDE).
env-keys:
	@grep -q '^COMPOSE_FILE=' .env || { printf '\n# szyfrowanie at rest (SEC-6)\nCOMPOSE_FILE=docker-compose.yml:docker-compose.crypto.yml\n' >> .env; echo "dopisano COMPOSE_FILE (TDE dla asi-db)"; }
	@if grep -q '^ASI_ENCRYPTION_KEYS=.\+' .env; then echo "ASI_ENCRYPTION_KEYS juz ustawione"; \
	else sed -i '/^ASI_ENCRYPTION_KEYS=$$/d' .env; echo "ASI_ENCRYPTION_KEYS=k1:$$(openssl rand -base64 32)" >> .env; echo "dopisano ASI_ENCRYPTION_KEYS (klucz k1)"; fi

# Dopisuje brakujace klucze z .env.example do istniejacego .env (bez zmiany istniejacych).
env-sync:
	@sh scripts/env-sync.sh

# nginx DD trzyma IP upstreamu uwsgi z chwili startu; gdy `up` odtworzy uwsgi, nginx daje 502,
# wiec restartujemy go po kazdym up (tani, ~1 s).
up: env-sync
	docker compose up -d --build
	@docker compose restart nginx >/dev/null 2>&1 && echo "nginx DD zrestartowany (bez 502 po odtworzeniu uwsgi)" || true

down:
	docker compose down

nuke:
	docker compose down -v

ps:
	docker compose ps -a

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
# Import idzie z kontenera nmap-scanner (curl+jq w obrazie, env z .env),
# skrypt: docker/nmap/scripts/import-defectdojo.sh. Token API pobierany
# automatycznie loginem admina, jesli DD_API_KEY w .env jest pusty.
# Product Type/Product/Engagement tworza sie same (DD_PRODUCT_* w .env).
# Uzycie: make import-defectdojo FILE=scans/results/fast-20261121-120000.xml
import-defectdojo:
	@if [ -z "$(FILE)" ]; then echo "Podaj FILE=scans/results/plik.xml"; exit 1; fi
	docker compose exec -T nmap-scanner /opt/asi/import-defectdojo.sh /scans/$(patsubst scans/%,%,$(FILE))

import-latest:
	@f=$$(ls -t $(OUT_DIR)/*.xml 2>/dev/null | head -1); \
	if [ -z "$$f" ]; then echo "Brak plikow XML w $(OUT_DIR)"; exit 1; fi; \
	$(MAKE) --no-print-directory import-defectdojo FILE=$$f

# Jeden przebieg petli PoC. Odpal dwa razy (np. po wlaczeniu/wylaczeniu
# uslugi albo hosta) - w DD w testach nmap-discover / nmap-fast widac diff.
poc:
	$(MAKE) --no-print-directory scan-discover STAMP=$(STAMP)
	$(MAKE) --no-print-directory scan-fast STAMP=$(STAMP)
	$(MAKE) --no-print-directory import-defectdojo FILE=$(OUT_DIR)/discover-$(STAMP).xml
	$(MAKE) --no-print-directory import-defectdojo FILE=$(OUT_DIR)/fast-$(STAMP).xml

clean:
	rm -f $(OUT_DIR)/*.xml $(OUT_DIR)/*.nmap $(OUT_DIR)/*.gnmap $(OUT_DIR)/*.json

# --- silnik asi (Go) ---
# Na VM: asi dziala w kontenerze nmap-scanner (network_mode: host, NET_RAW),
# czyta .env (DD_*), cele z ./targets, wyniki do ./results.
# Lokalnie (dev): `make build` i ./asi ... z `set -a; . ./.env`.
ASI_TARGETS ?= targets/targets.csv
ARGS ?= help

asi:
	docker compose exec nmap-scanner asi $(ARGS)

asi-scan:
	docker compose exec nmap-scanner asi scan -targets $(ASI_TARGETS) -ui 127.0.0.1:8094 -upload live

# Dowod szyfrowania w spoczynku (docs/guide/encryption.md): TDE wlaczone, tabele
# tde_heap, szyfrowany WAL, brak jawnego tekstu w plikach bazy, pola _enc z AES-GCM.
crypto-check:
	docker compose exec -T asi-db sh < docker/asi-db/crypto-check.sh

asi-serve:
	docker compose exec nmap-scanner asi serve -addr 127.0.0.1:8095

build:
	go build -o asi ./cmd/asi

test:
	go vet ./... && go test ./...

docs:
	cd docs && pnpm install --frozen-lockfile && pnpm build && pnpm preview --host 127.0.0.1 --port 4173

# Jedno repo, synchronizacja przez git po ssh (origin = blackarch:~/repos/asi.git).
sync:
	git pull --rebase --autostash && git push

# --- lab i demo (SEC-3) ---
# Osobny projekt compose `asi-lab` (docker/lab/compose.yml), siec TEST-NET-1 192.0.2.0/24.
# Skan idzie z kontenera nmap-scanner (network_mode: host), wyniki do results/lab, DD: produkt "ASI lab".
# Porty ograniczone do tych, ktore wystawia lab - demo trwa ~1 min zamiast top-1000.
LAB         := docker compose -f docker/lab/compose.yml
LAB_TARGETS ?= targets/lab.csv
LAB_UPLOAD  ?= end
LAB_NMAP    ?= -sT -sV --version-light -Pn -p 22,23,80,443,6379,8000,8080 -T4 --max-retries 2 --open
LAB_SCAN     = docker compose exec -T nmap-scanner asi scan -targets $(LAB_TARGETS) -out results/lab \
               -upload $(LAB_UPLOAD) -product "ASI lab" -engagement demo -nmap "$(LAB_NMAP)"

lab-up:
	$(LAB) up -d

lab-down:
	$(LAB) --profile pass2 down --remove-orphans

lab-ps:
	$(LAB) --profile pass2 ps

demo:
	$(LAB) --profile pass2 down --remove-orphans
	$(LAB) up -d
	@echo "== przebieg 1: stan wyjsciowy labu"
	$(LAB_SCAN)
	@echo "== zmiany w labie: legacy (.14) znika, app (.15) zmienia serwer, jenkins (.16) dochodzi"
	$(LAB) rm -sf legacy app
	$(LAB) --profile pass2 up -d app-v2 jenkins
	@echo "== przebieg 2"
	$(LAB_SCAN)
	docker compose exec -T nmap-scanner asi diff -results results/lab
