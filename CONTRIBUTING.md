# Praca nad kodem

Dla zespołu i agentów AI. Opis projektu dla czytelnika z zewnątrz: [`README.md`](README.md).

## Gdzie co jest

- [`AGENTS.md`](AGENTS.md): zasady dla agentów AI (zakres skanu, sekrety, konwencje, mapa katalogów).
  `CLAUDE.md` tylko go importuje.
- [`docs/VISION.md`](docs/VISION.md): architektura docelowa i model danych.
- [`docs/DECISIONS.md`](docs/DECISIONS.md): log decyzji z uzasadnieniami.
- [`docs/ROADMAP.md`](docs/ROADMAP.md): postęp etapów i dziennik zmian.
- [`docs/TASKS.md`](docs/TASKS.md): zadania i podział (DEV / SEC). Przed kodem zarezerwuj zadanie commitem.
- [`docs/status.md`](docs/status.md): wymagania z treści zadania i ich stan. Aktualizuj po każdej zmianie funkcjonalnej.
- [`docs/MENTOR.md`](docs/MENTOR.md): ustalenia z konsultacji z mentorem CBI AGH (wiążące).

## Repozytorium i synchronizacja

- Robocze `origin` zespołu: bare repo `daniel@blackarch:~/repos/asi.git`, klony w `~/asi` na każdej maszynie.
- Publiczne repo dla jury: https://github.com/Ch3shireDev/awesome-surface-intelligence. Przed pierwszym
  pushem przegląd historii pod kątem sekretów i realnych adresów (zadanie SEC-9).
- `make sync`: `git pull --rebase` + `git push`. Małe commity, sync przed i po pracy.
- Repo nie leży w `~/sync` (Syncthing psuje `.git` i rozsyła `.env`).

## Build, testy, dokumentacja

Na maszynie deweloperskiej: Go 1.27, opcjonalnie nmap ≥ 7.9 i Node + pnpm (tylko dokumentacja).

```bash
make build && make test          # go vet + go test
set -a; . ./.env; set +a         # zmienne DD_* / ASI_* dla ./asi poza kontenerem
./asi scan -targets targets/targets.csv -upload live   # wyniki w panelu ./asi server (:18090)
make docs                        # VitePress na http://127.0.0.1:4173
make slides                      # prezentacja (Beamer) -> docs/presentation/asi.pdf
```

Bez Go na hoście testy można uruchomić w kontenerze:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/src -w /src -e HOME=/tmp \
  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod golang:1.27.4-alpine sh -c 'go vet ./... && go test ./...'
```

Po `git pull` z nowymi zmiennymi: `make up` sam dopisuje brakujące klucze do `.env` (`make env-sync`).

## Stary PoC

`make poc` (nmap + skrypty `docker/nmap/scripts`, testy `nmap-discover` / `nmap-fast` w DefectDojo)
zostaje jako test dymny stacku: `echo 127.0.0.1 > scans/targets.txt && make poc`.

## Konwencje

- Kod Go: biblioteka standardowa, wyjątki zapisane w `DECISIONS.md` (np. pgx).
- Dokumentacja i commity po polsku. Nowa strona przewodnika = wpis w `docs/.vitepress/config.mts`.
- Sekrety tylko w `.env`. Skanujemy wyłącznie zatwierdzone cele i własny lab (`AGENTS.md`).
