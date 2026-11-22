# Praca nad kodem

Opis systemu: [`README.md`](README.md). Projekt i uzasadnienia: [architektura](docs/guide/architecture.md),
[decyzje](docs/DECISIONS.md). Po zmianie funkcjonalnej zaktualizuj [status](docs/status.md).

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
- Sekrety tylko w `.env`. Skanujemy wyłącznie zatwierdzone cele i własny lab.
