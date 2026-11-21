# Asia - Attack Surface Intelligence Aggregator

**HackNation 2026, zadanie CBI AGH: Attack Surface Intelligence.** Nazwa projektu w zgłoszeniu: *Asia -
Attack Surface Intelligence Aggregator*. W kodzie i dokumentacji skrót **ASI**.

System do cyklicznego discovery scanu dużych sieci (10 000+ IP). Wczytuje listę celów, skanuje ją
nmapem w adaptacyjnych paczkach, pokazuje postęp na żywo (CLI i panel web), porównuje przebiegi
i eksportuje wyniki do DefectDojo.

- Architektura docelowa: [`docs/VISION.md`](docs/VISION.md)
- Co jest zrobione, a co nie: [`docs/status.md`](docs/status.md)
- Zadania i podział pracy: [`docs/TASKS.md`](docs/TASKS.md)
- Dla agentów AI: [`AGENTS.md`](AGENTS.md)

## Start na VM (docker + make + openssl)

```bash
make env                      # .env z sekretami i hasłem admina DefectDojo
make up                       # DefectDojo :8080 + kontener skanera (nmap + asi)
cp targets/example.csv targets/targets.csv
make asi ARGS=plan            # co będzie skanowane, a co pominięte i dlaczego
make asi-scan                 # skan: pasek w terminalu, panel http://127.0.0.1:8090, upload do DD
make asi ARGS=diff            # zmiany względem poprzedniego przebiegu
```

DefectDojo: http://localhost:8080, login `admin`, hasło: `grep DD_ADMIN_PASSWORD .env`.
Z hosta VM forwardujesz 8080/tcp (DD) i opcjonalnie 8090/tcp (panel asi).

Test dymny samego stacku (stary PoC na skryptach): `echo 127.0.0.1 > scans/targets.txt && make poc`.

## Praca deweloperska (Go 1.27, pnpm)

```bash
make build && make test
set -a; . ./.env; set +a      # DD_* dla ./asi upload / scan -upload
./asi scan -targets targets/targets.csv -ui 127.0.0.1:8090 -upload live
make docs                     # dokumentacja na http://127.0.0.1:4173
make sync                     # git pull --rebase + push (origin: blackarch:~/repos/asi.git)
```
