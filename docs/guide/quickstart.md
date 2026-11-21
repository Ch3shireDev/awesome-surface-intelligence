# Szybki start

## Na VM (tak testuje jury)

Na hoście tylko docker + compose, `make`, `openssl`. nmap i `asi` są w kontenerze `nmap-scanner`
(`network_mode: host`, `NET_RAW`).

```bash
git clone https://github.com/Ch3shireDev/awesome-surface-intelligence.git asi && cd asi
make env                                # .env: sekrety + hasło admina DefectDojo
make up                                 # DefectDojo 3.5.202 :8080 + nmap-scanner
cp targets/example.csv targets/targets.csv
make asi ARGS=plan                      # co będzie skanowane, a co pominięte i dlaczego
make asi-scan                           # pasek w terminalu + panel http://127.0.0.1:8090 + upload live do DD
make asi ARGS=diff                      # zmiany względem poprzedniego przebiegu
make asi-serve                          # panel z historią bez skanowania
```

`asi` czyta z `.env` dane DefectDojo (`DD_PORT`, `DD_ADMIN_USER`, `DD_ADMIN_PASSWORD`, `DD_PRODUCT*`)
i sam pobiera token API. Nie trzeba ręcznie kopiować tokenu.

## Na maszynie deweloperskiej

| narzędzie | po co |
|---|---|
| Go 1.27 | `make build`, `make test` |
| nmap ≥ 7.9 | skan bez kontenera (`-sT`, bez roota) |
| Node + pnpm | tylko dokumentacja (`make docs`) |

```bash
make build && make test
set -a; . ./.env; set +a                # DD_* dla uploadu
./asi scan -ui 127.0.0.1:8090 -upload live
./asi diff
```

## Typowe warianty

```bash
./asi scan -targets targets/targets.json          # wejście JSON zamiast CSV
./asi scan -window 2h                             # okno czasowe: po 2h przerwij
./asi scan -parallel 10 -rate 1000                # więcej workerów, globalny limit 1000 pps
./asi scan -chunk 8                               # stała paczka zamiast adaptacyjnej
./asi scan -skip-discovery                        # sieć tnie sondy discovery -> skanuj wszystko
./asi upload -format nmap                         # surowy XML nmapa do DefectDojo (stały test asi-nmap)
```

## Dokumentacja lokalnie

```bash
make docs                              # http://127.0.0.1:4173
```
