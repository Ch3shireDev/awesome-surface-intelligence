# Szybki start

## 1. Uruchom

Potrzebujesz Linuksa z dockerem i pluginem compose, `make` i `openssl`. Skanery i bazy są w kontenerach.

```bash
git clone https://github.com/Ch3shireDev/awesome-surface-intelligence.git asi && cd asi
make env     # hasła i klucze w .env
make up      # cały system, za pierwszym razem kilka minut
make demo    # lab testowy i dwa skany ze zmianami, około 2-3 minut
```

## 2. Zaloguj się

| co | adres | login `admin`, hasło z |
|---|---|---|
| panel ASI | http://127.0.0.1:18090 | `grep ASI_ADMIN_PASSWORD .env` |
| DefectDojo | http://127.0.0.1:8080 | `grep DD_ADMIN_PASSWORD .env` |

## 3. Obejrzyj wynik demo

- **Dashboard**: najważniejsze znaleziska i zmiany.
- **Assety**: hosty i porty, po kliknięciu szczegóły i historia.
- **Skany**: przebiegi i ich porównanie.
- **DefectDojo**: produkt `ASI lab`.

Pełny scenariusz z oczekiwanymi wynikami: [ścieżka testowania](jury.md).

## 4. Przeskanuj własne cele

Skanuj tylko adresy, na które masz zgodę właściciela.

```bash
cp targets/example.csv targets/targets.csv   # wpisz swoje cele
make asi ARGS=plan                           # co będzie skanowane, a co pominięte
make asi-scan                                # skan i wysyłka do DefectDojo
make asi ARGS=diff                           # zmiany od poprzedniego przebiegu
```

To samo zrobisz w panelu, w zakładkach **Cele** i **Skany**.

## Gdy coś nie działa

| objaw | co zrobić |
|---|---|
| panel lub DefectDojo nie odpowiada | `make ps`, `make logs`; DefectDojo po starcie wykonuje migracje |
| port 8080 jest zajęty | ustaw `DD_PORT` w `.env`, potem `make up` |
| port 18090 jest zajęty | ustaw `ASI_WEB_ADDR` w `.env`, potem `make up` |
| cel nie jest skanowany | `make asi ARGS=plan` podaje powód pominięcia |

## Na maszynie deweloperskiej

| narzędzie | po co |
|---|---|
| Go 1.27 | `make build`, `make test` |
| nmap ≥ 7.9 | skan bez kontenera (`-sT`, bez roota) |
| Node + pnpm | tylko dokumentacja (`make docs`) |

```bash
make build && make test
set -a; . ./.env; set +a                # DD_* dla uploadu
./asi scan -upload live                 # wyniki w panelu (asi server), pasek w terminalu
./asi diff
```

## Typowe warianty

```bash
./asi scan -targets targets/targets.json          # wejście JSON zamiast CSV
./asi scan -window 2h                             # okno czasowe: po 2h przerwij
./asi scan -parallel 10 -rate 1000                # więcej workerów, globalny limit 1000 pps
./asi scan -chunk 8                               # stała paczka zamiast adaptacyjnej
./asi scan -skip-discovery                        # sieć tnie sondy discovery -> skanuj wszystko
./asi upload -format nmap                         # surowy XML nmapa do DefectDojo (bez historii)
```

## Dokumentacja lokalnie

```bash
make docs                              # http://127.0.0.1:4173
```
