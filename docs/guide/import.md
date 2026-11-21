# Import wyników skanów

Wymaganie z PDF (minimum): *„import wyników skanów w formie JSON lub CSV”*, a test jury obejmuje import (DEV-6).
Plik z wynikami skanu wykonanego gdzie indziej staje się **zwykłym przebiegiem** w bazie: ma przeliczone stany
(nowe, braki, zmiany), jest widoczny w panelu i eksportowalny.

```bash
asi import wyniki.xml                                   # nmap -oX
asi import -coverage none -at 2026-11-20T22:00:00Z dane.csv
```

W panelu: **Skany → Import wyników skanów** (rola `operator`).

## Formaty (wykrywane automatycznie)

| format | rozpoznanie | co trafia do bazy |
|---|---|---|
| **nmap XML** (`-oX`) | `.xml` / `<nmaprun>` | hosty, porty, usługi; pokrycie dokładne (hosty z pliku + porty z `<scaninfo>`) |
| **CSV z nagłówkiem** | `.csv` | kolumny (wielkość liter dowolna): `ip`/`host`/`address`, `port`, `proto`/`protocol`, `service`/`name`, `product`, `version`, `state`; także nasz eksport assetów (`key, kind, ip, port, state, service…`, czyli pełny „roundtrip”) |
| **JSON** | `[` / `{` | tablica wierszy jak w CSV albo `{"results"\|"services"\|"findings"\|"hosts": [...]}`; nasze `observations.json` (pełne obserwacje) |
| **JSONL httpx / nuclei** | `.jsonl` | obserwacje `http` / `signature` (+ host i port) |

Wiersze ze stanem `closed`, `down`, `gone` albo `missing` nie są obserwacjami (nie tworzą assetów). Wiersze bez
poprawnego IP są pomijane, a ich lista (do 20) wraca w odpowiedzi. Plik jest zapisany jako dowód w `raw_outputs`,
szyfrowany jak surowe wyjścia skanerów. Limit wielkości: 64 MB.

## Pokrycie, czyli kiedy import oznacza coś jako zniknięte

| tryb | znaczenie |
|---|---|
| `auto` (domyślny) | plik to pełny skan **tych hostów**. Port, którego brakuje w pliku, a był znany wcześniej, dostaje `missing`, ale tylko na hostach z pliku i tylko dla portów, które plik obejmował (nmap: `scaninfo`; CSV/JSON: suma portów występujących w pliku). Hosty spoza pliku się nie zmieniają. |
| `none` | tylko dodaje obserwacje: nowe assety, powroty, zmiany. Nic nie zniknie przez import. |

Import starszy niż ostatni przeliczony przebieg (`-at` w przeszłości) jest zapisywany tylko jako historia, a stany
assetów się nie zmieniają (inaczej import starego pliku „cofnąłby” rzeczywistość).

Mniej szczegółowa obserwacja tej samej usługi (np. CSV bez kolumny `version`) **nie** jest zmianą. Zostaje
bogatszy odcisk z wcześniejszego skanu (ta sama reguła działa, gdy nmap w którymś przebiegu nie odczyta wersji).

## Testy

`internal/importer/importer_test.go` (wszystkie formaty, roundtrip eksportu, odrzucenie nieznanego formatu) oraz
end-to-end na labie (21.11): eksport assetów → usunięcie jednego portu → import (`missing` dla tego portu);
XML nmapa → bez zmian; import ze starą datą → tylko historia; JSON przez API z `coverage=none`; zły plik →
czytelny błąd.
