# Asia - Attack Surface Intelligence Aggregator

**HackNation 2026, zadanie CBI AGH: Attack Surface Intelligence.** Nazwa projektu w zgłoszeniu: *Asia -
Attack Surface Intelligence Aggregator*. W kodzie i dokumentacji skrót **ASI**.

Prototyp systemu do **cyklicznego discovery scanu dużych sieci (10 000+ adresów IP)**, przygotowany na
HackNation 2026 dla Centrum Bezpieczeństwa Informacji AGH (wyzwanie *Attack Surface Intelligence*).

ASI wczytuje listę celów, dzieli ją na paczki dobierane do prędkości skanowania i uruchamia gotowe skanery
(nmap, httpx, nuclei). Wykrywa aktywne hosty, usługi, technologie webowe, CMS-y, panele administracyjne,
środowiska testowe, nagłówki i ciasteczka. **Porównuje kolejne przebiegi**: oznacza usługi nowe, znikające,
zmienione i niestabilne. Wyniki trafiają do **DefectDojo**: ASI jest źródłem danych (feedem) dla DD, nie
jego zamiennikiem. Całość obsługuje się z **panelu web z rolami**, a dane są **szyfrowane w spoczynku**.

Repozytorium publiczne (link ze zgłoszenia): **https://github.com/Ch3shireDev/awesome-surface-intelligence**
Klon: `git clone https://github.com/Ch3shireDev/awesome-surface-intelligence.git && cd awesome-surface-intelligence`.

## Uruchomienie

Wymagania: Linux z dockerem i pluginem compose, `make`, `openssl`. Wszystko inne (nmap, httpx, nuclei,
PostgreSQL, DefectDojo) działa w kontenerach.

```bash
git clone https://github.com/Ch3shireDev/awesome-surface-intelligence.git asi && cd asi
make env      # .env z wygenerowanymi sekretami, hasłami i kluczami szyfrowania
make up       # DefectDojo, baza ASI (szyfrowana), skaner i panel web
make demo     # lab testowy -> przebieg 1 -> zmiany w labie -> przebieg 2 -> porównanie + eksport do DD
```

Pierwszy `make up` buduje obrazy i pobiera DefectDojo, co zajmuje kilka minut. `make demo` trwa około 2 minut.

**Jak testować krok po kroku** (lab → 2 przebiegi → edycja znalezisk → import → role → eksport → DefectDojo →
szyfrowanie → bezpieczeństwo, z oczekiwanymi wynikami): [`docs/guide/jury.md`](docs/guide/jury.md).

| co | adres | login |
|---|---|---|
| panel ASI | http://127.0.0.1:18090 | `admin`, hasło: `grep ASI_ADMIN_PASSWORD .env` |
| DefectDojo | http://127.0.0.1:8080 | `admin`, hasło: `grep DD_ADMIN_PASSWORD .env` |

Wszystkie porty (żeby nie pomylić paneli: `asi server` to główny panel na 18090, `asi serve` to stary podgląd plików na 8095):

| port | co to jest | kto go stawia | logowanie |
|---|---|---|---|
| **18090** | **panel ASI** (`asi server`): dashboard, assety, cele, skany, harmonogram, role, eksport. **To jest główny interfejs.** | `make up` (kontener `nmap-scanner`), `ASI_WEB_ADDR` | tak (`admin` + `ASI_ADMIN_PASSWORD`) |
| 8091 | postęp skanu uruchomionego **z panelu**; nie otwierasz go osobno, panel pokazuje go pod `/live/` | panel przy starcie skanu, `ASI_LIVE_ADDR` | przez panel |
| 8094 | postęp skanu uruchomionego **z terminala**, działa tylko w trakcie tego skanu | `make asi-scan` (`asi scan -ui`) | nie (tylko `127.0.0.1`) |
| 8095 | **stary** panel plikowy (`asi serve`, bez „r”): historia i diff z katalogu `results/`, bez bazy i ról. Zastąpiony przez 18090, zostaje do podglądu samych plików | `make asi-serve` | nie (tylko `127.0.0.1`) |
| 8080 | DefectDojo (na fatusia-1: **18080**, decyzja 22) | `make up`, `DD_PORT` | tak (`admin` + `DD_ADMIN_PASSWORD`) |
| 4173 | ta dokumentacja | `make docs` | — |

Panel słucha domyślnie tylko na `127.0.0.1`. Dostęp z innej maszyny: `ASI_WEB_ADDR=0.0.0.0:18090` w `.env`
i `make up`.

### Własne cele

```bash
cp targets/example.csv targets/targets.csv   # IP, zakresy CIDR, domeny; też JSON i TXT
make asi ARGS=plan                           # co zostanie przeskanowane, a co pominięte i dlaczego
make asi-scan                                # skan z postępem na żywo i eksportem do DefectDojo
```

Cele można też dodać w panelu (zakładka **Cele**: formularz albo import CSV/JSON), a skany uruchamiać
ręcznie lub z harmonogramu (zakładka **Skany**).

## Co pokazuje demo

`make demo` stawia własny lab (sieć dokumentacyjna `192.0.2.0/24`, 8 hostów: WordPress, Jenkins,
staging z panelem admina, Redis bez hasła, stary PHP, usługa niestabilna), skanuje go, zmienia lab i
skanuje ponownie:

| zmiana w labie | co wykrywa ASI |
|---|---|
| host `legacy` znika | host *nie odpowiada (do potwierdzenia)*, po kolejnych brakach *zniknął* |
| `app` zmienia serwer | *zmiana usługi* z tabelą przed → po |
| dochodzi `jenkins` | nowe usługi, Jenkins 2.401.1, sygnatury |
| usługa włącza się i wyłącza | *niestabilna (flapping)* |

Wyniki: panel (Dashboard, Assety, porównanie przebiegów), terminal (`make asi ARGS=diff`) i DefectDojo
(produkt `ASI lab`).

## Pokrycie wymagań

| wymaganie z treści zadania | jak | szczegóły |
|---|---|---|
| lista IP, CIDR, domen (ręcznie, CSV, JSON) | formularz i import w panelu, pliki CSV/JSON/TXT | [cele](docs/guide/targets.md) |
| wielowątkowy skan, czas trwania, podział na podgrupy | pula workerów nmapa, paczki dobierane do zmierzonej prędkości, czas każdej paczki | [podział](docs/guide/chunking.md) |
| duże zakresy (10 000+ IP) | test 16 384 adresów: 86 s od startu do zapisu w bazie | [skala](docs/guide/scale.md) |
| aktywne hosty, usługi | discovery sondami TCP na typowych portach (ICMP opcjonalnie), `nmap -sV` na żywych hostach | [architektura](docs/guide/architecture.md) |
| HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | httpx | [fingerprint](docs/guide/fingerprint.md) |
| CMS, framework, serwer, staging, panel admina | httpx (technologie) + nuclei z naszymi sygnaturami | [fingerprint](docs/guide/fingerprint.md) |
| własne sygnatury detekcyjne | szablony nuclei w `signatures/`, tylko detekcja | [`signatures/README.md`](signatures/README.md) |
| porównanie przebiegów: nowe, znikające, zmienione | stany assetów, potwierdzanie zniknięć, porównanie dowolnych dwóch przebiegów | [historia](docs/guide/history.md), [diff](docs/guide/diff.md) |
| hosty niestabilne, różnice zależne od pory dnia | flapping, godziny odpowiedzi | [historia](docs/guide/history.md) |
| okno czasowe, częstotliwość, wznawianie | harmonogram (cron + okno), niedokończone cele wznawiane w kolejnym oknie | [harmonogram](docs/guide/schedule.md) |
| ograniczanie tempa, bezpieczeństwo skanowania | globalny limit pps, kontrola zakresu, dozwolone porty, sygnatury bez exploitów | [bezpieczeństwo](docs/guide/safety.md) |
| RBAC, 4 role | `admin`, `operator`, `analyst`, `viewer`, audit log | [panel](docs/guide/gui.md) |
| edycja danych trwała między skanami | tagi, notatki, ocena analityka na assecie | [panel](docs/guide/gui.md) |
| dashboard najważniejszych znalezisk | ocena „ciekawości” 0–100 z powodami, zmiany, niestabilne | [wnioski](docs/guide/insights.md) |
| szyfrowanie w spoczynku | PostgreSQL z TDE (`pg_tde`) + pola wrażliwe AES-256-GCM, `make crypto-check` | [szyfrowanie](docs/guide/encryption.md) |
| import i eksport JSON/CSV | import nmap XML/CSV/JSON/JSONL, eksport CSV/JSON | [import](docs/guide/import.md) |
| integracja z DefectDojo | 4 stałe testy z historią: usługi, zmiany, httpx, nuclei | [DefectDojo](docs/guide/defectdojo.md) |

Pełna lista ze stanem każdego punktu: [`docs/status.md`](docs/status.md).

## Architektura

```
panel web (role) ──┐
CLI `asi` ─────────┼─► PostgreSQL ASI (TDE + pola AES-GCM): cele, przebiegi, obserwacje, assety, historia
harmonogram ───────┘          ▲
        │                     │ obserwacje
        ▼                     │
  paczki celów ─► nmap (discovery, usługi) ─► httpx (HTTP) ─► nuclei (sygnatury)
                                                                    │
                                    eksport (reimport do stałych testów) ─► DefectDojo
```

Panel jest nakładką na komendy CLI i bazę (jak w MISP). Każdy skaner to wymienny adapter zwracający
wspólny format obserwacji. Więcej: [architektura](docs/guide/architecture.md), [wizja](docs/VISION.md),
[decyzje projektowe](docs/DECISIONS.md).

## Weryfikacja

```bash
make crypto-check                # dowód szyfrowania: tabele, WAL i pola wrażliwe (9 kontroli)
make asi ARGS='changes'          # zdarzenia ostatniego przebiegu
make asi ARGS='diff'             # porównanie z poprzednim przebiegiem tego samego zbioru
make lab-down                    # usunięcie labu
```

## Dokumentacja

Przewodniki w [`docs/guide/`](docs/guide/) (po polsku; strona VitePress: `make docs`), w tym
[komendy CLI](docs/guide/cli.md), [adaptery skanerów](docs/guide/adapters.md),
[baza danych](docs/guide/database.md) i [lab testowy](docs/guide/lab.md).

Praca nad kodem (build, testy, dokumentacja, zasady w repo): [`CONTRIBUTING.md`](CONTRIBUTING.md).
