# Status projektu

Stan na 21.11.2026. Legenda: ✅ zrobione i przetestowane · 🟡 częściowo · ❌ nie zrobione · ❓ wymaga decyzji.

## Wymagania ze specyfikacji

| # | wymaganie | stan | jak / co brakuje |
|---|---|---|---|
| 1 | wczytanie IP, CIDR, domen | ✅ | CSV/JSON/TXT, wspólny schemat, `asi convert`; [Format celów](/guide/targets) |
| 2 | bezpieczny, wielowątkowy skan nmap | ✅ | worker pool, `-sT`, `--version-light`, globalny `-rate` + twardy limit `ASI_MAX_RATE`; polityka SEC-8 w planie i w workerze (zakres, wykluczenia, allowlista portów i flag nmapa); [Bezpieczeństwo](/guide/safety) |
| 2 | czas trwania skanu | ✅ | `timings.csv` per faza, `run.json`, ETA na żywo |
| 2 | podział na optymalne podgrupy | ✅ | 2 fazy + adaptacyjny `Sizer` (EWMA s/host) + pamięć `tuning.json`; [Podział](/guide/chunking) |
| 3 | wykrycie aktywnych hostów | ✅ | faza discovery (`-sn`, TCP SYN/connect ping na 8 portów) |
| 3 | …w sieciach blokujących sondy | ✅ | `-skip-discovery`; profil `raw` (domyślny, `NET_RAW`) pozwala na ICMP `-PE` i ARP, profil `unprivileged` tylko connect; [Profile](/guide/safety#profile-z-surowymi-gniazdami-i-bez-roota) |
| 4 | identyfikacja usług | ✅ | `-sV --version-light`, profil `-ports auto` (pełne TCP `1-65535` dla ≤16 hostów, inaczej top 1000 **+ porty wysokiego ryzyka spoza top 1000** — Redis, MongoDB, Docker API, Kibana…), jawne `all`/`lab`/`allowed`/`top100`/`top1000`/własne w CLI i GUI (LAB-T1) |
| 4 | UDP | 🟡 | decyzja 15: domyślnie wyłączone; `ASI_ALLOW_UDP=1` włącza `-sU` tylko na 53,123,161 (DNS, NTP, SNMP), profil `raw`; [UDP](/guide/safety#udp-decyzja) |
| 5 | HTTP: tytuł, kod, nagłówki, cookies, TLS, przekierowania | ✅ | etap `http` (httpx): tytuł, status, **czas odpowiedzi `response_time_ms`** (poza `fp_hash`, kolumna `HTTP ms` i filtr wolnych w GUI, próg `ASI_HTTP_SLOW_MS=500`, LAB-T4), nagłówki, nazwy ciasteczek, `Location`, certyfikat (CN/SAN/wystawca/ważność/self-signed), favicon mmh3 ([Fingerprint](/guide/fingerprint)) |
| 6 | wykrywanie technologii / CMS / IoT | ✅ | Wappalyzer w httpx + sygnatury: generator CMS, WordPress po ścieżkach, wersje PHP/Jenkins, hashe favicony; **IoT (SEC-10): 9 sygnatur** — kamery Hikvision/Dahua/ogólne wizyjne, RouterOS, LuCI, drukarki, NAS (Synology/QNAP/TrueNAS), wbudowane serwery firmware'u (`GoAhead-Webs`, `Boa`, `uc-httpd`), opis UPnP; [Fingerprint](/guide/fingerprint#sygnatury-iot-sec-10) |
| 7 | staging / panel admina | ✅ | sygnatury `asi-staging-environment` (nagłówek/tytuł/ciasteczko), `asi-admin-panel`, `asi-login-redirect`, `asi-version-endpoint` |
| 8 | porównanie przebiegów | ✅ | dwa dowolne przebiegi w GUI (Skany), `asi diff -db`, automatycznie po skanie |
| 9 | nowe / znikające / zmienione usługi | ✅ | `new / gone / changed`, plus `created/closed/reactivated` w DefectDojo |
| 10 | własne sygnatury | ✅ | nuclei tylko z `signatures/` (14 szablonów, detekcja), instrukcja „jak dodać” w `signatures/README.md`, lint bezpieczeństwa w testach |
| 11 | formularz: ręcznie + CSV/JSON | ✅ | GUI: formularz ręczny + import CSV/JSON/TXT do bazy, walidacja wejścia ([Panel web](/guide/gui)); **cele z dowolnego tekstu** (inwentarz, notatki) przez DeepSeek lub regex, z podglądem przed zapisem, CLI `asi targets-extract`, serwer MCP `asi mcp` ([Cele z tekstu](/guide/targets-ai)) |
| 12–13 | RBAC, 4 role | ✅ | lokalne role viewer/analyst/operator/admin na każdej trasie API, użytkownicy w GUI, **tokeny API w GUI (DEV-3)**: zakładka Konto, ważność 0–3650 dni, tylko hash w bazie, unieważnianie, audyt; audit log |
| 14 | edycja wartości niezależnie od skanu, trwała | ✅ | GUI + CLI: tagi, notatka, **ocena analityka** (fałszywy alarm / zaakceptowane / nadpisana ocena, trwała i eksportowana do DD), edycja celów i harmonogramów; audit log |
| 15 | czytelny interfejs + dashboard | ✅ | dashboard: kafelki, najważniejsze znaleziska, zmiany, niestabilne, wykres zmian w czasie; postęp skanu na żywo |
| 16 | szyfrowanie at-rest | ✅ | 2 warstwy (sprawdzone `make crypto-check` 9/9 także na blackarch po `asi db reseal`): TDE `pg_tde` w `asi-db` (tabele, indeksy, WAL; AES-256) + pola `_enc` AES-256-GCM w aplikacji (`ASI_ENCRYPTION_KEYS`, rotacja); dowód `make crypto-check`; [Szyfrowanie](/guide/encryption) |
| — | harmonogram, okna czasowe | ✅ | cron + okno w GUI, wznawianie niezeskanowanych celów w kolejnym oknie, wstrzymaj/wznów/anuluj ([Harmonogram](/guide/schedule)) |
| — | obsługa >10 000 IP | ✅ | 16 384 adresy w 86 s end-to-end, 49 tys. assetów w panelu ([Test skali](/guide/scale)) |
| — | ograniczanie tempa | ✅ | `-rate` globalny, `-parallel`, timeouty |
| — | eksport JSON/CSV | ✅ | assety CSV/JSON z GUI/API; `services.json`, `findings_defectdojo.json` |
| — | import wyników skanów JSON/CSV | ✅ | nmap XML, CSV, JSON, JSONL httpx/nuclei; GUI + `asi import`; pokrycie `auto`/`none`, import historyczny ([Import](/guide/import)) |
| — | hosty / usługi niestabilne | ✅ | stany `new/active/missing/gone`, `reappeared`, `flapping`, progi braków, zasady pokrycia i hierarchii ([Historia](/guide/history)); skan potwierdzający |
| — | integracja DefectDojo | ✅ | Generic Findings, reimport do stałego testu, upload na żywo; test `asi-changes` (missing/gone/flapping/zmiany, zamykane w DD, gdy warunek mija; bez `close_old` dla przebiegów częściowych, też w `asi upload`); nmap XML natywnie do stałego `asi-nmap`; httpx i nuclei natywnymi parserami DD do `asi-httpx` / `asi-nuclei` (close_old tylko przy pełnym etapie); [DefectDojo](/guide/defectdojo) |
| — | grupowanie podobnych usług, pora dnia | ✅ | grupy po produkcie/wersji i technologii; wzorce z `hours_seen` |
| — | ocena „ciekawości” | ✅ | 0–100 z powodami: port, sygnatury, TLS, świeżość, flapping; ocena analityka wygrywa ([Ocena](/guide/insights)) |
| — | tagi | ✅ | tagi celów (formularz/import) i assetów (edycja w GUI, trwałe między skanami) |
| — | dokumentacja | ✅ | ta strona (VitePress); publiczne repo: https://github.com/Ch3shireDev/awesome-surface-intelligence |
| — | repozytorium publiczne (SEC-9) | ✅ | link ze zgłoszenia; historia bez `.env`/`.dd_token`/realnych celów (sprawdzone), czysty start z GitHuba: `make env && make build && make test` ([Quickstart](/guide/quickstart#czysty-start-od-zera-sec-9-sprawdzony)) |

## Lab i demo (SEC-3, 21.11)

✅ `make demo`: własny lab w compose (`docker/lab`, 8 hostów w 192.0.2.0/24) i 2 przebiegi ze zmianami
pomiędzy. Wykrywa nowy host, zniknięty host, zmienioną usługę, zniknięte i nowe porty oraz host niestabilny.
Sprawdzone z hosta i w kontenerze skanera. Lab ma też artefakty pod fingerprint i sygnatury (WordPress,
staging, panel admina, stary PHP, Jenkins, cert TLS). Opis: [Lab testowy i demo](/guide/lab).

## Elementy tej iteracji (co i jak przetestowano)

| element | test |
|---|---|
| dwufazowy skan + adaptacja | prawdziwy skan 37 IP: discovery 16+16+5 hostów, usługi 1–3 hosty; testy jednostkowe `Sizer` (adaptacja, clamp, wyrównanie końcówki, tryb stały) |
| pasek CLI | uruchomiony pod `script` (TTY) i bez TTY; widoczne procenty workerów, ETA, status DefectDojo |
| panel web + SSE | `/api/live`, `/api/events` w trakcie skanu; historia i diff z `asi serve` |
| upload na żywo | 8 reimportów w trakcie skanu + końcowy z `close_old` |
| cykl zmian w DefectDojo | selftest localhost: `created → closed → reactivated` |
| potwierdzanie zniknięć | selftest: port „zgubiony” w 1. przejściu → zachowany z tagiem `unstable`; port naprawdę zamknięty → `gone` |
| okno czasowe | `-window 5s`: nmapy zabite, `interrupted`, brak zamykania znalezisk |
| parsery wejścia | CSV, JSON, TXT + CIDR, dedup, `enabled=false` (test jednostkowy) |

## Decyzje do podjęcia

Rozstrzygnięte decyzje są w [`DECISIONS.md`](DECISIONS.md) (architektura, RBAC, baza, szyfrowanie, UDP, polityka skanera).
Otwarte:

1. **Zgoda na skan cudzych hostów**: wiersze bez zgody właściciela mają `enabled=false`.
2. **Licencje (regulamin §4.2).** nmap (NPSL) wołamy jako zewnętrzny program; httpx i nuclei (MIT) tak samo;
   DefectDojo BSD-3. Do potwierdzenia z mentorami, że wywołanie nmapa jest OK.
3. **Format i limity organizatorów** (SEC-2): przykładowy JSON/CSV, lista dozwolonych portów, limity ruchu.
   Polityka (`internal/safety`) i `-rate` są gotowe na te wartości.

## Następne kroki

Aktualna lista z priorytetami: [Roadmapa](ROADMAP.md), sekcja „Co zostało do wzięcia”.
