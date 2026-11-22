# Status projektu

Stan na 22.11.2026. Legenda: ✅ zrobione i przetestowane · 🟡 częściowo · ❌ nie zrobione · ❓ wymaga decyzji.

## Wymagania ze specyfikacji

| # | wymaganie | stan | jak / co brakuje |
|---|---|---|---|
| 1 | wczytanie IP, CIDR, domen | ✅ | CSV/JSON/TXT, wspólny schemat, `asi convert`; [Format celów](/guide/targets) |
| 2 | bezpieczny, wielowątkowy skan nmap | ✅ | worker pool, `-sT`, `--version-light`, globalny `-rate` + twardy limit `ASI_MAX_RATE`; polityka SEC-8 w planie i w workerze (zakres, wykluczenia, allowlista portów i flag nmapa); **LAB-T2**: automatyczne pomijanie własnych portów ASI/DefectDojo na hoście skanera (`ASI_SELF_PORTS`/`ASI_SELF_IPS`); **LAB-T7**: przekroczenie `--host-timeout` (`timedout="true"`) nie daje fałszywych braków; [Bezpieczeństwo](/guide/safety) |
| 2 | czas trwania skanu | ✅ | `timings.csv` per faza, `run.json`, ETA na żywo |
| 2 | podział na optymalne podgrupy | ✅ | 2 fazy + adaptacyjny `Sizer` (EWMA s/host) + pamięć `tuning.json`; [Podział](/guide/chunking) |
| 3 | wykrycie aktywnych hostów | ✅ | faza discovery (`-sn`, TCP SYN/connect ping na 8 portów) |
| 3 | …w sieciach blokujących sondy | ✅ | `-skip-discovery`; profil `raw` (domyślny, `NET_RAW`) pozwala na ICMP `-PE` i ARP, profil `unprivileged` tylko connect; [Profile](/guide/safety#profile-z-surowymi-gniazdami-i-bez-roota) |
| 4 | identyfikacja usług | ✅ | `-sV --version-light` + **drugi przebieg `--version-intensity 7` tylko na nierozpoznane porty TCP** (LAB-T10: PostgreSQL na 15432 w +7 s, limit 512 z logiem zamiast cichego pomijania), porty `tcpwrapped` z odpowiedzią httpx → `http` + `Server`, profil `-ports auto` (pełne TCP `1-65535` dla ≤16 hostów, inaczej top 1000 **+ porty wysokiego ryzyka spoza top 1000** — Redis, MongoDB, Docker API, Kibana…), jawne `all`/`lab`/`allowed`/`top100`/`top1000`/własne w CLI i GUI (LAB-T1) |
| 4 | UDP | 🟡 | decyzja 15: domyślnie wyłączone (czas, niepewne `open\|filtered`, sonda SNMP `public`); `ASI_ALLOW_UDP=1` włącza `-sU` tylko na 53,123,161 (DNS, NTP, SNMP), profil `raw`; [UDP](/guide/safety#udp-decyzja) |
| 5 | HTTP: tytuł, kod, nagłówki, cookies, TLS, przekierowania | ✅ | etap `http` (httpx): tytuł, status, **czas odpowiedzi `response_time_ms`** (poza `fp_hash`, kolumna `HTTP ms` i filtr wolnych w GUI, domyślny próg `ASI_HTTP_SLOW_MS=300`, LAB-T4/LAB-T9), nagłówki, nazwy ciasteczek, `Location`, certyfikat (CN/SAN/wystawca/ważność/self-signed), favicon mmh3 ([Fingerprint](/guide/fingerprint)) |
| 6 | wykrywanie technologii / CMS / IoT | ✅ | Wappalyzer w httpx + sygnatury: generator CMS, WordPress po ścieżkach i `?ver=` CSS, wersje PHP/Jenkins, hashe favicony; **IoT (SEC-10): 9 sygnatur** — kamery Hikvision/Dahua/ogólne wizyjne, RouterOS, LuCI, drukarki, NAS (Synology/QNAP/TrueNAS), wbudowane serwery firmware'u (`GoAhead-Webs`, `Boa`, `uc-httpd`), opis UPnP (atrapa `scripts/iot-stub.py`, poprawione FP z odbicia ścieżki w LAB-4); **usługi i lab organizatorów (LAB-T3, LAB-T6): 11 sygnatur** (phpMyAdmin, Adminer, DVWA, Gitea + instalator Gitea `high`, RabbitMQ Management, Nginx Proxy Manager, Traefik, Toxiproxy, httpbin, WordPress < 6.0); [Fingerprint](/guide/fingerprint#sygnatury-iot-sec-10) |
| 7 | staging / panel admina | ✅ | sygnatury `asi-staging-environment` (nagłówek/tytuł/ciasteczko), `asi-admin-panel` (`stop-at-first-match`, LAB-T12), `asi-login-redirect`, `asi-version-endpoint`, `asi-gitea-install` (`high`, LAB-T6) oraz panele z LAB-T3 (`asi-phpmyadmin`, `asi-adminer`, `asi-traefik-dashboard`, `asi-rabbitmq-management`, `asi-nginx-proxy-manager`, `asi-toxiproxy-api`) |
| 8 | porównanie przebiegów | ✅ | dwa dowolne przebiegi w GUI (Skany), `asi diff -db`, automatycznie po skanie; spójne nazwy zmian z historią (`missing`/`gone`/`reappeared`/`reverted`, LAB-T5) |
| 9 | nowe / znikające / zmienione usługi | ✅ | `new / missing / gone / reappeared / changed / reverted / filtered / flapping`, plus `created/closed/reactivated` w DefectDojo (LAB-T8: cofnięcie awarii za proxy = `reverted`; **LAB-T11**: wykryty firewall → `filtered`, wynik niepełny bez fałszywego `gone`, migracja 009) |
| 10 | własne sygnatury | ✅ | nuclei tylko z `signatures/` (**34 szablony**: 14 bazowych CMS/panel/staging/wersje/Redis, 9 IoT SEC-10, 11 pod usługi i lab organizatorów LAB-T3/T6; wyłącznie detekcja, `stop-at-first-match` w 12 wielościeżkowych), instrukcja „jak dodać” w `signatures/README.md`, lint bezpieczeństwa `TestTemplatesAreSafe` w testach |
| 11 | formularz: ręcznie + CSV/JSON | ✅ | GUI: formularz ręczny + import CSV/JSON/TXT do bazy, walidacja wejścia ([Panel web](/guide/gui)); **porty per cel** w formularzu, imporcie i edycji ([Porty](/guide/targets#porty)) |
| 12–13 | RBAC, 4 role | ✅ | lokalne role `viewer`/`analyst`/`operator`/`admin` na każdej trasie API, użytkownicy w GUI i CLI (`asi user list/passwd/add`), **tokeny API w GUI (DEV-3)**: zakładka Konto, ważność 0–3650 dni, tylko hash SHA-256 w bazie, unieważnianie, audyt (`make test-tokens` 24/24); **zarządzanie kontami (DEV-11)**: zmiana roli, blokada (unieważnia sesje/tokeny → 401), reset hasła, usuwanie, ochrona ostatniego admina (409), audyt (`make test-users` 35/35); **role 1:1 z pkt 13 PDF (DEV-12)**: *Odczyt* = `viewer`, *Modyfikacja i odczyt* = `analyst` (edycja istniejących celów/harmonogramów/assetów bez tworzenia i usuwania), *Dodawanie, usuwanie, modyfikacja* = `operator` (+ tworzenie, usuwanie, start/stop), *Administracja* = `admin` (`make test-roles` 28/28); dziennik audytu |
| 14 | edycja wartości niezależnie od skanu, trwała | ✅ | GUI + CLI (`asi asset edit`): tagi, notatka, **ocena analityka** (fałszywy alarm / zaakceptowane / nadpisana ocena, trwała i eksportowana do DD), edycja istniejących celów i harmonogramów; audit log |
| 15 | czytelny interfejs + dashboard | ✅ | **jeden panel ASI na `127.0.0.1:18090`** (decyzje 23–24, podgląd skanu `/live/` przez gniazdo Unix `unix:/tmp/asi-live.sock`); dashboard: kafelki, najważniejsze znaleziska, zmiany, niestabilne, grupy podobnych usług, wzorce pory dnia, wykres zmian w czasie; **adres = stan panelu (DEV-14)**: `/assets/<klucz>`, `/scans/<id>`, filtry w query, wstecz/dalej i linki do zasobu ([Panel](/guide/gui#adresy-widokow-wstecz-i-linki-do-zasobu-dev-14)) |
| 16 | szyfrowanie at-rest | ✅ | 2 warstwy (sprawdzone `make crypto-check` 9/9 także na blackarch po `asi db reseal`): TDE `pg_tde` w `asi-db` (tabele, indeksy, WAL; AES-256) + pola `_enc` AES-256-GCM w aplikacji (`ASI_ENCRYPTION_KEYS`, rotacja, `asi db reseal`); kontrola schematu `make schema-check` 12/12 i `scripts/tde-reenable.sql`; [Szyfrowanie](/guide/encryption) |
| — | harmonogram, okna czasowe | ✅ | cron + okno w GUI, wznawianie niezeskanowanych celów w kolejnym oknie, wstrzymaj/wznów/anuluj ([Harmonogram](/guide/schedule)) |
| — | obsługa >10 000 IP | ✅ | 16 384 adresy w 86 s end-to-end, 49 tys. assetów w panelu ([Test skali](/guide/scale)) |
| — | ograniczanie tempa | ✅ | `-rate` globalny, twarde limity `ASI_MAX_RATE` i `ASI_MAX_PARALLEL`, timeouty |
| — | eksport JSON/CSV i selektywny eksport | ✅ | assety CSV (z `http_ms`) i JSON z GUI/API; **eksport zaznaczonych assetów** (CSV, JSON oraz wybiórczo do DefectDojo `asi-selected` z `close_old=false`); `services.json`, `findings_defectdojo.json` ([Integracje](/guide/integrations)) |
| — | źródła pasywne i powiadomienia SIEM | ✅ | wykrywanie pasywne (CT logs, DNS, Shodan InternetDB) oraz powiadomienia SIEM (webhook / syslog) o zmianach ([Integracje](/guide/integrations)) |
| — | import wyników skanów JSON/CSV | ✅ | nmap XML, CSV, JSON, JSONL httpx/nuclei; GUI + `asi import`; pokrycie `auto`/`none`, import historyczny, przykładowy plik `inny-skaner.csv` pokryty testem ([Import](/guide/import)) |
| — | hosty / usługi niestabilne | ✅ | stany `new/active/missing/gone`, `reappeared`, `flapping`, progi braków, zasady pokrycia i hierarchii ([Historia](/guide/history)); skan potwierdzający |
| — | integracja DefectDojo | ✅ | 4 stałe testy z historią (reimport): `ASI discovery` (Generic Findings, upload na żywo), `asi-changes` (missing/gone/flapping/zmiany, zamykane w DD, gdy warunek mija; bez `close_old` dla przebiegów częściowych, też w `asi upload`), `asi-httpx` i `asi-nuclei` (natywne parsery DD, `close_old` tylko przy pełnym etapie) + opcjonalnie `asi-nmap` (natywny XML); [DefectDojo](/guide/defectdojo) |
| — | grupowanie podobnych usług, pora dnia | ✅ | grupy po produkcie/wersji i technologii; wzorce z `hours_seen` |
| — | ocena „ciekawości” | ✅ | 0–100 z powodami: port, sygnatury, TLS, świeżość, flapping; ocena analityka wygrywa ([Ocena](/guide/insights)) |
| — | tagi | ✅ | tagi celów (formularz/import) i assetów (edycja w GUI/CLI, trwałe między skanami) |
| — | dokumentacja | ✅ | ta strona (VitePress), w tym [Ścieżka testowania (dla jury)](/guide/jury) (ALL-2); publiczne repo: https://github.com/Ch3shireDev/awesome-surface-intelligence |
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
| panel web + SSE | `/api/live`, `/api/events` w trakcie skanu przez gniazdo Unix (`unix:/tmp/asi-live.sock`) proxowane w jednym panelu `:18090` (decyzja 24); historia i diff z bazy w panelu (Skany); zweryfikowane w Chrome: `/live/` 200, 0 błędów JS (DEV-13) |
| upload na żywo | 8 reimportów w trakcie skanu + końcowy z `close_old` |
| cykl zmian w DefectDojo | selftest localhost: `created → closed → reactivated` |
| potwierdzanie zniknięć | selftest: port „zgubiony” w 1. przejściu → zachowany z tagiem `unstable`; port naprawdę zamknięty → `gone` |
| okno czasowe | `-window 5s`: nmapy zabite, `interrupted`, brak zamykania znalezisk |
| parsery wejścia | CSV, JSON, TXT + CIDR, dedup, `enabled=false` (test jednostkowy) |
| profil portów `auto` + czas HTTP (LAB-T1, LAB-T4) | testy jednostkowe `ApplyPorts` (`≤ 16` hostów → `1-65535` z allowlistą) i `response_time_ms` poza `fp_hash`, kolumna `HTTP ms` i filtr wolnych w GUI |
| pomijanie własnych portów ASI/DD (LAB-T2) | testy `internal/safety` + `internal/scanner` i e2e na blackarch (`-p 22,5433,8080,8090,8091` na hoście skanera → tylko `22`) |
| sygnatury IoT i labu (SEC-10, LAB-T3) | `nuclei -validate`, atrapa `scripts/iot-stub.py` (6/9 trafień, 0 fałszywych), lint bezpieczeństwa `TestTemplatesAreSafe` dla wszystkich 34 szablonów |
| RBAC, konta i tokeny API (DEV-3, DEV-11, DEV-12) | `make test-tokens` 24/24, `make test-users` 35/35, `make test-roles` 28/28 (macierz 4 ról 1:1 z PDF, blokada → 401, ochrona ostatniego admina → 409, audyt); sprawdzone na działającym panelu w kontenerze `nmap-scanner` (obecnie `:18090`) |
| szyfrowanie at-rest i schemat (SEC-6) | `make crypto-check` 9/9 (`pg_tde` + WAL + `tde_heap` + 0 trafień jawnych + AES-256-GCM), `asi db reseal`, `make schema-check` 12/12 |
| integracja DefectDojo (SEC-7) | 4 stałe testy (`ASI discovery`, `asi-changes`, `asi-httpx`, `asi-nuclei`) + `asi-nmap`, bez zamykania przy przebiegu częściowym |
| skala >10 000 IP (DEV-10) | `127.0.0.0/18` (16 384 IP, 49 152 assety): 86 s end-to-end, 182 MB RAM, eksport CSV 0,31 s |
| czysty start z GitHuba i próbka importu (SEC-9, ALL-2) | klon `Ch3shireDev/awesome-surface-intelligence`, `make env && make build && make test`; test `docs/public/import/inny-skaner.csv` w `internal/importer` |
| adres widoków, wstecz i deep linki (DEV-14) | `go test ./internal/app -run TestSPARoutes` (ścieżki widoków → SPA, `/api/` i nieznane ścieżki nietknięte) + `scripts/ui-router-test.js` w headless Chrome **49/49**: menu i kafelki KPI zmieniają adres, klik w wiersz → `/assets/<klucz>`, wstecz zamyka szufladę i wraca do listy z filtrami, `Esc`, F5, link do portu z `%2F` (`/assets/192.0.2.15%2Ftcp%2F80`), link przy wylogowanej sesji, `/scans/<id>`, `/admin` dla `viewer` → przekierowanie na `/`, brak błędów JS |
| pełny stack i demo na aktualnym `main` (21–22.11) | `make up` (DefectDojo 3.5.202 + `asi-db` z TDE + skaner), `make demo` end-to-end: 12 celów → 7 hostów, 8 usług, etapy http i signatures, **4 testy w DD** (discovery `created 2/closed 3`, `asi-httpx`, `asi-nuclei`, `asi-changes`), diff 2 przebiegów: `+host .16`, `-host .14`, `~changed .15:80`, 3× `gone`, 1× `new`, potwierdzenie zniknięcia (`unstable`); `make crypto-check` 9/9 (0 jawnych `_enc`) |
| lab organizatorów (LAB-0…LAB-7, 21–22.11) | wszystkie 4 stacki przetestowane (`custom-network`, `modern`, `modern-proxy` + Toxiproxy, `vulnerable`): quickstart 8787 `missing → reappeared`, PostgreSQL 15432 rozpoznany (`--version-intensity 7`), WordPress 4.7 (75/100 `high`) i **0 prób logowania** w logach (111 GET / 0 POST, 0 FTP LOGIN), zmiana stacku LAB-6 (`reactivated 7 / created 0`, **0 duplikatów** w 4 testach DD), `timedout` nie robi fałszywych braków (LAB-T7), cofnięcie awarii za proxy = `reverted` (LAB-T8), próg wolnego HTTP 300 ms (LAB-T9), wykryty firewall = `filtered` bez fałszywego `gone` (LAB-T11), LAB-7 zdalnie przez Tailscale/DERP 6/6 portów (z zastrzeżeniem równoległego skanu); [Lab organizatorów](/guide/lab-organizers) |
| źródła pasywne, selektywny eksport i SIEM (`0ff4e8f`) | pasywne odpytywanie CT / DNS / InternetDB, selektywny eksport zaznaczonych assetów (CSV/JSON/DD `asi-selected`), powiadomienia SIEM (webhook/syslog); [Integracje](/guide/integrations) |

## Decyzje do podjęcia

Rozstrzygnięte decyzje są w [`DECISIONS.md`](DECISIONS.md) (architektura, RBAC, baza, szyfrowanie, UDP, polityka skanera).
Otwarte:

1. **Zgoda na skan cudzych hostów**: wiersze bez zgody właściciela mają `enabled=false`.
2. **Licencje (regulamin §4.2).** nmap (NPSL) wołamy jako zewnętrzny program; httpx i nuclei (MIT) tak samo;
   DefectDojo BSD-3. Do potwierdzenia z mentorami, że wywołanie nmapa jest OK.
3. **Format i limity organizatorów** (SEC-2 ✅): materiały z Discorda to lab (`docs/guide/lab-organizers.md`); osobnego przykładowego JSON/CSV ani limitów ruchu w nich nie ma, porty bierzemy z labu.
   Polityka (`internal/safety`) i `-rate` są gotowe na te wartości. **21.11: rozstrzygnięte** - limity i allowlistę
   portów ustalamy sami w `.env`, zakres skanu jest per przebieg (decyzja 19), a wykryty firewall raportujemy jako
   „wynik niepełny”, nie jako brak usług (decyzja 20, `LAB-T11`).

4. **Topologia DefectDojo (decyzja 22, rozstrzygnięta 21.11 21:12)**: **jedna instancja** - źródło prawdy dla
   wszystkich środowisk i maszyn. Kanoniczny DD na fatusia-1 (`:18080`), pozostałe VM tylko skaner + lab z
   `DD_URL` na kanoniczny. Do zrobienia: wpis adresu tailnetu w `DD_SITE_URL`/`DD_CSRF_TRUSTED_ORIGINS` na
   fatusia-1 i wyłączenie DD na fatusia-2 (`guide/defectdojo.md`, „Jedna instancja DD…”).

## Następne kroki

Aktualna lista z priorytetami: [Roadmapa](ROADMAP.md), sekcja „Co zostało, według priorytetu”.
