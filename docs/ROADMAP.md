# Roadmapa: gdzie jesteśmy

**Ostatnia aktualizacja: 21.11.2026, 20:00 CET** (LAB-T3 sygnatury labu organizatorów + synchronizacja z TASKS i audytem jury). Zasada: kto kończy zadanie z
[`TASKS.md`](TASKS.md), aktualizuje tu wiersz etapu i pasek postępu, a w [`status.md`](status.md) wymagania.

Legenda: ✅ zrobione · 🔨 w toku · ⏳ następne · ⬜ nie zaczęte · ⏸ odłożone.

```
M0 Stack + PoC            ██████████ 100%  ✅
M1 Silnik skanowania      ██████████ 100%  ✅
M2 Fundament (kontrakt+DB)█████████░  95%  🔨  DEV-0/1 ✅, SEC-1 ✅, SEC-3 lab ✅, SEC-2 🟡 (lab organizatorów w ~/lab na fh2, analiza gotowa)
M3 Historia i stany       ██████████ 100%  ✅  DEV-2
M4 Web GUI                ██████████ 100%  ✅  DEV-4 ✅, DEV-8 ✅, DEV-9 ✅; weryfikacja live progress PTY (DEV-13)
M5 Fingerprint i sygnatury██████████ 100%  ✅  SEC-4 httpx ✅, SEC-5 +14 ✅, SEC-10 +9 IoT ✅, LAB-T3 +10 lab ✅, DEV-7 ✅
M6 Ochrona danych i role  █████████░  95%  🔨  SEC-6 ✅ (pg_tde + AES-GCM + reseal), DEV-3 ✅; w toku: DEV-11 (konta), wolne: DEV-12 (rola analyst)
M7 Harmonogram i eksport  ██████████ 100%  ✅  DEV-5 ✅, SEC-8 ✅, SEC-7 ✅ (asi-changes, asi-nmap/httpx/nuclei natywnie), DEV-6 ✅
M8 Finisz dla jury        █████░░░░░  55%  🔨  DEV-10 ✅, SEC-9 ✅, LAB-T3 ✅; w toku: ALL-1 (Beamer, fh2), LAB-T1/T4 (agy); wolne: LAB-T2, LAB-0..6, ALL-2, OPS-1
```

## Etapy

| etap | cel (co widać w demo) | zadania | stan |
|---|---|---|---|
| **M0** Stack + PoC | DefectDojo 3.5.202 w compose, pierwszy import nmapa, pętla reimportu | Etap 0–1 PoC fatusi | ✅ |
| **M1** Silnik skanowania | `asi scan`: plan celów (CSV/JSON/TXT, CIDR, domeny, reguły zakresu), 2 fazy nmapa, adaptacyjne paczki, globalny limit pps, okno czasowe, pasek CLI + panel SSE, diff, skan potwierdzający, reimport Generic Findings (`created/closed/reactivated`) | silnik z `~/asi-poc` | ✅ |
| **M2** Fundament | kontrakt `Observation` + interfejs `Scanner` (adaptery), Postgres `asi-db` z migracjami, przebiegi i obserwacje w bazie, diff z bazy, cały stack przez `make up` | DEV-0 ✅, DEV-1 ✅, SEC-1 ✅, SEC-2, SEC-3 ✅ | 🔨 |
| **M3** Historia i stany | assety ze stanami `new/active/missing/gone`, `reappeared`, `flapping`, próg braków dla hostów, zasada pokrycia (`partial` nie zamyka), edycje użytkownika trwałe między skanami | DEV-2 | ✅ |
| **M4** Web GUI (najwyżej punktowane) | logowanie (na start 1 admin), formularz celów (ręcznie + CSV/JSON), start skanu z panelu, lista assetów z edycją, dashboard: najważniejsze znaleziska, zmiany, niestabilne hosty | DEV-4 ✅, DEV-8 ✅, DEV-9 ✅ | ✅ |
| **M5** Fingerprint i sygnatury | httpx: tytuł, kod, nagłówki, cookies, TLS, przekierowania, technologie, favicon; nuclei z naszymi szablonami (CMS, panel, staging, wersja, IoT) | SEC-4 ✅, SEC-5 ✅, DEV-7 ✅, SEC-10 ✅ | ✅ |
| **M6** Ochrona danych i role | AES-256-GCM dla pól `_enc` + szyfrowanie Postgresa w spoczynku (mentor: „darmowe 5%”), RBAC lokalny (4 role, jeśli starczy czasu), audit log | SEC-6 ✅, DEV-3 ✅ | ✅ |
| **M7** Harmonogram i eksport | cron + okno + wznawianie paczek `deferred`, eksport JSON/CSV, import cudzych wyników, eksport do DD natywnymi parserami, twarde limity skanera | DEV-5 ✅, DEV-6 ✅, SEC-7 ✅, SEC-8 ✅ | ✅ |
| **M8** Finisz | test skali ≥10k IP, publiczne repo bez sekretów, czyste uruchomienie od zera, prezentacja ≤10 slajdów, nagranie demo, dokumentacja 100% | DEV-10 ✅, SEC-9 ✅, ALL-1 🔨, ALL-2 🔨 | 🔨 |

## Ścieżka krytyczna

```
DEV-0 ✅ → DEV-1 ✅ → DEV-2 ✅ → DEV-4 ✅ ─────────────────────────────→ demo (2 przebiegi + GUI) ✅ działa
                         ↘ SEC-4 ✅ → SEC-5 ✅ → sekcja w GUI ✅ → SEC-7 ✅ (parsery httpx/nuclei) ↗
                         ↘ SEC-6 ✅ (szyfrowanie)                                                ↗
M8: SEC-9 (czyste repo + uruchomienie od zera) → ALL-1 (prezentacja + nagranie) → oddanie
```

## Pokrycie wymagań PDF (przegląd 21.11, 17:30)

Każdy punkt sprawdzony w kodzie, nie tylko w dokumentacji. Szczegóły: [`status.md`](status.md).

| wymaganie z PDF | stan | brakuje |
|---|---|---|
| 1. wczytanie IP / CIDR / domen | ✅ | – |
| 2. bezpieczny, wielowątkowy skan; czas trwania; podział na podgrupy | ✅ | – |
| 3–4. aktywne hosty, identyfikacja usług | ✅ | – |
| 5. HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | ✅ | – |
| 6. CMS, framework, serwer aplikacyjny, **urządzenia IoT** | ✅ | SEC-10: 9 sygnatur — kamery Hikvision/Dahua/ogólne, RouterOS, LuCI, drukarki, NAS, wbudowane serwery firmware'u, opis UPnP ([Fingerprint](/guide/fingerprint#sygnatury-iot-sec-10)) |
| 7. staging, panel administracyjny | ✅ | – |
| 8–9. porównanie przebiegów; nowe / znikające / zmienione | ✅ | porównanie w GUI (DEV-9); zmiana usługi i treści HTTP (tytuł, certyfikat, technologie) jako `changed` (DEV-7) |
| 10. własne sygnatury | ✅ | (opcja) wgrywanie sygnatur z GUI |
| 11. formularz celów, ręcznie + CSV/JSON | ✅ | – |
| 12–13. RBAC, 4 role | ✅ | – (DEV-3 domknięte: tokeny API w GUI z ważnością, unieważnianiem i audytem) |
| 14. edycja wartości niezależnie od skanu, trwała | ✅ | tagi, notatki, ocena analityka (FP / zaakceptowane / ocena) eksportowana do DD, edycja harmonogramu (DEV-9) |
| 15. czytelny interfejs, dashboard | ✅ | – |
| 16. szyfrowanie w spoczynku | ✅ | – |
| min.: import wyników skanów JSON/CSV | ✅ | DEV-6: nmap XML, CSV, JSON, JSONL; GUI i CLI |
| min.: obsługa >10 000 IP | ✅ | DEV-10: 16 384 adresy w 86 s (z bazą i przeliczeniem stanów), dashboard 0,22 s przy 49 tys. assetów ([Test skali](/guide/scale)) |
| min.: porównanie dwóch skanów | ✅ | GUI i CLI (DEV-9) |
| min.: edycja danych istniejących skanów, wyników i konfiguracji | ✅ | wyniki: ocena analityka, tagi, notatki; konfiguracja: cele, harmonogramy (DEV-9) |
| mile widziane: pora dnia, ocena ciekawości, grupowanie usług | ✅ | DEV-7: ocena 0–100 z powodami, grupy usług/technologii, wzorce pory dnia ([Ocena, grupy, pora dnia](/guide/insights)) |
| mile widziane: eksport wybranych obserwacji do DD | 🟡 | natywne parsery httpx/nuclei i `asi-changes` gotowe (**SEC-7 ✅**); eksport jest całościowy (brak selektywnego wyboru z GUI) |
| formalne: repozytorium, dokumentacja, prezentacja ≤10 slajdów + demo | 🟡 | repo ✅ (**SEC-9**: [GitHub](https://github.com/Ch3shireDev/awesome-surface-intelligence), czysty start sprawdzony), prezentacja (**ALL-1**, w toku na fh2), `status.md` 100% (**ALL-2**) |

## Co zostało do wzięcia (kolejność wg wagi w ocenie)

| zadanie | etap | co konkretnie | kto | waga |
|---|---|---|---|---|
| **DEV-6** | M7 | import wyników skanów (nmap XML, JSON/CSV) z GUI i CLI do bazy jako przebieg, z przeliczeniem stanów | ✅ agent blackarch | minimum PDF, test jury „import” |
| **DEV-9** | M4 | GUI: porównanie dwóch dowolnych przebiegów; oznaczanie wyników (fałszywy alarm, zaakceptowane, nadpisana ocena), honorowane przez dashboard i eksport; edycja harmonogramu | ✅ agent blackarch | minimum PDF, test jury „edycja znalezisk” |
| **DEV-10** | M8 | test skali: ≥10 000 adresów lokalnie (127.0.0.0/18, wyłącznie loopback), pomiar skanu, zapisu, przeliczania stanów i dashboardu; poprawki wydajności | ✅ agent blackarch | 30% („w dużej infrastrukturze”) |
| **DEV-7** | M5 | zmiana treści HTTP jako `changed`, ocena ciekawości z portów, HTTP i sygnatur razem, grupowanie podobnych usług, wzorce pory dnia z `hours_seen` | ✅ agent blackarch | 10–15% + „mile widziane” |
| **SEC-7** | M7 | natywne parsery httpx/nuclei do DD (`asi-httpx`, `asi-nuclei`) + `asi-changes` | ✅ agent fatusia-2 | 20% (integracja DD) |
| ~~SEC-10~~ | M5 | sygnatury IoT (kamery, routery, drukarki, panele urządzeń) | ✅ goose/blackarch (9 sygnatur + poprawka Hikvision/Dahua) | pkt 6 PDF |
| ~~LAB-T3~~ | M5 | 10 sygnatur pod lab organizatorów (phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ, NPM, Traefik, Toxiproxy, httpbin, WordPress < 6.0) | ✅ agy/blackarch (`nuclei -validate` + test na 12 usługach) | 10% + lab jury |
| ~~SEC-9~~ | M8 | publiczne repo bez sekretów i realnych IP; czysty start z GitHuba | ✅ goose (repo + test `make env && make build && make test`); README/quickstart fh2 | formalny wymóg |
| ~~DEV-3~~ | M6 | tokeny API w GUI (zakładka Konto, `scripts/test-tokens.sh` 24/24) | ✅ goose/blackarch | role 10% |
| **ALL-1** | M8 | prezentacja ≤10 slajdów (`docs/presentation/asi.tex`, uzupełnić `\TODO`) + nagranie demo | 🔨 agent fatusia-2 (szablon Beamer) | formalny wymóg |
| **DEV-11** | M6 | zarządzanie kontami (zmiana roli, blokada `disabled`, unieważnianie sesji/tokenów, ochrona ostatniego admina) | 🔨 goose/blackarch | role 10% (audyt jury) |
| **DEV-12** | M6 | wyrównanie roli `analyst` („modyfikacja i odczyt”: edycja celów i harmonogramów bez tworzenia/usuwania) | wolne (DEV) | role 10% (audyt jury) |
| **LAB-T1 / T4** | M8 | pełny zakres portów `-p-` dla małych celów / profilu lab + czas odpowiedzi HTTP z httpx (Toxiproxy) | 🔨 agy/blackarch (`lab-t1-t4`) | 30% (lab organizatorów) |
| **LAB-T2** | M8 | wykluczenie portów własnego stacku ASI/DD przy skanie localhosta/hosta skanera | wolne (SEC) | lab organizatorów |
| **LAB-0..6** | M8 | testy na żywo 4 stacków z `~/lab` (`custom-network`, `modern`, `vulnerable`, `modern-proxy`) | wolne (SEC, po LAB-T1..T4) | 30% (test jury) |
| **DEV-13** | M4 | przebudowa `nmap-scanner`, weryfikacja PTY nmapa 7.95 w kontenerze i podgląd widoku postępu (`626855b`) | wolne (DEV) | 15% (czytelność GUI) |
| **ALL-2** | M8 | strona ze ścieżką testowania pod jury, `status.md` 100%, quickstart na czystej VM z Dockerem | wolne (wszyscy) | 20% |
| **SEC-2** | M2 | materiały organizatorów — lab pobrany (`~/lab` na fh2, `docs/guide/lab-organizers.md`); brak: ew. przykładowy JSON/CSV, oficjalne limity, testowe DD | 🟡 częściowo (człowiek na miejscu) | ryzyko testu jury |
| **OPS-1** | docs | `make docs` (`vitepress preview` słucha na wszystkich interfejsach) + sprzątanie starych procesów na `blackarch` | wolne | bezpieczeństwo / porządek |

## Dziennik postępu

| kiedy | co się zmieniło |
|---|---|
| 22.11 ~09:50 | Decyzja 24: jeden panel ASI (18090), usunięte `asi serve`/`make asi-serve` (8095) i osobny podgląd `make asi-scan` (8094) |
| 22.11 ~09:00 | Decyzja 23: panel ASI domyślnie na 18090 (8090 zostaje dla DVWA z labu), `make test-*` biorą adres z `.env` |
| 22.11 ~08:20 | LAB-T5: diff przebiegów mówi słowami historii (`missing` zamiast „gone” przy pierwszym braku, `reappeared`), bez bazy „brak w tym przebiegu” |
| 21.11 ~22:15 | LAB-4 zaliczony (`vulnerable`: 0 prób logowania w logach usług); poprawione fałszywe trafienia sygnatur IoT; testy LAB-* równolegle na kilku VM + nakładki `docker/lab-org/*.bind.yml` |
| 21.11 ~21:45 | LAB-6 zaliczony (zmiana stacku labu organizatorów, 5 przebiegów, 0 duplikatów w DD); ALL-2: czysty start na czystej VM (`make up` 3 min 49 s, `make demo` 150 s); nowe LAB-T10 (PostgreSQL przy `--version-light`) |
| 21.11 ~20:20 | LAB-T2: skaner nie skanuje własnych portów ASI/DD na hoście skanera (osobna paczka z `--exclude-ports`, porty z `.env`) |
| 21.11 ~20:00 | LAB-T3: 10 bezpiecznych sygnatur pod lab organizatorów (phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ management, NPM, Traefik dashboard, Toxiproxy API, httpbin, WordPress < 6.0) + poprawka `asi-iot-camera-hikvision` (usunięty nagłówek Dahua `DNVRS-Webs`), `nuclei -validate` i test na 12 usługach OK; uporządkowane `TASKS.md` (SEC-2 🟡, DEV-13, OPS-1) |
| 21.11 ~19:40 | blackarch: szyfrowanie włączone na maszynie demo — `asi-db` przestawiona na `pg_tde` (15/15 tabel, WAL AES-256) z zachowaniem danych (dump → restore → `asi db reseal`), `make crypto-check` 9 OK / 0 FAIL; nowa komenda `asi db reseal` (szyfruje stare jawne `_enc`, idempotentna) |
| 21.11 ~18:45 | DEV-7: ocena 0–100 z powodami (port, sygnatury, TLS, świeżość, flapping, ocena analityka), grupy podobnych usług i technologii, wzorce pory dnia, zmiana treści HTTP jako `changed` |
| 21.11 ~18:30 | DEV-10: test skali 16 384 adresów (loopback) w 86 s, dashboard 0,22 s przy 49 tys. assetów; poprawione domyślne porównanie (ten sam zbiór celów), `-set` dla skanów z GUI, ponawianie `apk add` w Dockerfile |
| 21.11 ~18:10 | DEV-9: porównanie dwóch przebiegów w GUI, ocena analityka (FP / zaakceptowane / ocena) trwała i eksportowana do DD jako false_p / risk_accepted, edycja harmonogramu; ocena usunięta z opisu znaleziska DD (stabilny hash) |
| 21.11 ~17:50 | DEV-6: import wyników (nmap XML, CSV, JSON, JSONL httpx/nuclei) w GUI i `asi import`, pokrycie auto/none, import historyczny; mniej szczegółowa obserwacja usługi nie jest już „zmianą” |
| 21.11 ~17:30 | przegląd wymagań PDF vs kod: M4 85% (brak porównania przebiegów i edycji wyników w GUI), brak importu wyników, brak testu 10k, brak sygnatur IoT; nowe zadania DEV-9, DEV-10, SEC-10 |
| 21.11 ~17:10 | M5: SEC-4 httpx (etap `http`), SEC-5 nuclei + 14 sygnatur (etap `signatures`), porty wysokiego ryzyka spoza top 1000 (Redis wykryty), szuflada „HTTP i sygnatury” i sygnatury na dashboardzie; blokery: `make env-sync`, restart nginx, import scala tagi |
| 21.11 ~13:00 | PoC: chunkowany nmap → DefectDojo (`~/asi-poc`) |
| 21.11 ~14:00 | 2 fazy, adaptacyjne paczki, postęp CLI + web, diff, potwierdzanie zniknięć, Generic Findings |
| 21.11 14:44 | konsultacja z mentorem: GUI wymagane, Postgres + szyfrowanie, RBAC 10% ([MENTOR](MENTOR.md)) |
| 21.11 ~15:30 | scalenie repo `~/asi`; DEV-0 kontrakt `Observation`, adaptery nmap |
| 21.11 ~15:50 | DEV-1 baza `asi-db`, zapis przebiegów, `asi diff -db`; obraz skanera z pgx |
| 21.11 ~16:00 | stary DefectDojo z `~/asi-poc` usunięty; cały stack przez `make up`; skan z kontenera → baza + DD sprawdzony |
| 21.11 ~16:10 | DEV-2: assety ze stanami, flapping, zasady pokrycia (hosty i porty) i hierarchii, edycje trwałe; `asi changes/assets/asset edit` |
| 21.11 ~16:20 | DEV-4: panel web `asi server` (login, dashboard, assety z edycją, formularz/import celów, skany z GUI + postęp na żywo, role, audit, eksport CSV/JSON); kontener skanera startuje panel na :8090 |
| 21.11 ~16:25 | SEC-3: lab `docker/lab` (8 hostów, 192.0.2.0/24) + `make demo`: new/gone/changed/unstable w 2 przebiegach |
| 21.11 ~16:30 | DEV-5: harmonogram (cron + okno) w panelu, wznawianie niezeskanowanych celów w kolejnym oknie, wstrzymaj/wznów/anuluj, `asi scan -resume` |
| 21.11 ~16:47 | DEV-8: cele z dowolnego tekstu (DeepSeek / regex) w panelu i `asi targets-extract`, serwer MCP `asi mcp` |
| 21.11 ~16:50 | SEC-8: polityka skanera `internal/safety` (zakres, wykluczenia wbudowane i własne, allowlista portów i flag nmapa, twardy limit pps), sprawdzana w planie i w workerze; profile `raw`/`unprivileged`, decyzja UDP |
| 21.11 ~16:50 | SEC-6: `asi-db` na `pg_tde` (tabele, indeksy, WAL; AES-256) + pola `_enc` AES-256-GCM, rotacja kluczy, `make env-keys`, `make crypto-check` 9/9 OK ([Szyfrowanie](guide/encryption.md)) |
| 21.11 ~16:55 | panel: oś „Zmiany w czasie” z godziną i datą przebiegów, klikalne KPI (np. „otwarte usługi” → Assety z filtrem), filtr oceny; pliki celów do pobrania w dokumentacji |
| 21.11 ~17:50 | SEC-7 dokończone: httpx i nuclei do DD natywnymi parserami (`asi-httpx`, `asi-nuclei`), `close_old` tylko przy pełnym etapie; lab: diff w DD per narzędzie |
| 21.11 ~17:00 | SEC-7: test `asi-changes` w DD (missing/gone/flapping/zmiana, zamykane, gdy warunek mija), brak `close_old` dla przebiegów częściowych też w `asi upload`, `-format nmap` do stałego `asi-nmap`; lab: 4 przebiegi, missing → gone ([DefectDojo](guide/defectdojo.md)) |
| 21.11 ~19:20 | SEC-10: 9 sygnatur IoT (kamery Hikvision/Dahua/ogólne, RouterOS, LuCI, drukarki, NAS, wbudowane serwery firmware'u, opis UPnP); test na atrapie urządzeń pod 127.0.0.1, lint bezpieczeństwa w `go test` ([Fingerprint](guide/fingerprint.md)) |
| 21.11 ~19:30 | SEC-9: publiczne repo https://github.com/Ch3shireDev/awesome-surface-intelligence (remote `github`, push z blackarch), historia bez sekretów i realnych celów, czysty start z GitHuba: `make env && make build && make test` ([Quickstart](guide/quickstart.md#czysty-start-od-zera-sec-9-sprawdzony)) |
| 21.11 ~19:45 | DEV-3: tokeny API w GUI (zakładka Konto): ważność 0–3650 dni, w bazie tylko SHA-256, unieważnianie, audyt; `scripts/test-tokens.sh` 24/24 (401 bez sesji, CSRF, Bearer, revoke, walidacja wejścia) ([Panel](guide/gui.md#tokeny-api-dev-3)) |
| 21.11 ~19:15 | DEV-12: role 1:1 z pkt 13 PDF (Odczyt / Modyfikacja i odczyt / Dodawanie, usuwanie, modyfikacja / Administracja); `analyst` edytuje istniejące cele i harmonogramy, zmiana wartości celu wymaga `operator`; `scripts/test-roles.sh` 28/28, `make test-roles` ([Panel](guide/gui.md#role)) |
| 21.11 ~19:25 | db: `make schema-check` (migracje, indeksy/UNIQUE wymagane przez `ON CONFLICT`, duplikaty, tabele na `heap`) — po `pg_restore` bez `--clean/--create` baza była bez indeksów; `scripts/tde-reenable.sql` przywraca TDE po `DROP SCHEMA` (15/15 tabel, `make crypto-check` 9/9) ([Baza](guide/database.md#kontrola-schematu-make-schema-check)) |
| 21.11 ~20:40 | dashboard: kafelek „nowe w ostatnim skanie” liczy zdarzenia `new`/`reappeared` z ostatniego przebiegu i otwiera dokładnie tę listę (`?run=<id>&events=`), zamiast filtra `state=new`, który dawał 0; `asi db drop-set` do sprzątania zbiorów celów ([Panel](guide/gui.md)) |
| 21.11 ~20:55 | DEV-14: adres w pasku = widok + obiekt (`/assets/<klucz>`, `/scans/<id>`, filtry w query), historia wstecz/dalej, zamykanie szuflady krokiem wstecz, linki do zasobu; SPA pod ścieżkami widoków, bezwzględne `/api/…`; test w Chrome 49/49 ([Panel](guide/gui.md#adresy-widokow-wstecz-i-linki-do-zasobu-dev-14)) |
