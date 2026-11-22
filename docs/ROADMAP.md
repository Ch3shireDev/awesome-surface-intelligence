# Roadmapa: gdzie jesteśmy

**Ostatnia aktualizacja: 22.11.2026, 10:39 CET, stan `main` = `6f8f6c7`.** Oddanie finalne: **11:00 CET**. Zasada: kto kończy zadanie z
[`TASKS.md`](TASKS.md), aktualizuje tu wiersz etapu i pasek postępu, a w [`status.md`](status.md) wymagania.

Legenda: ✅ zrobione · 🔨 w toku · ⏳ następne · ⬜ nie zaczęte · ⏸ odłożone.

```
M0 Stack + PoC            ██████████ 100%  ✅
M1 Silnik skanowania      ██████████ 100%  ✅
M2 Fundament (kontrakt+DB)██████████ 100%  ✅  DEV-0/1 ✅, SEC-1/2/3 ✅
M3 Historia i stany       ██████████ 100%  ✅  DEV-2 ✅, LAB-T5/T7/T8/T11/T13 ✅ (testy integracyjne Postgres OK)
M4 Web GUI                ██████████ 100%  ✅  porty per cel, hosty przy portach, histogram, Admin/Tokeny/UI OK (`3f90610`, `7740529`)
M5 Fingerprint i sygnatury██████████ 100%  ✅  SEC-4/5/10 ✅, LAB-T3/T4/T6/T9/T10/T12 ✅ (34 sygnatury), DEV-7 ✅
M6 Ochrona danych i role  ██████████ 100%  ✅  SEC-6 ✅ (pg_tde + AES-GCM + reseal), DEV-3/11/12 ✅ (4 role, konta, tokeny)
M7 Harmonogram i eksport  ██████████ 100%  ✅  DEV-5/6 ✅, SEC-7/8 ✅, źródła pasywne + selektywny eksport + SIEM ✅
M8 Finisz dla jury        █████████░  90%  🔨  SEC-9 ✅, OPS-1 ✅, LAB-7 🟡; zostało: końcowy PDF + HackTribe, wdrożenie na demo
```

## Etapy

| etap | cel (co widać w demo) | zadania | stan |
|---|---|---|---|
| **M0** Stack + PoC | DefectDojo 3.5.202 w compose, pierwszy import nmapa, pętla reimportu | Etap 0–1 PoC fatusi | ✅ |
| **M1** Silnik skanowania | `asi scan`: plan celów (CSV/JSON/TXT, CIDR, domeny, reguły zakresu), 2 fazy nmapa, adaptacyjne paczki, globalny limit pps, okno czasowe, pasek CLI + panel SSE, diff, skan potwierdzający, reimport Generic Findings (`created/closed/reactivated`) | silnik z `~/asi-poc` | ✅ |
| **M2** Fundament | kontrakt `Observation` + interfejs `Scanner` (adaptery), Postgres `asi-db` z migracjami, przebiegi i obserwacje w bazie, diff z bazy, cały stack przez `make up` | DEV-0 ✅, DEV-1 ✅, SEC-1 ✅, SEC-2 ✅, SEC-3 ✅ | ✅ |
| **M3** Historia i stany | assety ze stanami `new/active/missing/gone`, `reappeared`, `reverted`, `filtered`, `flapping`, próg braków dla hostów, zasada pokrycia (`partial`/`timedout`/`filtered` nie zamyka), edycje użytkownika trwałe między skanami | DEV-2 ✅, LAB-T5/T7/T8 ✅, LAB-T11 ✅, LAB-T13 ✅ | ✅ |
| **M4** Web GUI (najwyżej punktowane) | jeden panel na `:18090` (podgląd na żywo przez Unix socket), logowanie, formularz celów (ręcznie + CSV/JSON, porty per cel), lista assetów z edycją, deep linki, dashboard: najważniejsze znaleziska, zmiany, niestabilne hosty | DEV-4 ✅, DEV-9 ✅, DEV-13 ✅, DEV-14 ✅ | ✅ |
| **M5** Fingerprint i sygnatury | httpx (w tym czas odpowiedzi ms, próg 300 ms): tytuł, kod, nagłówki, cookies, TLS, przekierowania, technologie, favicon; nuclei z 34 naszymi szablonami (CMS, panel, staging, wersje, 9 IoT, lab organizatorów) | SEC-4 ✅, SEC-5 ✅, SEC-10 ✅, DEV-7 ✅, LAB-T3/T4/T6/T9/T10/T12 ✅ | ✅ |
| **M6** Ochrona danych i role | AES-256-GCM dla pól `_enc` + szyfrowanie Postgresa w spoczynku (`pg_tde`), RBAC lokalny 4 role (1:1 z PDF), zarządzanie kontami, tokeny API w GUI, audit log | SEC-6 ✅, DEV-3 ✅, DEV-11 ✅, DEV-12 ✅ | ✅ |
| **M7** Harmonogram i eksport | cron + okno + wznawianie paczek `deferred`, eksport JSON/CSV, import cudzych wyników, eksport do DD natywnymi parserami (4 testy), selektywny eksport + SIEM, źródła pasywne (CT/DNS/InternetDB), twarde limity skanera | DEV-5 ✅, DEV-6 ✅, SEC-7 ✅, SEC-8 ✅, integracje (`0ff4e8f`) ✅ | ✅ |
| **M8** Finisz | test skali ≥10k IP, publiczne repo bez sekretów, czyste uruchomienie od zera, testy na labie organizatorów (LAB-0…6 ✅, LAB-7 🟡), prezentacja ≤10 slajdów, dokumentacja 100% | DEV-10 ✅, ALL-2 ✅, SEC-9 ✅, OPS-1 ✅, LAB-0…6 ✅ (LAB-3 poza TLS), LAB-7 🟡, ALL-1 🔨 | 🔨 |

## Ścieżka krytyczna do 11:00 CET

```
10:40 ostatnia funkcja na main (tylko z zielonymi testami)
  → 10:45 PDF z końcowego main + tekst formularza
  → wgranie do HackTribe i sprawdzenie zapisu
  → 11:00 termin

równolegle: LAB-7 (jeden skaner) → „LAB-7 koniec” → make up z origin/main → test dymny panelu
```

## Pokrycie wymagań PDF (przegląd 21.11, 17:30)

Przegląd z 21.11 sprawdzał każdy punkt w kodzie. 22.11 poprawione tylko wiersze, których stan się zmienił. Szczegóły: [`status.md`](status.md).

| wymaganie z PDF | stan | brakuje |
|---|---|---|
| 1. wczytanie IP / CIDR / domen | ✅ | – |
| 2. bezpieczny, wielowątkowy skan; czas trwania; podział na podgrupy | ✅ | – |
| 3–4. aktywne hosty, identyfikacja usług | ✅ | pełny TCP przez DERP zweryfikowany po LAB-T11/T13 (`6cbf91c`: 12/12 portów) + poprawka `6f8f6c7`; UDP opcjonalne (decyzja 15) |
| 5. HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | ✅ | – |
| 6. CMS, framework, serwer aplikacyjny, **urządzenia IoT** | ✅ | SEC-10: 9 sygnatur — kamery Hikvision/Dahua/ogólne, RouterOS, LuCI, drukarki, NAS, wbudowane serwery firmware'u, opis UPnP ([Fingerprint](/guide/fingerprint#sygnatury-iot-sec-10)) |
| 7. staging, panel administracyjny | ✅ | – |
| 8–9. porównanie przebiegów; nowe / znikające / zmienione | ✅ | firewall i utrata SYN obsłużone (LAB-T11/T13: `filtered` + reproba znanych portów); porównanie w GUI (DEV-9), diff z historią (LAB-T5), `reverted` (LAB-T8), testy integracyjne Postgres 18 OK |
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
| mile widziane: eksport wybranych obserwacji do DD | ✅ | zaznaczone assety z panelu do testu `asi-selected` (`close_old=false`), `guide/integrations` |
| formalne: repozytorium, dokumentacja, prezentacja ≤10 slajdów + demo | 🟡 | repo publiczne (nie open source), dokumentacja ✅; do zrobienia: końcowy PDF, formularz HackTribe, wdrożenie demo |

## Co zostało, według priorytetu

Właściciele według podziału z 10:13 CET. Zadania zamknięte: [`TASKS.md`](TASKS.md).

| priorytet | zadanie | gotowe, gdy | kto | stan |
|---|---|---|---|---|
| **P0** | ALL-1: oddanie | zrzuty na slajdach tylko z adresami dokumentacyjnymi lub loopback; PDF z końcowego `main` i opis zapisane w HackTribe | daniel-a8 (materiały), Daniel (wysyłka) | 🔨 |
| **P0** | wdrożenie demo | po LAB-7 `make up` z `origin/main`; migracje 008 i 009; działa: logowanie, dodanie celu z portami, skan, eksport | do przypisania | ⏳ |
| **P0** | SEC-9: kontrola publicznego repo | przegląd `835cb9d`: 0 sekretów, 0 prawdziwych publicznych IP, brak `LICENSE` / ekstrakcji tekstu, 0 martwych linków VitePress; zostaje końcowy push przed 11:00 | agy (audyt ✅), Daniel (końcowy push) | ✅ |
| **P1** | LAB-7: skan zdalny | wstępny wynik 6/6 portów jest w `lab-organizers.md` (`e4c4922`, `835cb9d`); do zaliczenia powtórka 3 przebiegów bez drugiego skanu w tle | goose + fatusia-2 | 🟡 |
| **P2** | kolizja ID przebiegu (`runID` z dokładnością do sekundy) | cudzy przebieg jest już chroniony (`0dd62b5`): skan, który przegrał wyścig o ID, nie pisze do bazy. Zostaje: unikalne ID, żeby zapisywały się oba skany | do przypisania | 🟡 |
| **P1** | LAB-T13: gubione porty przy pełnym TCP | zweryfikowane po LAB-T11 (`6cbf91c`: 12/12 portów przez DERP) + poprawka pełnego TCP (`6f8f6c7`); zalecenie jawnych portów za NAT w `lab-organizers.md` | goose / daniel-a8 | ✅ |
| **P2** | OPS-1: dokumentacja tylko lokalnie | proces na `:4173` zbindowany wyłącznie na `127.0.0.1` (`vitepress dev --host 127.0.0.1`) | agy | ✅ |

## Dziennik postępu

| kiedy | co się zmieniło |
|---|---|
| 22.11 10:39 | M3 na 100% ✅: pełne testy integracyjne `internal/store` na czystym PostgreSQL 18 (17/17 PASS, 0 pominiętych — w tym `TestReconcile`, `TestReconcileFiltered`, `TestReconcileHTTPChange`, `TestReconcileRevert`, `TestTargetPorts`) + `findings`/`scanner/nmap`/`cmd/asi` OK; zamknięte `LAB-T13` (`6cbf91c`) i poprawka pełnego TCP (`6f8f6c7`) |
| 22.11 10:35 | UI i prezentacja: zakładka Tokeny (`3f90610`), poprawki dashboardu i ocen PL (`7740529`), finalne teksty slajdów dla jury (`b32e4e5`), pełny TCP bez zera usług i poprawka RBAC `analyst` (`6f8f6c7`) |
| 22.11 10:40 | LAB-7 powtórzony **solo** (bez równoległych skanów): 3 przebiegi na stacku `custom-network` przez DERP, 6/6 portów labu, przebieg 2 = tylko 8787 `missing`, przebieg 3 = tylko 8787 `reappeared`, 0 fałszywych zmian, 0 adresów `172.x`, 731 GET / 0 POST w logu celu; LAB-7 ✅. Skan potwierdzający LAB-T11 odzyskał 4 porty zgubione w pierwszym przejściu pełnego TCP → LAB-T13 zawężone do portów nowych |
| 22.11 10:25 | audyt czystości repo i dokumentacji (`0ff4e8f`): 0 sekretów, 0 prawdziwych publicznych IP, brak `LICENSE` i wzmianek o ekstrakcji z tekstu, `vitepress build` 0 martwych linków; wyrównane `ROADMAP.md`, `status.md`, `README.md` |
| 22.11 10:23 | integracje (`0ff4e8f`): źródła pasywne (CT, DNS, InternetDB), selektywny eksport zaznaczonych (CSV/JSON/DD `asi-selected`) i powiadomienia SIEM (`guide/integrations.md`) |
| 22.11 10:22 | LAB-7 (`e4c4922`): skaner blackarch → lab na fatusia-2 przez DERP (6/6 portów, 0 FP, z zastrzeżeniem nakładki); nowe LAB-T13 i LAB-T14; kolizja ID przebiegu (`0dd62b5`): skan bez własnego wiersza `runs` nie pisze do bazy; histogram na górze dashboardu (`3395a45`) |
| 22.11 10:18 | LAB-T11 (`691406a`): wykryty firewall = wynik niepełny, zdarzenie `filtered`, migracja 009 |
| 22.11 10:16 | przegląd przed oddaniem: porty per cel (`ad0fc60`), hosty przy portach (`835fbbc`, `19b0913`), zawężony zakres formularza celów (`acf0e23`); `go test` i `go vet` zielone na `acf0e23` (bez testów integracyjnych bazy); M3, M7, M8 skorygowane o otwarte braki |
| 22.11 ~10:00 | ALL-1: prezentacja `docs/presentation/asi.tex` uzupełniona o wyniki LAB-1…6, prawdziwe zrzuty z `:18090` (dashboard + porównanie przebiegów), zostaje `\author`; DEV-13 potwierdzone na `:18090` (`/live/` 200, 0 błędów JS); OPS-1 (`make docs` na `127.0.0.1`); aktualizacja `ROADMAP.md` i `status.md` |
| 22.11 ~09:55 | Decyzja 24 (cd.): podgląd skanu `/live/` przez gniazdo Unix `unix:/tmp/asi-live.sock` zamiast TCP 8091 (`2ecf894`, `0be0bc5`) — jedynym portem ASI jest `18090`; LAB-T6 (instalator Gitea `high`), LAB-T10 (`--version-intensity 7` + limit 512 z logiem), LAB-T12 (`stop-at-first-match`, spójna ocena w `services.json`/DD/panelu) |
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
| 21.11 ~16:50 | SEC-8: polityka skanera `internal/safety` (zakres, wykluczenia wbudowane i własne, allowlista portów i flag nmapa, twardy limit pps), sprawdzana w planie i w workerze; profile `raw`/`unprivileged`, decyzja UDP |
| 21.11 ~16:50 | SEC-6: `asi-db` na `pg_tde` (tabele, indeksy, WAL; AES-256) + pola `_enc` AES-256-GCM, rotacja kluczy, `make env-keys`, `make crypto-check` 9/9 OK ([Szyfrowanie](guide/encryption.md)) |
| 21.11 ~16:55 | panel: oś „Zmiany w czasie” z godziną i datą przebiegów, klikalne KPI (np. „otwarte usługi” → Assety z filtrem), filtr oceny; pliki celów do pobrania w dokumentacji |
| 21.11 ~17:50 | SEC-7 dokończone: httpx i nuclei do DD natywnymi parserami (`asi-httpx`, `asi-nuclei`), `close_old` tylko przy pełnym etapie; lab: diff w DD per narzędzie |
| 21.11 ~17:00 | SEC-7: test `asi-changes` w DD (missing/gone/flapping/zmiana, zamykane, gdy warunek mija), brak `close_old` dla przebiegów częściowych też w `asi upload`, `-format nmap` do stałego `asi-nmap`; lab: 4 przebiegi, missing → gone ([DefectDojo](guide/defectdojo.md)) |
| 21.11 ~19:20 | SEC-10: 9 sygnatur IoT (kamery Hikvision/Dahua/ogólne, RouterOS, LuCI, drukarki, NAS, wbudowane serwery firmware'u, opis UPnP); test na atrapie urządzeń pod 127.0.0.1, lint bezpieczeństwa w `go test` ([Fingerprint](guide/fingerprint.md)) |
| 21.11 ~19:30 | SEC-9: publiczne repo https://github.com/Ch3shireDev/awesome-surface-intelligence (remote `github`, push z blackarch), czysty start z GitHuba: `make env && make build && make test` ([Quickstart](guide/quickstart.md#czysty-start-od-zera-sec-9-sprawdzony)) |
| 21.11 ~19:45 | DEV-3: tokeny API w GUI (zakładka Konto): ważność 0–3650 dni, w bazie tylko SHA-256, unieważnianie, audyt; `scripts/test-tokens.sh` 24/24 (401 bez sesji, CSRF, Bearer, revoke, walidacja wejścia) ([Panel](guide/gui.md#tokeny-api-dev-3)) |
| 21.11 ~19:15 | DEV-12: role 1:1 z pkt 13 PDF (Odczyt / Modyfikacja i odczyt / Dodawanie, usuwanie, modyfikacja / Administracja); `analyst` edytuje istniejące cele i harmonogramy, zmiana wartości celu wymaga `operator`; `scripts/test-roles.sh` 28/28, `make test-roles` ([Panel](guide/gui.md#role)) |
| 21.11 ~19:25 | db: `make schema-check` (migracje, indeksy/UNIQUE wymagane przez `ON CONFLICT`, duplikaty, tabele na `heap`) — po `pg_restore` bez `--clean/--create` baza była bez indeksów; `scripts/tde-reenable.sql` przywraca TDE po `DROP SCHEMA` (15/15 tabel, `make crypto-check` 9/9) ([Baza](guide/database.md#kontrola-schematu-make-schema-check)) |
| 21.11 ~20:40 | dashboard: kafelek „nowe w ostatnim skanie” liczy zdarzenia `new`/`reappeared` z ostatniego przebiegu i otwiera dokładnie tę listę (`?run=<id>&events=`), zamiast filtra `state=new`, który dawał 0; `asi db drop-set` do sprzątania zbiorów celów ([Panel](guide/gui.md)) |
| 21.11 ~20:55 | DEV-14: adres w pasku = widok + obiekt (`/assets/<klucz>`, `/scans/<id>`, filtry w query), historia wstecz/dalej, zamykanie szuflady krokiem wstecz, linki do zasobu; SPA pod ścieżkami widoków, bezwzględne `/api/…`; test w Chrome 49/49 ([Panel](guide/gui.md#adresy-widokow-wstecz-i-linki-do-zasobu-dev-14)) |
