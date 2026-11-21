# Zadania i podział pracy

Stan na 21.11.2026, ~20:00 CET. Źródła: PDF zadania, `VISION.md` (architektura docelowa), `status.md` (co działa),
`ROADMAP.md` (postęp etapów), `guide/lab-organizers.md` (analiza labu organizatorów).

## Zgłoszenie (HackTribe)

| pole | wartość |
|---|---|
| nazwa projektu | **Asia - Attack Surface Intelligence Aggregator** |
| repozytorium | https://github.com/Ch3shireDev/awesome-surface-intelligence |
| zadanie | Attack Surface Intelligence (CBI AGH) |
| terminy | **21.11 20:00 DRAFT ✅ złożone**, **22.11 11:00 FINALNE** (wszystkie pola + prezentacja i materiały) |
| uwaga | zgłoszenie utworzone przed 20:00 można edytować po 20:00; nie da się już zmienić zadania |

Kod jest rozwijany dalej w repo roboczym (bare `daniel@blackarch:~/repos/asi.git`, klony `~/asi` na blackarch,
fatusia-hacknation-1 i fatusia-hacknation-2). **GitHub (`github`) to drugi remote** — push po każdym `make sync`
i przed 11:00 jutro. Historia jest czysta (bez `.env`, `.dd_token`, `targets/targets.csv`, `results/`), więc
publiczne repo nie wymaga przepisywania historii. Zadanie SEC-9 pilnuje tego linku.

**Role:** **DEV** to Daniel (kod rdzenia, API, UI). **SEC** to fatusia (DevSecOps: stack, środowisko testowe,
skanery i sygnatury, bezpieczeństwo, szyfrowanie, DefectDojo, demo).

## Gdzie jesteśmy

Rdzeń systemu (M0–M7, 16 wymagań „musi” z PDF) jest zaimplementowany i przetestowany — szczegóły w
[`ROADMAP.md`](ROADMAP.md) i [`status.md`](status.md). Zostały zadania domykające na finisz:
- weryfikacja widoku postępu na żywo (`DEV-13`) — poprawki RBAC (`DEV-11`, `DEV-12`) są już zrobione,
- dopasowanie do labu organizatorów (`LAB-T1`, `LAB-T2`, `LAB-T4`) i przejście testów `LAB-0`…`LAB-6`,
- prezentacja ≤10 slajdów + wideo demo (`ALL-1`), dokumentacja 100% + ścieżka testowania + czysty start z Dockerem (`ALL-2`), porządki (`OPS-1`).

## Priorytety po konsultacji z mentorem (21.11, 14:44)

Szczegóły: [`MENTOR.md`](MENTOR.md). Wpływ na zadania:

- **DEV-4 (Web GUI: formularz celów, assety, dashboard) w górę**: GUI to „całe mięso” oceny. GUI może wołać
  komendy CLI `asi` i czytać bazę (wzorzec MISP).
- **DEV-3 (RBAC) w dół**: najpierw jedno konto admina z `.env` i logowanie. 4 role tylko, jeśli starczy czasu.
  Żadnej synchronizacji użytkowników z DefectDojo.
- **SEC-6 + szyfrowanie Postgresa**: encryption at rest to „darmowe” 5%. Oprócz pól AES-GCM zaszyfrować dane
  bazy (wolumen LUKS albo `pg_tde`) i opisać to w dokumentacji.
- Eksport do DD zostaje obowiązkowy: ASI to feed dla DefectDojo.

## Kto co bierze (na bieżąco)

Oznaczenie przy ID: 🔨 *w toku: kto*, ✅ *zrobione: commit*. Bierz wolne zadanie, oznacz je commitem w tym pliku,
dopiero potem pisz kod. Podział DEV/SEC jest orientacyjny.

## Zasada, żeby się nie blokować

Na start **DEV-0** ustala kontrakt `Observation` i interfejs adaptera skanera (`VISION.md` 4.3).
Od tej chwili SEC pisze adaptery (httpx, nuclei) i sygnatury, które zwracają `[]Observation`, i nie czeka na bazę.
DEV podłącza je do bazy i reconcile. Każde zadanie kończy się wpisem w `status.md`, a każdy wynik to commit
i `make sync`.

## P0: dziś wieczorem (fundament i odblokowanie)

| ID | kto | zadanie | gotowe, gdy |
|---|---|---|---|
| SEC-1 | SEC ✅ *zrobione (agent blackarch #2, 21.11 15:50: build arm64, 2 skany, `make poc`)* | Migracja fatusia-2 na `~/asi` (instrukcja w `~/sync/komunikacja/asi_blackarch.md`). `make up` buduje obraz `nmap-scanner` z `asi` na arm64. Potem `make asi-scan` na 127.0.0.1 i usunięcie `~/sync/hacknation-asi`. | panel :8090 i findingi w DD z kontenera |
| SEC-2 | SEC ✅ *materiały od organizatorów z Discorda = pobrany lab (`~/lab` na `fatusia-2`), przeanalizowany w `docs/guide/lab-organizers.md` → zadania `LAB-*`. Osobnego przykładowego JSON/CSV, listy portów/limitów, wyników referencyjnych ani testowego DD w tych materiałach nie ma: porty i scenariusze bierzemy z labu* | Materiały od organizatorów (Discord albo stanowisko AGH): kontenery labu, dozwolone porty, limity ruchu, wyniki referencyjne, przykładowe sygnatury, format JSON/CSV, testowe DD. Wpisać do `DECISIONS.md` „Otwarte pytania”. | zakres labu w `targets/`, limity w profilu |
| SEC-3 | SEC ✅ *zrobione (agent blackarch #2): `make demo`, `docs/guide/lab.md`* | Własny mini-lab w compose (profil `lab`): nginx, WordPress, panel `/admin`, nagłówek `X-Environment: staging`, ciekawe cookie, usługa „migająca” (cron on/off). Do tego `make demo`: 2 przebiegi ze zmianą pomiędzy. | `make demo` pokazuje new/gone/changed/unstable |
| DEV-0 | DEV ✅ *zrobione (blackarch)* | Kontrakt: `Observation` (kind, asset_key, data, fp_hash, confidence), interfejs `Scanner` i adapter nmap przepięty na niego. | SEC może pisać adaptery |
| DEV-1 | DEV ✅ *zrobione (blackarch)* | Baza `asi-postgres` (osobna od DD) z migracjami SQL w binarce. Tabele: targets, runs, chunks, observations, assets, asset_events, users, api_tokens, audit_log. Zapis przebiegu do bazy zamiast `results/*.json` (pliki zostają jako eksport). | 2 przebiegi w bazie, diff z bazy |

## P1: jutro rano (wymagania „musi” i największe wagi)

| ID | kto | zadanie | waga w ocenie |
|---|---|---|---|
| SEC-4 | SEC ✅ *zrobione (agent blackarch): `internal/scanner/httpx`, etap `http`* | Etap `http`: adapter **httpx** (tytuł, kod, nagłówki, cookies, cert TLS, przekierowania, tech, hash favicony) na usługach http/https z fazy 2. httpx dochodzi do obrazu skanera. | fingerprint 10% + discovery 30% |
| SEC-5 | SEC ✅ *zrobione (agent blackarch): `internal/scanner/nuclei`, `signatures/` (14), `signatures/README.md`* | Etap `signatures`: **nuclei** z naszymi szablonami w `signatures/` (nagłówek, cookie, favicon, fragment HTML, ścieżki `/login` `/admin` `/version` bez logowania, wersja w stopce, CMS, staging). Tagi `intrusive,dos,fuzz,brute-force` wykluczone. Krótki opis „jak dodać sygnaturę”. | sygnatury (pkt 10 PDF) |
| DEV-2 | DEV ✅ *zrobione (blackarch)* | Reconcile w bazie: stany `new/active/missing(n)/gone`, `reappeared`, `flapping`, `hours_seen`, próg braków dla hostów. Edycje użytkownika (tagi, notatki, nadpisania) trzymane na assecie. | zmiany w czasie 15% |
| DEV-3 | DEV ✅ *zrobione (goose/blackarch, 21.11): 4 role, sesje, audit log, użytkownicy + **tokeny API w GUI** (zakładka Konto, `GET/POST/DELETE /api/v1/tokens`, test `scripts/test-tokens.sh` 24/24)* | API `/api/v1` i RBAC: role `admin` / `operator` (dodawanie, usuwanie, modyfikacja) / `analyst` (modyfikacja i odczyt) / `viewer` (odczyt), tokeny (w bazie tylko hash), middleware, audit log. Pierwszy admin z `.env`. | role 10% |
| SEC-6 | SEC ✅ *zrobione (agent fatusia, 21.11): pg_tde + pola AES-256-GCM, `make crypto-check`* | `internal/crypto`: AES-256-GCM dla pól wrażliwych (surowe wyjścia, nagłówki, cookies, certyfikaty, notatki). Klucze `ASI_ENCRYPTION_KEYS` z id, żeby dało się rotować. Opis w dokumentacji, co jest szyfrowane i dlaczego. | ochrona danych (część 10%) |
| DEV-4 | DEV ✅ *zrobione (blackarch)* | Panel web na API: logowanie, **formularz celów** (ręcznie oraz upload CSV/JSON), lista assetów z edycją, **dashboard**: najważniejsze znaleziska, zmiany z ostatniego przebiegu, niestabilne hosty. Widoki zależne od roli. | dashboard 15% |

## P2: jutro do południa (punkty „mile widziane” i dopięcie)

| ID | kto | zadanie |
|---|---|---|
| DEV-5 | DEV ✅ *zrobione (blackarch)* | Harmonogram: cron, okno, wznawianie niedokończonych paczek w kolejnym oknie (`deferred`). Z panelu: start, pauza, anulowanie. |
| DEV-6 | DEV ✅ *zrobione (agent blackarch): import nmap XML/CSV/JSON/JSONL w GUI i CLI, eksport CSV/JSON* | Eksport JSON i CSV (assety, obserwacje, zdarzenia). Import cudzych wyników (nmap XML, JSON/CSV w formacie organizatorów). |
| SEC-7 | SEC ✅ *zrobione (agent fatusia, 21.11): `asi-changes`, `asi-nmap`, `asi-httpx`, `asi-nuclei`, brak `close_old` dla częściowych/niepełnych etapów. Test na DD organizatorów: po SEC-2* | Eksport do DD po nowemu: natywne parsery (Nmap, httpx, Nuclei) plus test `asi-changes` (Generic: gone, changed, flapping), bez `close_old` dla przebiegów częściowych. Test na instancji DD organizatorów. |
| SEC-8 | SEC ✅ *zrobione (agent fatusia-1): `internal/safety`, worker, profile raw/unprivileged, UDP, `docs/guide/safety.md`* | Bezpieczeństwo skanera: kontrola zakresu i wykluczeń także w workerze, lista dozwolonych portów, sztywny górny limit pps, profil z `NET_RAW` (`-sS`, ICMP) i bez roota (`-sT`). Decyzja co do UDP (DNS, SNMP, NTP). Strona „Bezpieczeństwo” zaktualizowana. |
| DEV-7 | DEV ✅ *zrobione (agent blackarch): docs/guide/insights.md* | Ocena „ciekawości” rozszerzona o dane HTTP i sygnatury, grupowanie podobnych usług, wizualizacja zmian w czasie na dashboardzie. |
| DEV-8 | DEV ✅ *zrobione (sesja koordynująca): panel, API, `asi targets-extract`, `asi mcp`, docs/guide/targets-ai* | Cele z dowolnego tekstu: wklejony inwentarz/notatki → lista celów w naszym formacie (DeepSeek `deepseek-flash`, bez klucza fallback regex). Walidacja: tylko cele obecne w tekście, adresy wewnętrzne/Tailscale `enabled=false`. Pole tekstowe w panelu (podgląd przed zapisem), `POST /api/v1/targets/extract`, `asi targets-extract`, serwer MCP `asi mcp`. Pliki: `internal/targetsai/`, `internal/app/extract.go`, `cmd/asi/{extract,mcp}.go`, karta w `ui.html`. |

## P3: finisz (formalności, ostatnie godziny)

| ID | kto | zadanie |
|---|---|---|
| DEV-9 | DEV ✅ *zrobione (agent blackarch)* | GUI: porównanie dwóch dowolnych przebiegów; oznaczanie wyników (fałszywy alarm, zaakceptowane ryzyko, nadpisana ocena) honorowane przez dashboard i eksport; edycja harmonogramu. |
| DEV-10 | DEV ✅ *zrobione (agent blackarch): docs/guide/scale.md* | Test skali ≥10 000 adresów (127.0.0.0/18, tylko loopback): czas skanu, zapis do bazy, przeliczanie stanów, dashboard; poprawki wydajności. |
| SEC-10 | SEC ✅ *zrobione (goose/blackarch, 21.11): 9 sygnatur IoT w `signatures/http/`, test na atrapie 7 urządzeń pod 127.0.0.1, lint `go test ./internal/scanner/nuclei`* | Sygnatury IoT (kamery, routery, drukarki, panele urządzeń) do `signatures/` (pkt 6 PDF). |
| SEC-9 | SEC ✅ *zrobione (goose/blackarch, 21.11): https://github.com/Ch3shireDev/awesome-surface-intelligence — publiczne, remote `github` w `~/asi`, historia bez sekretów i realnych celów; czysty start z GitHuba potwierdzony (`make env && make build && make test`), `make up` wymaga dockera na VM* | Publiczne repo dla jury: GitHub jako drugi remote (origin zespołu zostaje na blackarch). Przed pushem przegląd historii pod kątem sekretów i realnych IP. Czyste uruchomienie od zera: `git clone && make env && make up && make demo`. |
| DEV-11 | DEV ✅ *zrobione (goose/blackarch, 21.11): `PATCH`/`DELETE /api/v1/users/{id}`, ochrona ostatniego admina (409), blokada i reset hasła unieważniają sesje/tokeny (401), GUI w Administracji, `make test-users` 35/35* | **Zarządzanie kontami (pkt 12–13 PDF, „Administracja”).** Dziś admin może w API/GUI tylko tworzyć konta (`POST /api/v1/users`); w CLI jest `asi user list/passwd/add` (4772620). Brak zmiany roli, blokady (`disabled`) i usunięcia, więc nie da się odebrać dostępu. Do zrobienia: `PATCH /api/v1/users/{id}` (rola, `disabled`, nowe hasło) + unieważnienie sesji/tokenów zablokowanego konta, ochrona przed odebraniem sobie ostatniego admina, widok w GUI (Administracja), wpisy w audit logu. Test: zablokowany użytkownik dostaje 401 na istniejącej sesji. |
| DEV-12 | DEV ✅ *zrobione (goose/blackarch, 21.11): `PUT /targets/{id}` i `PUT /schedules/{id}` dostępne dla `analyst`, zmiana samej wartości celu wymaga `operator` (400), edycja nieistniejącego celu 404, tabela ról w `docs/guide/gui.md` 1:1 z pkt 13 PDF, `scripts/test-roles.sh` 28/28 na `:8099`* | **Wyrównanie ról z treścią zadania (pkt 13).** Role z PDF: *Odczyt* (`viewer`), *Modyfikacja i odczyt* (`analyst`), *Dodawanie, usuwanie, modyfikacja* (`operator`), *Administracja* (`admin`). `analyst` = modyfikacja istniejących wartości (asset, cel, harmonogram) niezależnie od stanu skanu, bez tworzenia/usuwania/uruchamiania; `operator` = + dodawanie i usuwanie celów i harmonogramów, start/stop skanów. Uwaga: `scripts/test-roles.sh` zakłada komplet indeksów i ograniczeń `UNIQUE` w bazie (`ON CONFLICT`) — sprawdź `pg_indexes` po restore z dumpa. |
| DEV-13 | DEV 🔨 *w toku: agy/blackarch; wyniki od agenta blackarch #2 (20:20): PTY potwierdzone w kontenerze (nmap 7.95: 20 linii `--stats-every` na paczkę, wcześniej 0); reguła zmieniona: postęp z narzędzia wygrywa nad szacunkiem z czasu (pełne TCP przy `-ports auto` jest wolniejsze niż zmierzona szybkość top-1000); widok na żywo obejrzany na zrzucie z prawdziwym snapshotem. Zostaje: obejrzeć `:8090` po `make up`* | **Weryfikacja postępu skanu na żywo i UI (`626855b`).** Po przebudowie obrazu `nmap-scanner` (`make up`) sprawdzić w kontenerze, czy nmap 7.95 z PTY (`internal/scanner/tty_linux.go`) zwraca realny procent postępu (nie tylko szacunek z czasu), oraz obejrzeć wizualnie w przeglądarce nowy 4-etapowy widok na żywo i dashboard na `:8090`. |
| ALL-1 | oboje 🔨 *w toku: fatusia-2 (szablon Beamer `docs/presentation/asi.tex`, `make slides`)* | Prezentacja do 10 slajdów (szablon Beamer: `docs/presentation/asi.tex`, `make slides`): uzupełnić `\TODO` o wyniki demo/labu i zrzuty ekranu (problem, architektura, 2 przebiegi, role, szyfrowanie, DD, bezpieczeństwo skanowania). Nagranie wideo demo jako plan B. |
| ALL-2 | oboje ✅ *zrobione (fatusia-1 + agent blackarch): strona `guide/jury.md`, `status.md`; czysty start na czystej VM (fatusia-1): `make up` 3 min 49 s, `make demo` 150 s, crypto-check 9/9, import; poprawka: `results/` tworzone przez `make up`* | Dokumentacja i ścieżka testowania: nowa strona krok po kroku pod test jury (lab → 2 przebiegi → edycja znalezisk → import → role → eksport → DefectDojo → szyfrowanie), `status.md` na 100%, weryfikacja czystego startu na czystej VM z Dockerem (`git clone && make env && make up && make demo`). |
| OPS-1 | dowolny 🔨 *w toku: agy/blackarch* | Drobne/porządkowe: naprawić `make docs` (`vitepress preview` ignoruje `--host` i słucha na wszystkich interfejsach — zbindować na `127.0.0.1`), posprzątać osierocone procesy testowe na `blackarch` (`slow.py` :8777, `./asi server` :8097, stary `docker run` ze skasowanego `~/asi-sec`). |

## Blokery (na bieżąco)

| bloker | blokuje | kto | stan |
|---|---|---|---|
| `make env` nie dopisuje nowych kluczy do istniejącego `.env` (compose nie startuje po DEV-1) | każdy `make up` po pullu | agent blackarch | ✅ `make env-sync` (wołane przez `make up`) |
| nginx DD daje 502 po odtworzeniu `uwsgi` przy `make up` (stary IP upstreamu) | upload do DD, demo | agent blackarch | ✅ `make up` restartuje nginx |
| import celów (.txt) kasował tagi i notatki wcześniej wgranych celów (zgłosił agent #2) | pkt 14 PDF | agent blackarch | ✅ import/dodawanie scala (`MergeTargets`), jawna edycja dalej zastępuje |

## Testy na labie organizatorów (LAB-*), od 21.11 wieczór

Środowisko: `~/lab` na fatusia-hacknation-2 (poza repo). To są **materiały od organizatorów z Discorda** (SEC-2). Opis, analiza i sposób testowania:
[Lab organizatorów](guide/lab-organizers.md). Jeden stack naraz. Cel `127.0.0.1` (`targets/lab-org.csv`).
Każdy test kończy się wpisem wyniku (OK / FAIL + liczby) w tej tabeli i w `status.md`.

| ID | kto | test | zaliczony, gdy |
|---|---|---|---|
| LAB-0 | SEC ✅ *zrobione (agent fatusia, 21.11): `targets/lab-org.csv`; porty ASI/DD wycięte jawnie z `-p` (przed LAB-T2), po LAB-T2 automatycznie* | Przygotowanie: `targets/lab-org.csv` (127.0.0.1), przeniesienie portów ASI/DD w `.env` przed `modern` i `vulnerable` (konflikt 8080/8090), lista portów skanu bez portów ASI (8080, 8090, 8091, 8094, 5433). | `make asi ARGS='plan -targets targets/lab-org.csv'` pokazuje tylko 127.0.0.1, `make up` działa na nowych portach |
| LAB-1 | SEC ✅ *zaliczony (agent fatusia, 21.11 19:01-19:26): 3 przebiegi OK; luka portów potwierdzona na kodzie sprzed LAB-T1 i zamknięta po LAB-T1/T2; wyniki: `docs/guide/lab-organizers.md`* | **Scenariusz quickstart** (`custom-network`, `./quickstart.sh up/change/up`), 3 przebiegi z pełnym zakresem TCP (`-p-`). | przebieg 2: tylko `8787` jako `missing` (pozostałe 4 porty `untouched`), przebieg 3: `8787` `reappeared`; w DD `asi-changes` „nie odpowiada” otwarte, a potem zamknięte; **ten sam test z domyślnym zestawem portów pokazuje lukę** (8787 niewidoczny) |
| LAB-2 | SEC 🔨 *w toku: goose/blackarch (21.11 20:45), czeka na wolny lab na fatusia-2 (dziś `modern-proxy`)* | `custom-network` w całości: httpbin, PostgreSQL, RabbitMQ (AMQP + panel), Gitea (HTTP + SSH), nginx. | 7 portów, poprawne usługi z `-sV`, Gitea i RabbitMQ rozpoznane w HTTP (tytuł/tech) |
| LAB-3 | SEC 🔨 *w toku: goose/blackarch (21.11 20:45), po LAB-2 (jeden stack naraz)* | `modern`: WordPress latest, phpMyAdmin, Redis bez hasła, Nginx Proxy Manager (80/81/443). | WordPress z wersją, `asi-redis-noauth` high, panele phpMyAdmin i NPM rozpoznane (po LAB-T3), TLS na 443 |
| LAB-4 | SEC | `vulnerable`: WordPress 4.7, Adminer, DVWA, vsftpd. **Bez prób logowania** (domyślne hasła w compose). | WordPress 4.7 oznaczony jako przestarzały i wysoko w ocenie, Adminer/DVWA rozpoznane, vsftpd z wersją; w logach skanera brak żądań logowania |
| LAB-5 | SEC ✅ *przetestowany (agent fatusia, 21.11 19:37-20:15): opóźnienie/wolne łącze/wolne zamykanie OK; wyszły LAB-T7 (krytyczne), LAB-T8, LAB-T9; wyniki: `docs/guide/lab-organizers.md`* | `modern-proxy` + Toxiproxy: przebiegi z `ENABLE_LATENCY` 500 ms, potem `ENABLE_TIMEOUT`, `ENABLE_BANDWIDTH`, `ENABLE_SLOW_CLOSE`. | skan kończy się w oknie, brak fałszywych `gone` przy opóźnieniu, timeout odnotowany jako brak odpowiedzi HTTP (nie zniknięcie portu); czas odpowiedzi widoczny (po LAB-T4); dashboard Traefika i API Toxiproxy (8474) wykryte jako panele bez uwierzytelniania |
| LAB-6 | SEC 🔨 *w toku: agent fatusia (fatusia-1, własna kopia labu)* | Zmiana stacku między przebiegami (`custom-network` → `modern`) i powrót. | masowe `missing` → `gone` po progu, nowe usługi, powrót = `reappeared`; DD bez duplikatów; czas przebiegów w normie |

Zadania kodu wynikające z analizy (przed LAB-1…5):

| ID | kto | zadanie |
|---|---|---|
| LAB-T1 | DEV ✅ *zrobione (agy/blackarch): `-ports auto` (pełne TCP ≤16 hostów), `all`/`lab`/`allowed` w CLI i GUI, zgodne z `ASI_ALLOWED_PORTS`* | Zakres portów: pełne TCP (`-p-`) automatycznie dla małych zbiorów celów (np. ≤ 16 hostów, z limitem tempa) albo profil „lab” / „lista portów od organizatorów” w GUI i CLI. Dziś domyślnie top 1000 + 14 ryzykownych, więc 8787, 15432, 5673, 15673, 2223, 8474 są niewidoczne. |
| LAB-T2 | SEC ✅ *zrobione (agent fatusia-1): porty stacku z `.env` pomijane na hoście skanera (loopback, interfejsy, `ASI_SELF_IPS`), osobna paczka z `--exclude-ports`, `ASI_SELF_PORTS`; sprawdzone na żywym stacku blackarch* | Nie skanować samego siebie: wykluczenie portów ASI/DD przy celu = host skanera (wykluczenia per port albo automatyczne). |
| LAB-T3 | SEC ✅ *zrobione (agy/blackarch, 21.11): 10 sygnatur w `signatures/http/` (phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ management, NPM, Traefik, Toxiproxy, httpbin, WordPress < 6.0) + poprawka `asi-iot-camera-hikvision` (usunięty nagłówek Dahua `DNVRS-Webs`), `nuclei -validate` OK, test na 12-usługowej atrapie HTTP 100% trafień / 0 FP* | Sygnatury detekcyjne (`signatures/`): phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ management, Nginx Proxy Manager, Traefik dashboard (`api.insecure`), API Toxiproxy, httpbin, nieaktualny WordPress (< 6.0). Tylko detekcja, bez logowania. Uzupełnia SEC-10 (IoT). |
| LAB-T4 | DEV ✅ *zrobione (agy/blackarch): `httpx -rt` → `response_time_ms` poza `fp_hash`, kolumna `HTTP ms` + filtr wolnych + szuflada + CSV, `ASI_HTTP_SLOW_MS=500`* | Czas odpowiedzi HTTP z httpx (`time`) jako metryka obserwacji, poza `fp_hash`; w panelu kolumna i próg „wolna odpowiedź”; zmiana opóźnienia nie może dawać `changed`. |
| LAB-T5 | DEV | Spójne nazwy zmian: dla tego samego przebiegu `asi diff` (porównanie plikowe) pisze „gone” / „+ new”, a historia w bazie „missing” / „reappeared” (LAB-1, przebiegi 2-3). Jury może to wziąć za sprzeczność: diff powinien używać stanów z reconcile albo pisać „brak w tym przebiegu”. |
| LAB-T6 | SEC | Sygnatura „Gitea: niedokończona instalacja” (strona `Installation - Gitea` dostępna bez logowania = ryzyko przejęcia instancji). Dziś `asi-gitea` ma severity `info` i nie odróżnia instalatora (LAB-1, 21.11). |
| LAB-T7 | DEV ✅ *zrobione (agent fatusia, 21.11): `timedout` w `nmapxml`, host niepokryty (pending, bez braków, `SetChunkTargets`), `close_old` głównego testu DD tylko przy pełnych etapach discovery/services (też `asi upload`); sprawdzone na żywo `--host-timeout 5s`: 0 fałszywych zdarzeń, DD `close_old=false`* | **KRYTYCZNE: przekroczony `--host-timeout` = „host bez portów” = masowe fałszywe zniknięcia.** nmap dla hosta, który przekroczył `--host-timeout`, zwraca `<host timedout="true">` **bez żadnych portów** i kod wyjścia `success`. ASI (`internal/nmapxml`, `internal/scanner`) nie czyta `timedout`, więc paczka jest `done`, a reconcile oznacza wszystkie usługi hosta jako `missing` (LAB-5: 10 fałszywych `missing` + `flapping`, 11 fałszywych warunków w DD). Przy pełnym przebiegu główny reimport (`close_old` = `!interrupted`) zamknąłby też w DD wszystkie findingi hosta. Wyzwalacz w LAB-5: skok zegara ściennego (VM wstrzymana ~20 min, zegar monotoniczny ASI 92 s vs nmap 1303 s), ale to samo zrobi bardzo wolny host lub `-sV` na wiszącej usłudze. Do zrobienia: (1) `timedout="true"` → host niepokryty (do `pending`/resume, bez braków, błąd paczki), (2) główny reimport `ASI discovery` z `close_old` tylko, gdy wszystkie paczki usług bez błędu (jak `asi-httpx`/`asi-nuclei`), (3) test z XML z `timedout`. |
| LAB-T8 | DEV 🔨 *w toku: agent fatusia (fatusia-2)* | **Przejściowa awaria zaplecza = 2× „changed” + rotacja w DD.** LAB-5 (Toxiproxy `timeout`): WordPress za Traefikiem przestaje odpowiadać, na porcie odpowiada sam Traefik (TLS, 404), więc `-sV` i httpx dają inny fingerprint: `changed` (Apache/WordPress → Go/Traefik), a po ustąpieniu awarii znowu `changed`. DD: closed/created, potem closed/reactivated. `flapping` tego nie łapie (port cały czas otwarty). Do zrobienia: potwierdzanie `changed` (ponowny probe w tym samym przebiegu albo zmiana musi się utrzymać 2 przebiegi) i/lub klasa „zdegradowana” (5xx / timeout zaplecza) zamiast zmiany; wykrywanie migania fingerprintu. |
| LAB-T9 | SEC | Próg wolnej odpowiedzi `ASI_HTTP_SLOW_MS=500` = scenariusz organizatorów `LATENCY_MS=500` (±50 ms), w LAB-5 zmierzone 493 ms, czyli flaga losowa. Obniżyć (np. 300 ms) albo liczyć względnie do poprzednich pomiarów usługi (np. ×5 mediany). |

## Ryzyka

- **Porty i opóźnienia w labie organizatorów (`LAB-T1`, `LAB-T4`, `LAB-0`…`6`):** domyślny zestaw top 1000 nie obejmuje m.in. `8787` z quickstartu organizatorów — stąd priorytet na `LAB-T1` i przejście wszystkich 4 stacków przed 11:00.
- **Mirror Alpine w Docker buildzie:** bywa wolny (Dockerfile ma 3 próby `apk add`); warto przebudować obraz skanera z wyprzedzeniem przed demo (`DEV-13`).
- **Równoległa praca wielu agentów w jednym repo:** małe commity, `make sync` przed i po pracy, rezerwacja zadania w `TASKS.md` i rozdzielone pliki, żeby unikać konfliktów.
