# Wizja i architektura - ASI (Attack Surface Intelligence)

Dokument docelowy dla ludzi i agentow AI. Opisuje **co budujemy, jak to dziala
i dlaczego tak**. Zanim zaczniesz implementowac cokolwiek wiekszego niz
poprawka, przeczytaj ten plik, `docs/DECISIONS.md` i `docs/ROADMAP.md`.
Zmiany architektoniczne najpierw tutaj, potem w kodzie.

Status: zaakceptowany kierunek (21.11.2026), kod rdzenia jeszcze nie istnieje.

## 1. Co budujemy

Wlasny system do **cyklicznego discovery scanu duzych sieci (>10 000 IP)**,
ktory:

- przyjmuje cele (IP, CIDR, domeny; recznie, CSV, JSON),
- dzieli zakres na podzakresy (chunki) i rozdziela je na wielu workerow,
- uruchamia **gotowe skanery** (nmap, naabu/masscan, httpx, nuclei) etapami,
- pokazuje postep i czas trwania,
- przechowuje historie i **porownuje przebiegi** (nowe / znikajace /
  zmienione / niestabilne uslugi),
- ma RBAC (4 role z briefu) i audit log,
- **eksportuje wyniki do DefectDojo**.

DefectDojo to **system koncowy, do ktorego eksportujemy**. Nie jest naszym
UI ani magazynem danych. CBI AGH juz go uzywa, ale skanowanie duzych sieci
"z poziomu DD" jest niewygodne. Nasz system to brakujacy "detektor" przed DD.

~~Na teraz bez web UI~~ **Zmienione 21.11 po konsultacji z mentorem
([`MENTOR.md`](MENTOR.md))**: Web GUI jest wymagane i najwyzej punktowane.
Budujemy je jako nakladke na CLI `asi` i baze (wzorzec MISP). RBAC: wystarczy
jedno konto admina, role tylko lokalne. Encryption at rest w Postgresie = 5%.

## 2. Zasady projektowe

1. **Gotowe skanery, nie wlasne.** Uruchamiamy narzedzia jako procesy z
   wyjsciem XML/JSON. Wlasny kod to orkiestracja, normalizacja, historia.
2. **Wlasny kod tylko tam, gdzie wnosi wartosc**: chunking adaptacyjny,
   stan zasobow i diff, obsluga hostow niestabilnych, eksport zmian do DD.
3. **Bezpieczenstwo skanowania ponad szybkosc**: zakres i wykluczenia
   sprawdzane przed kazdym chunkiem, globalny limit tempa, lista dozwolonych
   portow, sygnatury tylko detekcyjne (bez exploitacji, bez prob logowania).
4. **Wszystko w repo i w compose**: konfiguracja w repo, na hoscie tylko
   docker, make, openssl.
5. **API-first**: CLI i przyszle web UI to klienci tego samego API.

## 3. Komponenty

```
 CLI `asi` (teraz) / Web UI (pozniej)
            |  REST /api/v1 + Bearer token (RBAC)
            v
   +------------------+         +---------------------------+
   |   asi server     |<------->|  asi-postgres             |
   |  API, scheduler, |         |  dane + kolejka (River)   |
   |  planner,        |         +---------------------------+
   |  reconcile,      |                 ^
   |  export          |                 | zadania / wyniki
   +------------------+                 |
                                +------------------+
                                |  asi worker  xN  |  nmap, naabu,
                                |  (host network,  |  httpx, nuclei
                                |   NET_RAW)       |  (CLI w obrazie)
                                +------------------+
            |
            v  reimport-scan (API v2)
        DefectDojo  (system koncowy; w compose instancja testowa)
```

Jeden binarny plik Go `asi` z podkomendami:

- `asi server` - API, scheduler, planner, reconcile, eksport.
- `asi worker` - pobiera zadania z kolejki, uruchamia skanery, zapisuje wyniki.
- `asi <komenda>` - CLI (klient REST).

### Stos technologiczny (Go)

| Potrzeba | Wybor | Powod |
|---|---|---|
| Jezyk | Go | sugestia briefu; ekosystem skanerow ProjectDiscovery jest w Go |
| Baza | PostgreSQL (osobna instancja `asi-postgres`, nie baza DD) | izolacja od DD |
| Dostep do bazy | `pgx` + `sqlc` | typowany SQL bez ORM |
| Migracje | `goose` | pliki SQL w `migrations/` |
| Kolejka zadan | `river` (kolejka w Postgresie) | bez Redisa, transakcyjne kolejkowanie, retry, timeouty |
| HTTP API | `net/http` (routing Go 1.22+) lub `chi` | maly, standardowy |
| Specyfikacja API | `api/openapi.yaml` (spec-first, `oapi-codegen`) | kontrakt dla CLI i przyszlego UI |
| CLI | `cobra` | standard |
| Operacje na CIDR | `net/netip` + `mapcidr` (ProjectDiscovery) | agregacja, odejmowanie, dzielenie zakresow |
| Logi | `log/slog` (JSON) | standard |

## 4. Rdzen - szczegolowo

Rdzen to: **model danych + planner (chunking) + wykonanie etapow + ingest +
reconcile (historia/diff) + eksport**. Bez niego nic dalej nie ma sensu,
dlatego jest opisany najdokladniej.

### 4.1 Pojecia

- **Target set** - nazwany zbior celow (np. `lab`, `agh-dmz`) z wykluczeniami.
- **Profile** - "jak skanowac": lista etapow i ich ustawien, limity tempa,
  wspolbieznosc, harmonogram, progi dla hostow niestabilnych.
- **Run** - jeden przebieg profilu na target secie.
- **Chunk** - porcja celow jednego etapu w ramach runu. Jednostka pracy
  workera, postepu, przerwania i ponowienia.
- **Observation** - pojedyncza znormalizowana obserwacja z jednego runu
  (host zyje, port otwarty, usluga X w wersji Y, odpowiedz HTTP...).
- **Asset** - trwaly byt sledzony w czasie (host, host+port), ze stanem i
  edycjami uzytkownika. Obserwacje sa per run, assety zyja miedzy runami.
- **Asset event** - zmiana stanu assetu w danym runie (new, changed,
  missing, gone, reappeared, flapping). To jest zrodlo historii i diffu.

### 4.2 Model danych (szkic)

```
users          (id, username, role, disabled, created_at)
api_tokens     (id, user_id, token_hash, name, expires_at, last_used_at)
audit_log      (id, user_id, action, object_type, object_id, changes jsonb, at)

target_sets    (id, name, description, created_by, ...)
targets        (id, set_id, kind[ip|cidr|domain], value, enabled, tags[], note*)
exclusions     (id, set_id NULL=globalne, value cidr|domain, reason)

profiles       (id, name, stages jsonb, rate_pps, max_concurrency,
                chunk_target_sec, allowed_ports, schedule_cron,
                window_minutes, miss_threshold, gone_after interval,
                flap_window, flap_transitions)

runs           (id, set_id, profile_id, profile_snapshot jsonb,
                status[planned|running|paused|completed|partial|failed|cancelled],
                trigger[manual|schedule], created_by,
                started_at, finished_at, stats jsonb)

chunks         (id, run_id, stage, targets text[], size,
                status[pending|queued|running|done|failed|deferred|cancelled],
                attempts, worker_id, started_at, finished_at,
                progress_pct, duration_ms, error, river_job_id)

raw_outputs    (chunk_id, tool, format, data* bytea zstd)   -- evidence
observations   (id, run_id, chunk_id, asset_key, kind, data* jsonb,
                fp_hash, confidence, observed_at)

assets         (id, key UNIQUE, kind[host|port], parent_id, set_id,
                state[new|active|missing|gone], flapping bool,
                first_seen, last_seen, last_seen_run, consecutive_misses,
                seen_count, transitions_recent, hours_seen int(24-bit),
                current_fp_hash, current jsonb,
                user_tags[], user_note*, user_overrides jsonb)
asset_events   (id, asset_id, run_id, type, before jsonb, after jsonb, at)

exports        (id, run_id, target[defectdojo], status, dd_test_ids jsonb,
                error, at)
```

`*` = pole szyfrowane w aplikacji (patrz 6).

Klucze assetow: host = `10.0.0.5`, port = `10.0.0.5/tcp/443`. Domena jest
atrybutem hosta (rozwiazanie DNS to obserwacja), nie osobnym kluczem.

`profile_snapshot` w runie zamraza ustawienia, wiec edycja profilu nie
zmienia interpretacji starych runow.

### 4.3 Etapy (lejek)

Kazdy etap dostaje **tylko to, co znalazl poprzedni**. Przy duzych sieciach
to glowna oszczednosc ruchu i czasu.

| Etap | Narzedzie | Wejscie | Wyjscie (observation.kind) |
|---|---|---|---|
| `discovery` | `nmap -sn` (ICMP/TCP/ARP probes) albo naabu host discovery | CIDR/IP z target setu | `host` (zyje) |
| `ports` | `naabu` (szybkie, `-rate`) albo `nmap -sS --top-ports N` | zywe hosty | `port` (otwarty) |
| `services` | `nmap -sV` na znalezionych portach | host:porty | `service` (nazwa, produkt, wersja, conf) |
| `http` | `httpx -json` (tytul, kod, naglowki, cookies, TLS, redirecty, tech, favicon hash) | porty HTTP(S) | `http` |
| `signatures` | `nuclei -jsonl` z naszymi szablonami + bezpieczne tagi (`tech`, `panel`) | URL-e z `http` | `signature` |

Profil wlacza wybrane etapy i ich opcje. Zasada dla hostow bez odpowiedzi na
ping: profil moze miec `discovery.treat_all_as_live` (odpowiednik `-Pn`) dla
sieci, w ktorych ICMP jest filtrowany. Host jest uznany za zywy, jesli
odpowiedzial na discovery **albo** ma choc jeden otwarty port.

Adapter skanera to interfejs Go:

```go
type Scanner interface {
    Stage() Stage
    // Buduje komende dla chunku; limity tempa i porty z profilu.
    Command(ctx context.Context, c Chunk, p StageConfig) (*exec.Cmd, OutputSpec)
    // Parsuje surowe wyjscie na znormalizowane obserwacje.
    Parse(raw io.Reader) ([]Observation, error)
}
```

Dodanie nowego skanera = nowy adapter + binarka w obrazie workera.

### 4.4 Planner i chunking

Gdy run startuje:

1. **Rozwiniecie zakresu**: targety z setu -> `netip.Prefix`, agregacja,
   deduplikacja, **odjecie wykluczen** (globalnych i setu). Domeny
   rozwiazywane do IP; rozwiazanie zapisywane jako obserwacja.
2. **Kontrola zakresu**: nic spoza target setu nie moze trafic do chunku.
   Sprawdzane ponownie przez workera tuz przed uruchomieniem skanera.
3. **Podzial na chunki** etapu `discovery` o rozmiarze `S` adresow.
4. **Okno kolejkowania**: planner trzyma w kolejce maksymalnie
   `max_concurrency` chunkow danego runu i dokolejkowuje kolejne, gdy
   poprzednie sie koncza. Dzieki temu limit wspolbieznosci per run dziala
   bez dodatkowych mechanizmow, a pauza/anulowanie to po prostu
   "nie kolejkuj dalej".

**Adaptacyjny rozmiar chunku** (wymog briefu: "podzial w zaleznosci od
szybkosci skanowania"):

- cel: chunk trwa okolo `chunk_target_sec` (domyslnie 300 s),
- planner trzyma srednia ruchoma (EWMA) czasu na adres dla pary
  (profil, etap) z poprzednich chunkow i runow,
- `S = clamp(chunk_target_sec / sec_per_ip, S_min, S_max)`, np. 16..4096,
- pierwszy run bez historii startuje od `S = 256`.

Krotkie chunki daja drobny postep, latwe przerwanie i ponowienie. Za male
chunki zwiekszaja narzut uruchamiania procesow, stad ograniczenia.

**Przejscie miedzy etapami jest strumieniowe, bez bariery**: gdy chunk
`discovery` sie konczy, jego zywe hosty od razu tworza chunk(i) `ports`.
Nie czekamy, az skonczy sie cala siec. Chunki etapow dalszych grupowane sa
po hostach (np. do 64 hostow lub 512 par host:port na chunk).

### 4.5 Wykonanie, limity tempa, okna czasowe

- Zadanie w kolejce River: `scan_chunk{chunk_id}`. Worker oznacza chunk
  `running`, uruchamia adapter, zapisuje `raw_outputs`, parsuje do
  `observations`, oznacza `done` - wszystko w jednej transakcji z
  zakonczeniem zadania.
- **Limit tempa**: `rate_pps` profilu dzielony przez liczbe rownoleglych
  chunkow runu i przekazywany skanerowi (`nmap --max-rate`, `naabu -rate`,
  `httpx -rl`, `nuclei -rl`). Dodatkowo globalny limit systemu, ktorego
  zaden profil nie przekroczy.
- **Dozwolone porty**: `allowed_ports` z profilu (i globalna lista od
  organizatora) przekazywane do kazdego skanera portow.
- **Timeout chunku**: `min(timeout etapu, koniec okna czasowego)`. Proces
  skanera dostaje `context` z deadlinem; po przekroczeniu jest zabijany.
- **Okna czasowe**: scheduler tworzy run zgodnie z `schedule_cron`; okno
  trwa `window_minutes`. Na koniec okna przerwane i niezaczete chunki
  przechodza w `deferred` i wracaja do kolejki na poczatek kolejnego okna.
  Dzieki chunkom wznowienie jest naturalne - nie potrzebujemy
  `nmap --resume`.
- **Ponowienia**: chunk z bledem ponawiany do N razy z backoffem
  (mechanizm River), potem `failed`.
- **Postep chunku**: nmap `--stats-every` parsowane do `progress_pct`.

### 4.6 Postep runu

Liczony z tabeli `chunks`, bez dodatkowego stanu:

- per etap: pending / queued / running / done / failed / deferred,
- adresy przeskanowane / wszystkie, przepustowosc (adresy/s),
- ETA = pozostale adresy / biezaca przepustowosc,
- czas trwania runu i kazdego chunku.

CLI: `asi run status <id> [--watch]`. API: `GET /api/v1/runs/{id}/progress`.

### 4.7 Reconcile - historia, diff, hosty niestabilne

Uruchamiany jako zadanie `finalize_run`, gdy wszystkie chunki runu sa w
stanie koncowym (rowniez gdy run konczy sie jako `partial` po oknie).

**Zasada pokrycia**: brak obserwacji liczy sie jako "brak" tylko dla
adresow, ktore w tym runie **faktycznie zostaly przeskanowane** (chunk
`done`). Chunk `failed`/`deferred` nie generuje brakow - inaczej awaria
workera wygladalaby jak zniknieta siec.

**Zasada hierarchii**: brak portu liczy sie tylko wtedy, gdy host zostal w
tym runie uznany za zywy. Jesli host nie odpowiedzial, jego porty
dziedzicza stan hosta i nie dostaja wlasnych brakow (zeby filtrowany ping
nie "zamykal" wszystkich uslug).

Dla kazdego assetu w pokryciu:

```
obserwowany w runie:
    jesli asset nie istnial          -> state=new,    event new
    jesli state in (missing, gone)   -> state=active, event reappeared
    jesli fp_hash sie zmienil        -> event changed (before/after)
    last_seen=teraz, consecutive_misses=0, hours_seen |= godzina_runu

nieobserwowany w runie:
    consecutive_misses++
    jesli consecutive_misses == 1    -> state=missing, event missing
    jesli consecutive_misses >= miss_threshold
       i teraz - last_seen >= gone_after -> state=gone, event gone

flapping = liczba przejsc active<->missing w ostatnich `flap_window` runach
           >= `flap_transitions`  -> flaga flapping, event flapping
```

- `fp_hash` = hash znormalizowanych, istotnych pol obserwacji (np. dla
  uslugi: nazwa+produkt+wersja; dla HTTP: kod, tytul, zbior naglowkow
  bez dat, cookies po nazwach, tech, odcisk certyfikatu). Pola zmienne
  (daty, nonce) sa wycinane przed hashowaniem.
- `hours_seen` (bitmapa 24 godzin) pozwala wykryc wzorce "odpowiada tylko
  w dzien" (mile widziane w briefie).
- `confidence`: z narzedzia (np. `-sV` conf 0-10, pewnosc tech z httpx),
  podnoszona przez zgodne powtorzenia w kolejnych runach (odpowiedz na
  pytanie z briefu "jak okreslic pewnosc identyfikacji").

**Edycje uzytkownika** (`user_tags`, `user_note`, `user_overrides`) zyja na
assecie, nie na obserwacji, wiec przetrwaja kazdy kolejny skan (wymog
briefu).

**Diff**:

- `asi changes --run <id>` - eventy z danego runu (nowe, zmienione,
  zniknione, powroty, niestabilne).
- `asi diff <runA> <runB>` - porownanie dowolnych dwoch runow po zbiorach
  `(asset_key, fp_hash)` z obserwacji (bez stanu, czysta roznica zbiorow).

### 4.8 Eksport do DefectDojo

Zadanie `export_run{run_id}`, automatycznie po `finalize_run` (opcja
profilu) lub na zadanie `asi export dd <run>`.

- **Mapowanie**: target set -> Product, profil -> Engagement, etap ->
  staly Test (`asi-<etap>`). Konfigurowalne.
- **Wyniki 1:1** idą natywnymi parserami DD przez `reimport-scan`
  (nmap XML -> `Nmap Scan`, nuclei JSONL -> `Nuclei Scan`, httpx ->
  `httpx Scan`), zbudowanymi z `raw_outputs` chunkow runu.
- **Nasza wartosc dodana** (eventy: zniknione uslugi, zmiany wersji,
  flapping, hosty zywe bez portow) idzie jako `Generic Findings Import`
  (Info) do osobnego testu `asi-changes`, z tagami (`new`, `gone`,
  `changed`, `flapping`).
- Wazne: w DD `close_old_findings` dla testow 1:1 wlaczamy tylko dla
  runow z pelnym pokryciem; dla `partial` - nie (zeby czesciowy skan nie
  zamykal findingow w DD). Decyzja o "zniknieciu" i tak nalezy do naszego
  reconcile, nie do DD.
- Wynik eksportu (id testow, statystyki DD) zapisywany w `exports`.

Logika eksportu to rozwiniecie `docker/nmap/scripts/import-defectdojo.sh`
z etapu PoC.

## 5. RBAC i API

| Rola | Uprawnienia |
|---|---|
| `admin` | uzytkownicy, tokeny, globalne wykluczenia i limity, wszystko ponizej |
| `operator` (dodawanie/usuwanie/modyfikacja) | target sety, cele, profile, uruchamianie/pauza/anulowanie runow, eksport |
| `analyst` (modyfikacja i odczyt) | edycja assetow (tagi, notatki, nadpisania), bez tworzenia/usuwania i bez uruchamiania skanow |
| `viewer` (odczyt) | tylko odczyt |

- Uwierzytelnianie: tokeny API (Bearer), w bazie tylko hash tokenu.
  Pierwszy admin tworzony przy starcie z env (jak w DD).
- Autoryzacja: kazda trasa API ma przypisane wymagane uprawnienie,
  sprawdzane w middleware. Role hierarchiczne.
- Kazda zmiana (POST/PATCH/DELETE) trafia do `audit_log` z diffem pol.
- API: REST JSON `/api/v1`, kontrakt w `api/openapi.yaml`. Import celow:
  JSON body lub plik CSV/JSON (multipart). Eksport: JSON/CSV dla assetow,
  obserwacji, eventow.

Przykladowe CLI:

```
asi targets import lab.csv --set lab        # albo .json, albo --add 10.0.0.0/16
asi profile create quick --stages discovery,ports --rate 500
asi run start --set lab --profile quick
asi run status 12 --watch
asi changes --run 12
asi diff 11 12
asi assets list --state missing --tag prod
asi assets edit 10.0.0.5/tcp/443 --tag admin-panel --note "sprawdzic"
asi export dd 12
asi user add jan --role analyst
```

## 6. Szyfrowanie danych w spoczynku

Zwykly PostgreSQL nie ma wbudowanego TDE. Przyjmujemy dwie warstwy:

1. **Szyfrowanie pol w aplikacji (wymagane)**: AES-256-GCM w Go dla pol
   oznaczonych `*` w modelu (surowe wyjscia skanerow, dane obserwacji z
   naglowkami/cookies/certyfikatami, notatki uzytkownikow). Klucz z env
   (`ASI_ENCRYPTION_KEYS`, lista z identyfikatorami, zeby dalo sie
   rotowac); w zaszyfrowanej wartosci zapisany jest id klucza.
   Pola potrzebne do wyszukiwania (IP, port, stan, nazwa uslugi) zostaja
   jawne w osobnych kolumnach.
2. **Szyfrowanie calej bazy (opcjonalne)**: szyfrowany wolumen (LUKS) albo
   TDE przez rozszerzenie (np. Percona `pg_tde`) - do zweryfikowania,
   czy dziala z naszym stosem.

Tokeny i hasla sa hashowane, nie szyfrowane.

## 7. Bezpieczenstwo skanowania

- Zakres: tylko cele z target setu minus wykluczenia; sprawdzane w
  plannerze i ponownie w workerze.
- Limity: globalny i per-profil limit pps, limit wspolbieznosci, lista
  dozwolonych portow.
- Sygnatury: tylko detekcja (naglowek, cookie, hash favicony, fragment
  HTML, sciezka bez prob logowania, wersja w stopce). Nuclei z
  wykluczonymi tagami `intrusive,dos,fuzz,brute-force` i tylko naszymi /
  zatwierdzonymi szablonami.
- Kazdy run ma wlasciciela i jest w audit logu.

## 8. Wdrozenie (compose)

Dochodza serwisy:

- `asi-postgres` - baza ASI (osobna od DD), port tylko na `127.0.0.1`.
- `asi-server` - API (port wewnetrzny, np. 8090; wystawiany pozniej dla UI).
- `asi-worker` - obraz: binarka `asi` + nmap, naabu, httpx, nuclei;
  `network_mode: host`, `NET_RAW`/`NET_ADMIN`; skalowany
  `docker compose up --scale asi-worker=N`. Laczy sie z bazą przez
  `127.0.0.1` (siec hosta).
- DefectDojo zostaje jako instancja testowa do eksportu.

CLI: `docker compose exec asi-server asi ...` (alias w Makefile).

## 9. Struktura repo (docelowo)

```
cmd/asi/                 main, podkomendy cobra
internal/api/            handlery REST, middleware auth/RBAC/audit
internal/auth/           tokeny, role
internal/planner/        rozwijanie zakresu, chunking, okno kolejkowania
internal/scanner/        interfejs + adaptery: nmap/, naabu/, httpx/, nuclei/
internal/worker/         wykonanie zadan River
internal/reconcile/      stan assetow, eventy, diff
internal/export/dd/      eksport do DefectDojo
internal/crypto/         szyfrowanie pol
internal/store/          zapytania sqlc
migrations/              SQL (goose)
api/openapi.yaml         kontrakt API
signatures/              nasze szablony nuclei
docker/asi/Dockerfile    obraz server/worker
```

## 10. Otwarte decyzje

- Czy workery lacza sie z bazą bezposrednio (River - prostsze), czy przez
  API (lepsza izolacja). Na start: bezposrednio.
- `discovery` przez nmap czy naabu - zmierzyc na labie.
- Czy `services` (`nmap -sV`) robic na kazdym runie, czy tylko dla nowych
  /zmienionych portow (oszczednosc czasu w cyklicznych skanach).
- TDE w bazie: wolumen LUKS vs `pg_tde`.
- Weryfikacja alternatyw przed pisaniem rdzenia: IVRE (framework recon
  sieci) - czy moze przejac czesc przechowywania/importu wynikow.
