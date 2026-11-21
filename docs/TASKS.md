# Zadania i podział pracy

Stan na 21.11.2026, ok. 15:40. Źródła: PDF zadania, `VISION.md` (architektura docelowa), `status.md` (co działa),
rozmowy z agentami na blackarch i fatusia-hacknation-2.

**Role:** **DEV** to Daniel (kod rdzenia, API, UI). **SEC** to fatusia (DevSecOps: stack, środowisko testowe,
skanery i sygnatury, bezpieczeństwo, szyfrowanie, DefectDojo, demo).

## Gdzie jesteśmy

Działa i jest przetestowane na 127.0.0.1 (21.11, scalone repo):

- plan celów z CSV, JSON i TXT, z rozwijaniem CIDR,
- dwie fazy skanu nmap, adaptacyjne paczki, globalny limit tempa, okno czasowe,
- postęp w CLI i panelu web,
- diff przebiegów, potwierdzanie zniknięć (tag `unstable`),
- reimport do DefectDojo: `created → closed → reactivated`,
- stack DefectDojo 3.5.202 w compose.

Brakuje (wymagania „musi” z PDF):

- baza z edycją trwałą między skanami,
- RBAC z 4 rolami,
- formularz celów w UI,
- dashboard najważniejszych znalezisk,
- szyfrowanie pól,
- fingerprinting HTTP/TLS, wykrywanie CMS, własne sygnatury,
- harmonogram ze wznawianiem w kolejnym oknie,
- eksport CSV, import cudzych wyników.

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
| SEC-2 | SEC | Materiały od organizatorów (Discord albo stanowisko AGH): kontenery labu, dozwolone porty, limity ruchu, wyniki referencyjne, przykładowe sygnatury, format JSON/CSV, testowe DD. Wpisać do `DECISIONS.md` „Otwarte pytania”. | zakres labu w `targets/`, limity w profilu |
| SEC-3 | SEC ✅ *zrobione (agent blackarch #2): `make demo`, `docs/guide/lab.md`* | Własny mini-lab w compose (profil `lab`): nginx, WordPress, panel `/admin`, nagłówek `X-Environment: staging`, ciekawe cookie, usługa „migająca” (cron on/off). Do tego `make demo`: 2 przebiegi ze zmianą pomiędzy. | `make demo` pokazuje new/gone/changed/unstable |
| DEV-0 | DEV ✅ *zrobione (blackarch)* | Kontrakt: `Observation` (kind, asset_key, data, fp_hash, confidence), interfejs `Scanner` i adapter nmap przepięty na niego. | SEC może pisać adaptery |
| DEV-1 | DEV ✅ *zrobione (blackarch)* | Baza `asi-postgres` (osobna od DD) z migracjami SQL w binarce. Tabele: targets, runs, chunks, observations, assets, asset_events, users, api_tokens, audit_log. Zapis przebiegu do bazy zamiast `results/*.json` (pliki zostają jako eksport). | 2 przebiegi w bazie, diff z bazy |

## P1: jutro rano (wymagania „musi” i największe wagi)

| ID | kto | zadanie | waga w ocenie |
|---|---|---|---|
| SEC-4 | SEC ⏳ *rezerwacja: agent blackarch #2 po SEC-3, jeśli nikt nie zacznie wcześniej* | Etap `http`: adapter **httpx** (tytuł, kod, nagłówki, cookies, cert TLS, przekierowania, tech, hash favicony) na usługach http/https z fazy 2. httpx dochodzi do obrazu skanera. | fingerprint 10% + discovery 30% |
| SEC-5 | SEC | Etap `signatures`: **nuclei** z naszymi szablonami w `signatures/` (nagłówek, cookie, favicon, fragment HTML, ścieżki `/login` `/admin` `/version` bez logowania, wersja w stopce, CMS, staging). Tagi `intrusive,dos,fuzz,brute-force` wykluczone. Krótki opis „jak dodać sygnaturę”. | sygnatury (pkt 10 PDF) |
| DEV-2 | DEV ✅ *zrobione (blackarch)* | Reconcile w bazie: stany `new/active/missing(n)/gone`, `reappeared`, `flapping`, `hours_seen`, próg braków dla hostów. Edycje użytkownika (tagi, notatki, nadpisania) trzymane na assecie. | zmiany w czasie 15% |
| DEV-3 | DEV 🟡 *w dużej części w DEV-4: 4 role, sesje/tokeny (hash), audit log, użytkownicy w GUI; brak: wydawanie tokenów API w GUI* | API `/api/v1` i RBAC: role `admin` / `operator` (dodawanie, usuwanie, modyfikacja) / `analyst` (modyfikacja i odczyt) / `viewer` (odczyt), tokeny (w bazie tylko hash), middleware, audit log. Pierwszy admin z `.env`. | role 10% |
| SEC-6 | SEC | `internal/crypto`: AES-256-GCM dla pól wrażliwych (surowe wyjścia, nagłówki, cookies, certyfikaty, notatki). Klucze `ASI_ENCRYPTION_KEYS` z id, żeby dało się rotować. Opis w dokumentacji, co jest szyfrowane i dlaczego. | ochrona danych (część 10%) |
| DEV-4 | DEV ✅ *zrobione (blackarch)* | Panel web na API: logowanie, **formularz celów** (ręcznie oraz upload CSV/JSON), lista assetów z edycją, **dashboard**: najważniejsze znaleziska, zmiany z ostatniego przebiegu, niestabilne hosty. Widoki zależne od roli. | dashboard 15% |

## P2: jutro do południa (punkty „mile widziane” i dopięcie)

| ID | kto | zadanie |
|---|---|---|
| DEV-5 | DEV 🔨 *w toku: agent blackarch* | Harmonogram: cron, okno, wznawianie niedokończonych paczek w kolejnym oknie (`deferred`). Z panelu: start, pauza, anulowanie. |
| DEV-6 | DEV 🟡 *eksport assetów CSV/JSON jest (DEV-4); brak importu cudzych wyników* | Eksport JSON i CSV (assety, obserwacje, zdarzenia). Import cudzych wyników (nmap XML, JSON/CSV w formacie organizatorów). |
| SEC-7 | SEC | Eksport do DD po nowemu: natywne parsery (Nmap, httpx, Nuclei) plus test `asi-changes` (Generic: gone, changed, flapping), bez `close_old` dla przebiegów częściowych. Test na instancji DD organizatorów. |
| SEC-8 | SEC | Bezpieczeństwo skanera: kontrola zakresu i wykluczeń także w workerze, lista dozwolonych portów, sztywny górny limit pps, profil z `NET_RAW` (`-sS`, ICMP) i bez roota (`-sT`). Decyzja co do UDP (DNS, SNMP, NTP). Strona „Bezpieczeństwo” zaktualizowana. |
| DEV-7 | DEV | Ocena „ciekawości” rozszerzona o dane HTTP i sygnatury, grupowanie podobnych usług, wizualizacja zmian w czasie na dashboardzie. |

## P3: finisz (formalności, ostatnie godziny)

| ID | kto | zadanie |
|---|---|---|
| SEC-9 | SEC | Publiczne repo dla jury (GitHub) jako drugi remote. Przed pushem przegląd historii pod kątem sekretów i realnych IP. Czyste uruchomienie od zera: `git clone && make env && make up && make demo`. |
| ALL-1 | oboje | Prezentacja do 10 slajdów: problem, architektura, demo 2 przebiegów, role, szyfrowanie, DD, bezpieczeństwo skanowania. Nagranie demo jako plan B. |
| ALL-2 | oboje | Dokumentacja: `status.md` na 100%, quickstart przetestowany przez drugą osobę na czystej VM. |

## Ryzyka

- **Ścieżka krytyczna to DEV-1 → DEV-2 → DEV-3 → DEV-4** (baza, reconcile, API, UI). Jeśli do jutra rana nie
  będzie bazy, awaryjnie zostaje obecny zapis w plikach plus prosty RBAC na tokenach z `.env`. Wtedy formularz i
  edycja zapisują się do pliku `assets.json`, szyfrowanego AES-GCM.
- Build obrazu `nmap-scanner` z `asi` sprawdzony na blackarch (amd64, 21.11 ~15:50, po dodaniu go.sum).
  arm64 (fatusia-2) sprawdza SEC-1. Mirror Alpine bywa bardzo wolny: jeśli `apk add` padnie, ponów build.
- Środowisko jury jest nieznane. Bez SEC-2 stroimy na ślepo (porty, tempo, ICMP).
- Dwóch agentów w jednym repo: małe commity, `make sync` przed i po pracy, każdy w swoich pakietach
  (SEC: `internal/scanner/{httpx,nuclei}`, `internal/crypto`, `signatures/`, `docker/`; DEV: reszta).
