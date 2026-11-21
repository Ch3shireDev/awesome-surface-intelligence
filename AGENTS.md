# AGENTS.md

Kontekst dla agentow AI pracujacych w tym repo (Claude Code / inne).

## Co to jest

Projekt hackathonowy na HackNation 2026, wyzwanie **Attack Surface
Intelligence** (partner: AGH/CBI AGH). Budujemy wlasny system (Go) do
cyklicznego discovery scanu duzych sieci: chunking zakresow, gotowe skanery
(nmap, naabu, httpx, nuclei), postep, historia i diff, RBAC, eksport do
DefectDojo (system koncowy CBI AGH - eksportujemy do niego, nie budujemy na
nim).

Przeczytaj PRZED wieksza zmiana:
- `docs/VISION.md` - architektura, rdzen, model danych, schemat dzialania,
- `docs/DECISIONS.md` - log decyzji z uzasadnieniami,
- `docs/ROADMAP.md` - brief w skrocie i etapy.

## Twarde zasady

- **Stack uruchamiamy tylko na dedykowanej VM** (nmap potrzebuje
  NET_ADMIN/NET_RAW i `network_mode: host`). Na innej maszynie tylko
  walidacja skladni (`docker compose config`, `make -n <cel>`).
- **Wszystko zamyka sie w repo.** Konfiguracja jako pliki w repo podpinane
  bind-mountami do kontenerow, narzedzia (nmap, curl, jq) tylko w
  kontenerach. Na hoscie wymagane wylacznie: docker + compose plugin, make,
  openssl. Nie instaluj niczego innego na hoscie.
- **Nie skanuj niczego poza `scans/targets.txt`.** Do czasu potwierdzenia
  zakresu z mentorami CBI AGH (patrz "Otwarte pytania" w
  `docs/DECISIONS.md`) jedynym dozwolonym celem jest `127.0.0.1` (sama VM,
  do testow pipeline'u). Nie wpisuj przykladowych adresow IP jako
  "defaultowych" celow skanu.
- **Nie commituj `.env`, `scans/targets.txt` ani plikow wynikowych
  `scans/results/*.xml`** - sa w `.gitignore` celowo (dane ze srodowiska
  sandbox, API key DefectDojo).
- DefectDojo to **cel eksportu**, nie nasze UI ani baza. Nasze dane zyja w
  `asi-postgres`. Web UI ASI powstanie pozniej - na razie tylko API + CLI,
  nie zaczynaj frontendu bez ustalenia.
- Skanery uruchamiamy jako gotowe narzedzia (adaptery w
  `internal/scanner/`). Nie piszemy wlasnych skanerow portow/HTTP.
- Repo lezy w katalogu synchronizowanym przez Syncthing (`~/sync`).
  `.gitignore` nie chroni przed Syncthingiem - `.env` (hasla, klucze) i
  `scans/results/` rozchodza sie na inne urzadzenia, chyba ze sa w
  `.stignore`.
- `docker-compose.yml` jest wyrownany do upstreamowego compose DefectDojo
  3.5.202. Jesli cos w nim poprawiasz, zaktualizuj rowniez
  `docs/DECISIONS.md` (sekcja decyzji nr 3).

## Konwencje

- Etap przejsciowy (PoC): dopoki nie ma `asi`, inwokacje nmapa ida przez
  `Makefile`. Docelowo flagi skanerow zyja w adapterach i profilach ASI
  (`docs/VISION.md`, 4.3), a `make poc` zostaje jako test dymny.
- Nowe cele `make` dopisuj w sekcji odpowiadajacej istniejacemu wzorcowi
  (patrz `scan-fast` jako referencja) i dodaj je do listy w `help:`.
- Sekrety/klucze (`DD_API_KEY`, hasla) tylko w `.env` (gitignored), nigdy w
  `docker-compose.yml`, `Makefile` ani kodzie.

## Gdzie co jest

- `docker-compose.yml` - caly stack (DefectDojo + nmap-scanner).
- `docker/nmap/Dockerfile` - obraz skanera (alpine + nmap + curl + jq).
- `docker/nmap/scripts/` - skrypty montowane do skanera w `/opt/asi`
  (`import-defectdojo.sh` - import wynikow przez API v2).
- `docker/defectdojo/extra_settings/` - nadpisania settings DefectDojo.
- `Makefile` - sterowanie skanami i importem do DefectDojo.
- `scans/targets.example.txt` - szablon listy celow (skopiuj do
  `scans/targets.txt` PO potwierdzeniu zakresu).
- `docs/VISION.md` - wizja, architektura i rdzen (zrodlo prawdy dla
  projektu systemu).
- `docs/ROADMAP.md` - streszczenie briefu, mapa wymaganie -> narzedzie,
  plan etapow. Przed nowym etapem sprawdz, co pokrywa gotowe narzedzie/DD.
- `docs/DECISIONS.md` - log decyzji, otwarte pytania, TODO wedlug
  priorytetu. Aktualizuj na biezaco zamiast trzymac ustalenia tylko w
  rozmowie.
