# AGENTS.md

Kontekst dla agentow AI (Claude Code i inne) pracujacych w tym repo. `CLAUDE.md` tylko importuje ten plik.

## Co to jest

HackNation 2026, wyzwanie **Attack Surface Intelligence** (CBI AGH). Budujemy wlasny system w Go do cyklicznego
discovery scanu duzych sieci (powyzej 10 000 IP):
- podzial zakresu na paczki, gotowe skanery (nmap, potem httpx/nuclei/naabu),
- postep na zywo, historia i diff, RBAC, szyfrowanie wrazliwych pol,
- eksport do DefectDojo. DD to system koncowy CBI AGH: eksportujemy do niego, nie budujemy na nim.

## WAZNE: ustalenia z mentorem CBI AGH (21.11, 14:44), wiazace

Pelny zapis: `docs/MENTOR.md` (decyzja 11 w `docs/DECISIONS.md`). Maja pierwszenstwo przed starszymi zapisami w repo.
1. ASI to **feed dla DefectDojo** (skanery -> wyniki -> DD), nie konkurencja dla DD.
2. **Web GUI jest wymagane** i najwyzej punktowane (formularze, role, szyfrowanie). Nie "pozniej".
3. Architektura jak w MISP: **Web GUI = nakladka na komendy CLI** (`asi`, nmap, httpx...) i na baze. Mentor to zaleca.
4. **PostgreSQL + encryption at rest = darmowe 5%**. Szyfrowanie ma byc wlaczone i pokazane w demo/dokumentacji.
5. **RBAC to tylko 10%**: jedno konto admina wystarczy. RBAC tylko lokalny, **bez synchronizacji z kontami DD**.
6. Skanery CLI (nmap, httpx, Wappalyzer, wykrywanie uslug) zaakceptowane; im bardziej modularne, tym lepiej.

Przeczytaj PRZED wieksza zmiana:
- `docs/MENTOR.md`: ustalenia z mentorem (wiazace),
- `docs/VISION.md`: architektura docelowa, model danych, rdzen (zrodlo prawdy dla projektu),
- `docs/status.md`: co z wymagan PDF jest zrobione, a co nie (aktualizuj po kazdym kroku),
- `docs/DECISIONS.md`: log decyzji z uzasadnieniami,
- `docs/ROADMAP.md`: brief w skrocie, mapa wymaganie -> narzedzie, etapy,
- `docs/TASKS.md`: aktualne zadania i podzial (dev / devsecops).

## Gdzie jest repo i jak sie synchronizujemy

- **Jedno repo**, origin to bare repo na blackarch: `daniel@blackarch:~/repos/asi.git`.
  Klony robocze: `~/asi` na blackarch i `~/asi` na fatusia-hacknation-2 (remote po ssh, alias `ba`).
- Synchronizacja tylko przez git: `make sync` (pull --rebase + push). Commituj male kawalki i czesto syncuj.
- **Repo NIE lezy w `~/sync`** (Syncthing). Synchronizowany `.git` psuje repo przy rownoleglej pracy, a
  Syncthing rozsylalby `.env` i wyniki skanow. `~/sync` sluzy tylko do notatek miedzy ludzmi i agentami
  (`~/sync/komunikacja/`).
- Stare lokalizacje (`~/sync/hacknation-asi`, `~/asi-poc`) sa nieaktualne. Nie pracuj w nich.

## Twarde zasady

- **Zakres skanu.** Skanuj wylacznie cele z `targets/targets.csv` lub `scans/targets.txt` (oba gitignored).
  Do czasu potwierdzenia zakresu z mentorami CBI AGH jedynym wspolnym celem jest `127.0.0.1`. Nie wpisuj
  przykladowych IP jako domyslnych celow. Wyjatek: wlasny lab `docker/lab` (siec dockera 192.0.2.0/24,
  cele `targets/lab.csv`, `make demo`) - to nasze kontenery, wolno go skanowac zawsze. W dokumentacji i testach uzywaj adresow dokumentacyjnych
  (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- **Nie commituj** `.env`, `.dd_token`, `targets/*` (poza `example.*`), `results/`, `scans/results/`.
  Sa tam realne IP, domeny i hasla.
- **Stack (compose) uruchamiamy na VM z dockerem.** nmap w kontenerze potrzebuje `NET_RAW`/`NET_ADMIN` i
  `network_mode: host`. Na hoscie wymagane: docker + compose, make, openssl. Go i pnpm tylko na maszynie
  deweloperskiej (`make build`, `make test`, `make docs`).
- **Bezpieczenstwo skanowania ponad szybkosc**: globalny limit tempa (`-rate`), okno czasowe (`-window`),
  sygnatury tylko detekcyjne (bez prob logowania i exploitow).
- Sekrety tylko w `.env`, nigdy w compose, Makefile ani kodzie.
- `docker-compose.yml` jest wyrownany do upstreamowego compose DefectDojo 3.5.202. Zmiany w nim odnotuj w
  `docs/DECISIONS.md` (decyzja nr 3).

## Konwencje

- Kod Go: tylko biblioteka standardowa, chyba ze decyzja w `DECISIONS.md` mowi inaczej (np. sterownik
  Postgresa). Przed commitem: `make test` (go vet + go test).
- Flagi nmapa dla silnika zyja w `cmd/asi` / `internal/scanner` (profile). `Makefile` `scan-*` i `make poc`
  to stary PoC fatusi, zostaje jako test dymny stacku.
- Dokumentacja: VitePress w `docs/`, po polsku. Nowa strona = wpis w `docs/.vitepress/config.mts`.
  Po kazdej zmianie funkcjonalnej zaktualizuj `docs/status.md`.
- Commity po polsku, krotko, w trybie "co zmienia".

## Gdzie co jest

| sciezka | co |
|---|---|
| `cmd/asi/` | CLI: `convert`, `plan`, `scan`, `upload`, `diff`, `serve` |
| `internal/obs` | kontrakt `Observation` + interfejs `Scanner` (adaptery skanerow), patrz `docs/guide/adapters.md` |
| `internal/scanner/nmap` | adaptery nmap (discovery, services) |
| `internal/store` | Postgres `asi-db` (pgx), migracje SQL w binarce, `Sealer` dla pol `_enc`; `docs/guide/database.md` |
| `internal/targets` | wejscie CSV/JSON/TXT, plan, CIDR, DNS, reguly bezpieczenstwa |
| `internal/targetsai` | dowolny tekst -> cele (DeepSeek `deepseek-flash` albo regex, walidacja: tylko cele z tekstu, wewnetrzne wylaczone); `asi targets-extract`, `asi mcp`, `docs/guide/targets-ai.md` |
| `internal/scanner` | pula workerow, adaptacyjny Sizer, nmap `--stats-every`, skan potwierdzajacy |
| `internal/safety` | polityka skanera (SEC-8): zakres, wykluczenia, allowlista portow i flag nmapa, twarde limity z `.env`, profile raw/unprivileged; `docs/guide/safety.md` |
| `internal/nmapxml` | parser XML nmapa |
| `internal/findings` | model uslug, ocena "ciekawosci", diff, Generic Findings dla DD |
| `internal/progress`, `internal/cli`, `internal/web` | stan na zywo, pasek CLI, panel web (SSE) |
| `internal/crypto` | AES-256-GCM dla kolumn `_enc` (`ASI_ENCRYPTION_KEYS`, rotacja), `docs/guide/encryption.md` |
| `internal/dojo` | klient DefectDojo API v2 (login, import, reimport) |
| `docker-compose.yml` | DefectDojo 3.5.202 + `nmap-scanner` (nmap + `asi`) |
| `docker/asi-db/`, `docker-compose.crypto.yml` | asi-db z TDE (`pg_tde`), init SQL, `make crypto-check` |
| `docker/nmap/` | obraz skanera i skrypty PoC (`import-defectdojo.sh`, `nmap-hosts-to-generic.sh`) |
| `Makefile` | `make help`: stack, PoC, `asi`, `build`, `test`, `docs`, `sync` |
| `targets/example.csv` | szablon celow (kopiuj do `targets/targets.csv`) |
| `docker/lab/`, `targets/lab.csv` | lab testowy (8 hostow, 2 stany) i jego cele; `make demo`, `docs/guide/lab.md` |
| `README.md` / `CONTRIBUTING.md` | opis dla jury (bez spraw zespołowych) / praca zespołu: sync, build, testy, zadania |
| `docs/` | VitePress: VISION, status, DECISIONS, ROADMAP, TASKS, przewodniki |
