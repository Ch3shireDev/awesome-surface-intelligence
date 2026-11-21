# Decyzje i ustalenia - Attack Surface Intelligence (HackNation 2026)

Stan na: 21.11.2026 (dzien startu Wydarzenia). Ten plik to zywy log decyzji -
aktualizuj go, nie zgaduj na nowo przy kazdej sesji.

## Kontekst wyzwania

- Wyzwanie: **Attack Surface Intelligence**, partner: AGH / Centrum
  Bezpieczenstwa Informacji AGH (CBI AGH), hackathon HackNation 2026
  (21-22.11.2026, Bydgoszcz).
- Pelny brief: https://hacknation.pl/zadania (PDF "Szczegoly"); streszczenie,
  mapa wymagan i plan etapow: [`ROADMAP.md`](ROADMAP.md).
- Cel wg briefu: kompleksowe rozwiazanie do automatycznego skanowania
  bezpieczenstwa - integracja narzedzi pentestowych (m.in. Nmap), pipeline
  skanowania podatnosci, dashboard do wizualizacji wynikow, raportowanie.
- Dostarczone przez organizatora: DefectDojo (API v2, swagger dostepny),
  dokumentacja Nmap, SecureCodeBox (framework orkiestracji skanow), srodowisko
  sandbox z danymi testowymi.
- Kryteria oceny: funkcjonalnosc skanowania, jakosc integracji z dostarczonymi
  narzedziami/API, UX/czytelnosc dashboardu, jakosc i dokumentacja kodu,
  innowacyjnosc ponad wymagany zakres.

## Prawa autorskie / zasady konkursu (sprawdzone w pelnym regulaminie CBI AGH)

- Tylko **zwycieski zespol** podpisuje Umowe o dzielo i przenosi na AGH pelne
  autorskie prawa majatkowe do rozwiazania (laczne wynagrodzenie 25 000 zl
  brutto, dzielone rowno miedzy czlonkow zespolu, chyba ze zlozą inny podzial
  na pismie przed podpisaniem).
- Brak NDA, brak klauzuli zakazu konkurencji w regulaminie.
- Ten sam szablon prawny (slowo w slowo) wystepuje w regulaminie UZP
  (Odwolania2json) - najpewniej identyczny we wszystkich 15 wyzwaniach.
- Jesli zespol NIE podpisze umowy w 7 dni, traci prawo do nagrody (idzie do
  kolejnej druzyny z rankingu) - ale zachowuje pelne prawa do wlasnego kodu.
- Nic nie stoi na przeszkodzie, zeby repo bylo publiczne/open source JUZ
  teraz, w trakcie zgloszenia (regulamin tego wymaga/dopuszcza - link do repo
  w materialach konkursowych) - kwestia cesji dotyczy wylacznie wygranej.

## Decyzje architektoniczne

1. **Docker Compose, nie VM/K8s jako platforma orkiestracji.** Szybsze do
   postawienia w 24h, reprodukowalne, zgodne z tym jak jury testuje repo
   ("praktyczne przetestowanie dzialania (...) przeglad struktury kodu").
   Docelowo uruchamiane na dedykowanej VM (nie lokalnie), bo kontener
   nmapa potrzebuje uprawnien (NET_ADMIN/NET_RAW) do skanow SYN/wersji.

2. **SecureCodeBox swiadomie ODRZUCONY.** SCB jest naciwnie K8s-owy
   (operator + CRD-y ScanType/Scan/ScheduledScan) - postawienie go
   wymagaloby lokalnego klastra (kind/k3d) w srodku hackathonu, co jest
   zbyt duzym ryzykiem czasowym jak na 24h. Robimy "po swojemu": wlasny
   maly kontener z nmapem + Makefile zamiast frameworka orkiestracji.
   (Mozliwy stretch goal pozniej, patrz "Zaleglosci / TODO".)

3. **DefectDojo z oficjalnych obrazow Docker Hub** (`defectdojo/defectdojo-django`,
   `defectdojo/defectdojo-nginx`), NIE build lokalny z zrodel. Wersja
   przypieta w `.env` (`DD_VERSION=3.5.202`, obrazy multi-arch amd64/arm64).
   Compose wyrownany do upstreamowego `docker-compose.yml` z tej wersji:
   `DD_DATABASE_URL`, `DD_CELERY_BROKER_URL`, `DD_CACHE_URL`, valkey zamiast
   redis, `/wait-for-it.sh` przed procesami django, `DD_UWSGI_HOST/PORT` dla
   nginx. Wystawiony tylko port 8080 (HTTP, bez TLS). Wszystko zamyka sie w
   repo: konfiguracja bind-mountami z `./docker/...`, dane runtime w nazwanych
   wolumenach (`make nuke` czysci).

4. **[ZASTAPIONA przez 8]** **DefectDojo = dashboard.** Nie budujemy wlasnego UI/frontendu -
   DefectDojo juz ma pelny interfejs (findings, severity, engagements,
   metryki, raporty). Nasz wklad to pipeline: skan -> XML -> import do
   DefectDojo (`/api/v2/import-scan/`, `scan_type=Nmap Scan` - wbudowany
   parser, nic nie trzeba pisac recznie).
   Brief wymaga tez formularza celow, RBAC z 4 rolami i dashboardu - zakladamy,
   ze pokrywa to DefectDojo (endpointy produktu, role Owner/Maintainer/Writer/
   Reader, dashboard). Nieaktualne - patrz decyzja 8.

5. **Nmap w osobnym, malym kontenerze** (alpine + nmap + curl + jq,
   `network_mode: host` - skanuje z perspektywy VM, bez NAT-u dockera),
   sterowany z `Makefile` (cele `scan-discover` / `scan-fast` / `scan-full`
   / `scan-service` / `scan-udp`), wyniki ladowane do `scans/results/*.xml`
   (zamontowany wolumen), gotowe do importu.

6. **Import do DefectDojo z kontenera skanera** (`docker/nmap/scripts/import-defectdojo.sh`),
   nie z hosta - na hoscie nie potrzeba curla/jq. Token API pobierany
   loginem admina (`/api/v2/api-token-auth/`), jesli `DD_API_KEY` pusty.
   `auto_create_context=true` - Product Type/Product/Engagement tworza sie
   same, nie trzeba recznie klikac w UI ani trzymac `DD_ENGAGEMENT_ID`.

7. **Cykliczne skany przez `reimport-scan` do stalych testow** (jeden test na
   rodzaj skanu, np. `nmap-fast`, `close_old_findings=true`). Diff miedzy
   przebiegami liczy DD - nie piszemy wlasnego porownywania. Liveness (`-sn`)
   konwertujemy na `Generic Findings Import` (kilka linii awk+jq), bo parser
   Nmapa ignoruje hosty bez otwartych portow.

8. **Wlasny system ASI w Go; DefectDojo tylko jako cel eksportu**
   (21.11, po doprecyzowaniu z zespolem). CBI AGH ma DefectDojo, ale
   skanowanie duzych sieci z jego poziomu jest niewygodne - budujemy
   brakujacy "detektor" przed DD: wlasna baza (PostgreSQL), chunking
   zakresow, kolejka zadan (River), gotowe skanery jako adaptery,
   historia/diff, RBAC (4 role), eksport do DD przez `reimport-scan`. Na
   razie API + CLI, web UI pozniej. Go: sugestia briefu i ekosystem
   ProjectDiscovery. Szczegoly: `docs/VISION.md`.

9. **Szyfrowanie w spoczynku: pola szyfrowane w aplikacji (AES-256-GCM)**.
   Zwykly PostgreSQL nie ma TDE (`pgcrypto` przepuszcza klucz przez SQL).
   Szyfrowanie wolumenu / `pg_tde` jako opcjonalna druga warstwa.

10. **Jedno repo poza Syncthingiem, synchronizacja gitem po ssh** (21.11).
    Origin: `daniel@blackarch:~/repos/asi.git` (bare), klony `~/asi` na
    blackarch i fatusia-hacknation-2. Polaczone dwa rownolegle PoC: compose +
    PoC na Makefile (fatusia) i silnik `asi` w Go (blackarch: plan, 2 fazy
    skanu, adaptacyjne paczki, postep CLI/web, diff, reimport Generic
    Findings). `asi` jest budowany w obrazie `nmap-scanner` (multi-stage), wiec
    na hoscie VM dalej wystarcza docker + make. Kod `asi` to obecna
    implementacja planera/skanera/eksportu z VISION; baza, RBAC, API i
    szyfrowanie dochodza na nim (patrz `docs/TASKS.md`).

11. **Wytyczne mentora CBI AGH, konsultacje 21.11 14:44 (WIAZACE)**.
    Pelny zapis i transkrypcja: [`MENTOR.md`](MENTOR.md). Skrot:
    - ASI to zrodlo danych (feed) dla DefectDojo, nie jego zamiennik. Potwierdza decyzje 8.
    - **Web GUI jest wymagane** ("tam jest cale mieso": formularze, role, enkrypcja).
      Zastepuje fragment decyzji 8 "na razie API + CLI, web UI pozniej".
    - Zalecana architektura jak w MISP: Web GUI jako wrapper na komendy CLI w Linuksie
      i na baze danych. Nasz `asi` CLI + skanery jako komendy pasuja do tego wprost.
    - PostgreSQL; **encryption at rest = darmowe 5%**. Rozszerza decyzje 9: oprocz pol
      AES-GCM wlaczamy szyfrowanie danych Postgresa (szyfrowany wolumen albo `pg_tde`)
      i opisujemy to w dokumentacji. Zwykly Postgres nie ma TDE, mimo slow mentora.
    - **RBAC = tylko 10%**, jedno konto admina jest akceptowalne. RBAC wylacznie lokalny,
      bez synchronizacji z uzytkownikami DD. 4 role (DEV-3) obnizone do "jesli starczy czasu".
    - Skanery: nmap, httpx, Wappalyzer i inne narzedzia CLI zaakceptowane.

12. **Baza ASI: osobny Postgres `asi-db`, sterownik pgx, bez River na razie** (21.11, DEV-1).
    - Osobny kontener `asi-db` (postgres:18-alpine), port tylko `127.0.0.1:5433`, wolumen `asi_db_data`.
      Nie dzielimy bazy z DefectDojo: inne cykle zycia, migracje i kopie; DD to tylko cel eksportu.
    - Sterownik `github.com/jackc/pgx/v5` (wyjatek od "tylko stdlib"): COPY dla obserwacji, typy `inet`/`text[]`.
    - Migracje SQL osadzone w binarce (`internal/store/migrations`, tabela `schema_migrations`),
      `asi db migrate` albo automatycznie przy `asi scan` z `ASI_DATABASE_URL`.
    - Kolumny `*_enc` (dane obserwacji, surowe wyjscia skanerow, notatki) ida przez `store.Sealer`.
      Domyslnie `Plain`, SEC-6 podpina AES-256-GCM bez zmiany schematu.
    - Kolejka River (VISION 4.5) odlozona: obecna pula workerow w procesie wystarcza do demo.
      Wraca, gdy bedzie harmonogram z wieloma workerami (DEV-5).
    - Pliki w `results/` zostaja jako eksport i fallback, gdy bazy nie ma.

13. **Panel web = `asi server` w kontenerze `nmap-scanner`** (21.11, DEV-4).
    - Kontener skanera ma `entrypoint: ["asi", "server"]` (zmiana w compose wzgledem decyzji 3) i zalezy od
      `asi-db`. Panel na `127.0.0.1:8090`, postep skanu z GUI na `127.0.0.1:8091` (proxy pod `/live/`).
      `make asi-scan` (CLI) uzywa `:8094`, `make asi-serve` (stary panel plikowy) `:8095`.
    - Skan z GUI to podproces `asi scan` (wzorzec MISP z konsultacji), jeden naraz.
    - RBAC lokalny z 4 rolami od razu (koszt byl niski przy pisaniu API); hasla PBKDF2 ze stdlib,
      sesje jako tokeny w `api_tokens` (tylko hash), CSRF przez naglowek `X-ASI`.

## Otwarte pytania / do potwierdzenia z CBI AGH

- [ ] **Dokladny zakres skanu** (CIDR/hostname'y sandboxa) - bez tego nie ma
      czego wpisac do `scans/targets.txt`.
- [ ] Czy zalozenie "plaski intranet bez firewalli/segmentacji do omijania"
      jest poprawne, czy jest tam cos, co moze zmylic wyniki skanu.
- [ ] Czy sandbox jest dostepny z poziomu VM od razu, czy wymaga VPN/dostepu
      specjalnego.

## Ustalenia z uruchomienia (21.11)

- Import `-sn` (liveness) do DD przechodzi, ale tworzy 0 findingow - parser
  Nmapa robi findingi tylko z otwartych portow.
- DD 3.5.202 ma parsery: Nmap, Masscan, Naabu, httpx, Nuclei, WhatWeb,
  Testssl, Generic Findings Import (JSON/CSV).
- `reimport-scan` zwraca diff created/closed/reactivated/untouched - porownanie
  przebiegow robi DD.
- Pierwszy `make up` na VM zawiesil sie bez outputu (nic sie nie pobieralo
  przez ~10 min, pojedynczy `docker pull` tez wisial). Po ubiciu compose
  drugi `make up` przeszedl normalnie. Przyczyna nieustalona - jesli sie
  powtorzy: ubic i odpalic ponownie.
- Ponowny `import-scan` tego samego pliku duplikuje findingi (dedup domyslnie
  wylaczony) - do cyklicznych skanow uzywac `reimport-scan`.

## Zaleglosci / TODO (kolejnosc wedlug priorytetu)

Aktualny plan etapow: [`ROADMAP.md`](ROADMAP.md). Ponizsza lista to
pierwotne TODO.

1. Postawic stack na VM (`make env && make up`), test petli na `127.0.0.1`:
   `make scan-fast && make import-latest`.
2. Potwierdzic zakres skanu z mentorami, uzupelnic `scans/targets.txt`.
3. Przejsc petle: `make scan-fast` -> `make import-defectdojo FILE=...` ->
   sprawdzic findings w UI DefectDojo. To jest core MVP.
4. Jak dziala podstawowa petla: dodac `scan-service` do wzbogacenia wynikow
   (wersje uslug), ew. CVSS/CVE jesli DefectDojo tego nie robi automatycznie
   z samego Nmapa.
5. Stretch goal (tylko jesli zostanie czas): drugi typ skanera na inna
   warstwe attack surface (np. Nikto pod warstwe webowa) - DefectDojo ma
   gotowy parser, wiec koszt dodania jest niski a podnosi "kompletnosc"
   wzgledem kryteriow oceny.
6. Stretch goal (opcjonalny, niski priorytet): k3d + prawdziwe SecureCodeBox,
   tylko jesli MVP dziala i zostaje czas do konca.
