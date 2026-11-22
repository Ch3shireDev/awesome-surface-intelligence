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
- **Regulaminy zadan nie sa identyczne.** Sprawdzone w pelnym PDF regulaminu CBI AGH (21.11, agent na
  fatusia-hacknation-1): AGH ma Umowe o dzielo na 25 000 zl brutto, **nie wspomina o terminach ani o
  repozytorium** (KOWR wymaga prywatnego repo do konca wydarzenia - AGH nie wymaga). Wczesniejszy zapis
  "ten sam szablon slowo w slowo co UZP" byl nieprawdziwy.
- Terminy zgloszen pochodza z Regulaminu Wydarzenia i przewodnika uczestnika, nie z regulaminu zadania:
  **21.11 20:00 DRAFT** (zalozenie projektu w HackTribe: nazwa projektu i zespolu, repozytorium, numer
  stolika, wstepny opis; po 20:00 nie da sie zalozyc projektu ani zmienic zadania) i **22.11 11:00
  zgloszenie finalne** (wszystkie pola + prezentacja i materialy do sprawdzenia). Zgloszenie utworzone
  przed 20:00 mozna edytowac dalej.
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

14. **Szyfrowanie at rest asi-db: `pg_tde` (Percona) + pola AES-256-GCM w aplikacji** (21.11, SEC-6).
    - Zwykly PostgreSQL nie ma TDE; `pgcrypto` przepuszcza klucz przez SQL. Szyfrowany wolumen (LUKS)
      wymaga roota i konfiguracji hosta poza repo - odrzucone (zasada "wszystko w repo/compose").
    - `asi-db` z obrazu `percona/percona-distribution-postgresql:18.7.1-1` (`docker/asi-db`), nakladka
      `docker-compose.crypto.yml` wlaczana `COMPOSE_FILE` w `.env` - osobny plik, zeby nie kolidowac ze
      zmianami w `docker-compose.yml` (SEC-3). Do scalenia z glownym plikiem, gdy compose sie ustabilizuje.
    - TDE: AES-256, WAL szyfrowany, `default_table_access_method=tde_heap` + `enforce_encryption` w bazie
      `asi` - migracje bez zmian. Keyring plikowy w osobnym wolumenie (hackathon); produkcyjnie OpenBao/Vault/KMIP.
    - Pola `_enc`: `internal/crypto` (stdlib), keyring `id:base64` z rotacja; bledny klucz = blad startu,
      brak klucza = jawny zapis z ostrzezeniem.
    - Nowy wolumen `asi_db_tde_data`: dane ze starego `asi_db_data` nie sa migrowane (byly tylko testowe).
    - Zweryfikowane na arm64 (fatusia-2): `make crypto-check` 9/9 OK; proba kontrolna na zwyklym postgres:18
      znajduje jawny tekst w pliku tabeli, na `pg_tde` nie. Opis: `docs/guide/encryption.md`.

15. **Polityka bezpieczenstwa skanera w `internal/safety`, sprawdzana takze w workerze** (21.11, SEC-8).
    - Twarde limity tylko z `.env` (operator wdrozenia): `ASI_MAX_RATE` 1000 pps, `ASI_MAX_PARALLEL` 32,
      `ASI_ALLOWED_PORTS`, `ASI_SCOPE`/`ASI_EXCLUDE` (+ pliki `targets/scope.txt`, `targets/exclude.txt`).
      Flagi CLI i GUI (max 5000 pps) sa do nich obnizane z wpisem w logu.
    - Wykluczenia wbudowane: `0.0.0.0/8`, `169.254.0.0/16` (metadane chmury), multicast, `240.0.0.0/4`, IPv6 link-local/multicast.
    - Dwa punkty kontroli: plan (wykluczone w `skipped` z powodem) i worker tuz przed startem nmapa
      (filtr IP paczki + walidacja calej linii polecen). Paczka odrzucona przez polityke ma status `failed`
      i blad `policy: ...` - bez nowego statusu w `chunks` (bez migracji).
    - Argumenty nmapa: allowlista flag zamiast denylisty. Zadnych celow w argumentach (jedno `-iL` = plik paczki),
      bez spoofingu/evasion, bez `--min-rate`, `-T5`, `-A`, `-sC`, `--allports`; NSE tylko z listy nazw
      detekcyjnych (kategorie zabronione - to sumy zbiorow, `discovery` zawiera brute-force).
    - Porty: `-p` przycinane do allowlisty; bez `-p` dochodzi `-p <allowlista>` + `--top-ports` (nmap wybiera
      top N sposrod dozwolonych - sprawdzone na 7.95/7.99). Porty sond `-PS/-PA` tez przycinane.
    - Profile: `raw` (domyslny, NET_RAW: `-sS`, ICMP, ARP) i `unprivileged` (`docker-compose.unprivileged.yml`,
      `cap_drop NET_RAW/NET_ADMIN`, nmap `--unprivileged`, tylko `-sT`). Domyslne argumenty dzialaja w obu.
    - **UDP domyslnie wylaczone**: wolne, duzo `open|filtered`. `ASI_ALLOW_UDP=1` tylko na `53,123,161`
      (DNS, NTP, SNMP - typowe nieswiadomie wystawione uslugi) i tylko w profilu `raw`.
      Uzupelnienie 22.11: `open|filtered` w UDP daje falszywe new/missing/flapping w historii (klasa LAB-T7/T8),
      a baza sond nmapa ma `SNMPv1public` (community `public`, rarity 4) - przy intensywnosci `-sV` >= 4 (LAB-T10)
      i `ASI_ALLOW_UDP=1` skaner wysylalby do SNMP domyslne "haslo". Opis i kiedy wlaczyc: `guide/safety.md`.
    - Zweryfikowane: testy jednostkowe (`internal/safety`, worker w `internal/scanner`), skan 127.0.0.1 bez roota
      na blackarch (amd64) i oba profile w obrazie `nmap-scanner` na fatusia-2 (arm64: `syn` vs `connect`).

16. **Zmiany w czasie trafiaja do DD jako test `asi-changes` oparty o STAN, nie o log zdarzen** (21.11, SEC-7).
    - Finding (Generic) istnieje, dopoki warunek trwa: `missing`, `gone`, `flapping`, ostatnia zmiana uslugi.
      Reimport z `close_old` zamyka go, gdy warunek mija - "closed" w DD znaczy "problem minal".
      Log zdarzen zostaje w ASI (`asset_events`, `asi changes`, panel); w DD bylby szumem.
    - Opis stabilny, dopoki warunek trwa (DD hashuje tytul+opis Generic findings), bez `service`
      (reimporter zamyka tylko findingi z tym samym `service`) i bez `protocol` w endpointach.
    - Przebieg czesciowy nigdy nie zamyka (`close_old=false`) - tez w `asi upload`, ktory czyta status z `run.json`.
    - Budowanie raportu w `internal/dojo/changes.go` (czysta funkcja, testy), wywolanie w `cmd/asi/changes_export.go`.
    - Zweryfikowane na labie (4 przebiegi): missing -> (3 braki) gone zamyka "do potwierdzenia" i otwiera
      "zniknal"; w przebiegu bez zmian oba findingi `untouched` (hash stabilny na prawdziwym DD 3.5.202).

17. **Fingerprint HTTP = httpx, sygnatury = nuclei tylko z naszymi szablonami** (21.11, SEC-4/SEC-5).
    - Gotowe narzedzia ProjectDiscovery (MIT) jako adaptery `obs.Scanner`, binarki z oficjalnych wydan z
      weryfikacja SHA-256 w Dockerfile (wersje przypiete). Wlasny modul `net/http` odrzucony: Wappalyzer,
      TLS i favicon mmh3 mamy gratis.
    - httpx bez podazania za przekierowaniami i z `-nfs`, zeby obserwacja zawsze dotyczyla tego IP:portu.
    - nuclei: wylacznie `signatures/` (bez publicznej bazy szablonow), `-ni`, `-etags` z lista wykluczen,
      lint w testach (tylko GET, prefiks `asi-`). Sygnatury sa w repo i przechodza review jak kod.
    - Etap services skanuje top-N nmapa **plus porty wysokiego ryzyka spoza top 1000** (Redis, MongoDB,
      Docker API...). Bez tego Redis z labu byl niewidoczny.

18. **httpx i nuclei do DD natywnymi parserami, kazde do stalego testu** (21.11, SEC-7).
    - `asi-httpx` (`httpx Scan`) i `asi-nuclei` (`Nuclei Scan`): surowe JSONL z `results/<run>/{http,signatures}`
      bez przepakowania - DD liczy diff per narzedzie, a nasze dane (naglowki, cookies, TLS) zostaja w ASI.
    - `close_old` tylko gdy przebieg pelny, etap sie wykonal (`timings.csv`) i zadna paczka nie miala bledu;
      pusty raport z etapu niepelnego/pominietego nie jest wysylany (zamknalby wszystkie wyniki webowe).
    - Sprawdzone: DD 3.5.202 przyjmuje pusty JSONL (201) i zamyka poprzednie wyniki; lab `make demo`:
      httpx `closed 1 / created 2 / untouched 5`, nuclei `created 2 / untouched 16` w przebiegu 2.

19. **Sandbox = compose stawiany sami; jeden stack na maszyne, cele przez tailnet** (21.11, ustalenia zespolu).
    - `lab.zip` -> `~/lab-org` (poza repo). Cztery stacki, **jeden naraz na jednej maszynie**. Powod (poprawka
      21.11 22:00): stacki NIE koliduja portami miedzy soba; koliduja tylko z naszym stackiem (`modern` 8080 = DD,
      `vulnerable` 8090 = panel ASI). "Jeden naraz" chroni przed mieszaniem wynikow (skan 127.0.0.1 widzi wszystko
      na hoscie) i przed brakiem RAM. Start: `docker compose -f docker-compose-<stack>.yml up -d`, dla
      `custom-network` scenariusz `./quickstart.sh up|change|up`.
    - **Testy LAB-* rownolegle na kilku VM** (21.11 22:00): kopia `~/lab` na kazda VM z dockerem, na kazdej
      wlasny skaner ASI (`docker compose up -d nmap-scanner asi-db`) i jeden stack labu; **DefectDojo jest
      wspolny** - jedna instancja, decyzja 22. Nie czekamy na "wolny lab" na jednej maszynie. Rezerwacja w
      TASKS jako `stack@VM`. LAB-6 (fatusia-1) szedl rownolegle z LAB-5 (fatusia-2), wyniki czyste.
    - Cel skanu zalezy od tego, gdzie stoi skaner: ta sama VM -> `127.0.0.1`; inna maszyna w tailnecie ->
      `<tailscale-ip>` tej VM. **Nie skanujemy adresow mostkow dockera (172.x) z innej maszyny** - tailscale
      ich nie routuje, z zewnatrz widoczne sa tylko porty opublikowane (`ports:` = DNAT na hoscie). Skaner w
      `network_mode: host` widzi `tailscale0` bez dodatkowej konfiguracji (decyzja 5), widzi tez uslugi samej
      VM (SSH, Syncthing, procesy lokalne) - to szum, wycinany zakresem/portami (LAB-T2).
    - Plik celow **per maszyna** (`targets/lab-org-<host>.csv`, w `note` nazwa stacku), bo reconcile porownuje
      przebiegi: zmiana stacku to celowe masowe `missing` -> `gone` (LAB-6), a nie awaria. GUI: Cele -> Import,
      CLI: `asi scan -targets targets/lab-org-<host>.csv`.
    - **Etap 2 = wlasna infrastruktura zespolu** (potwierdzone 21.11 21:05): `targets/targets.csv` to nasze cele
      (Hetzner/Oracle + tailscale `100.x`), a nie przyklad. Wiersze `enabled=false` (ams, hf-brain) to hosty
      klientow - wlaczamy dopiero po zgodzie wlasciciela, wiec zakres etapu 2 to narazie wiersze `enabled=true`.
      Oba etapy (lab + wlasna infra) uzywaja tego samego mechanizmu: plik celow + `-targets`, bez zmian w kodzie.
    - Bezpieczenstwo: stacki maja domyslne hasla (WordPress, DVWA, FTP `test/test123`, RabbitMQ `guest`) i
      publikuja na `0.0.0.0`, czyli w tailnecie sa widoczne dla **calego tailnetu** (na maszynie bez firewalla
      takze w LAN). Stawiac tylko na maszynie testowej, po testach `docker compose down`. **Domyslnie nakladka
      `docker/lab-org/<stack>.bind.yml`**: porty labu na `LAB_BIND` (domyslnie `127.0.0.1`; adres tailnetu, gdy
      skaner jest na innej VM), nigdy `0.0.0.0`. Docker omija firewall hosta, a fatusia-1 ma port forwarding.

20. **Wykryty firewall = "nie da sie sprawdzic", nigdy "brak uslug"** (21.11, zespol; dotyczy zalozenia o
    plaskim intranecie z sekcji pytan).
    - Zasada: zaden brak i zadna obserwacja nie moga powstac z ciszy. `filtered` / `open|filtered` w nmapie oraz
      host `down` z `reason=no-response` znacz "nie wiem", a nie "zamkniete". Firewalla **nie omijamy** (zakaz
      technik evasion, decyzja 15) - raportujemy go.
    - **Luka w kodzie (21.11)**: `nmap.FromHosts` zapisuje tylko `state=open`, a domyslne argumenty etapu uslug
      maja `--open`, wiec porty filtrowane nie trafiaja nawet do XML. Host za polityka drop-all wyglada jak host
      bez uslug, a jego uslugi z poprzedniego przebiegu staja sie `missing` -> falszywe `gone` w DD. To ten sam
      skutek co LAB-T7 (timeout), tylko inne zrodlo. Do zrobienia: `LAB-T11`.
    - Docelowo: (1) przed oznaczeniem braku celowana reproba portow znanych z poprzedniego przebiegu z
      `--reason` (kilka portow, nie pelny skan): `reset` = zamkniety, `no-response` = filtrowany;
      (2) obserwacja `port state=filtered` (informacyjna, bez `service`, poza `fp_hash`); (3) flaga przebiegu
      i paczki "wykryto filtrowanie ruchu - wynik niepelny", traktowana jak `timedout` (bez brakow,
      `close_old=false`); (4) w DD finding `info` "host filtruje ruch / wynik niepelny" zamiast znikania uslug.

21. **Adres w pasku = stan panelu: ścieżki, nie `#hash`** (DEV-14, 21.11).
    - Wybór: `/assets/<klucz>`, `/scans/<id>` i filtry w query stringu (`?state=live&kind=host`). Hash routing nie
      wymagałby zmian w serwerze, ale daje brzydkie linki i nie działa przy „otwórz w nowej karcie” w części
      narzędzi; mentor patrzy na GUI, więc adres ma być normalny.
    - Koszt: serwer musi zwracać SPA także pod ścieżkami widoków. Rejestrujemy **tylko znane widoki**
      (`GET /assets`, `/assets/`, `/targets`, `/scans`, `/scans/`, `/account`, `/admin`), a nie `/{path...}`,
      bo wildcard koliduje z `/live/` (dowolne metody) i wyłapywałby literówki w `/api/…`.
    - Klucz assetu zawiera `/` (`192.0.2.15/tcp/80`), więc w ścieżce jest `%2F`. Przeglądarki nie dekodują `%2F`
      w `location.pathname`, serwer dekoduje, ale i tak trafia w subtree `/assets/` — dlatego obie strony widzą
      poprawny klucz. Sprawdzone testem `Q1–Q3`.
    - Skutek uboczny: wszystkie `fetch` w panelu muszą być bezwzględne (`/api/v1/…`), bo względne `api/…`
      rozwiązywałyby się pod `/assets/…`. Ten sam powód dla `/live/` w iframe.
    - Zamykanie panelu szczegółów: klik w wiersz dokłada wpis historii, „✕”/`Esc` robi krok wstecz; wejście
      z linku (bez wpisu w historii) tylko czyści adres `replaceState`, żeby nie wypychać użytkownika z panelu.

22. **Dokładnie jedna instancja DefectDojo = źródło prawdy dla wszystkich środowisk** (21.11 21:12).
    - Stan: fatusia-1 ma pełny stack (DD `:18080`, `asi server`, `asi-db`, LAB-4), fatusia-2 ma pełny stack
      (DD `:8080`, `asi server`, lab `modern-proxy`, LAB-T8), blackarch bez DD (stacja dev). Oba DD są osiągalne
      z tailnetu (`/login` z blackarch: 200, 0,27 s f1 i 1,19 s f2).
    - Wniosek (potwierdzony przez zespół 21.11 21:12): **dokładnie jedna instancja**, bez „scratch”. Testy robimy
      na różnych środowiskach (lab organizatorów, nasz lab, własna infrastruktura), ale DD jest **jednym końcowym
      punktem, do którego pchamy wyniki** - więc między środowiskami i maszynami ma być jedna baza, jako źródło
      prawdy. Powody:
      (1) jury widzi jeden system końcowy - findings rozproszone po VM to dwa źródła prawdy;
      (2) `asi-changes`, `close_old` i dedupe po hashu są per-instancja, więc porównanie przebiegów z różnych
      maszyn ma sens tylko w jednej bazie;
      (3) koszt: 5 kontenerów i ~1,1-1,9 GB RAM na instancję, a VM 7 GB z labem (WordPress + mariadb + NPM +
      Traefik) nie ma zapasu;
      (4) DD na `8080` = port labu `modern` (WordPress), panel `8090` = DVWA - z DD domyślnym każda VM musi
      przenumerować porty i dokumentację, a `:18080` zostawia 8080/8090 labom;
      (5) jeden admin, jeden token, jedna wersja `DD_VERSION` (brak rozjazdu migracji przy równoległej pracy).
    - Wdrożenie: kanoniczny = fatusia-1 `http://100.113.45.50:18080` (6 rdzeni, relay „waw”). Pozostałe VM:
      **tylko skaner + lab**, `DD_URL` na kanoniczny (nie stawiają własnego DD). fatusia-2: DD wyłączyć
      (`docker compose stop nginx uwsgi celeryworker celerybeat postgres valkey`) albo zostawić wyłączony na stałe;
      jego skaner pcha wyniki do fatusia-1.
    - Zasady pracy ze wspólną instancją:
      (1) **produkt = środowisko, nie maszyna** (`ASI lab-org`, `ASI lab`, `ASI infra`), bo to ten sam asset
      niezależnie od tego, która VM skanuje;
      (2) ten sam produkt skanowany równolegle z dwóch maszyn = duplikaty w jednym teście, więc albo jeden skan
      naraz na środowisko, albo różne engagementy (`lab-org@f1`, `lab-org@ba`) - diff działa wtedy w obrębie
      engagementu;
      (3) `make nuke` na maszynie z DD tylko po uzgodnieniu: dane odtwarza `asi upload` z `results/`, ale
      historia reimportów i diff w DD przepadają;
      (4) `DD_VERSION` podnosimy **tylko tutaj** i tylko po sprawdzeniu, że nikt nie robi przebiegu - inaczej
      migracje rozjadą się w środku testu;
      (5) token API **per maszyna** (`DD_API_KEY` w `.env` każdej VM, tworzony w UI admina) - ta sama instancja,
      ale widać, kto co wysłał.
    - Wyjątek (dozwolony, ale nie jest źródłem prawdy): lokalny DD na innej VM do eksperymentu offline. Po
      teście `asi upload` do kanonicznego i lokalny stack do kosza - findings mają być w jednym miejscu.
    - Wymóg konfiguracji: do `DD_SITE_URL` i `DD_CSRF_TRUSTED_ORIGINS` kanonicznego dopisać
      `http://100.113.45.50:18080` - bez tego logowanie z przeglądarki przez tailnet wpadnie na CSRF (dziś
      wpisany jest tylko `localhost`).
    - Odporność (dlaczego wspólny DD nie jest pojedynczym punktem awarii danych): każdy przebieg zostawia
      `results/<run>` + `run.json`, a `asi upload` odtwarza import po podniesieniu DD. DD jest celem eksportu,
      nie magazynem prawdy (decyzja 8).
    - **Demo:** jeśli prezentacja idzie z innej VM, nie przenosimy bazy - puszczamy `asi upload` do świeżego DD
      na maszynie demo (albo pokazujemy UI fatusia-1 przez tailnet). Świadoma decyzja: historia diff z DD jest
      mniej warta niż to, że demo nie zależy od drugiej maszyny.

23. **Panel ASI domyślnie na `127.0.0.1:18090`, nie 8090** (22.11, fatusia).
    - Powód: lab organizatorów `vulnerable` publikuje DVWA na 8090. Przy panelu na 8090 każdy test LAB-4 wymagał
      przeniesienia panelu w `.env` i przywrócenia po teście; po LAB-4 na fatusia-1 port nie wrócił i panel
      „zniknął” z 8090. Zgodne z decyzją 22 pkt (4): 8080/8090 zostawiamy labom.
    - Zmienione: `.env.example`, domyślne `asi server -addr`, komentarz w compose, domyślne porty własne skanera
      (LAB-T2), skrypty `make test-*` (adres panelu teraz z `ASI_WEB_ADDR` w `.env`), dokumentacja.
      `asi serve` (stary panel plikowy) domyślnie na 8095 jak `make asi-serve`; przykłady `asi scan -ui` na 8094.
    - Istniejące `.env` zostają na 8090, bo `make env-sync` nie nadpisuje wartości: zmienić ręcznie
      `ASI_WEB_ADDR=127.0.0.1:18090` i `make up`.
    - DefectDojo zostaje domyślnie na 8080 (koliduje tylko z `modern`). Na fatusia-1 stoi na 18080 (decyzja 22).

24. **Jeden panel ASI (`asi server`, :18090) - wszystko w nim** (22.11, fatusia).
    - Były trzy strony WWW: panel `asi server` (18090), stary panel plikowy `asi serve` / `make asi-serve` (8095) i
      podgląd postępu skanu z terminala `make asi-scan -ui` (8094). Nazwy `server`/`serve` się myliły, a opisy portów
      w dokumentacji się rozjeżdżały.
    - Teraz: **jeden panel na 18090**. `asi serve` i `make asi-serve` usunięte (wypisują, gdzie jest panel);
      historia i porównanie przebiegów są w panelu (z bazy, LAB-T5). `make asi-scan` bez osobnej strony: pasek w
      terminalu, przebieg zapisuje się do bazy na bieżąco i widać go w panelu (Skany, Dashboard).
    - Podgląd na żywo skanu z panelu jest pod `/live/` panelu. Proces skanu wystawia go na gnieździe uniksowym
      `ASI_LIVE_ADDR=unix:/tmp/asi-live.sock` (prawa 600, w kontenerze), a panel robi do niego proxy - **jedynym
      portem ASI jest 18090** (wcześniej TCP 8091). Stary `.env` z `127.0.0.1:8091` dalej działa.
    - Bezpieczeństwo: podgląd skanu nie ma własnego logowania. Na TCP `127.0.0.1:8091` przy `network_mode: host`
      mógł go czytać każdy proces i użytkownik VM (IP, usługi). Gniazdo ma prawa `600` i leży w kontenerze, więc
      otworzy je tylko proces tego kontenera; użytkownik dochodzi do podglądu wyłącznie przez panel (logowanie,
      rola `viewer`). Przy starcie usuwane jest tylko istniejące **gniazdo** (stare po przerwanym skanie); każdy
      inny plik pod podaną ścieżką zatrzymuje start błędem, więc literówka w `-ui unix:...` niczego nie skasuje.
      `asi scan -ui` zostaje tylko jako opcja deweloperska.

## Pytania do CBI AGH - rozstrzygnięte przez zespół (21.11, wieczór)

- [x] **Przykładowe środowisko testowe** od organizatorów: otrzymane 21.11 z Discorda (`~/lab`, poza repo; to są materiały SEC-2), analiza i plan
      testów w `docs/guide/lab-organizers.md`, zadania `LAB-*` w `TASKS.md`. Wniosek: usługi na niestandardowych
      portach (np. 8787 w ich quickstarcie) są poza domyślnym zestawem portów ASI.
- [x] **Lista dozwolonych portów i limity ruchu** (brief, pkt 7.2-7.3) - **nie czekamy na jury, wpisujemy własne.**
      Profil portów (LAB-T1) i limity (decyzja 15) są parametrami naszego wdrożenia, nie czekają na brief:
      `-ports auto` (pełne TCP dla ≤16 hostów, zawsze przycinane do `ASI_ALLOWED_PORTS`), `ASI_MAX_RATE=1000`,
      `ASI_MAX_PARALLEL=32`, `ASI_SCOPE`/`ASI_EXCLUDE`. Jeśli jury poda listę portów, trafia do
      `ASI_ALLOWED_PORTS` + `-ports allowed` (bez zmian w kodzie); jeśli poda niższe limity ruchu - do `.env`.
      Domyślnie allowlista portów jest **pusta** (wszystkie porty), więc nie zgubimy usługi spoza listy jury.
- [x] **Dokładny zakres skanu** (CIDR/hostname'y) - **nie wiadomo jeszcze, na czym jury testuje.** Nie ma jednego
      `scans/targets.txt`: zakres jest argumentem przebiegu, w pliku celów. Etap 1 (dziś) = lab organizatorów
      z `lab.zip` (`~/lab-org`, compose, jeden stack naraz); etap 2 = własna infrastruktura zespołu (maszyny
      w tailnecie `100.x` + publiczne IP z `targets/targets.csv`). Konkretne CIDR-y jury dostarczymy, gdy będą -
      nie zgadujemy ich w repo. Szczegóły i pułapki: decyzja 19.
- [x] **"Płaski intranet bez firewalli/segmentacji"** - **założenie poprawne** (potwierdzone przez zespół), ale
      **wykryty firewall ma być raportowany jako "nie da się sprawdzić", nie jako "brak usług"**. Dziś kod tego
      nie robi - patrz decyzja 20 i `LAB-T11`.
- [x] **Dostęp do sandboxa** - **bez osobnego VPN od organizatorów**: sandbox to `lab.zip` z compose, który
      stawiamy sami na swoich maszynach. Dostęp = localhost na maszynie ze stackiem albo tailnet (`100.x`),
      bo maszyny zespołu są w Tailscale. Nie ma "specjalnego dostępu" do wyproszenia. Szczegóły: decyzja 19.

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
