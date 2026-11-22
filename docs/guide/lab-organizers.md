# Lab organizatorów (przykładowe środowisko testowe)

Przykładowe środowisko od organizatorów (CBI AGH), udostępnione na Discordzie 21.11: to są materiały od organizatorów z zadania SEC-2. Leży **poza repo**
(`~/lab` na VM fatusia-hacknation-2): to materiał organizatorów, z domyślnymi hasłami do usług. Tutaj jest
opis, analiza względem ASI i plan testów (zadania `LAB-*` w [TASKS](../TASKS.md)).

## Co zawiera

Cztery niezależne stacki docker compose. Organizatorzy zaznaczają: **uruchamiać jeden naraz**. Dotyczy to jednej
maszyny: stacki nie kolidują portami między sobą, a na kilku VM testujemy równolegle
([Testy równolegle](#testy-rownolegle-na-kilku-vm)). Wszystkie
publikują porty na **jednym hoście** (`0.0.0.0` na VM), więc testują rozpoznawanie usług, fingerprint i
wykrywanie zmian, a nie discovery wielu hostów.

| stack (plik) | usługi i porty na hoście | co sprawdza |
|---|---|---|
| `custom-network` | httpbin `8888`, PostgreSQL `15432`, RabbitMQ AMQP `5673` + panel `15673`, Gitea `3001` + SSH `2223`, nginx `8787` | usługi na niestandardowych portach; **scenariusz quickstart** |
| `modern` | WordPress `8080`, phpMyAdmin `8081`, Redis `6379` (bez hasła), Nginx Proxy Manager `80/81/443` | CMS, panele administracyjne, Redis |
| `modern-proxy` | WordPress przez Traefik `8085`, dashboard Traefika `8086` (`api.insecure`), API Toxiproxy `8474` | opóźnienia, timeouty, wolne łącze (Toxiproxy), panele bez uwierzytelniania |
| `vulnerable` | WordPress **4.7** `8088`, Adminer `8089`, DVWA `8090`, vsftpd `21` + pasywne `21000-21010` | przestarzałe komponenty, panele, FTP |

**Scenariusz quickstart** (`./quickstart.sh up | change | up`) to podstawowe demo organizatorów: 3 przebiegi,
w drugim usługa na `8787` jest zatrzymana, w trzecim wraca. Pozostałe porty mają być widoczne cały czas.

**Toxiproxy** (`.env`: `ENABLE_LATENCY=true`, `LATENCY_MS=500`, też `ENABLE_TIMEOUT`, `ENABLE_BANDWIDTH`,
`ENABLE_SLOW_CLOSE`) wstawia opóźnienia między Traefikiem a WordPressem. Według README organizatorów
„aplikacja powinna odnotować dłuższy czas odpowiedzi”.

## Analiza względem ASI (21.11, przed testami)

Sprawdzone w kodzie i na nmapie z kontenera skanera, bez uruchamiania stacków.

### 1. Porty poza domyślnym zestawem: blokuje scenariusz quickstart

Domyślny skan usług to top 1000 portów nmapa + 14 portów ryzykownych (`internal/scanner/nmap`). Poza
zestawem są:

| stack | poza domyślnym zestawem |
|---|---|
| `custom-network` | **`8787`** (port scenariusza quickstart), `15432`, `5673`, `15673`, `2223` |
| `modern-proxy` | `8474` (API Toxiproxy) |
| `vulnerable` | `21000-21010` (pasywne FTP, nieistotne) |
| `modern` | wszystko w zestawie |

**Rozwiązane (LAB-T1):** domyślny profil portów `-ports auto` (w CLI i GUI) automatycznie używa pełnego zakresu TCP (`-p 1-65535`, zawsze przycinanego do `ASI_ALLOWED_PORTS`, jeśli jest ustawione) dla małych zbiorów celów (≤ 16 hostów), a dla większych sieci zostaje przy top 1000 + portach ryzykownych. Dostępne są też jawne profile `-ports all` / `lab` / `allowed` / `top100` / `top1000` oraz własna lista portów. Jawne `-p` w `-nmap` (np. w `make demo`) zachowuje pierwszeństwo.

### 2. Konflikty portów z naszym stackiem

Od 22.11 (decyzja 23) **panel ASI ma domyślnie port 18090**, więc DVWA z `vulnerable` (8090) już z nim nie koliduje.
Zostaje jeden konflikt:

| port | lab | ASI |
|---|---|---|
| `8080` | `modern`: WordPress | DefectDojo (`DD_PORT`, domyślnie 8080) |

W zespole ten konflikt nie występuje: DefectDojo stoi tylko na maszynie kanonicznej (fatusia-1) i to na 18080
(decyzja 22), pozostałe VM mają sam skaner. Dotyczy jedynie pełnego stacku z domyślnym DD (np. jury na jednej
maszynie): przed `modern` przenieść DefectDojo w `.env` (`DD_PORT=18080`, `DD_SITE_URL` i
`DD_CSRF_TRUSTED_ORIGINS` na 18080) i `make up`.

### 3. Skanujemy sami siebie

Cel to `127.0.0.1` (albo IP VM), na którym działa też ASI i DefectDojo. **Załatwione przez LAB-T2:** na hoście
skanera porty naszego stacku (z `.env`: `DD_PORT`, `ASI_WEB_ADDR`, `ASI_LIVE_ADDR`, `ASI_DB_PORT`)
są pomijane automatycznie, a reszta portów jest skanowana normalnie. Ręczna lista portów bez naszych nie jest
już potrzebna. Wykluczenie idzie za wartościami z `.env`, więc DVWA na 8090 (panel jest na 18090) i, po
przeniesieniu DD (pkt 2), WordPress na 8080 są skanowane. Szczegóły: [Bezpieczeństwo](safety.md#skaner-nie-skanuje-samego-siebie-lab-t2).

### 4. Fingerprint: co powinniśmy rozpoznać

| aplikacja | dziś |
|---|---|
| WordPress (latest i 4.7), Redis bez hasła | nasze sygnatury (`asi-cms-wordpress`, `asi-html-generator`, `asi-redis-noauth`) |
| nginx, PostgreSQL, RabbitMQ (AMQP), SSH, vsftpd | `nmap -sV` |
| phpMyAdmin, Adminer, DVWA, Gitea, Traefik, RabbitMQ management, Nginx Proxy Manager, httpbin | tylko technologie z httpx (zależnie od bazy Wappalyzera), **brak naszych sygnatur** (LAB-T3) |
| panele bez uwierzytelniania (dashboard Traefika, API Toxiproxy) | brak sygnatur (LAB-T3) |
| WordPress 4.7 jako przestarzały | wersja wyciągana, ocena „przestarzały” do sprawdzenia w LAB-4 |

Zasada briefu: **tylko detekcja**. Domyślne hasła (DVWA, phpMyAdmin, FTP `test/test123`, RabbitMQ `guest`)
nie są sprawdzane, a anonimowe logowanie FTP też byłoby próbą logowania.

### 5. Czas odpowiedzi (Toxiproxy)

**Rozwiązane (LAB-T4):** adapter `httpx` uruchamia `-rt` i zapisuje metrykę `response_time_ms` w obserwacji `http` (celowo poza `fp_hash`, więc zmiana opóźnienia nie tworzy fałszywych zdarzeń `changed`). Panel web pokazuje kolumnę `HTTP ms`, filtr „tylko wolne HTTP” oraz ostrzeżenie w szufladzie assetu powyżej progu `ASI_HTTP_SLOW_MS` (domyślnie `300` ms, LAB-T9). Metryka trafia także do eksportu CSV (`http_ms`).

## Wyniki LAB-1 (21.11, VM fatusia-hacknation-2, arm64)

Stack `custom-network` przez `quickstart.sh`, cel `127.0.0.1`, `-parallel 1 -rate 1000`. Przebiegi 1-3 na kodzie
sprzed LAB-T1/T2, z ręcznym pełnym TCP bez portów ASI/DD (`-p 1-5432,5434-8079,8081-8089,8092-8093,8096-65535`).
Produkt DD `ASI lab-org`, engagement `quickstart`.

| przebieg | zmiana w labie | ASI (reconcile) | DefectDojo |
|---|---|---|---|
| 1 | `quickstart.sh up` | 10 usług (5 labu + 5 samej VM), `new` | `ASI discovery` 10, `asi-httpx` 5 |
| 2 | `change` (8787 stop) | **tylko** `8787` → `missing`, 9 bez zmian | `closed 1` (discovery i httpx), `asi-changes`: „nie odpowiada” |
| 3 | `up` | `8787` → `reappeared` | `reactivated 1` (discovery i httpx), „nie odpowiada” zamknięte |

Przebieg trwa około 115 s (65 tys. portów, 1 host, 1000 pps). Rozpoznane: nginx 1.31.9 (8787), Gitea (tech, tytuł
strony **instalacji**), RabbitMQ Management (tytuł, Cowboy/Erlang), AMQP (5673), OpenSSH 10.3 (2223).

**Domyślne ustawienia:**

| kod | widoczne porty | usługi labu |
|---|---|---|
| przed LAB-T1/T2 | `22, 3001, 8080, 8090` | **4 z 5 niewidoczne** (8787, 2223, 5673, 15673) |
| po LAB-T1/T2 (`-ports auto`, pomijanie własnych portów) | 22, 2223, 3001, 5673, 8384, 8787, 15673, 22000 i 2 procesy VM | **5 z 5**, bez 8080/8090 |

Po LAB-T3/T4: sygnatury `asi-gitea` (info) i `asi-rabbitmq-management` (low), czas odpowiedzi HTTP 1-4 ms.

Poprawione w trakcie: `asi-changes` wysyłał do produktu bieżącego przebiegu warunki **wszystkich** assetów w
bazie (u nas hosty 192.0.2.14/.15 z własnego labu trafiły do `ASI lab-org`). Teraz idą tylko adresy z planu
przebiegu (`plan.json`). Zweryfikowane: 0 obcych warunków, a DD zamknął 2 błędnie wysłane.

Zostaje: ~~LAB-T5~~ (zrobione: diff używa słów z historii), LAB-T6 (instalator Gitea), szum usług samej
VM (SSH, Syncthing, procesy lokalne). To prawdziwe usługi hosta, w labie jury wykluczyć je zakresem/portami.

## Wyniki LAB-2 (21.11, `custom-network` na blackarch, amd64)

Własna, niezależna kopia stacku organizatorów: `lab.zip` → `~/lab-org` (poza repo), `docker compose -f
docker-compose-custom-network.yml up -d`, jeden stack naraz. Cel `127.0.0.1`, porty podane jawnie
(`-ports 2223,3001,5673,8787,8888,15432,15673`), `-rate 200 -parallel 2`, przebieg ~60 s.

| wymóg LAB-2 | wynik |
|---|---|
| 7 portów | **7/7** otwarte: 2223, 3001, 5673, 8787, 8888, 15432, 15673 |
| poprawne usługi z `-sV` | ssh OpenSSH 10.3 · http Golang net/http (Gitea) · amqp · nginx 1.31.9 · http gunicorn/19.9.0 (httpbin) · **postgresql PostgreSQL DB 9.6.0 or later** · http Cowboy httpd (RabbitMQ) |
| Gitea w HTTP | tytuł `Installation - Gitea: Git with a cup of tea`, tech `Gitea`, `Go` |
| RabbitMQ w HTTP | tytuł `RabbitMQ Management`, tech `Bootstrap`, `Cowboy`, `Erlang`, `jQuery:3.5.1` |
| httpbin | tytuł `httpbin.org`, `gunicorn/19.9.0`, `Python`, `Swagger UI` |
| nginx | tytuł `Welcome to nginx!`, `Nginx:1.31.9` |

**LAB-T10 (22.11, fatusia-2, pomiary na 127.0.0.1, 13 otwartych portów):**

| tryb `-sV` | czas | PostgreSQL 15432 |
|---|---|---|
| `--version-light` (główny przebieg) | 47 s | nie |
| `--version-intensity 4` na wszystkich | 48 s | tak |
| `--version-all` na wszystkich | 366 s | tak |
| druga próba tylko na nierozpoznanych (3 porty): `--version-all` / intensywność 7 / 4 | 16 s / 6 s / 7 s | tak |

Decyzja: główny przebieg bez zmian (`--version-light`, więc UDP przy `ASI_ALLOW_UDP=1` nie dostaje sondy SNMP
`public`), druga próba tylko na nierozpoznanych portach TCP z **`--version-intensity 7`** zamiast
`--version-all` (ta sama identyfikacja, 2-3× szybciej; na portach naprawdę nieznanych `--version-all` wysyła
wszystkie sondy na próżno). Limit 512 par host:port: wcześniej po przekroczeniu cała próba była **po cichu
pomijana** (czyli właśnie w dużej sieci), teraz sprawdzane są pierwsze 512 (adres, port rosnąco), a reszta
jest w logu. Na żywo: druga próba 7 s, `15432 → postgresql`. Uwaga: obraz `kennethreitz/httpbin` jest tylko
amd64, na arm64 (fatusia-2) kontener `custom-api` kończy się `exec format error`, więc 8888 testuje się na amd64.

**Dwie luki wykryte tym testem (naprawione w tym samym dniu):**

1. **PostgreSQL na 15432 bez usługi.** `--version-light` probkuje tylko porty znane nmapowi, więc niestandardowe
   porty wracały bez identyfikacji (puste `service`). Dodany etap *version probe*: po fazie usług ASI robi drugi,
   wąski przebieg `-sV --version-all` tylko na porty bez rozpoznania (≤512 par host-port), z tą samą polityką
   i limitem tempa (`--max-rate`), a wynik zastępuje słaby wpis (licznik usług się nie zmienia).
   Efekt: `15432 → postgresql PostgreSQL DB 9.6.0 or later`.
2. **httpbin na 8888 jako `tcpwrapped`** — nmap zamyka sondę, ale httpx pobiera stronę. Teraz po fazie HTTP porty
   z `tcpwrapped`/`unknown`, dla których httpx ma odpowiedź, dostają `http` + `product` z nagłówka `Server`
   (tu `gunicorn/19.9.0`) i przeliczoną ocenę. `--version-all` jest na allowliście `internal/safety` jako flaga
   wyłącznie detekcyjna (`TestEnforceVersionAll`, skrypty NSE poza allowlistą nadal blokowane).

**Do decyzji przy LAB-3:** stack `modern` wiąże WordPressa na 8080, a u nas na 8080 stoi DefectDojo — lokalną
kopię uruchamiamy z remapem portu (np. `18080:80`), żeby nie zatrzymywać naszego stacku. Wynik LAB-3 opisze
faktyczne porty.

## Wyniki LAB-3 (21.11, `modern` na blackarch, amd64)

Ta sama niezależna kopia (`~/lab-org`), `docker-compose-modern-local.yml` z **remapem WordPressa 8080 → 18080**
(na 8080 stoi nasze DefectDojo; reszta portów jak u organizatorów). Cel `127.0.0.1`, porty
`80,81,443,6379,8081,18080`, `-rate 200 -parallel 2`, przebieg ~40 s.

| wymóg LAB-3 | wynik |
|---|---|
| WordPress z wersją | `http Apache httpd` na 18080; tytuł strony instalatora, **wersja 7.1.5** z `?ver=` arkuszy CSS rdzenia (readme.html od WP 5.8 nie podaje już wersji) |
| `asi-redis-noauth` high | Redis 7.4.12 na 6379, sygnatura `asi-redis-noauth` **high**; dodatkowo ocena portu `medium` („Redis reachable internally”) |
| phpMyAdmin | tytuł `phpMyAdmin`, `Apache/2.4.71`, `PHP 8.3.37`, sygnatura `asi-phpmyadmin` (low) |
| Nginx Proxy Manager | tytuł `Nginx Proxy Manager`, `openresty`, sygnatura `asi-nginx-proxy-manager` (low) z wersją panelu `2.17.1` z `/api/` |
| TLS na 443 | **domknięte 22.11**: na 443 w sieci `modern` wstawiono terminator TLS (nginx) z certyfikatem self-signed `CN=asi.lab`, proxujący do WordPressa (świeży NPM nie ma konta admina/hosta, więc nie dało się dodać certu przez API bez pierwszej konfiguracji; sam NPM z panelem 81 pozostaje wykrywany jak wyżej). `curl -k https://asi.lab/` → 302 do instalatora WP; ASI zapisał `tls_subject=asi.lab`, `tls_issuer=asi.lab`, `self_signed=true`, `tls13` (przebieg `20261122-094056`, `-ports 443`) |

**Weryfikacja TLS poza labem** (żeby nie zostawić tej ścieżki niesprawdzonej): tymczasowy serwer HTTPS z certyfikatem
self-signed (`CN=lab-tls.local`) na `127.0.0.1:8443`, skan `-ports 8443`. Wynik: `https`, tytuł `ASI TLS test`,
`tls_subject`/`tls_issuer` = `lab-tls.local`, `tls_not_after` = data z certyfikatu, `tls_sans` = `lab-tls.local`,
a w surowej obserwacji httpx `tls.self_signed=true`, `tls.mismatched=true`, `tls_version=tls13`,
`cipher=TLS_AES_256_GCM_SHA384`. Czyli parser TLS działa; do zaliczenia „TLS na 443” w labie wystarczy dodać
host + certyfikat w NPM (albo wystawić 443 z certyfikatem w `docker-compose-modern`).

**Zmiana w kodzie:** szablon `signatures/http/asi-cms-wordpress.yaml` dostał drugie żądanie (`GET /`) z ekstrakcją
wersji rdzenia z `wp-(includes|admin)/css/*.css?ver=…` — bez tego WordPress z instalatora nie miał wersji,
a readme jej już nie zawiera (tylko wersje PHP/MySQL). Sprawdzone: `extracted-results = ["7.1.5"]`,
po zawężeniu do CSS rdzenia bez fałszywych jQuery 3.7.1/3.4.1.

## Wyniki LAB-5 (21.11, Toxiproxy, `modern-proxy`)

Domyślne ustawienia skanera (pełne TCP przez `-ports auto`, pomijanie portów ASI/DD), cel `127.0.0.1`,
przełączanie zakłóceń przez `.env` labu jak w README organizatorów. Przebieg trwa około 97 s.

| przebieg | zakłócenie (8085: Traefik → Toxiproxy → WordPress) | curl 8085 | ASI | wynik |
|---|---|---|---|---|
| 1 | brak (tuż po starcie stacku) | 302, 36 ms | **0 portów**, 10× `missing` + `flapping` | ❌ błąd LAB-T7 (opis niżej) |
| 1' | brak (powtórka) | 302, 6 ms | 8 usług, WordPress (sygnatury), 6 ms | ✅ |
| 2 | `latency` 500 ms ±50 | 302, 537 ms | bez zmian, **czas odpowiedzi 493 ms** | ✅ (wtedy próg „wolna” 500 ms - LAB-T9; teraz 300 ms, flaga pewna) |
| 3 | `timeout` 1000 ms | 502, 1,0 s | 8085: `changed` (Apache → Go/Traefik, TLS, 404), DD closed/created | ⚠️ LAB-T8 |
| 4 | brak | 302 | 8085: znowu `changed`, DD closed/reactivated | ⚠️ LAB-T8 |
| 5 | `bandwidth` 100 KB/s | 200 | bez zmian | ✅ |
| 6 | `slow_close` 1000 ms | 200 | bez zmian | ✅ |

**Przebieg 1 (LAB-T7, krytyczne).** Przebieg ruszył tuż po starcie stacku. W trakcie `-sV` zegar ścienny
przeskoczył o ~20 min (VM wstrzymana: ASI zmierzył zegarem monotonicznym 92 s, nmap zegarem ściennym
1303 s), więc nmap uznał przekroczenie `--host-timeout 10m` i zwrócił `<host timedout="true">` **bez portów**
(kod wyjścia `success`). ASI nie czyta `timedout`, uznał host za w pełni przeskanowany i oznaczył wszystkie
usługi jako `missing`. Powtórka bez wstrzymania: 97 s, poprawnie. Wyzwalacz był środowiskowy, ale ten sam
skutek da każdy host, który przekroczy `--host-timeout` (wolny host, wisząca usługa przy `-sV`).

**Poprawka LAB-T7 (21.11, sprawdzona na żywo).** ASI czyta `timedout="true"`: taki host jest
**nieprzeskanowany** (znika z pokrycia paczki, trafia do `pending` / `asi scan -resume`, nie dostaje braków),
a główny reimport `ASI discovery` używa `close_old` tylko przy etapach discovery i services bez błędów (też
`asi upload`). Test: ten sam zbiór z historią, `--host-timeout 5s`. Wynik: host w `pending`, reconcile bez
zdarzeń (wcześniej 10× `missing` + `flapping`), skan potwierdzający odzyskał 8 znanych usług (tag
`unstable`), DD `close_old=false`.

**Poprawka LAB-T8 (21.11, sprawdzona na żywo).** Powrót odcisku do stanu sprzed ostatniej zmiany to
zdarzenie `reverted`, a nie drugie `changed`. Powtarzające się awarie podnoszą `flapping`, a test `asi-changes`
w DD zamyka finding „zmiana” po cofnięciu. Na żywo (`timeout` → brak zakłóceń): awaria `changed:2` (usługa +
HTTP), powrót `reverted:2`, w `asi-changes` brak otwartej zmiany dla 8085. Główny test `ASI discovery` dalej
zamyka i reaktywuje finding (DD dopasowuje po hashu opisu), to zachowanie DefectDojo.

**Szum hosta:** krótkotrwałe porty lokalnych procesów VM (np. 39963, 43683) dają `new`/`missing` między
przebiegami. To prawdziwe usługi hosta skanera, w labie jury poza zakresem.

## Wyniki LAB-4 (21.11, `vulnerable`, VM fatusia-hacknation-1)

Własna kopia labu, stack **z nakładką** `docker/lab-org/vulnerable.bind.yml` (wszystkie 15 portów tylko na
`127.0.0.1`, sprawdzone `ss -ltn`). Panel ASI na `ASI_WEB_ADDR=127.0.0.1:18090` (DVWA zajmuje 8090; od decyzji 23 to domyślny port panelu),
DD na 18080. Domyślne ustawienia skanera (`-ports auto`, pełne TCP), jeden przebieg 124 s.

| kryterium | wynik |
|---|---|
| WordPress 4.7 przestarzały i wysoko w ocenie | ✅ `asi-cms-wordpress` 4.7.5, **`asi-wordpress-outdated` (medium)**, `asi-php-outdated` PHP 5.6.30; w panelu **75/100 (high)** |
| Adminer rozpoznany | ✅ `asi-adminer`, `asi-admin-panel` („Login - Adminer”), 55/100 |
| DVWA rozpoznane | ✅ `asi-dvwa` (medium, „DVWA v1.10”), ciasteczka `PHPSESSID`, `security`, 75/100 (high) |
| vsftpd z wersją | ✅ `vsftpd 3.0.2` (nmap), 60/100; pasywne porty FTP 21000–21010 widoczne jako otwarte |
| **brak prób logowania** | ✅ logi usług od chwili przed skanem: HTTP **111 GET, 2 OPTIONS, 0 POST**; do logowania tylko `GET /wp-login.php` (wykrycie strony, bez danych); vsftpd: same `CONNECT`, **0 `LOGIN` / `FAIL LOGIN`** |

**Znalezione i poprawione (fałszywe trafienia sygnatur IoT):** `asi-iot-router-openwrt` trafiał w Adminera,
a `asi-iot-router-mikrotik` w DVWA. Przyczyna: dopasowanie słowa z **własnej ścieżki żądania odbitej w
odpowiedzi** (Adminer wstawia nazwę skryptu do linków: `href="luci?file=…"`, strona 404 Apache cytuje
`/webfig/`). Teraz obie sygnatury szukają słowa tylko w `<title>`. Sprawdzone nucleiem w kontenerze: strona
LuCI z atrapy i WebFig („RouterOS router configuration page”) dalej trafiają, Adminer i DVWA już nie.

**Do poprawy (LAB-T12):** `asi-admin-panel` zgłasza Adminera 5 razy (po jednym na każdą sprawdzaną ścieżkę, bo
Adminer odpowiada stroną logowania pod każdym URL-em); `services.json` w pliku przebiegu ma starą ocenę z samego
nmapa (`low` dla WordPressa), a panel i DD liczą ją z sygnaturami (75, high).

## Wyniki LAB-6 (21.11, zmiana stacku, VM fatusia-hacknation-1)

Własna kopia labu (`~/lab`) na fatusia-1 (x86_64), aktualny `main`, domyślne ustawienia skanera: `-ports auto`
(pełne TCP dla 1 hosta), `-parallel 1 -rate 1000`, pomijanie portów ASI/DD (LAB-T2). DefectDojo przeniesione na
`DD_PORT=18080`, bo `modern` zajmuje 8080. Cel `127.0.0.1`, produkt DD `ASI lab-org`, engagement `lab6`.
Progi domyślne: port `gone` po 2 brakach. Każdy przebieg trwał 118–128 s.

| przebieg | lab | ASI (reconcile) | DD `ASI discovery` | DD `asi-changes` |
|---|---|---|---|---|
| 1 | `custom-network` (7 portów) | 14× `new` (7 labu + 6 portów VM + host) | utworzone | 0 warunków |
| 2 | `modern` | 7× `missing` (1 brak), 6× `new` | closed 7, created 6 | +7 „nie odpowiada” |
| 3 | `modern` (bez zmian) | **7× `gone`** (2 braki) | untouched 12, **0 zmian** | 7 „nie odpowiada” → 7 „zniknęła” |
| 4 | `custom-network` | **7× `reappeared`**, 6× `missing` | **reactivated 7, created 0**, closed 6 | 7 „zniknęła” zamknięte, +6 „nie odpowiada” |
| 5 | `custom-network` (bez zmian) | **6× `gone`** | untouched 13, 0 zmian | 6 „nie odpowiada” → 6 „zniknęła” |

**Duplikaty w DD (API, po przebiegu 5): 0** w każdym z 4 testów. `ASI discovery` ma 19 znalezisk = dokładnie
19 różnych portów (7 `custom-network` + 6 `modern` + 6 VM), z czego 13 aktywnych (`custom-network` + VM),
6 zamkniętych (`modern`). `asi-changes`: 6 aktywnych warunków (porty `modern` „zniknęła”), reszta to historia.
Powrót usługi reaktywuje stare znalezisko zamiast tworzyć nowe. Żaden port nie dostał `flapping`
(każdy zmienił stan raz w jedną i raz w drugą stronę, poniżej progu 3 przejść).

Rozpoznane usługi: `custom-network`: nginx 1.31.9 (8787), Gitea (3001, tytuł **instalacji**, LAB-T6),
OpenSSH 10.3 (2223), AMQP (5673), RabbitMQ Management (15673, Cowboy), httpbin (8888, httpx: gunicorn 19.9.0,
Swagger UI). `modern`: Apache 2.4.71 (WordPress 8080, phpMyAdmin 8081), Redis 7.4.12 (6379), OpenResty
(Nginx Proxy Manager 80/81), TLS na 443.

**Znalezione luki:**

- **PostgreSQL (15432) bez nazwy usługi**, tylko otwarty port. `-sV --version-light` (intensywność 2) nie ma
  sondy, która go rozpoznaje. Od `--version-intensity 4` nmap zwraca `postgresql` / `PostgreSQL DB`
  (sprawdzone na 3, 4, 5, 6, 7). Zadanie **LAB-T10**.
- httpbin (8888) z nmapa wychodzi jako `tcpwrapped`, ale httpx go rozpoznaje (tytuł, gunicorn), więc fingerprint
  HTTP jest kompletny. Bez działań.
- Szum hosta jak w LAB-1/LAB-5: SSH, Syncthing (8384, 22000), dokumentacja (4173) i 2 porty lokalnych procesów VM.

## Wyniki LAB-7 (22.11, skaner na innej maszynie; stack na fatusia-hacknation-2)

**Układ (decyzja 19):** stack = VM A `fatusia-hacknation-2` (`<tailscale-ip-A>`, arm64, `custom-network` + `quickstart.sh`),
skaner = VM B `blackarch` (`<tailscale-ip-B>`). Połączenie szło **przez relay DERP „waw”** (`tailscale ping`: „via DERP
(waw) in 43 ms, direct connection not established”) — czyli gorszy wariant niż direct. Cel: `<tailscale-ip-A>`
(`targets/lab-remote.csv`), `-parallel 1 -rate 500`, porty labu jawnie:
`-ports 2223,3001,5673,8787,15432,15673` (dlaczego nie pełne TCP — luka LAB-T13 niżej).

> **Zastrzeżenie (pierwsze przejście):** żaden z trzech przebiegów `091643`, `091750`, `091901` nie szedł sam —
> nakładały się z równoległymi skanami tego celu (`091214`, `091721`). Dlatego wykonano **powtórkę solo** poniżej.

### Powtórka solo (22.11 10:27-10:36 UTC)

Bez równoległych skanów (sprawdzane `pgrep -af 'asi scan'` przed każdym przebiegiem). Skaner uruchomiony jako
**binarka na hoście** VM B, nie w kontenerze: inne sesje restartowały w tym czasie `nmap-scanner` i zabijały skany
(pierwsza próba `092601` padła po 37 s). Cel i porty jak wyżej, `quickstart.sh up → change → up`.

| przebieg | stan labu | otwarte | zdarzenia reconcile | czas |
|---|---|---|---|---|
| `20261122-092710` | `up` | 12 (6/6 labu) | **brak** (`map[]`) — czysta baza | 68 s |
| `20261122-093109` | `change` (8787 stop) | 11 (5/6 labu) | **`missing:1` = tylko 8787** | 93 s |
| `20261122-093446` | `up` | 11 (6/6 labu) | **`reappeared:1` = tylko 8787**; `filtered:1` na `4173` (usługa dokumentacji VM A, LAB-T11: nie liczone jako brak); `flapping:1` na 8787 (historia z wcześniejszych, nakładających się przebiegów) | 107 s |

**Kryteria powtórki:** ✅ wszystkie 6 opublikowanych portów labu widoczne w każdym przebiegu; ✅ jedyna realna
zmiana to 8787 (`missing` → `reappeared`); ✅ zero adresów `172.x` w `plan.json` i `observations.json` (0/0/0);
✅ w logu nginx celu **731 GET / 0 POST** z `<tailscale-ip-B>`, tylko ścieżki detekcyjne (`/wp-admin/`,
`/manager/html`, `/login` — 404) i zero prób logowania. Potwierdzenie: pierwsze przejście pełnego TCP (`092710`)
zgubiło w pierwszym przebiegu 4 znane porty — **skan potwierdzający LAB-T11 odzyskał wszystkie 4** (tag `unstable`),
czyli mechanizm „filtered + reproba” działa; nowy port zgubiony w pierwszym przejściu nadal przepadnie (LAB-T13).

Trzy przebiegi z prawdziwą zmianą w środku (`quickstart.sh up → change → up`):

| przebieg | stan labu | otwarte | zmiany (reconcile) | czas |
|---|---|---|---|---|
| `20261122-091643` | `up` (8787 stoi) | 6/6 | `reappeared:1` (8787 wrócił po wcześniejszym `missing`) | 62 s |
| `20261122-091750` | `change` (8787 zatrzymany) | 5/6 | **`missing:1` = tylko 8787**, pozostałe 5 bez zmian | 65 s |
| `20261122-091901` | `up` (8787 wrócił) | 6/6 | **`reappeared:1` = tylko 8787** | 64 s |

**Kryteria:**
- ✅ **wszystkie opublikowane porty labu widoczne z VM B** (2223, 3001, 5673, 8787, 15432, 15673),
- ✅ **brak fałszywych `missing`** — jedyna zmiana w każdym przebiegu to realnie zatrzymany/wrócony 8787,
- ✅ **źródło w logu celu to `<tailscale-ip-B>`** (tailscale VM B), nie adres mostka,
- ✅ **zero adresów `172.x`** w `plan.json`, `merged.xml` i obserwacjach — mostki dockera nie są celem skanu.

Rozpoznane usługi z daleka: OpenSSH 10.3 (2223, Gitea), nginx 1.31.9 (8787), AMQP (5673), **PostgreSQL (15432 —
rozpoznany drugą próbą `--version-intensity 7`, czyli LAB-T10 działa też przez DERP)**, RabbitMQ Management
(15673, Cowboy), Gitea (3001, tytuł instalatora → `asi-gitea-install` **85/high**, LAB-T6). Pełny `-p 1-65535`
(przebieg `20261122-091214`) widzi dodatkowo usługi samej VM: 22, 4173, 8080 (DD), 18090 (panel), 22000 (Syncthing), 33324.

**Dowód po stronie celu** (`docker logs hacknation-custom-network-flask-app-1` na VM A): 88 żądań z `<tailscale-ip-B>`,
**same GET, 0 POST** (`GET /manager/html` 404, `GET /` 200 — ścieżki detekcyjne sygnatur), zero prób logowania.

**Luka → LAB-T13: pełny TCP przez DERP gubi otwarte porty.** `-p 1-65535` przy `-rate 500` daje w nmapie
`extraports state="filtered"` i **w każdym przebiegu ginął inny otwarty port**: `20261122-084757` bez 5673,
`20261122-091214` bez 8787 (sprawdzone 3 s wcześniej: 8787 otwarty). Ten sam port odpowiada `open syn-ack` na
`nmap -sT -p <port> --reason` z tego samego kontenera, a ASI nie raportuje go wcale — to ten sam skutek co LAB-T11
(port `filtered` = cisza), więc po 2 przebiegach byłby fałszywy `missing`/`gone`. Przyczyna to utrata SYN-ów na
ścieżce relay (nie firewall), dlatego porty labu podaliśmy jawną listą. Dla celów za NAT/relay: jawna lista portów
albo reproba portów „filtered” w tym samym przebiegu (LAB-T11/T13).

**Sprawdzone po LAB-T11** (✅ 22.11 09:17: `filtered` + reproba znanych portów, migracja 009): powtórzony pełny przebieg
`-p 1-65535 -rate 500` przez DERP (`20261122-092205`, ten sam cel) widzi **12/12 portów, w tym 5673 i 8787** — wcześniej
w każdym przebiegu ginął jeden. Reprobe portów oznaczonych `filtered` w tym samym przebiegu domyka więc także utratę
SYN-ów na relay. Zostaje zalecenie z LAB-T13 pkt 4 (cele za NAT/relay: pewniejsza jawna lista portów) i **LAB-T14**.

**Uwaga o równoległych skanach tego samego celu:** w trakcie testu dwie sesje agentów na blackarch skanowały
`<tailscale-ip-A>` jednocześnie (`20261122-084757` + `20261122-084819`, potem `085308` + `085801`/`090326`). Dwa skany
na jednej ścieżce DERP gubią więcej portów i mieszają historię w bazie dla tego IP. Wnioski: **jeden skan celu
naraz** (rezerwacja w TASKS) i unikalny `-set` na eksperyment. Przy okazji wyszła kolizja identyfikatora przebiegu
(co do sekundy) → `db: create run: ERROR: duplicate key … runs_pkey` (LAB-T14).

## Jak testować

Wspólne przygotowanie (LAB-0):

```bash
cd ~/lab && cp -n .env.example .env              # tylko dla modern-proxy
printf 'target,asset,owner,tags,enabled,note\n127.0.0.1,lab-org,secops,lab-org,true,lab organizatorow\n' \
  > ~/asi/targets/lab-org.csv                    # gitignored
```

Każdy test: uruchomić **jeden** stack, odczekać na gotowość (`docker compose -f <plik> ps`), skan ASI z pełnym
zakresem portów, zmiana w labie, kolejny skan, potem wynik w panelu (Assety, porównanie przebiegów) i w
DefectDojo (testy `ASI discovery`, `asi-changes`, `asi-httpx`, `asi-nuclei`). Na koniec
`docker compose -f <plik> down -v`.

Oczekiwane wyniki i kryteria zaliczenia: zadania `LAB-1` … `LAB-7` w [TASKS](../TASKS.md).

## Kilka maszyn w tailnecie (decyzja 19)

Zespół ma kilka VM w Tailscale. **Jeden stack naraz na maszynę**, ale na wielu maszynach jednocześnie. Stacki
nie kolidują portami między sobą. Z naszym stackiem koliduje już tylko `modern` (8080 = domyślny DefectDojo); panel ASI
ma od decyzji 23 port 18090.

| gdzie stoi skaner | cel w pliku celów | co widać |
|---|---|---|
| ta sama VM co stack | `127.0.0.1` | wszystko, także porty z `0.0.0.0` i usługi samej VM (szum) |
| inna VM w tailnecie | `<tailscale-ip>` VM ze stackiem (np. `100.x.y.z`) | tylko porty **opublikowane** (`ports:` w compose) |

Adresy mostków dockera (`172.x`) **nie są celem skanu** - Tailscale ich nie routuje, więc z innej maszyny ich
nie ma. Nie ma też osobnego VPN od organizatorów: `lab.zip` stawiamy sami, dostęp to localhost albo tailnet.

```bash
# na VM ze stackiem
docker compose -f docker-compose-custom-network.yml up -d
tailscale ip -4                                  # -> 100.x.y.z
# na VM ze skanerem: osobny plik celów na tę maszynę, note = stack
printf 'target,asset,owner,tags,enabled,note\n100.x.y.z,lab-org,secops,lab-org,true,custom-network\n' \
  > ~/asi/targets/lab-org-$(hostname -s).csv
make asi ARGS="scan -targets targets/lab-org-$(hostname -s).csv -ports auto -rate 500 -parallel 1"
```

Uwagi:

- **Zmiana stacku = celowe masowe `missing`** (LAB-6). Aktualizuj `note` w pliku celów, żeby nie czytać tego jako
  awarii; `gone` po progu i `reappeared` po powrocie to poprawne zachowanie.
- **Ekspozycja:** stacki mają domyślne hasła i publikują na `0.0.0.0`, a Docker omija firewall hosta: widzi je
  cały tailnet, LAN i port forwarding. **Zawsze z nakładką** `docker/lab-org/<stack>.bind.yml` (niżej), po testach
  `docker compose down`.

## Testy równolegle na kilku VM

Nie czekamy na „wolny lab” na jednej maszynie. Każda VM z dockerem może prowadzić inny test LAB-* w tym samym
czasie (LAB-6 na fatusia-1 szedł równolegle z LAB-5 na fatusia-2, wyniki czyste).

1. **Rezerwacja** w `docs/TASKS.md`: przy zadaniu `🔨 w toku: <kto>, <stack>@<VM>`. Na jednej VM tylko jeden stack labu.
2. **Kopia labu** (materiał organizatorów, poza repo, bez `.env` z cudzej maszyny):
   `rsync -a --exclude .env fh:lab/ ~/lab/` (albo z dowolnej VM, która go ma).
3. **Własny skaner ASI + wspólny DefectDojo** (decyzja 22): na tej VM wstaje tylko skaner i baza,
   `docker compose up -d nmap-scanner asi-db`, a `DD_URL` w `.env` wskazuje kanoniczny DD
   (`http://100.113.45.50:18080`). Nie stawiamy drugiej instancji DD - wyniki z każdej VM mają trafiać do jednej
   bazy. Konfiguracja: [Integracja z DefectDojo](defectdojo.md#jedna-instancja-dd-na-wiele-srodowisk-i-maszyn-decyzja-22).
   Skan idzie na `127.0.0.1`, produkt = środowisko, engagement per VM (`lab-org@f2`), żeby równoległe przebiegi
   się nie dublowały.
4. **Porty naszego stacku** przed stackiem, który z nim koliduje (w `.env`):

   | stack labu | koliduje z | w `.env` |
   |---|---|---|
   | stack labu | koliduje z | w `.env` |
   |---|---|---|
   | wszystkie cztery | — | — |

   Od 22.11 nic nie trzeba przenosić: DefectDojo stoi tylko na maszynie kanonicznej (fatusia-1) i to na **18080**
   (decyzja 22), a panel ASI ma domyślnie **18090** (decyzja 23), więc 8080 (`modern`) i 8090 (`vulnerable`)
   są wolne dla labu. Wyjątek: starszy `.env` może mieć jeszcze `ASI_WEB_ADDR=127.0.0.1:8090` albo lokalny DD
   na 8080 (`make env-sync` nie zmienia istniejących wartości) - wtedy ustaw `ASI_WEB_ADDR=127.0.0.1:18090`
   i `make up` przed `vulnerable`/`modern`.

   Wykluczenie własnych portów ze skanu (LAB-T2) samo idzie za nowymi wartościami.
5. **Start z nakładką** (porty labu tylko na `LAB_BIND`, domyślnie `127.0.0.1`):

   ```bash
   cd ~/lab
   docker compose -f docker-compose-vulnerable.yml -f ~/asi/docker/lab-org/vulnerable.bind.yml up -d
   # skaner na innej VM: porty tylko w tailnecie, nie w LAN
   LAB_BIND=$(tailscale ip -4) docker compose -f docker-compose-modern.yml -f ~/asi/docker/lab-org/modern.bind.yml up -d
   ```

   Sprawdzone `docker compose config`: bez nakładki 31 portów czterech stacków na `0.0.0.0`, z nakładką wszystkie na `127.0.0.1`.
6. **Wynik** w tabeli zadania i w sekcji „Wyniki LAB-n” niżej, z nazwą VM (różne VM = różny szum własnych usług,
   dlatego engagement nazywamy `lab-org@<vm>`).
7. **Sprzątanie po teście:** `docker compose -f docker-compose-<stack>.yml -f ~/asi/docker/lab-org/<stack>.bind.yml down -v`.
   Portów naszego stacku nie przestawiamy (krok 4), więc nie ma czego przywracać. Kontrola:
   `grep -E '^(ASI_WEB_ADDR|DD_PORT)=' .env` i `ss -ltn | grep -E ':(18090|18080) '`. (Lekcja z LAB-4: panel
   przeniesiony na czas testu i nieprzywrócony „zniknął” z 8090 - stąd decyzja 23.)

**Firewall po drodze:** jeśli porty nie odpowiadają, bo po drodze stoi filtr (tailscale ACL, firewall VM), ASI
ma to pokazać jako „nie da się sprawdzić”, nie jako brak usług - patrz decyzja 20 i `LAB-T11`.
