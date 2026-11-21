# Lab organizatorów (przykładowe środowisko testowe)

Przykładowe środowisko od organizatorów (CBI AGH), udostępnione na Discordzie 21.11: to są materiały od organizatorów z zadania SEC-2. Leży **poza repo**
(`~/lab` na VM fatusia-hacknation-2): to materiał organizatorów, z domyślnymi hasłami do usług. Tutaj jest
opis, analiza względem ASI i plan testów (zadania `LAB-*` w [TASKS](../TASKS.md)).

## Co zawiera

Cztery niezależne stacki docker compose. Organizatorzy zaznaczają: **uruchamiać jeden naraz**. Wszystkie
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

| port | lab | ASI |
|---|---|---|
| `8080` | `modern`: WordPress | DefectDojo (`DD_PORT`) |
| `8090` | `vulnerable`: DVWA | panel ASI (`ASI_WEB_ADDR`) |

Przed testem `modern` / `vulnerable` przenieść nasze porty w `.env` (np. `DD_PORT=18080`,
`DD_SITE_URL` i `DD_CSRF_TRUSTED_ORIGINS` na 18080, `ASI_WEB_ADDR=127.0.0.1:18090`) i `make up`.

### 3. Skanujemy sami siebie

Cel to `127.0.0.1` (albo IP VM), na którym działa też ASI i DefectDojo. **Załatwione przez LAB-T2:** na hoście
skanera porty naszego stacku (z `.env`: `DD_PORT`, `ASI_WEB_ADDR`, `ASI_LIVE_ADDR`, `ASI_DB_PORT` + 8094, 8095)
są pomijane automatycznie, a reszta portów jest skanowana normalnie. Ręczna lista portów bez naszych nie jest
już potrzebna. Po przeniesieniu portów w `.env` (pkt 2) wykluczenie idzie za nimi, więc WordPress na 8080
i DVWA na 8090 są skanowane. Szczegóły: [Bezpieczeństwo](safety.md#skaner-nie-skanuje-samego-siebie-lab-t2).

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

**Rozwiązane (LAB-T4):** adapter `httpx` uruchamia `-rt` i zapisuje metrykę `response_time_ms` w obserwacji `http` (celowo poza `fp_hash`, więc zmiana opóźnienia nie tworzy fałszywych zdarzeń `changed`). Panel web pokazuje kolumnę `HTTP ms`, filtr „tylko wolne HTTP” oraz ostrzeżenie w szufladzie assetu powyżej progu `ASI_HTTP_SLOW_MS` (domyślnie `500` ms). Metryka trafia także do eksportu CSV (`http_ms`).

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

Zostaje: LAB-T5 (diff „gone/new” vs baza „missing/reappeared”), LAB-T6 (instalator Gitea), szum usług samej
VM (SSH, Syncthing, procesy lokalne). To prawdziwe usługi hosta, w labie jury wykluczyć je zakresem/portami.

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

Oczekiwane wyniki i kryteria zaliczenia: zadania `LAB-1` … `LAB-6` w [TASKS](../TASKS.md).
