# Bezpieczeństwo skanowania

Kryterium oceny (15%): *bezpieczeństwo działania, kontrola intensywności skanowania*.
Zasada: skaner ma **wykrywać obecność**, nie eksploatować, i nigdy nie wychodzić poza
zatwierdzony inwentarz. Twarde granice ustawia operator wdrożenia w `.env`. Ani flaga CLI,
ani użytkownik panelu nie może ich podnieść.

Polityka jest w `internal/safety` (SEC-8) i działa w **dwóch miejscach**:

1. **przy budowie planu** (`asi plan`, `asi scan`, `asi scan -resume`): adresy spoza zakresu i
   wykluczone trafiają do `plan.json` → `skipped` z powodem (`policy: excluded (…)`),
2. **w workerze, tuż przed startem każdego procesu nmap** (obrona w głąb): ponowny filtr IP paczki
   i walidacja całej linii poleceń nmapa. Wznowiony przebieg, ręcznie poprawiony plan czy błąd w
   plannerze nie dotrą do wykluczonego adresu. Naruszenie trafia do logu jako `POLICY …`, a paczka
   kończy się błędem `policy: …` i nie wysyła żadnego pakietu.

Każdy przebieg zapisuje reguły, w jakich działał: linia `policy: …` w logu i pole `policy` w `run.json`
oraz w parametrach przebiegu w `asi-db`.

## Zakres i wykluczenia

| mechanizm | domyślnie | efekt |
|---|---|---|
| `enabled=false` w pliku celów | — | cel zostaje w inwentarzu, nigdy nie jest skanowany |
| `-only-inventory` | **włączone** | domena nie dodaje nowych IP, tylko podpisuje IP już zatwierdzone |
| `-skip-cdn` | **włączone** | IP Cloudflare nie są skanowane portowo (to nie nasza infrastruktura) |
| limit CIDR | 65 536 adresów | literówka `/8` zamiast `/24` nie odpali skanu 16 mln adresów |
| `ASI_SCOPE` / `targets/scope.txt` | puste = bez dodatkowego ograniczenia | **allowlista**: skanowane są tylko adresy z tych sieci, nawet jeśli plik celów zawiera więcej |
| `ASI_EXCLUDE` / `targets/exclude.txt` | puste | **nigdy nie skanowane** (wygrywa z zakresem i z plikiem celów) |
| wykluczenia wbudowane | zawsze | `0.0.0.0/8`, `169.254.0.0/16` (link-local, **metadane chmury 169.254.169.254**), `224.0.0.0/4` (multicast), `240.0.0.0/4` (w tym broadcast), IPv6 `::/128`, `fe80::/10`, `ff00::/8` |

Pliki `targets/scope.txt` i `targets/exclude.txt` mają jeden adres lub CIDR w linii, komentarze po `#`.
Wzory: `targets/scope.example.txt`, `targets/exclude.example.txt`. Pliki z prawdziwymi adresami są w `.gitignore`.

```bash
# przykład: lab + localhost, bez drukarki i bez bramy
cat > targets/scope.txt <<'EOF'
192.0.2.0/24
127.0.0.1
EOF
printf '192.0.2.1   # brama labu\n' > targets/exclude.txt
./asi plan -targets targets/lab.csv      # wykluczone widać w sekcji "skipped"
```

## Intensywność

| mechanizm | domyślnie | gdzie |
|---|---|---|
| globalny limit pakietów `-rate` | 300 pps łącznie, dzielone na procesy (`--max-rate` per nmap) | flaga |
| **twardy limit `ASI_MAX_RATE`** | **1000 pps** | `.env`: `-rate` i GUI (max 5000) są obniżane do tej wartości, z wpisem w logu |
| **twardy limit `ASI_MAX_PARALLEL`** | **32 procesy** | `.env`; równoległość nie przekracza też tempa (≥ 1 pps na proces) |
| `--max-rate` w każdej paczce | wymagane | worker odrzuca nmapa bez `--max-rate` albo z wyższym niż przydział na proces |
| `--min-rate` | **zabronione** | omijałoby limit tempa |
| timing | maks. `-T4` | `-T5` (insane) odrzucone |
| `--max-retries` | 1 (discovery) / 2 (usługi), maks. 10 | |
| `--host-timeout` | 10 min na host | |
| `-chunk-timeout` | 20 min na paczkę | |
| `-window` | twarde okno czasowe całego przebiegu | |
| `-sV --version-light` | lekkie sondy wersji (intensywność 2 zamiast 7) | |
| `--allports` | **zabronione** | `-sV` domyślnie omija porty drukarek 9100–9107 (drukują sondy); tak zostaje |

## Porty

`ASI_ALLOWED_PORTS` (np. `1-1024,3389,8000-8999`, puste = wszystkie TCP) to **lista dozwolonych portów TCP**.
Worker przycina do niej każdą linię nmapa:

- `-p 22,80,3389` przy allowliście `1-1024` daje `-p 22,80`. Jeśli nic nie zostanie, paczka jest odrzucona,
- bez `-p` (np. `--top-ports 1000`) dochodzi `-p <allowlista>`. nmap wybiera wtedy 1000 najpopularniejszych
  portów **spośród dozwolonych** (sprawdzone na nmap 7.95/7.99),
- `-F` zamieniane na `--top-ports 100` (żeby dało się je połączyć z `-p`),
- porty sond discovery (`-PS…`, `-PA…`) też są przycinane, więc nawet ping nie dotyka portów spoza listy.

## Skaner nie skanuje samego siebie (LAB-T2)

Gdy celem jest **host skanera**, czyli loopback (`127.0.0.0/8`, `::1`), dowolny adres lokalnego interfejsu
(kontener skanera ma `network_mode: host`, więc widzi interfejsy VM) albo adres z `ASI_SELF_IPS`, skaner
pomija **porty naszego stacku**. Bez tego przebieg na `127.0.0.1` (np. lab organizatorów) raportowałby własny
panel, DefectDojo i asi-db jako „znaleziska” i wysyłał do nich sondy `-sV`.

| porty stacku (domyślnie z `.env`) | |
|---|---|
| `DD_PORT` | DefectDojo (8080) |
| port z `ASI_WEB_ADDR`, `ASI_LIVE_ADDR` | panel ASI i postęp na żywo (18090, 8091) |
| `ASI_DB_PORT` | asi-db (5433) |
| port z `-ui` bieżącego skanu (jeśli podany) | dodatkowa strona postępu (tylko dev) |

Przeniesienie portów w `.env` (np. `DD_PORT=18080` przed labem `modern`) automatycznie przenosi wykluczenie,
więc WordPress labu na 8080 jest wtedy normalnie skanowany. `ASI_SELF_PORTS` podaje listę ręcznie,
`ASI_SELF_PORTS=off` wyłącza mechanizm.

Jak to działa: nmap nie ma wykluczeń portów per host, więc worker wydziela adresy hosta skanera do **osobnej
paczki** i tylko jej nmap dostaje `--exclude-ports <porty stacku>`. Inne hosty w tym samym przebiegu są skanowane
bez zmian. `-p` jest przycinane (same porty stacku → paczka odrzucona z komunikatem), `--top-ports N` wybiera
N portów spośród pozostałych (sprawdzone na nmap 7.99), a z sond discovery `-PS/-PA` znikają porty stacku.
Skan potwierdzający pomija je tak samo. W logu przebiegu jest linia
`… target(s) are the scanner host (…) - own stack ports … left out`, a w `run.json` pole `policy.self_ports`.

Sprawdzone na blackarch z działającym stackiem: `-p 22,5433,8080,8090,8091` na `127.0.0.1` daje nmapowi
`-p 22 --exclude-ports 5433,8080,8090-8091,8094-8095` i tylko port 22 w wynikach. Z `ASI_SELF_PORTS=off`
widać też 5433, 8080 i 8090.

## Dozwolone flagi nmapa

Argumenty profili (`-nmap`, `-discovery-args`, port z formularza GUI, skan potwierdzający) przechodzą
przez **allowlistę flag**. Nieznana flaga oznacza błąd przed startem skanu. Najważniejsze reguły:

| reguła | dlaczego |
|---|---|
| **żadnych celów w argumentach** (`-nmap "-sT 8.8.8.8"` → błąd) | cele tylko z planu przez `-iL`; dokładnie jedno `-iL` = plik paczki |
| `-iR`, `--resume`, `-iL` w profilu | losowe/obce listy celów |
| `-D`, `-S`, `-e`, `--spoof-mac`, `-f`, `--mtu`, `--data*`, `--badsum`, `-g`, `--ttl`, `--proxies`, `-sI`, `-b` | spoofing i omijanie detekcji: skaner ma być widoczny i rozliczalny |
| `-A`, `-sC`, `--script` poza listą | skrypty NSE tylko detekcyjne: `version`, `banner`, `http-title`, `http-headers`, `http-server-header`, `http-favicon`, `http-generator`, `http-robots.txt`, `ssl-cert`, `ssh-hostkey`. **Kategorie (`safe`, `discovery`, `default`) są zabronione**: to sumy zbiorów, `discovery` zawiera brute-force (`dns-brute`) i skrypty broadcast w całym LAN-ie |
| `--script-args newtargets` | skrypt nie może dopisywać celów |
| `-oN`, `-oG`, `-oA`, `-oS`, `--datadir`, `--servicedb`, `--script-updatedb` | zapis/odczyt plików poza katalogiem przebiegu; wynik tylko `-oX` od runnera |
| `-sA -sW -sM -sN -sF -sX -sO -sY -sZ --scanflags`, `--traceroute` | niepotrzebne do discovery |

## Profile: z surowymi gniazdami i bez roota

| | `ASI_SCAN_PROFILE=raw` (domyślny w compose) | `ASI_SCAN_PROFILE=unprivileged` |
|---|---|---|
| uprawnienia | kontener z `NET_RAW` (+`NET_ADMIN`) | `docker-compose.unprivileged.yml`: `cap_drop NET_RAW, NET_ADMIN` |
| skan portów | `-sT` (domyślnie) albo `-sS` (SYN, szybszy i cichszy dla aplikacji) | tylko `-sT` (connect) |
| discovery | TCP SYN ping na porty `-PS`, ICMP echo (`-PE`), ARP w LAN | „ping” przez connect na porty `-PS`, bez ICMP |
| nmap dostaje | — | `--unprivileged`; `-sS`, `-sU`, `-O`, `-PE/-PP/-PM` odrzucone z komunikatem |

```bash
# .env: compose czyta COMPOSE_FILE (SEC-6 dodaje tam nakladke crypto) - dopisz nakladke profilu
COMPOSE_FILE=docker-compose.yml:docker-compose.crypto.yml:docker-compose.unprivileged.yml
docker compose up -d nmap-scanner
```

Oba profile sprawdzone w obrazie `nmap-scanner` (arm64, 21.11): `raw` → `scaninfo type="syn"`,
`unprivileged` → `scaninfo type="connect"`. Bez `NET_RAW` nmap z `-sS` kończy się błędem
`Couldn't open a raw socket`, dlatego profil wyłapuje to przed startem.

Domyślne argumenty (`-sT`, discovery `-PS`) działają w obu profilach. Profil `raw` zostaje domyślny,
bo daje ICMP i ARP do wykrywania hostów w sieciach, które tną TCP (wymaganie 3 z PDF).

## UDP: decyzja

Domyślnie **wyłączone** (`-sU` odrzucane). Skan UDP jest bardzo wolny (limit ICMP unreachable
po stronie celu) i daje dużo fałszywych `open|filtered`. `ASI_ALLOW_UDP=1` włącza go **tylko na portach
`ASI_UDP_PORTS`** (domyślnie `53,123,161`: DNS, NTP, SNMP, czyli usługi, które w ASM najczęściej są
nieświadomie wystawione i bywają wzmacniaczami DDoS). Wymaga profilu `raw`.

```bash
ASI_ALLOW_UDP=1 ./asi scan -nmap "-sS -sU -sV --version-light -Pn -p T:22,80,443,U:53,123,161"
# porty U: spoza ASI_UDP_PORTS są wycinane; bez -p: --top-ports 1000 -p T:<allowlista>,U:53,123,161
```

## Konfiguracja (`.env`)

| zmienna | domyślnie | co |
|---|---|---|
| `ASI_SCOPE` | — | allowlista sieci, po przecinku |
| `ASI_SCOPE_FILE` | `targets/scope.txt` | to samo z pliku (brak pliku = brak ograniczenia) |
| `ASI_EXCLUDE` | — | wykluczenia, po przecinku |
| `ASI_EXCLUDE_FILE` | `targets/exclude.txt` | wykluczenia z pliku |
| `ASI_ALLOWED_PORTS` | wszystkie TCP | lista dozwolonych portów TCP |
| `ASI_MAX_RATE` | `1000` | twardy limit pps całego przebiegu |
| `ASI_MAX_PARALLEL` | `32` | twardy limit procesów nmap |
| `ASI_SCAN_PROFILE` | `raw` | `raw` albo `unprivileged` |
| `ASI_ALLOW_UDP` | wyłączone | `1` włącza `-sU` |
| `ASI_UDP_PORTS` | `53,123,161` | dozwolone porty UDP |
| `ASI_SELF_PORTS` | z `.env` (patrz wyżej) | porty naszego stacku pomijane na hoście skanera; `off` wyłącza |
| `ASI_SELF_IPS` | — | dodatkowe adresy hosta skanera (np. publiczny IP za NAT) |

Błędna wartość (np. `ASI_SCAN_PROFILE=root`, zły CIDR) zatrzymuje `asi scan` przed wysłaniem
jakiegokolwiek pakietu.

## Jak pokazać w demo

```bash
export ASI_EXCLUDE=127.0.0.2 ASI_MAX_RATE=200 ASI_ALLOWED_PORTS=1-1024
printf 'target\n127.0.0.1\n127.0.0.2\n169.254.169.254\n' > targets/policy-demo.csv
./asi plan -targets targets/policy-demo.csv                     # 2 adresy w "skipped: policy: excluded"
./asi scan -targets targets/policy-demo.csv -nmap "-sT -Pn 8.8.8.8"   # błąd: cel przemycony w argumentach
./asi scan -targets targets/policy-demo.csv -rate 5000 \
  -nmap "-sT -sV --version-light -Pn -p 22,80,3389,8090 --open"   # log: rate obniżone do 200; -p 22,80
head -1 results/*/services/chunk_0000.log                       # faktyczna linia nmapa
```

## Dane

- Wyniki leżą lokalnie w `results/` i w `asi-db`, który jest szyfrowany w spoczynku (`pg_tde`) + pola `_enc` AES-256-GCM:
  [Szyfrowanie](/guide/encryption).
- `.env` i `.dd_token` mają prawa `600` i są w `.gitignore`.
- Panel web słucha tylko na `127.0.0.1`.
