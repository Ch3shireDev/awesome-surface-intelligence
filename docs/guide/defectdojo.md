# Integracja z DefectDojo

## Uruchomienie

DefectDojo **3.5.202** stoi w głównym `docker-compose.yml` (oficjalne obrazy: django, nginx,
postgres 18, valkey 9, compose wyrównany do upstreamu, patrz `DECISIONS.md`, decyzja 3):

```bash
make env && make up
```

UI: `http://localhost:8080`, login `admin`, hasło: `grep DD_ADMIN_PASSWORD .env`.

`asi` bierze token z `DD_TOKEN` albo `DD_API_KEY`, a gdy oba są puste, loguje się
`DD_ADMIN_USER`/`DD_ADMIN_PASSWORD` (`/api/v2/api-token-auth/`). Produkt i typ produktu biorą się
z `DD_PRODUCT` i `DD_PRODUCT_TYPE` w `.env`, engagement to `discovery`, a test `ASI discovery`.
Stary PoC (`make poc`) pisze do engagementu `nmap` w tym samym produkcie.

## Dlaczego nie surowy XML nmapa

Parser „Nmap Scan” w DefectDojo tworzy **jedno znalezisko na port** i dokleja do niego wszystkie
hosty jako endpointy (pierwszy test: 6 znalezisk na 11 hostów). Nie da się wtedy śledzić,
że *na tym konkretnym hoście* port się pojawił lub zniknął, ani nadać różnej ważności RDP
w LAN i RDP w internecie.

Dlatego `asi` pakuje wyniki jako **Generic Findings Import** (`findings_defectdojo.json`):

| pole | wartość |
|---|---|
| `title` | `Open port 443/tcp on 203.0.113.10 (http)` — stabilny między przebiegami |
| `unique_id_from_tool` | `asi:203.0.113.10:443/tcp` |
| `severity` | z oceny ciekawości: high→Medium, medium→Low, low→Info |
| `description` | tabela: usługa, produkt, wersja, TLS, asset, domeny, powód oceny |
| `component_name` / `_version` | produkt i wersja z `-sV` |
| `endpoints` | IP + każda domena wskazująca na to IP, z portem i schematem (`https`, `ssh`, `rdp`…) |
| `tags` | `asi`, `interest-high/medium/low`, `svc-<usługa>`, tagi z pliku celów |

Surowy XML nadal można wysłać natywnym parserem: `./asi upload -format nmap`. Trafia do stałego testu
`asi-nmap` przez reimport, więc DefectDojo śledzi też w nim nowe i zamknięte porty (z tą samą zasadą
`close_old` co niżej).

## Historia zmian po stronie DefectDojo

Wszystkie przebiegi trafiają do **jednego testu** `ASI discovery` (produkt `ASI PoC`, engagement
`discovery`) przez `/api/v2/reimport-scan/`:

- `-upload live` — po każdej paczce usług reimport z `close_old_findings=false`
  (znaleziska pojawiają się w DefectDojo w trakcie skanu),
- na końcu pełny reimport z `close_old_findings=true` — DefectDojo **zamyka jako mitigated**
  usługi, których już nie ma, **reaktywuje** te, które wróciły, i liczy deltę
  (`created / closed / reactivated / untouched`), widoczną w logu i panelu,
- **przebieg przerwany** (okno, Ctrl+C) nigdy nie zamyka znalezisk — niezeskanowane hosty
  zostałyby błędnie oznaczone jako naprawione.

`-upload end` wysyła tylko końcowy reimport, `-upload off` (domyślnie) — nic;
`./asi upload` wysyła istniejący przebieg ręcznie. Dla przebiegu przerwanego (`status: interrupted` w
`run.json`) `asi upload` sam ustawia `close_old=false`; wymusić można `-close-old=true`.

## Test `asi-changes`: zmiany w czasie (SEC-7)

Test `ASI discovery` pokazuje **stan** usług, a DefectDojo zamyka w nim usługę już po jednym
przebiegu, w którym jej nie było. ASI wie więcej (reconcile, [Historia i stany](/guide/history)): odróżnia
chwilowy brak od potwierdzonego zniknięcia, wykrywa hosty niestabilne i zmiany wersji. To trafia
do osobnego testu **`asi-changes`** (Generic Findings) w tym samym engagemencie, po każdym przebiegu
`asi scan` z uploadem i przy `asi upload` (wyłączenie: `-changes=false`). Raport jest też zapisywany
w `results/<przebieg>/findings_changes.json`.

| warunek w ASI | finding w DD | severity | zamyka się w DD, gdy |
|---|---|---|---|
| `missing`: nie odpowiada, poniżej progu | `Usługa 192.0.2.14:80/tcp (http): nie odpowiada (do potwierdzenia)` | Info | wróci albo przejdzie w `gone` |
| `gone`: zniknięcie potwierdzone po N brakach | `…: zniknęła (potwierdzone)` / `Host …: zniknął (potwierdzone)` | Info | wróci |
| `flapping`: wielokrotnie znika i wraca | `…: niestabilna (flapping)` | Low | przestanie migać |
| ostatnia zmiana usługi (`changed`) | `…: zmiana`, w opisie tabela przed → po, zmienione pola oznaczone `≠` | Low | dojdzie nowsza zmiana albo usługa zniknie |

Zasady:

- **Stan, nie log.** Finding jest w raporcie, dopóki warunek trwa, więc reimport z `close_old` zamyka
  go dokładnie wtedy, gdy warunek się kończy („closed” w DD = „problem minął”). Pełna historia zdarzeń
  zostaje w ASI (`asi changes`, panel).
- **Stabilny opis.** DD dopasowuje Generic findings po hashu tytułu i opisu, więc opis zawiera tylko
  wartości stałe, dopóki warunek trwa (bez liczników braków i „teraz”). Inaczej każdy przebieg
  zamykałby i otwierał finding od nowa (test `TestChangesStableWhileConditionLasts`).
- **Bez pola `service`** (reimport zamyka tylko findingi z tym samym `service`) i bez `protocol` w endpointach.
- **Przebieg częściowy** wysyła `asi-changes` z `close_old=false`: dodaje nowe warunki, niczego nie zamyka.
- **Tagi** `asi`, `asi-change`, `change-<warunek>` plus tagi użytkownika z ASI: edycja assetu w ASI trafia
  do DefectDojo.
- Wyniki httpx i nuclei idą dodatkowo natywnymi parserami DD (sekcja niżej).

Przykład z labu (`make demo` + 2 przebiegi bez zmian; `legacy` .14 wyłączony po przebiegu 1,
próg braków hosta = 3):

| przebieg | główny test `ASI discovery` | `asi-changes` |
|---|---|---|
| 1 | 9 usług | 0 warunków |
| 2 | `closed 3` (porty .14 zamknięte od razu), `created 2` | `created 2`: `Host 192.0.2.14: nie odpowiada (do potwierdzenia)`, `Usługa 192.0.2.15:80/tcp: zmiana` (nginx 1.27.5 → nowy serwer) |
| 3 | bez zmian | `untouched 2` (hash stabilny) |
| 4 | `closed 1` | `closed 1` (do potwierdzenia), `created 2`: `Host 192.0.2.14: zniknął (potwierdzone)` i brak „migającej” usługi .17, `untouched 1` |

DefectDojo zamienia tytuły na Title Case („Nie Odpowiada (Do Potwierdzenia)”); to kosmetyka po jego
stronie, dopasowanie przy reimporcie działa.

## Znane ograniczenia

- Pole `protocol` endpointu ma w DefectDojo max 10 znaków — nazwy usług nmapa są mapowane na
  schematy (`ms-wbt-server`→`rdp`), nieznane są pomijane (zostaje `host:port`).
  Wcześniej powodowało to HTTP 500 przy reimporcie.
- Reimport porównuje znaleziska po hashu (tytuł + opis). Zmiana wersji usługi zmienia opis →
  DefectDojo widzi to jako zamknięcie starego i utworzenie nowego znaleziska. Dla nas to
  pożądane („zmieniona usługa”), ale w DefectDojo nie jest oznaczone wprost jako „changed”.

## Natywne parsery: `asi-httpx` i `asi-nuclei` (SEC-7)

Surowe wyjście etapów `http` i `signatures` trafia do DD bez przepakowywania, każde do swojego stałego
testu przez reimport. DD śledzi wtedy nowe i zamknięte wyniki per narzędzie:

| etap | pliki w przebiegu | parser DD | test | DD dopasowuje po |
|---|---|---|---|---|
| `http` | `http/*.jsonl` (`httpx -json`) | `httpx Scan` | `asi-httpx` | tytuł (URL + kod HTTP) + endpoint |
| `signatures` | `signatures/*.jsonl` (`nuclei -jsonl`) | `Nuclei Scan` | `asi-nuclei` | nazwa sygnatury + cwe + severity + komponent |

Wysyłane na końcu `asi scan` z uploadem i przez `asi upload` (wyłączenie: `-native=false`).

**Główny test `ASI discovery`** zamyka wyniki (`close_old`) tylko po pełnym przebiegu, w którym etapy
discovery i services przeszły bez błędów paczek. Host, który przekroczył `--host-timeout` nmapa, liczy się
jako błąd: nmap zwraca go bez portów, a bez tej zasady DD zamknąłby wszystkie jego usługi (LAB-T7).

**Kiedy DD może zamknąć wynik (`close_old`):** tylko gdy cały przebieg jest pełny, etap naprawdę się
wykonał (`<etap>/timings.csv` istnieje) i żadna jego paczka nie skończyła się błędem. Etap pominięty (np.
brak httpx w obrazie), przerwany albo z błędami niczego w DD nie zamyka. Pusty raport z takiego etapu
nie jest wysyłany, bo inaczej zamknąłby wszystkie wyniki webowe. Pełny etap bez wyników wysyła pusty
raport z `close_old`: sygnatura, która przestała pasować, zostaje zamknięta.

Parser httpx w DD przenosi URL, kod, tytuł strony, serwer, technologie, typ treści i przekierowania.
Nagłówki, cookies i certyfikat TLS zostają w ASI (obserwacje `http`, zaszyfrowane, panel i `asi assets`).


## Jedna instancja DD na wiele środowisk i maszyn (decyzja 22)

Testy robimy na różnych środowiskach (lab organizatorów, nasz lab `docker/lab`, własna infrastruktura z
`targets/targets.csv`), ale **DefectDojo jest jednym końcowym punktem, do którego pchamy wyniki**. Jedna baza =
jedno źródło prawdy: diff i historia zmian (`asi-changes`, `close_old`, dedupe po hashu) działają tylko
w obrębie jednej instancji, więc rozbicie na DD per VM gubi najciekawszą rzecz w projekcie.

| rola maszyny | co stoi | `DD_URL` |
|---|---|---|
| **kanoniczny** (dziś fatusia-1) | pełny stack: DD `:18080`, `asi-db`, `asi server` | — |
| pozostałe VM (fatusia-2, blackarch…) | **tylko skaner + lab**: `docker compose up -d nmap-scanner asi-db` | `http://100.113.45.50:18080` |

### Konfiguracja kanonicznego (jednorazowo)

```bash
# fatusia-1:~/asi/.env - DD ma być dostępny z tailnetu, nie tylko z localhost
DD_PORT=18080                                          # 8080/8090 zostają labom (WordPress, DVWA)
DD_SITE_URL=http://100.113.45.50:18080
DD_CSRF_TRUSTED_ORIGINS=http://localhost:18080,http://127.0.0.1:18080,http://100.113.45.50:18080
```

Bez wpisu z adresem tailnetu przeglądarka dostanie błąd CSRF przy logowaniu. Po zmianie wystarczy
`docker compose up -d nginx uwsgi` (nie `make nuke`).

### Konfiguracja maszyny ze skanerem

```bash
# .env na VM, która nie stawia DD
DD_URL=http://100.113.45.50:18080
DD_API_KEY=<token z UI admina na kanonicznym>            # osobny token per maszyna (audyt)
DD_PRODUCT_TYPE=HackNation
DD_PRODUCT="ASI lab-org"                                # produkt = ŚRODOWISKO, nie maszyna
DD_ENGAGEMENT="lab-org@f1"                              # równoległy skan tego samego środowiska = inny engagement
```

`DD_URL` ma pierwszeństwo przed `DD_PORT` (`cmd/asi/main.go`), więc nie trzeba ruszać portu lokalnego.

### Zasady

- **Produkt = środowisko** (`ASI lab-org`, `ASI lab`, `ASI infra`), a nie maszyna: ten sam asset ma trafiać do
  tego samego produktu niezależnie od tego, kto skanował.
- **Ten sam produkt z dwóch maszyn równolegle = duplikaty** w jednym teście. Albo jeden skan naraz na środowisko,
  albo różne engagementy (`lab-org@f1`, `lab-org@ba`) - wtedy diff działa w obrębie engagementu.
- **`make nuke` wymaga uzgodnienia**: dane odtwarza `asi upload` z `results/`, ale historia reimportów i diff
  w DD przepadają.
- **`DD_VERSION` podnosimy tylko na kanonicznym** i tylko gdy nikt nie robi przebiegu - inaczej migracje rozjadą
  się w środku testu.
- **DD padnie w trakcie testu?** Każdy przebieg zostawia `results/<run>` + `run.json`, więc po podniesieniu DD
  robimy `asi upload -out results/<run>` i nic nie ginie. DD jest celem eksportu, nie magazynem prawdy.
