# Ścieżka testowania (dla jury)

Jedna ścieżka przez cały system, w kolejności, w jakiej najłatwiej go sprawdzić: **start → lab i dwa przebiegi →
fingerprint, sygnatury i zmiany → edycja znalezisk → import → role → eksport → DefectDojo → szyfrowanie →
bezpieczeństwo i skala**. Każdy krok ma polecenie albo kliknięcie, oczekiwany wynik i wymaganie z treści zadania
(sekcje 2, 6 i 8 PDF CBI AGH), które sprawdza. Całość zajmuje ok. 30 minut, z czego kilka minut to pierwszy `make up`.

Wymagania hosta: Linux z dockerem i pluginem compose, `make`, `openssl`, ok. 4 GB RAM wolne dla DefectDojo.
Wszystko inne (nmap, httpx, nuclei, PostgreSQL, DefectDojo) działa w kontenerach.

## Mapa 12 punktów walidacji jury (sekcja 6 PDF)

| # | punkt walidacji jury (sekcja 6 PDF) | kryterium oceny (sekcja 8) | krok poniżej |
|---|---|---|---|
| 1 | Poprawność wykrycia aktywnych hostów | Discovery i usługi (30%) | [1. Lab i dwa przebiegi skanu](#krok-1) |
| 2 | Poprawność identyfikacji usług | Discovery i usługi (30%) | [1. Lab i dwa przebiegi skanu](#krok-1) |
| 3 | Trafność fingerprintingu HTTP/HTTPS | Fingerprinting i sygnatury (10%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 4 | Umiejętność wykrycia CMS-ów lub technologii | Fingerprinting i sygnatury (10%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 5 | Wykrywanie ciekawych nagłówków i ciasteczek | Fingerprinting i sygnatury (10%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 6 | Działanie customowych sygnatur | Fingerprinting i sygnatury (10%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 7 | Porównanie wyników między skanami | Zmiany w czasie i raportowanie (15%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 8 | Obsługa hostów niestabilnych lub zmieniających odpowiedź | Zmiany w czasie i raportowanie (15%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 9 | Bezpieczeństwo i ostrożność działania skanera | Bezpieczeństwo i dashboard (15%) | [9. Bezpieczeństwo i skala](#krok-9) |
| 10 | Czytelność dashboardu lub raportu | Bezpieczeństwo i dashboard (15%) | [2. Fingerprint, sygnatury i zmiany](#krok-2) |
| 11 | Import oraz eksport danych | Jakość, import/eksport, DefectDojo (20%) | [4. Import](#krok-4) · [6. Eksport](#krok-6) |
| 12 | Rozgraniczenie funkcjonalności między role | Role i zabezpieczenie danych (10%) | [5. Role (RBAC), konta i audyt](#krok-5) |

Sekcja 6 i wymagania 14–16 obejmują ponadto [3. Edycję znalezisk trwałą między skanami](#krok-3),
[7. Integrację z DefectDojo](#krok-7) oraz [8. Szyfrowanie w spoczynku](#krok-8).

## 0. Start od zera {#krok-0}

```bash
git clone https://github.com/Ch3shireDev/awesome-surface-intelligence.git asi && cd asi
make env      # .env: wygenerowane hasła, sekrety DefectDojo, COMPOSE_FILE (TDE), ASI_ENCRYPTION_KEYS
make up       # DefectDojo :8080, asi-db (szyfrowana, pg_tde), skaner + panel ASI :18090
grep -E '^(ASI_ADMIN_PASSWORD|DD_ADMIN_PASSWORD)=' .env    # hasła do obu paneli (login: admin)
```

| oczekiwany wynik | |
|---|---|
| `make up` kończy się bez błędu, `docker compose ps` pokazuje kontenery `asi-*` jako `running`/`healthy` | |
| http://127.0.0.1:18090: logowanie do panelu ASI (`admin` + `ASI_ADMIN_PASSWORD`) | |
| http://127.0.0.1:8080: logowanie do DefectDojo (`admin` + `DD_ADMIN_PASSWORD`) | DefectDojo startuje dłużej (migracje), po 1–3 min |

Panel słucha tylko na `127.0.0.1`. Test z innej maszyny: `ASI_WEB_ADDR=0.0.0.0:18090` w `.env` i ponownie `make up`.

**Zarządzanie kontami z CLI (`asi user`)** — konto `admin` tworzy się raz przy pustej bazie; odzyskanie hasła
lub dodanie konta testowego z terminala:

```bash
make asi ARGS='user list'
make asi ARGS='user add -user jury -password HasloJury2026 -role viewer'
make asi ARGS='user passwd -user admin -password NoweHasloAdmin1'
```

## 1. Lab i dwa przebiegi skanu {#krok-1}

Pokrywa punkty walidacji **1** i **2** (30% oceny). Przed skanem można obejrzeć plan (co będzie skanowane, a co
pominięte i dlaczego):

```bash
make asi ARGS='plan -targets targets/lab.csv'
make demo     # lab 192.0.2.0/24 -> przebieg 1 -> zmiany w labie -> przebieg 2 -> porównanie + eksport do DD
```

Lab to 8 kontenerów w sieci dokumentacyjnej `192.0.2.0/24` (RFC 5737, nieroutowalna, więc pakiety nie
wychodzą poza VM; zakres `targets/lab.csv` obejmuje 12 adresów — 4 puste adresy `.8`, `.9`, `.18`, `.19` i
nieuruchomiony `.16` w przebiegu 1 pozostają nieaktywne). Między przebiegami `make demo` sam zmienia lab:

| zmiana w labie | oczekiwany wynik po przebiegu 2 | wymaganie |
|---|---|---|
| host `legacy` (.14) znika | jego usługi: *brak odpowiedzi (do potwierdzenia)*, po kolejnych brakach *zniknął* | pkt 8–9, zmiany w czasie |
| `app` (.15) zmienia serwer | *zmiana usługi*: przed → po (`nginx 1.27.5` → `BusyBox httpd`) | pkt 9 |
| dochodzi `jenkins` (.16) | nowe usługi (`8080/tcp`), Jenkins 2.401.1, trafienia sygnatur | pkt 9, 6, 10 |
| `cache` (.13) wystawia Redis `6379` | wykryty mimo że 6379 jest poza domyślnym top 1000 nmapa (`RiskyPorts`) + sygnatura `asi-redis-noauth` | pkt 4, 10 |
| usługa `.17` (`flaky`) włącza się i wyłącza co 30 s | *niestabilna (flapping)* po kilku przebiegach | hosty niestabilne |

W terminalu na końcu jest porównanie z przebiegiem 1. Trwa to ok. 2 minut.

**To samo z panelu** (zamiast `make demo`): `make lab-up`, potem **Cele → Import z pliku** z plikiem
[lab.csv](/cele/lab.csv) (albo [lab.json](/cele/lab.json)), potem **Skany → Nowy skan** na tym zbiorze.
Postęp widać na żywo: etapy, paczki nmapa, czas.

### Lab organizatorów (`custom-network` / scenariusz quickstart)

Domyślny profil portów `-ports auto` (w CLI i GUI, LAB-T1) dla małych zbiorów celów (≤ 16 hostów) automatycznie
używa pełnego zakresu TCP (`1-65535`, zawsze przycinanego do `ASI_ALLOWED_PORTS`, jeśli ustawione). Dzięki temu
wykrywa niestandardowe porty labu organizatorów (`8787`, `15432`, `5673`, `15673`, `2223`, `3001`, `8888`), a
własne porty ASI i DefectDojo na hoście skanera są automatycznie pomijane (LAB-T2):

```bash
# w katalogu labu organizatorów (np. ~/lab):
./quickstart.sh up

# w katalogu ASI: przygotuj cel i uruchom przebieg 1 (profil -ports auto)
printf 'target,asset,owner,tags,enabled,note\n127.0.0.1,lab-org,secops,lab-org,true,lab organizatorow\n' \
  > targets/lab-org.csv
make asi ARGS='scan -targets targets/lab-org.csv -ports auto -upload end'

# zatrzymanie usługi 8787 -> przebieg 2 -> przywrócenie -> przebieg 3
./quickstart.sh change
make asi ARGS='scan -targets targets/lab-org.csv -ports auto -upload end'
./quickstart.sh up
make asi ARGS='scan -targets targets/lab-org.csv -ports auto -upload end'
```

> [!NOTE]
> Stack `modern` (WordPress `:8080`) koliduje z domyślnym portem DefectDojo (`8080`). Przed jego uruchomieniem
> przenieś `DD_PORT` w `.env` i wykonaj `make up` ([Lab organizatorów](/guide/lab-organizers#_2-konflikty-portow-z-naszym-stackiem)).
> Panel ASI ma port 18090, więc `vulnerable` (DVWA `:8090`) nie wymaga zmian.

## 2. Przegląd wyników, fingerprint HTTP/HTTPS, sygnatury i zmiany {#krok-2}

Pokrywa punkty walidacji **3, 4, 5, 6, 7, 8, 10** (10% fingerprinting + 15% zmiany + 15% dashboard).

| gdzie | co sprawdzić | wymaganie |
|---|---|---|
| **Dashboard** | kafelki (aktywne hosty, usługi, nowe, braki, zniknięte, niestabilne), *Najważniejsze znaleziska* z oceną 0–100 i powodem, *Niestabilne i zniknięte*, *Grupy podobnych usług*, *Wzorce pory dnia* (`hours_seen`), wykres *Zmiany w czasie* | pkt 15, ocena, grupy, pora dnia |
| **Assety** | filtr po stanie (`new`, `active`, `missing`, `gone`), **tylko flapping**, kolumna **HTTP ms** i filtr **tylko wolne HTTP** (próg `ASI_HTTP_SLOW_MS=300`, LAB-T4/LAB-T9); szuflada portu: sekcja **HTTP i sygnatury** (tytuł, kod, czas odpowiedzi, nagłówki, ciasteczka, przekierowania, certyfikat TLS, technologie, favicon mmh3), historia zdarzeń, pasek *Godziny, w których odpowiadał (UTC)* `0–23` | pkt 4–9 |
| **Skany → Porównanie dwóch przebiegów** | usługi nowe, zniknięte i zmienione (przed → po) między dowolnymi dwoma przebiegami; przycisk **zmiany →** przy przebiegu | pkt 8–9 |
| terminal | `make asi ARGS='changes'`, `make asi ARGS='changes -asset 192.0.2.15/tcp/80'`, `make asi ARGS='diff -db'`, `make asi ARGS='diff -db -json'`, `make asi ARGS='assets -state missing'`, `make asi ARGS='assets -flapping'` | pkt 8–9 |

Kluczowe artefakty labu w szufladzie assetu (**Assety**):
- `192.0.2.10/tcp/443` (`web-prod`): `Server: nginx/1.27.5`, `X-Powered-By: PHP/7.4.33` (`asi-php-outdated`), ciasteczko
  `PHPSESSID` (sama nazwa, bez wartości), przekierowanie `/login`, certyfikat TLS `intranet.lab.example` (`self-signed`),
  stopka `LabPortal 1.8.2` (`asi-footer-version`),
- `192.0.2.11/tcp/80` (`wordpress`): WordPress 6.4.2 (`asi-html-generator`, `asi-cms-wordpress`, Wappalyzer), ciasteczko
  `wordpress_test_cookie`, nagłówek `Link`,
- `192.0.2.12/tcp/8080` (`staging-admin`): staging (`X-Environment: staging`, tytuł `[STAGING]`, cookie
  `staging_session` → `asi-staging-environment`), panel `/admin/` (`asi-admin-panel`), `/version` (`2.3.1-rc1`),
- `192.0.2.13/tcp/6379` (`cache`): Redis bez hasła (`asi-redis-noauth`, high — tylko bezpieczny `PING`),
- `192.0.2.16/tcp/8080` (`jenkins`, po przebiegu 2): `X-Jenkins: 2.401.1`, `JSESSIONID`, `asi-jenkins`.

Pełna lista artefaktów: [Lab testowy](/guide/lab#hosty-i-co-powinien-wykryc-skaner).

### Sygnatury IoT (SEC-10), usługi labu (LAB-T3) i własna sygnatura

Etap `signatures` uruchamia wyłącznie lokalne szablony z `signatures/` (**33 bezpieczne szablony**: 14 bazowych,
**9 IoT** SEC-10 oraz **10 pod usługi i lab organizatorów** LAB-T3: phpMyAdmin, Adminer, DVWA, Gitea, RabbitMQ
Management, Nginx Proxy Manager, Traefik, Toxiproxy, httpbin, WordPress < 6.0).

**Szybki test sygnatur IoT bez fizycznych urządzeń (`scripts/iot-stub.py`):**

```bash
python3 scripts/iot-stub.py &
STUB_PID=$!
sleep 1
docker compose exec -T nmap-scanner nuclei -t signatures/http -u http://127.0.0.1:18080 -nc -duc -ni
kill "$STUB_PID"
```

Oczekiwane: dokładnie **6 trafień pozytywnych** (`asi-iot-camera-hikvision`, `asi-iot-camera-generic`,
`asi-iot-embedded-server`, `asi-iot-router-openwrt`, `asi-iot-printer`, `asi-iot-upnp-description`) i **0 fałszywych
trafień** dla Dahua, MikroTik i NAS.

**Dodanie i walidacja własnej sygnatury** (katalog `./signatures` jest podmontowany do kontenera, działa od
następnego skanu bez przebudowy):

```bash
cat > signatures/http/asi-jury-demo.yaml <<'EOF'
id: asi-jury-demo
info:
  name: Jury Demo Header
  author: jury
  severity: low
  description: Wykrycie nagłówka X-Environment w teście jury.
  tags: asi,demo
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "X-Environment: staging"
EOF
docker compose exec -T nmap-scanner nuclei -t signatures/http/asi-jury-demo.yaml -validate
docker compose exec -T nmap-scanner nuclei -t signatures/http/asi-jury-demo.yaml -u http://192.0.2.12:8080 -nc -duc -ni
# (na hoście z Go) lint bezpieczeństwa wszystkich sygnatur (tylko GET/detekcja, bez haseł, interactsh i zakazanych tagów):
go test -v ./internal/scanner/nuclei -run TestTemplatesAreSafe
rm -f signatures/http/asi-jury-demo.yaml
```

### Potwierdzenie `gone` i `flapping` (hosty niestabilne)

Domyślne progi reconcile: host przechodzi w `gone` po **3** kolejnych brakach (`-miss-threshold 3`), port po **2**
(`-port-miss-threshold 2`), a flaga `flapping` zapala się przy **≥ 3 przejściach** `active ↔ missing` w ostatnich 10
przebiegach. Po `make demo` uruchom jeszcze 2–3 przebiegi w odstępie ~35 s:

```bash
for i in 1 2 3; do
  docker compose exec -T nmap-scanner asi scan -targets targets/lab.csv -out results/lab \
    -upload end -product "ASI lab" -engagement demo \
    -nmap "-sT -sV --version-light -Pn -p 22,23,80,443,6379,8000,8080 -T4 --max-retries 2 --open"
  sleep 35
done
make asi ARGS='assets -flapping'
```

`192.0.2.14` przejdzie z `missing` w `gone`, a `192.0.2.17/tcp/80` dostanie flagę `flapping` (widoczną także przez
filtr **tylko flapping** w zakładce **Assety**).

## 3. Edycja znalezisk trwała między skanami {#krok-3}

1. **Assety** → kliknij dowolny port (np. WordPress na `192.0.2.11/tcp/80` lub `192.0.2.10/tcp/443`).
2. W szufladzie w sekcji **Twoje dane (zachowane przy kolejnych skanach)** dodaj tag i notatkę, a w sekcji
   **Ocena analityka** ustaw **Status wyniku** (np. *zaakceptowane ryzyko* lub *fałszywy alarm*), **Ocenę** i
   **Uzasadnienie**. Kliknij **Zapisz**.
   Alternatywnie z CLI (tagi i notatka):
   ```bash
   make asi ARGS='asset edit 192.0.2.10/tcp/443 -tags lab,zweryfikowane -note "Potwierdzone przez zespol"'
   ```
3. Uruchom kolejny przebieg: **Skany → Nowy skan** na zbiorze labu (albo powtórz skan labu z kroku 2).

| oczekiwany wynik | wymaganie |
|---|---|
| po nowym przebiegu tag, notatka, status i ocena są dalej na assecie (też w `make asi ARGS='assets -q 192.0.2.10/tcp/443'`) | pkt 14 |
| port oznaczony jako fałszywy alarm albo zaakceptowane ryzyko znika z *Najważniejszych znalezisk* | pkt 14–15 |
| w DefectDojo znalezisko ma `false_p` / `risk_accepted` i `severity_justification` | integracja DD |
| zmiana jest w **Administracja → Dziennik audytu** | rozliczalność |

Notatki są szyfrowane AES-256-GCM w bazie (krok 8).

## 4. Import wyników z innego skanera (i celów) {#krok-4}

Pokrywa punkt walidacji **11** (20% oceny) i wymaganie 11 PDF.

Przykładowy plik: [inny-skaner.csv](/import/inny-skaner.csv) (3 hosty z sieci dokumentacyjnej
`198.51.100.0/24`, 5 otwartych usług, w tym SNMP po UDP, i jeden zamknięty port, który nie jest obserwacją).

**Skany → Import wyników skanów** → wybierz plik, tryb pokrycia (`auto` lub `none`) oraz opcjonalnie datę
historyczną → **Importuj wyniki**. Albo z terminala:

```bash
cp inny-skaner.csv targets/                                    # targets/ jest widoczne w kontenerze skanera
make asi ARGS='import targets/inny-skaner.csv'                 # pokrycie auto
make asi ARGS='import -coverage none targets/inny-skaner.csv'  # tylko dopisanie obserwacji bez oznaczania braków
# import historyczny (data w przeszłości: trafia do historii, nie cofa bieżących stanów):
make asi ARGS='import -at 2026-11-20T22:00:00Z targets/inny-skaner.csv'
# import surowego XML nmapa z ostatniego przebiegu labu:
LAST_XML=$(ls -t results/lab/*/merged.xml | head -1)
make asi ARGS="import $LAST_XML"
```

Plik do importu kładź w `targets/` (albo w `results/`, jeśli należy do ciebie). Sprawdzone na świeżym klonie
(21.11, fatusia-1): `import targets/inny-skaner.csv` daje `rows 6, hosts 3, events new 8` (3 hosty + 5 portów).

| oczekiwany wynik | wymaganie |
|---|---|
| nowy przebieg (import) na liście przebiegów, 3 nowe hosty i 5 nowych usług w **Assetach** | import JSON/CSV |
| zamknięty telnet nie tworzy assetu | |
| obsługiwane też: nmap XML (`merged.xml`), JSON, JSONL httpx/nuclei (`results/lab/<przebieg>/http/*.jsonl`), nasz własny eksport CSV/JSON (pełny „roundtrip”) | [Import](/guide/import) |

**Wprowadzanie celów (wymaganie 11 PDF):** w GUI zakładka **Cele** — **Dodaj ręcznie**, **Import z pliku**
(CSV/JSON/TXT) oraz **Wklej dowolny tekst** (ekstrakcja adresów regex/DeepSeek); w CLI:
`make asi ARGS='convert -in targets/lab.csv -out results/lab-targets.json'` i
`make asi ARGS='db import-targets -set lab -targets targets/lab.csv'`.

## 5. Role (RBAC), zarządzanie kontami i audyt {#krok-5}

Pokrywa punkt walidacji **12** (10% oceny) oraz wymagania 12–13 PDF (wyrównane 1:1 w DEV-12).

**Administracja → Użytkownicy**: utwórz `jury-viewer` (`viewer`), `jury-analyst` (`analyst`) i `jury-operator`
(`operator`), hasła min. 10 znaków. Zaloguj się na nie w oknie prywatnym.

| rola w PDF | konto w ASI | sprawdź | oczekiwany wynik |
|---|---|---|---|
| **Odczyt** | `viewer` | otwórz Dashboard i Assety, spróbuj zapisać tag lub cel | odczyt i eksport działają, zapis kończy się odmową (**403**), brak zakładki Administracja |
| **Modyfikacja i odczyt** | `analyst` | edytuj tag/notatkę/ocenę assetu, edytuj istniejący cel lub harmonogram, spróbuj dodać/usunąć cel lub uruchomić skan | modyfikacja istniejących wartości działa, tworzenie/usuwanie i start skanu: odmowa (**403**) |
| **Dodawanie, usuwanie, modyfikacja** | `operator` | dodaj/usuń cel, dodaj/usuń harmonogram, uruchom/zatrzymaj skan, importuj wyniki | działa; brak zakładki Administracja (**403** na `/api/v1/users`, `/api/v1/audit`) |
| **Administracja** | `admin` | zmień rolę, kliknij **zablokuj**, **reset hasła**, **usuń** (DEV-11) | zablokowany użytkownik od razu dostaje **401** (sesje i tokeny API unieważnione); wszystko w **Dzienniku audytu** |

Nie da się odebrać roli, zablokować ani usunąć **ostatniego aktywnego administratora** (**HTTP 409**). Każda zmiana
trafia do **Administracja → Dziennik audytu**.

**Testy automatyczne end-to-end (DEV-3, DEV-11, DEV-12):**

```bash
make test-roles     # 28/28 sprawdzeń: pełna macierz viewer/analyst/operator/admin (DEV-12)
make test-users     # 35/35 sprawdzeń: role, blokada -> 401, reset hasła, ochrona ostatniego admina -> 409, audyt (DEV-11)
make test-tokens    # 24/24 sprawdzeń: auth, CSRF (X-ASI: 1), Bearer, unieważnianie, audyt, walidacja (DEV-3)
```

Szczegóły ról: [Panel web](/guide/gui#role).

## 6. Eksport i tokeny API {#krok-6}

Pokrywa punkt walidacji **11** (20% oceny).

| gdzie | co | wymaganie |
|---|---|---|
| **Assety → Eksport CSV** (i **JSON**) | assety ze stanem, usługą, czasem odpowiedzi `http_ms`, pierwszym/ostatnim wystąpieniem, tagami i notatką | eksport JSON/CSV |
| **Konto → Nowy token** (DEV-3) | utwórz token (ważność 0–3650 dni, wartość `asi_…` widać raz, w bazie SHA-256), użyj z `Bearer`, potem kliknij **unieważnij** (`401`) | integracja, automatyzacja |
| pliki przebiegu | `results/lab/<przebieg>/`: `services.json`, `observations.json`, `findings_defectdojo.json`, `merged.xml`, `timings.csv` | [Pliki wynikowe](/guide/outputs) |

Eksport przez API (zapis do `results/`, dzięki czemu plik nadaje się od razu do roundtripu przez `asi import`):

```bash
export ASI_TOKEN="asi_..."
curl -fsS -H "Authorization: Bearer $ASI_TOKEN" http://127.0.0.1:18090/api/v1/export/assets.csv -o results/export.csv
curl -fsS -H "Authorization: Bearer $ASI_TOKEN" http://127.0.0.1:18090/api/v1/export/assets.json -o results/export.json
head -n 5 results/export.csv
```

## 7. DefectDojo {#krok-7}

Pokrywa kryterium integracji z DefectDojo (20% oceny).

http://127.0.0.1:8080 → **Products → ASI lab → engagement `demo`** (dla własnych skanów produkt z `DD_PRODUCT` w `.env`,
engagement `discovery`). Każdy przebieg robi reimport do **4 stałych testów**, więc DefectDojo prowadzi historię
zamiast mnożyć duplikaty:

| test | parser DD | co zawiera | czego oczekiwać po przebiegu 2 |
|---|---|---|---|
| **`ASI discovery`** | *Generic Findings Import* | usługi (1 znalezisko na `IP:port/proto`) | usługi zniknięte zamknięte (*mitigated*), nowe dodane; delta `created / closed / reactivated` |
| **`asi-changes`** | *Generic Findings Import* | zdarzenia: `missing`, `gone`, `flapping`, `changed` (tabela przed → po) | otwarte, dopóki warunek trwa, zamykane, gdy mija |
| **`asi-httpx`** | *httpx Scan* (natywny) | wynik httpx: URL, kod, tytuł, serwer, technologie, przekierowania | strony HTTP/HTTPS labu |
| **`asi-nuclei`** | *Nuclei Scan* (natywny) | trafienia sygnatur z `signatures/` | WordPress, panel admina, staging, stary PHP, Redis, Jenkins |

Ocena analityka z kroku 3 trafia do DD jako `risk_accepted` / `false_p` z `severity_justification`. Przebieg przerwany
(okno, Ctrl+C) nigdy niczego w DD nie zamyka. Opcjonalnie można wysłać surowy XML nmapa do piątego stałego testu
**`asi-nmap`**:

```bash
LAST_RUN=$(ls -dt results/lab/*/ | head -1)
docker compose exec -T nmap-scanner asi upload -run "$LAST_RUN" -format nmap -product "ASI lab" -engagement demo
```

Szczegóły: [DefectDojo](/guide/defectdojo).

## 8. Szyfrowanie danych w spoczynku i integralność schematu {#krok-8}

Pokrywa wymaganie 16 PDF i kryterium zabezpieczenia danych (10% oceny).

```bash
make crypto-check                # dowód szyfrowania at-rest (oczekiwane: Wynik: 9 OK, 0 FAIL)
make asi ARGS='db reseal -dry-run'  # sprawdzenie czy w kolumnach *_enc zostały jawne wartości (oczekiwane: 0)
make asi ARGS='db reseal'        # idempotentne doszyfrowanie starszych rekordów aktywnym kluczem (SEC-6)
make schema-check                # integralność schematu, migracji, indeksów UNIQUE i TDE (oczekiwane: 12/12 OK)
```

Oczekiwane w `make crypto-check`: **`Wynik: 9 OK, 0 FAIL`**, w tym `pg_tde` w `shared_preload_libraries`,
`pg_tde.wal_encrypt=on`, `pg_tde.enforce_encryption=on`, `default_table_access_method=tde_heap`, wszystkie tabele
aplikacji zaszyfrowane, **0 trafień** jawnego tekstu z bazy (np. adresu IP) w surowych plikach tabel, indeksów i WAL
na dysku, oraz **0 jawnych wartości** w kolumnach `*_enc` (wszystkie z prefiksem `ASI1` — AES-256-GCM z rotacją
kluczy `ASI_ENCRYPTION_KEYS`). Opis i ograniczenia: [Szyfrowanie](/guide/encryption).

## 9. Bezpieczeństwo skanowania i skala >10 000 IP {#krok-9}

Pokrywa punkt walidacji **9** (bezpieczeństwo 15%) oraz wymaganie dużych sieci (30% oceny).

### A. Polityka bezpieczeństwa skanera (SEC-8, LAB-T2)

```bash
make asi ARGS='scan -targets targets/lab.csv -nmap "-sT -Pn 8.8.8.8"'   # cel przemycony w argumentach nmapa
make asi ARGS='scan -targets targets/lab.csv -nmap "-sT --script vuln"' # skrypty NSE spoza listy detekcyjnej
printf 'target\n127.0.0.1\n169.254.169.254\n' > targets/policy-demo.csv
make asi ARGS='plan -targets targets/policy-demo.csv'                   # 169.254.169.254 -> skipped (policy: excluded)
rm -f targets/policy-demo.csv
```

| oczekiwany wynik | |
|---|---|
| przemycony cel i `--script vuln` kończą się błędem **przed wysłaniem pakietu** (`targets come only from the plan`, `--script vuln is not allowed`) | allowlista flag nmapa |
| `169.254.169.254` (metadane chmury) automatycznie trafia do `skipped` | wykluczenia wbudowane |
| żądanie `-rate 5000` jest obniżane do twardego limitu `ASI_MAX_RATE=1000` z `.env`; w logu `policy: profile=… max_rate=…pps …` i w `run.json` pole `policy` | kontrola intensywności |
| skan `127.0.0.1` automatycznie pomija własne porty ASI i DefectDojo (`8080`, `18090`, `8091`, `5433`, `8094`, `8095`) | LAB-T2 (`ASI_SELF_PORTS`) |

Testy jednostkowe polityki i bezpieczeństwa sygnatur (na hoście z Go):

```bash
go test -v ./internal/safety/...
go test -v ./internal/scanner/nuclei -run TestTemplatesAreSafe
```

Zakres i wykluczenia (`ASI_SCOPE`, `ASI_EXCLUDE`), lista dozwolonych portów, profil bez roota i decyzja o UDP:
[Bezpieczeństwo skanowania](/guide/safety).

### B. Skala >10 000 IP (DEV-10) oraz okno czasowe i wznawianie

Zmierzony benchmark na `127.0.0.0/18` (**16 384 adresy**, 100% żywych, wyłącznie loopback): **86 s** od startu do
zapisu i przeliczenia **49 152 assetów** w bazie, szczyt RAM **182 MB**, API panelu: dashboard `0,22 s`, pełny eksport
CSV `0,31 s` ([Test skali](/guide/scale)). Reprodukcja (zero ruchu poza maszyną):

```bash
printf 'target,asset,owner,tags,enabled\n127.0.0.0/18,scale-test,secops,scale,true\n' > targets/scale.csv
docker compose exec -T nmap-scanner asi scan -targets targets/scale.csv \
  -parallel 8 -rate 1000 -http off \
  -nmap "-sT -Pn -p 22,8080 -T4 --max-retries 1 --open"
rm -f targets/scale.csv
```

**Okno czasowe i wznawianie:** w GUI (**Skany → Nowy skan**) ustaw **Okno czasowe** (np. `1m`) lub kliknij **Wstrzymaj**
w trakcie skanu — przebieg kończy się statusem `partial` (nie generuje fałszywych zniknięć i nie zamyka znalezisk w DD),
a przy wierszu pojawia się przycisk **Wznów (N)** (CLI: `make asi ARGS='scan -resume <run_id> -window 2h'`).

## 10. Dodatkowo i sprzątanie {#krok-10}

| co | gdzie |
|---|---|
| harmonogram cykliczny z oknem czasowym i automatycznym wznawianiem | **Skany → Harmonogram**, [Harmonogram](/guide/schedule) |
| cele z dowolnego tekstu (inwentarz, notatka, serwer MCP) | **Cele → Wklej dowolny tekst**, [Cele z tekstu](/guide/targets-ai) |
| pełny opis benchmarku 16 384 IP | [Test skali](/guide/scale) |
| analiza 4 stacków labu organizatorów | [Lab organizatorów](/guide/lab-organizers) |

```bash
make lab-down     # usuwa lab 192.0.2.0/24 (stack ASI i dane w bazie zostają)
make down         # zatrzymuje stack (dane zostają)
make nuke         # zatrzymuje stack i usuwa wolumeny (baza ASI, DefectDojo)
```
