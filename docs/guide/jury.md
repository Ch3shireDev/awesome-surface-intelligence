# Ścieżka testowania (dla jury)

Jedna ścieżka przez cały system, w kolejności, w jakiej najłatwiej go sprawdzić: **lab → dwa przebiegi →
przegląd zmian → edycja znalezisk → import → role → eksport → DefectDojo → szyfrowanie → bezpieczeństwo**.
Każdy krok ma polecenie albo kliknięcie, oczekiwany wynik i wymaganie z treści zadania, które sprawdza.
Całość zajmuje ok. 30 minut, z czego kilka minut to pierwszy `make up`.

Wymagania hosta: Linux z dockerem i pluginem compose, `make`, `openssl`, ok. 4 GB RAM wolne dla DefectDojo.
Wszystko inne (nmap, httpx, nuclei, PostgreSQL, DefectDojo) działa w kontenerach.

## 0. Start od zera

```bash
git clone https://github.com/Ch3shireDev/awesome-surface-intelligence.git asi && cd asi
make env      # .env: wygenerowane hasła, sekrety DefectDojo, klucz szyfrowania pól
make up       # DefectDojo :8080, asi-db (szyfrowana, pg_tde), skaner + panel ASI :8090
grep -E '^(ASI_ADMIN_PASSWORD|DD_ADMIN_PASSWORD)=' .env    # hasła do obu paneli (login: admin)
```

| oczekiwany wynik | |
|---|---|
| `make up` kończy się bez błędu, `docker compose ps` pokazuje kontenery `asi-*` jako `running`/`healthy` | |
| http://127.0.0.1:8090: logowanie do panelu ASI (`admin` + `ASI_ADMIN_PASSWORD`) | |
| http://127.0.0.1:8080: logowanie do DefectDojo (`admin` + `DD_ADMIN_PASSWORD`) | DefectDojo startuje dłużej (migracje), po 1–3 min |

Panel słucha tylko na `127.0.0.1`. Test z innej maszyny: `ASI_WEB_ADDR=0.0.0.0:8090` w `.env` i ponownie `make up`.

## 1. Lab i dwa przebiegi skanu

```bash
make demo     # lab 192.0.2.0/24 -> przebieg 1 -> zmiany w labie -> przebieg 2 -> porównanie + eksport do DD
```

Lab to 8 kontenerów w sieci dokumentacyjnej `192.0.2.0/24` (RFC 5737, nieroutowalna, więc pakiety nie
wychodzą poza VM). Między przebiegami `make demo` sam zmienia lab:

| zmiana w labie | oczekiwany wynik po przebiegu 2 | wymaganie |
|---|---|---|
| host `legacy` (.14) znika | jego usługi: *brak odpowiedzi (do potwierdzenia)*, po kolejnych brakach *zniknął* | pkt 8–9, zmiany w czasie |
| `app` (.15) zmienia serwer | *zmiana usługi*: przed → po | pkt 9 |
| dochodzi `jenkins` (.16) | nowe usługi, Jenkins z wersją, trafienia sygnatur | pkt 9, 6, 10 |
| usługa włącza się i wyłącza | *niestabilna (flapping)* | hosty niestabilne |

W terminalu na końcu jest porównanie z przebiegiem 1. Trwa to ok. 2 minut.

**To samo z panelu** (zamiast `make demo`): `make lab-up`, potem **Cele → Import z pliku** z plikiem
[lab.csv](/cele/lab.csv) (albo [lab.json](/cele/lab.json)), potem **Skany → Nowy skan** na tym zbiorze.
Postęp widać na żywo: etapy, paczki nmapa, czas.

## 2. Przegląd wyników i zmian

| gdzie | co sprawdzić | wymaganie |
|---|---|---|
| **Dashboard** | kafelki (aktywne hosty, usługi, nowe, braki, zniknięte, niestabilne), *najważniejsze znaleziska* z oceną 0–100 i powodem, zmiany ostatniego przebiegu, wykres zmian | pkt 15 |
| **Assety** | filtr po stanie (`new`, `active`, `missing`, `gone`) i *flapping*; szuflada portu: ostatnia obserwacja HTTP (tytuł, kod, nagłówki, ciasteczka, certyfikat), sygnatury, historia zdarzeń, godziny odpowiedzi | pkt 4–9 |
| **Skany → Porównanie dwóch przebiegów** | usługi nowe, zniknięte i zmienione (przed → po) między dowolnymi dwoma przebiegami | pkt 8–9 |
| terminal | `make asi ARGS='changes'` (zdarzenia ostatniego przebiegu), `make asi ARGS='diff'` | pkt 8 |

Na hoście `web-prod` (.10) widać m.in. `X-Powered-By: PHP/7.4.33`, ciasteczko `PHPSESSID`, przekierowanie
`/login` i certyfikat self-signed. Na `wordpress` (.11) CMS z wersją. Pełna lista artefaktów:
[Lab testowy](/guide/lab#hosty-i-co-powinien-wykryc-skaner).

## 3. Edycja znalezisk trwała między skanami

1. **Assety** → kliknij dowolny port (np. WordPress na 192.0.2.11:80).
2. W szufladzie dodaj tag i notatkę, ustaw **Status wyniku** (np. *zaakceptowane ryzyko*), ocenę i uzasadnienie. Zapisz.
3. Uruchom kolejny przebieg: **Skany → Nowy skan** na zbiorze labu (albo `make demo` jeszcze raz).

| oczekiwany wynik | wymaganie |
|---|---|
| po nowym przebiegu tag, notatka, status i ocena są dalej na assecie | pkt 14 |
| port oznaczony jako fałszywy alarm albo zaakceptowane ryzyko znika z *najważniejszych znalezisk* | pkt 14–15 |
| zmiana jest w **Administracja → dziennik audytu** | rozliczalność |

Notatki są szyfrowane w bazie (krok 8).

## 4. Import wyników z innego skanera

Przykładowy plik: [inny-skaner.csv](/import/inny-skaner.csv) (3 hosty z sieci dokumentacyjnej
`198.51.100.0/24`, 5 otwartych usług, w tym SNMP po UDP, i jeden zamknięty port, który nie jest obserwacją).

**Skany → Import wyników skanów** → wybierz plik → **Importuj wyniki**. Albo z terminala:

```bash
cp inny-skaner.csv results/                      # katalog results/ jest widoczny w kontenerze skanera
make asi ARGS='import results/inny-skaner.csv'
```

| oczekiwany wynik | wymaganie |
|---|---|
| nowy przebieg (import) na liście przebiegów, 3 nowe hosty i 5 nowych usług w **Assetach** | import JSON/CSV |
| zamknięty telnet nie tworzy assetu | |
| obsługiwane też: nmap XML (np. `results/lab/<przebieg>/merged.xml`), JSON, JSONL httpx/nuclei, nasz własny eksport CSV (pełny „roundtrip”) | [Import](/guide/import) |

## 5. Role (RBAC)

**Administracja → Dodaj użytkownika**: utwórz `jury-viewer` (rola `viewer`) i `jury-analyst` (rola `analyst`),
hasła min. 10 znaków. Zaloguj się na nie w oknie prywatnym.

| konto | sprawdź | oczekiwany wynik |
|---|---|---|
| `viewer` | otwórz Dashboard i Assety, spróbuj zapisać tag | odczyt działa, zapis kończy się odmową (403), brak zakładki Administracja |
| `analyst` | edytuj tag/notatkę assetu, spróbuj dodać cel | edycja assetu działa, dodanie celu: odmowa |
| `operator` | dodaj cel, uruchom skan | działa |
| `admin` | zmień rolę, zablokuj konto | zablokowany użytkownik od razu dostaje 401 (sesje i tokeny unieważnione) |

Nie da się odebrać roli, zablokować ani usunąć **ostatniego** administratora (409). Każda zmiana trafia do
dziennika audytu. Automatycznie: `make test-users` (35 sprawdzeń). Szczegóły ról: [Panel web](/guide/gui#role).

## 6. Eksport

| gdzie | co | wymaganie |
|---|---|---|
| **Assety → Eksport CSV** (i JSON) | assety ze stanem, usługą, pierwszym/ostatnim wystąpieniem, tagami i notatką | eksport JSON/CSV |
| **Konto → token API** | utwórz token (wartość widać raz), potem: `curl -s -H "Authorization: Bearer asi_…" http://127.0.0.1:8090/api/v1/export/assets.json` | integracja, automatyzacja |
| pliki przebiegu | `results/lab/<przebieg>/`: `services.json`, `observations.json`, `findings_defectdojo.json`, `merged.xml`, `timings.csv` | [Pliki wynikowe](/guide/outputs) |

## 7. DefectDojo

http://127.0.0.1:8080 → **Products → ASI lab → engagement `demo`**. Każdy przebieg robi reimport do
stałych testów, więc DefectDojo prowadzi historię zamiast mnożyć duplikaty:

| test | co zawiera | czego oczekiwać po przebiegu 2 |
|---|---|---|
| `ASI discovery` | usługi (1 znalezisko na IP:port) | usługi zniknięte zamknięte (*mitigated*), nowe dodane; delta `created / closed / reactivated` |
| `asi-changes` | zdarzenia: brak odpowiedzi, zniknięcie, zmiana, flapping | otwarte, dopóki warunek trwa, zamykane, gdy mija |
| `asi-httpx` | wynik httpx natywnym parserem DD | strony HTTP labu |
| `asi-nuclei` | trafienia sygnatur natywnym parserem DD | WordPress, panel admina, staging, stary PHP |

Ocena analityka z kroku 3 trafia do DD jako `risk_accepted` / `false_p` z uzasadnieniem. Przebieg przerwany
(okno, Ctrl+C) nigdy niczego w DD nie zamyka. Szczegóły: [DefectDojo](/guide/defectdojo).

## 8. Szyfrowanie danych w spoczynku

```bash
make crypto-check
```

Oczekiwane: same `[OK]`, w tym zaszyfrowane wszystkie tabele aplikacji, **0 trafień** jawnego tekstu z bazy
(np. adresu IP) w surowych plikach tabel, indeksów i WAL na dysku, oraz 0 jawnych wartości w kolumnach `_enc`
(dane obserwacji, surowe wyjścia skanerów, notatki). Dwie warstwy: `pg_tde` (AES-256, cała baza i WAL) i pola
wrażliwe AES-256-GCM w aplikacji z rotacją kluczy. Opis i ograniczenia: [Szyfrowanie](/guide/encryption).

## 9. Bezpieczeństwo skanowania

```bash
make asi ARGS='scan -targets targets/lab.csv -nmap "-sT -Pn 8.8.8.8"'   # cel przemycony w argumentach nmapa
make asi ARGS='scan -targets targets/lab.csv -nmap "-sT --script vuln"' # skrypty NSE spoza listy detekcyjnej
```

| oczekiwany wynik | |
|---|---|
| oba polecenia kończą się błędem **przed wysłaniem pakietu**, z powodem (`targets come only from the plan`, `--script vuln is not allowed`) | allowlista flag nmapa |
| w logu każdego przebiegu: linia `policy: profile=… max_rate=…pps …`; w `run.json` pole `policy` | twarde limity z `.env` |
| skan `127.0.0.1` nie zgłasza portów samego ASI ani DefectDojo (8080, 8090, 5433…) | LAB-T2 |

Zakres i wykluczenia (`ASI_SCOPE`, `ASI_EXCLUDE`, wykluczenia wbudowane, np. metadane chmury), lista dozwolonych
portów, limit pps, profil bez roota i decyzja o UDP: [Bezpieczeństwo skanowania](/guide/safety).

## 10. Dodatkowo (opcjonalnie)

| co | gdzie |
|---|---|
| harmonogram z oknem czasowym i wznawianiem w kolejnym oknie | **Skany → Harmonogram**, [Harmonogram](/guide/schedule) |
| cele z dowolnego tekstu (inwentarz, notatka) | [Cele z tekstu](/guide/targets-ai) |
| skala: 16 384 adresy w 86 s | [Test skali](/guide/scale) |
| lab organizatorów (4 stacki) | [Lab organizatorów](/guide/lab-organizers) |

## Sprzątanie

```bash
make lab-down     # usuwa lab
make down         # zatrzymuje stack (dane zostają)
make nuke         # zatrzymuje stack i usuwa wolumeny (baza ASI, DefectDojo)
```
