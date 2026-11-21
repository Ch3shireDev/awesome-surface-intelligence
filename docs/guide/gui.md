# Panel web (GUI)

`asi server` to główny interfejs systemu (DEV-4). Zgodnie z zaleceniem mentora (wzorzec MISP) GUI jest
**nakładką na CLI i bazę**: skan z panelu to podproces `asi scan`, a dane pochodzą z `asi-db`.

```bash
make env && make up            # panel: http://127.0.0.1:8090
grep ASI_ADMIN_PASSWORD .env   # login: admin
```

Lokalnie bez dockera: `set -a; . ./.env; set +a; ./asi server`.

## Zakładki

| zakładka | co jest | wymaganie z treści zadania |
|---|---|---|
| **Dashboard** | kafelki (aktywne hosty, usługi, nowe, braki, zniknięte, niestabilne, krytyczne ekspozycje), najważniejsze znaleziska wg oceny ciekawości, zmiany w ostatnim przebiegu, lista niestabilnych i zniknięte, wykres zmian w kolejnych przebiegach, stan skanu | pkt 15, „wizualizacja zmian w czasie”, „ocena ciekawości” |

| **Assety** | filtry (stan, rodzaj, flapping, szukaj), tabela, panel szczegółów: ostatnia obserwacja, godziny odpowiedzi (24 h), historia zdarzeń, **edycja tagów i notatki** zachowanych przy kolejnych skanach; eksport CSV/JSON | pkt 14, 8–9, eksport |
| **Cele** | zbiory celów, **formularz ręczny** (IP/CIDR/domena, tagi, właściciel, notatka szyfrowana), **import CSV/JSON/TXT**, włącz/wyłącz, usuń | pkt 1, 11 |
| **Skany** | start z parametrami (zbiór, równoległość, globalny limit pps, porty, okno czasowe, eksport do DefectDojo), zatrzymanie (przebieg `partial`), **postęp na żywo** (panel skanu przez proxy), lista przebiegów i ich zmian | pkt 2, harmonogram/okno, ograniczanie tempa |
| **Konto** | **tokeny API** zalogowanego użytkownika: lista (nazwa, data utworzenia, ostatnie użycie, ważność), utworzenie z nazwą i terminem ważności, unieważnienie; wartość tokenu pokazywana **raz** | pkt 12–13, integracja z DD/automatyzacja |
| **Administracja** | użytkownicy z rolami, dziennik audytu | pkt 12–13 |

Każdy kafelek otwiera zakładkę **Assety** z filtrem odpowiadającym swojej liczbie. „Nowe w ostatnim skanie”
liczy **zmiany z ostatniego przebiegu** (zdarzenia `new` i `reappeared`), a nie stan assetu — taki asset ma
zwykle stan `active`, więc filtr `state=new` pokazywał 0. Kafelek przekazuje `run=<id przebiegu>&events=new,reappeared`,
czyli pokazuje dokładnie te assety, które w tym przebiegu się pojawiły; filtr można wyczyścić linkiem
„wyczyść” przy liczbie assetów. API: `GET /api/v1/assets?run=<id>&events=new,reappeared`.

## Adresy widoków, wstecz i linki do zasobu (DEV-14)

Pasek adresu pokazuje, gdzie jesteś, więc działa **wstecz/dalej** przeglądarki i można wysłać komuś link
do widoku, assetu albo przebiegu (pkt 15 PDF — czytelny interfejs, integracja z codzienną pracą).

| adres | co pokazuje |
|---|---|
| `/` | Dashboard |
| `/assets` | Assety; filtry w query stringu: `q`, `state`, `kind`, `flapping`, `slow`, `int`, `svc`, `run`, `events` |
| `/assets/<klucz>` | Assety + panel szczegółów assetu (klucz URL-encoded; port ma `/` jako `%2F`, np. `/assets/192.0.2.15%2Ftcp%2F80`) |
| `/targets` | Cele |
| `/scans` | Skany |
| `/scans/<id przebiegu>` | Skany + panel zmian tego przebiegu, np. `/scans/20261121-193230` |
| `/account` | Konto (tokeny API) |
| `/admin` | Administracja (tylko rola `admin`) |

Zachowanie:

- kliknięcie wiersza assetu/przebiegu **dopisuje wpis w historii**, a „zamknij ✕” i `Esc` robią krok wstecz —
  wstecz zamyka panel szczegółów i wraca do listy z tymi samymi filtrami;
- filtry zakładki Assety są w adresie, więc `/assets?state=live&kind=host` można zapisać w zakładkach
  albo wysłać koledze;
- wejście z linku przy wygasłej sesji: najpierw logowanie, a po nim panel otwiera dokładnie ten widok/asset;
- `/admin` bez roli `admin` przekierowuje na `/` (poprawiamy adres, nie tylko ukrywamy widok);
- SPA serwują też same ścieżki (`GET /assets`, `/scans/<id>`, …), więc F5 i bezpośredni link działają;
  `/api/` i `/live/` nie są przechwytywane (`go test ./internal/app -run TestSPARoutes`);
- wszystkie wywołania API w panelu są bezwzględne (`/api/v1/…`), bo dokument żyje też pod `/assets/<klucz>`
  (wcześniej relatywne `api/…` trafiałoby pod ścieżkę widoku).

Test w prawdziwej przeglądarce (dev machine: `node` + Chrome; panel może działać w kontenerze):

```bash
make test-router        # 49/49: menu, kafelki KPI, szuflady, wstecz/dalej, F5, deep linki, %2F, role
BASE=http://127.0.0.1:8090 NODE_PATH=/tmp/node_modules node scripts/ui-router-test.js
```

## Role

Nazwy ról w kodzie odpowiadają wprost czterem rolom z pkt 13 treści zadania. Każda rola widzi tylko te
elementy interfejsu, do których ma uprawnienia (pkt 15), a API sprawdza to samo jeszcze raz po stronie serwera.

| rola w PDF | w ASI | może |
|---|---|---|
| **Odczyt** | `viewer` | czytać wszystko poza administracją: dashboard, assety i historię zmian, przebiegi, postęp skanu |
| **Modyfikacja i odczyt** | `analyst` | + edytować istniejące wartości niezależnie od stanu skanu: tagi, notatki i właściciel assetu, tagi/notatka/właściciel celu, parametry istniejącego harmonogramu. Nie dodaje ani nie usuwa celów i nie uruchamia skanów |
| **Dodawanie, usuwanie, modyfikacja** | `operator` | + dodawać i usuwać cele (formularz, CSV/JSON, import), dodawać i usuwać harmonogramy, uruchamiać i zatrzymywać skany |
| **Administracja** | `admin` | + użytkownicy i konta (role, blokada, reset hasła, usuwanie), dziennik audytu |

Pierwszy admin powstaje przy starcie z `ASI_ADMIN_USER` / `ASI_ADMIN_PASSWORD`, gdy w bazie nie ma
użytkowników. Kolejnych dodaje admin w GUI. RBAC jest lokalny, bez synchronizacji z DefectDojo (ustalenie z mentorem).

Zmiana hasła w `.env` **nie zmienia** hasła istniejącego konta (konto powstaje tylko raz, przy pustej tabeli
`users`). Odzyskanie dostępu bez logowania do panelu:

```bash
asi user list                                   # kto jest w bazie
asi user passwd -user admin -password 'nowe-haslo'  # reset (min. 10 znaków, zdejmuje blokadę)
asi user add -user jury -password 'haslo-jury' -role viewer
```

## Zarządzanie kontami (DEV-11, pkt 12–13 PDF)

Zakładka **Administracja** (rola `admin`) oprócz dodawania kont pozwala nimi zarządzać:

| operacja | jak | co się dzieje |
|---|---|---|
| zmiana roli | lista rozwijana w wierszu | nowe uprawnienia działają od następnego żądania (rola jest czytana z bazy) |
| blokada / odblokowanie | „zablokuj” / „odblokuj” | **sesje i tokeny API tego konta są unieważnione**, zalogowany użytkownik dostaje 401 |
| reset hasła | „reset hasła” | nowe hasło (min. 10 znaków) bez znajomości starego; sesje/tokeny unieważnione |
| usunięcie konta | „usuń” | konto i jego tokeny znikają; operacji nie można cofnąć |

Zabezpieczenia: nie da się odebrać roli, zablokować ani usunąć **ostatniego aktywnego administratora**
(API zwraca 409) — inaczej panel zostałby bez administracji. Odebranie roli sobie samemu jest dozwolone tylko
wtedy, gdy istnieje drugi admin, a GUI dodatkowo ostrzega. Wszystkie zmiany trafiają do `audit_log`
(`user_update`, `user_delete`). API: `PATCH /api/v1/users/{id}` (`role`, `disabled`, `password`),
`DELETE /api/v1/users/{id}`; test end-to-end: `make test-users` (35 sprawdzeń).

## Bezpieczeństwo panelu

- Hasła: PBKDF2-SHA256, 600 000 iteracji. Sesje: losowy token, w bazie tylko jego SHA-256, ważność 12 h,
  ciasteczko `HttpOnly` + `SameSite=Strict` (`-secure-cookie` za HTTPS).
- CSRF: zmiany stanu wymagają nagłówka `X-ASI: 1`, którego formularz z obcej strony nie ustawi.
- Walidacja wejścia: cele tylko jako IP, CIDR albo nazwa domenowa; porty tylko jako lista/zakresy liczb;
  twarde limity GUI: równoległość ≤ 32, ≤ 5000 pps, okno 1 min – 24 h. Skan dostaje zamrożoną kopię zbioru celów.
- Jeden skan naraz; zatrzymanie = SIGINT, częściowe wyniki zapisane jako `partial`.
- Nagłówki: CSP, `X-Frame-Options: SAMEORIGIN`, `nosniff`, `no-referrer`. Panel słucha na `127.0.0.1`.
- Każda zmiana (logowanie, nieudane logowanie, cele, edycje, skany, eksport, użytkownicy) trafia do `audit_log`.

## Tokeny API (DEV-3)

Zakładka **Konto** wydaje tokeny do automatyzacji (skrypty, cron, integracje). Token działa jak hasło:

```bash
curl -s -H "Authorization: Bearer asi_…" http://127.0.0.1:8090/api/v1/assets
```

- Wartość tokenu jest pokazywana **tylko raz**, przy tworzeniu; w bazie leży wyłącznie SHA-256 (`api_tokens`).
- Zakres ważności: 0 (bez terminu) do 3650 dni, domyślnie 90. Po wygaśnięciu token przestaje działać,
  ale zostaje na liście z oznaczeniem „wygasł” — można go posprzątać.
- Token widzi tylko jego właściciel; nie da się unieważnić cudzego (404). Bieżąca sesja też jest tokenem
  i jest oznaczona jako „ta sesja” — nie ma przycisku unieważnienia, żeby nie wylogować się przez pomyłkę.
- Uprawnienia wynikają z roli użytkownika, który token utworzył (token nie podnosi roli).
- Utworzenie i unieważnienie trafiają do `audit_log` (`token_create`, `token_revoke`).
- Żądania z `Bearer` nie wymagają nagłówka `X-ASI` (CSRF dotyczy tylko ciasteczka).

Test: `BASE=http://127.0.0.1:8090 bash scripts/test-tokens.sh` (24 sprawdzenia: brak sesji, CSRF, Bearer,
unieważnienie, audyt, walidacja wejścia).

## API

Wszystko, co robi GUI, jest dostępne pod `/api/v1` (sesja albo `Authorization: Bearer <token>`):
`login`, `logout`, `me`, `dashboard`, `assets`, `asset` (PATCH), `asset/events`, `runs`, `runs/{id}/events`,
`target-sets`, `targets` (GET/POST/PUT/DELETE), `targets/import`, `scans`, `scans/current`,
`scans/current/stop`, `export/assets.csv|json`, `users`, `audit`, `tokens` (GET/POST/DELETE),
a postęp skanu pod `/live/`.

## Ocena analityka (DEV-9)

W szufladzie portu: **Status wyniku** (do analizy / fałszywy alarm / zaakceptowane ryzyko), **Ocena** (automatyczna
albo high/medium/low) i **uzasadnienie**. Decyzja jest zapisana na assecie (`user_overrides`), więc:

- przetrwa każdy kolejny skan,
- fałszywy alarm i zaakceptowane ryzyko znikają z „Najważniejszych znalezisk”, a nadpisana ocena dotyczy też trafień sygnatur na tym porcie,
- w eksporcie do DefectDojo znalezisko ma `false_p` / `risk_accepted`, a uzasadnienie trafia do `severity_justification`.
  Ocena nie jest częścią opisu, więc jej zmiana nie zamyka i nie tworzy znaleziska w DD na nowo.

Walidacja: tylko znane wartości statusu i oceny, uzasadnienie do 500 znaków. Każda zmiana jest w dzienniku audytu.

## Porównanie dwóch przebiegów (DEV-9)

Skany → **Porównanie dwóch przebiegów**: dowolne dwa przebiegi z bazy (domyślnie dwa ostatnie zakończone):
usługi nowe, zniknięte i zmienione (przed i po) oraz hosty nowe i znikłe. API: `GET /api/v1/diff?from=A&to=B`,
CLI: `asi diff -db A B`.

## Edycja harmonogramu

Przy harmonogramie: **edytuj** wypełnia formularz (nazwa, zbiór, cron, okno oraz parametry skanu z formularza
„Nowy skan”), a **Zapisz zmiany** wysyła `PUT /api/v1/schedules/{id}`. Następny start przelicza się od razu.
