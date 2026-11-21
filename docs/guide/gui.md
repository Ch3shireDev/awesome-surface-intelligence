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
| **Administracja** | użytkownicy z rolami, dziennik audytu | pkt 12–13 |

## Role

| rola | może |
|---|---|
| `viewer` | czytać wszystko poza administracją |
| `analyst` | + edytować assety (tagi, notatki) |
| `operator` | + cele (dodawanie, import, usuwanie), start/stop skanów |
| `admin` | + użytkownicy, dziennik audytu |

Pierwszy admin powstaje przy starcie z `ASI_ADMIN_USER` / `ASI_ADMIN_PASSWORD`, gdy w bazie nie ma
użytkowników. Kolejnych dodaje admin w GUI. RBAC jest lokalny, bez synchronizacji z DefectDojo (ustalenie z mentorem).

## Bezpieczeństwo panelu

- Hasła: PBKDF2-SHA256, 600 000 iteracji. Sesje: losowy token, w bazie tylko jego SHA-256, ważność 12 h,
  ciasteczko `HttpOnly` + `SameSite=Strict` (`-secure-cookie` za HTTPS).
- CSRF: zmiany stanu wymagają nagłówka `X-ASI: 1`, którego formularz z obcej strony nie ustawi.
- Walidacja wejścia: cele tylko jako IP, CIDR albo nazwa domenowa; porty tylko jako lista/zakresy liczb;
  twarde limity GUI: równoległość ≤ 32, ≤ 5000 pps, okno 1 min – 24 h. Skan dostaje zamrożoną kopię zbioru celów.
- Jeden skan naraz; zatrzymanie = SIGINT, częściowe wyniki zapisane jako `partial`.
- Nagłówki: CSP, `X-Frame-Options: SAMEORIGIN`, `nosniff`, `no-referrer`. Panel słucha na `127.0.0.1`.
- Każda zmiana (logowanie, nieudane logowanie, cele, edycje, skany, eksport, użytkownicy) trafia do `audit_log`.

## API

Wszystko, co robi GUI, jest dostępne pod `/api/v1` (sesja albo `Authorization: Bearer <token>`):
`login`, `logout`, `me`, `dashboard`, `assets`, `asset` (PATCH), `asset/events`, `runs`, `runs/{id}/events`,
`target-sets`, `targets` (GET/POST/PUT/DELETE), `targets/import`, `scans`, `scans/current`,
`scans/current/stop`, `export/assets.csv|json`, `users`, `audit`, a postęp skanu pod `/live/`.

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
