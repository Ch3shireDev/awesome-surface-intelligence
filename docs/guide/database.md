# Baza danych

ASI trzyma przebiegi w **własnym PostgreSQL** (`asi-db`), osobnym od bazy DefectDojo (decyzja 12).
Pliki w `results/<run>/` nadal powstają jako eksport i jako fallback, gdy bazy nie ma.

## Uruchomienie

```bash
make env                        # nowy .env: generuje ASI_DB_PASSWORD i ASI_DATABASE_URL
docker compose up -d asi-db     # port tylko na 127.0.0.1:5433
set -a; . ./.env; set +a
./asi db migrate                # schemat (robi to też samo `asi scan`)
```

Gdy `ASI_DATABASE_URL` jest ustawione, `asi scan` zapisuje przebieg do bazy automatycznie
(`-db ""` wyłącza zapis). Błąd bazy nie przerywa skanu: zostaje w logu, a wyniki są w plikach.

## Komendy

| komenda | co robi |
|---|---|
| `asi db migrate` | stosuje brakujące migracje |
| `asi db import-targets -targets targets/targets.csv -set default` | wczytuje cele (CSV/JSON/TXT) do zbioru; ponowny import aktualizuje istniejące wpisy po wartości |
| `asi db targets -set default` | lista celów zbioru (notatki odszyfrowane) |
| `asi db runs` | przebiegi ze statusem i liczbą paczek w każdym stanie |
| `asi db reseal [-dry-run]` | zaszyfruj wartości `_enc` zapisane wcześniej jawnie (idempotentne; [Szyfrowanie](/guide/encryption#włączenie)) |
| `asi diff -db [A B]` | diff dwóch przebiegów liczony z bazy (domyślnie dwa ostatnie `completed`) |

## Kontrola schematu (`make schema-check`)

`pg_restore` na istniejącym schemacie bez `--clean/--create` potrafi **pominąć indeksy i ograniczenia
`UNIQUE`**: odczyty działają, a zapis kończy się `ON CONFLICT ... SQLSTATE 42P10`. `make schema-check`
(tylko odczyt, w kontenerze `asi-db`) sprawdza migracje, obecność indeksów wymaganych przez kod
(`targets_set_id_value_key`, `assets_key_key`, `users_username_key`, `schedules_name_key`,
`target_sets_name_key`, `api_tokens_token_hash_key`, klucze `chunks` i `raw_outputs`), duplikaty w tych
kluczach i brak tabel na `heap`. Uruchom po każdym restorze i przed demo; naprawa: `asi db migrate`,
`pg_restore --data-only`, [`scripts/tde-reenable.sql`](/guide/encryption#warstwa-1-tde-pg_tde).

## Co jest zapisywane w trakcie skanu

| moment | tabela |
|---|---|
| start | `runs` (status `running`, zamrożony profil: równoległość, tempo, argumenty nmapa) |
| start paczki | `chunks` (`running`, lista celów, rozmiar) |
| koniec paczki | `chunks` (`done`/`failed`/`killed`, czas), `observations` (COPY), `raw_outputs` (XML nmapa jako dowód) |
| skan potwierdzający | `observations` z etapem `confirm` |
| koniec | `runs` (`completed` albo `partial`, gdy okno/Ctrl+C przerwało skan; statystyki) |

`partial` jest ważne dla reconcile (DEV-2): adresy z niedokończonych paczek nie mogą generować „braków”.

## Schemat

`internal/store/migrations/001_init.sql`, zgodnie z VISION 4.2: `users`, `api_tokens`, `audit_log`,
`target_sets`, `targets`, `exclusions`, `runs`, `chunks`, `raw_outputs`, `observations`, `assets`,
`asset_events`, `exports`.

Kolumny z sufiksem `_enc` przechodzą przez `store.Sealer` (dane obserwacji, surowe wyjścia, notatki).
Pola potrzebne do wyszukiwania (IP, port, protokół, nazwa usługi, stan) są w jawnych kolumnach.
Od SEC-6 `Sealer` to AES-256-GCM (`internal/crypto`, klucze `ASI_ENCRYPTION_KEYS`), a pliki całej bazy
szyfruje `pg_tde`. Szczegóły i weryfikacja: [Szyfrowanie danych w spoczynku](/guide/encryption).

## Testy

```bash
ASI_TEST_DATABASE_URL=$ASI_DATABASE_URL go test ./internal/store/
```

Test integracyjny sprawdza zapis przebiegu, paczek i obserwacji, odszyfrowanie, to, że w `data_enc` nie ma
jawnego tekstu, oraz upsert celów (edycja zamiast duplikatu). Bez zmiennej test jest pomijany.
