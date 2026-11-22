# Szyfrowanie danych w spoczynku

Wymaganie 16 ze specyfikacji: baza ma zapewniać szyfrowanie w spoczynku (encryption at rest) dla
wszystkich pól z danymi wrażliwymi. Mentor CBI AGH zalecił PostgreSQL z włączonym szyfrowaniem
(„darmowe 5%” oceny). ASI szyfruje dane w **dwóch niezależnych warstwach**.

| warstwa | co chroni | czym | klucz |
|---|---|---|---|
| **1. TDE bazy** (`pg_tde`) | pliki wszystkich tabel i indeksów aplikacji oraz WAL na dysku | AES-256, Percona `pg_tde` w serwerze PostgreSQL 18 | klucz główny w keyringu `pg_tde` (wolumen `asi_db_keys`, poza `PGDATA`) |
| **2. Pola w aplikacji** | kolumny `*_enc` (patrz niżej), także w zapytaniach, kopiach `pg_dump` i u administratora bazy | AES-256-GCM w Go (`internal/crypto`) | `ASI_ENCRYPTION_KEYS` w `.env` (nigdy w bazie) |

Zwykły PostgreSQL nie ma wbudowanego szyfrowania plików bazy. `pgcrypto` to tylko funkcje SQL, a klucz
przechodzi wtedy przez zapytania i może trafić do logów, więc go nie używamy. Dlatego warstwa 1 to
`pg_tde`, a warstwa 2 jest w aplikacji.

## Warstwa 1: TDE (`pg_tde`)

- Obraz `asi-db` to [Percona Distribution for PostgreSQL 18](https://docs.percona.com/pg-tde/)
  (`docker/asi-db/Dockerfile`). Ta sama główna wersja co `postgres:18`, wire-compatible dla `pgx`.
- Nakładka `docker-compose.crypto.yml`, włączona przez `COMPOSE_FILE` w `.env` (domyślnie w `.env.example`).
- Konfiguracja przy pierwszym starcie pustej bazy: `docker/asi-db/initdb/10-pg_tde.sql`:
  - szyfr `aes_256`, klucz główny `asi-principal-1` w keyringu plikowym `asi-keyring`,
  - ten sam klucz jako domyślny dla baz i serwerowy (WAL),
  - `pg_tde.wal_encrypt = on`: WAL szyfrowany,
  - `default_table_access_method = tde_heap` dla bazy `asi`: migracje aplikacji tworzą tabele
    szyfrowane bez żadnych zmian w kodzie,
  - `pg_tde.enforce_encryption = on`: utworzenie niezaszyfrowanej tabeli w `asi` kończy się błędem.

## Warstwa 2: pola wrażliwe (AES-256-GCM)

`store.Sealer` z `internal/crypto` szyfruje każdą wartość osobno (losowy nonce 96 bit, tag
uwierzytelniający GCM; modyfikacja szyfrogramu jest wykrywana).

| kolumna | zawartość |
|---|---|
| `observations.data_enc` | dane obserwacji: usługi, wersje, a z etapu HTTP nagłówki, cookies, certyfikaty |
| `raw_outputs.data_enc` | surowe wyjście skanerów (XML nmapa itd.) |
| `assets.current_enc` | bieżący stan assetu |
| `asset_events.before_enc`, `after_enc` | historia zmian |
| `assets.user_note_enc`, `targets.note_enc` | notatki użytkowników |

Jawne zostają tylko pola potrzebne do wyszukiwania i filtrowania (IP, port, protokół, nazwa usługi,
stan). Na dysku i tak chroni je warstwa 1. Hasła i tokeny nie są szyfrowane, tylko hashowane (PBKDF2,
w bazie tylko hash tokenu).

Format wartości: `ASI1 | len(id) | id klucza | nonce | szyfrogram+tag`. Wartości bez prefiksu `ASI1`
(zapisane, zanim włączono klucze) są odczytywane bez zmian.

### Klucze i rotacja

```
ASI_ENCRYPTION_KEYS=k2:<base64 32 bajty>,k1:<base64 32 bajty>
```

- **Pierwszy** klucz szyfruje nowe wartości, wszystkie z listy odszyfrowują.
- Rotacja: nowy klucz na początek listy, stare zostają, dopóki są w bazie wartości nimi zaszyfrowane.
- `make env` generuje klucz dla nowej instalacji, `make env-keys` dopisuje go do istniejącego `.env`.
- Brak zmiennej: `asi` zapisuje jawnie i loguje `WARNING ... NOT encrypted`. Błędna zmienna: `asi`
  kończy się błędem, nie zapisuje po cichu jawnego tekstu.
- **Utrata klucza = utrata danych** z kolumn `_enc`. Kopię `.env` trzymaj poza maszyną ze skanerem.

## Włączenie

Nowa instalacja: `make env && make up` (wszystko domyślnie).

Istniejąca instalacja (`.env` sprzed SEC-6):

```bash
make env-keys     # dopisuje COMPOSE_FILE (TDE) i ASI_ENCRYPTION_KEYS do .env
make up           # nowa, zaszyfrowana baza asi-db (wolumen asi_db_tde_data)
asi db reseal     # zaszyfruj wartości _enc zapisane wcześniej jawnie (idempotentne)
```

Baza z TDE to **nowy wolumen**. Przebiegi ze starego `asi_db_data` (zwykły `postgres:18`) nie są
przenoszone, a stary wolumen zostaje nietknięty (`docker volume rm asi_asi_db_data`, gdy niepotrzebny).

Dane przeniesione z jawnej bazy (`pg_dump`/`pg_restore`) mają w kolumnach `_enc` wartości bez prefiksu
`ASI1`, więc `make crypto-check` pokaże je jako jawne. `asi db reseal` (Store.Reseal) przepisuje je przez
aktywny klucz w jednej transakcji; rekordy już zaszyfrowane pomija, więc można go uruchamiać wielokrotnie.
`asi db reseal -dry-run` tylko liczy. Bez `ASI_ENCRYPTION_KEYS` komenda odmawia pracy.

Odbudowa schematu (`DROP SCHEMA public CASCADE` + `pg_restore`) usuwa rozszerzenie `pg_tde`, a wraz z nim
szyfrowanie tabel: tabele wracają z dumpa na `heap`, mimo że baza ma `default_table_access_method = tde_heap`.
Po takiej operacji uruchom idempotentny `scripts/tde-reenable.sql` (rozszerzenie, istniejący key provider
i klucz z wolumenu `asi_db_keys`, `ALTER TABLE ... SET ACCESS METHOD tde_heap`, raport `pg_tde_is_encrypted`).
Potem `make crypto-check` musi wrócić do 9 OK / 0 FAIL, a `asi db reseal` domknąć kolumny `_enc`.

## Weryfikacja (do demo): `make crypto-check`

Skrypt `docker/asi-db/crypto-check.sh` uruchamiany w kontenerze `asi-db` (tylko odczyt + `CHECKPOINT`):

1. `pg_tde` załadowane, rozszerzenie w bazie, WAL szyfrowany, `enforce_encryption`, domyślne `tde_heap`.
2. Każda tabela aplikacji: `pg_tde_is_encrypted = true`.
3. Bierze wartość widoczną przez SQL (np. `127.0.0.1`) i szuka jej **w surowych plikach** tabel,
   indeksów i WAL na dysku: oczekiwane 0 trafień.
4. Każda kolumna `_enc`: liczba wartości zaszyfrowanych i jawnych, oczekiwane 0 jawnych.

Przykład (VM A, 21.11, po `asi scan` 127.0.0.1):

```
== 1. TDE (pg_tde) w serwerze
  [OK]   pg_tde w shared_preload_libraries
  [OK]   rozszerzenie pg_tde w bazie asi
  [OK]   WAL szyfrowany (pg_tde.wal_encrypt=on)
  [OK]   enforce_encryption=on (nie da sie utworzyc tabeli bez szyfrowania)
  [OK]   domyslny access method: tde_heap
== 2. Tabele aplikacji
  [OK]   zaszyfrowane tabele: 15/15
== 3. Surowe pliki na dysku (szukamy jawnego tekstu z bazy)
  wartosc widziana przez SQL: '127.0.0.1'
  [OK]   pliki tabel i indeksow aplikacji: 0 trafien
  [OK]   WAL: 0 trafien
== 4. Pola wrazliwe (_enc) szyfrowane w aplikacji (AES-256-GCM, prefiks ASI1)
         observations.data_enc              zaszyfrowane: 8  jawne: 0
         raw_outputs.data_enc               zaszyfrowane: 2  jawne: 0
  [OK]   brak jawnych wartosci w kolumnach _enc
Wynik: 9 OK, 0 FAIL
```

Próba kontrolna tą samą metodą na zwykłym `postgres:18` (21.11): znacznik tekstowy wstawiony do
tabeli jest w jej pliku na dysku (1 trafienie). Na `pg_tde`: 0 trafień w pliku tabeli, w WAL i w całym
`PGDATA`. Po restarcie kontenera dane czytają się poprawnie (klucz ładowany z keyringu).

## Ograniczenia (świadomie)

- **Keyring plikowy.** Klucz główny `pg_tde` leży w osobnym wolumenie (`asi_db_keys`), ale na tym samym
  hoście i niezaszyfrowany. To chroni przed wyciekiem samych plików bazy, kopii wolumenu danych i dysku z
  danymi bez wolumenu kluczy, ale nie przed kimś z dostępem roota do całego hosta. Produkcyjnie:
  zewnętrzny KMS. `pg_tde` obsługuje OpenBao/HashiCorp Vault (`pg_tde_add_global_key_provider_vault_v2`) i KMIP.
  Zmiana dotyczy tylko `10-pg_tde.sql` i compose.
- **Czego `pg_tde` nie szyfruje** (dokumentacja `pg_tde` 2.2): katalogi systemowe i statystyki planera
  (`pg_statistic` może zawierać przykładowe wartości kolumn) oraz pliki tymczasowe zapytań większych niż
  `work_mem`. Wrażliwe treści są dodatkowo w warstwie 2, więc nie trafiają tam jawnie.
- `pg_hba.conf` i inne pliki konfiguracyjne w `PGDATA` są jawne. To konfiguracja, nie dane
  (np. reguła dla `127.0.0.1/32`, którą `crypto-check` wypisuje jako trafienie poza danymi).
- Kopie zapasowe z WAL wymagają narzędzi `pg_tde` (`pg_tde_basebackup`, `pg_tde_archive_decrypt`).
  Zwykły `pg_dump` działa, ale zapisuje dane odszyfrowane przez TDE. Kolumny `_enc` zostają zaszyfrowane.
- DefectDojo ma własną bazę (`postgres` w compose), nieobjętą SEC-6. To system końcowy CBI AGH,
  szyfrowanie po ich stronie.
