#!/bin/sh
# Kontrola kompletnosci schematu asi-db: migracje, klucze glowne i ograniczenia UNIQUE,
# ktorych wymaga kod (ON CONFLICT), oraz brak tabel na heap.
#
# Po co: `pg_restore` uruchomiony na istniejacym schemacie bez --clean/--create potrafi
# pominac definicje indeksow i ograniczen. Odczyty wtedy dzialaja, a zapis konczy sie
# bledem `there is no unique or exclusion constraint matching the ON CONFLICT
# specification (SQLSTATE 42P10)` - najlepiej wykryc to przed demem, nie w trakcie.
#
# Uzycie: make schema-check   (docker compose exec -T asi-db sh < ten plik)
# Tylko odczyt - niczego nie zmienia.
set -eu

DB="${POSTGRES_DB:-asi}"
U="${POSTGRES_USER:-asi}"
q() { psql -U "$U" -d "$DB" -qAtX -v ON_ERROR_STOP=1 -c "$1"; }
ok=0; fail=0
pass() { echo "  [OK]   $1"; ok=$((ok+1)); }
bad()  { echo "  [FAIL] $1"; fail=$((fail+1)); }

echo "== 1. Migracje ($DB)"
applied=$(q "SELECT count(*) FROM schema_migrations")
last=$(q "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")
if [ "${applied:-0}" -ge 5 ]; then pass "migracje: $applied (ostatnia $last)"
else bad "migracje: $applied (oczekiwane >= 5) - uruchom 'asi db migrate'"; fi

echo
echo "== 2. Indeksy i ograniczenia, na ktorych opiera sie kod (ON CONFLICT)"
missing=0
for idx in targets_set_id_value_key assets_key_key users_username_key \
           schedules_name_key target_sets_name_key api_tokens_token_hash_key \
           chunks_pkey raw_outputs_pkey; do
  if [ "$(q "SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname='$idx'")" = 1 ]; then
    pass "$idx"
  else bad "$idx brak - pg_restore pominol definicje? (migracje + pg_restore --data-only)"; missing=$((missing+1)); fi
done
total=$(q "SELECT count(*) FROM pg_indexes WHERE schemaname='public'")
if [ "${total:-0}" -ge 28 ]; then pass "indeksow w schemacie public: $total (>= 28)"
else bad "indeksow w schemacie public: $total (oczekiwane >= 28)"; missing=$((missing+1)); fi

echo
echo "== 3. Dane nie naruszaja unikalnosci (inaczej zapis padnie)"
dups=$(q "SELECT
   (SELECT count(*) FROM (SELECT set_id, value FROM targets GROUP BY 1,2 HAVING count(*)>1) t)
 + (SELECT count(*) FROM (SELECT key FROM assets GROUP BY 1 HAVING count(*)>1) a)
 + (SELECT count(*) FROM (SELECT username FROM users GROUP BY 1 HAVING count(*)>1) u)
 + (SELECT count(*) FROM (SELECT name FROM schedules GROUP BY 1 HAVING count(*)>1) s)")
[ "${dups:-0}" = 0 ] && pass "brak duplikatow w kluczach unikalnych" || bad "duplikaty w kluczach unikalnych: $dups grup"

echo
echo "== 4. Tabele (TDE; szczegoly: make crypto-check)"
q "SELECT c.relname, a.amname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     JOIN pg_am a ON a.oid=c.relam WHERE n.nspname='public' AND c.relkind='r' ORDER BY 1" > /tmp/schema_tables.txt
total_t=$(wc -l < /tmp/schema_tables.txt); heap_t=$(grep -c '|heap$' /tmp/schema_tables.txt || true)
if [ "${heap_t:-0}" = 0 ]; then pass "tabele: $total_t, na heap: 0"
else bad "tabele: $total_t, na heap: $heap_t - uruchom scripts/tde-reenable.sql"; fi

echo
echo "Wynik: $ok OK, $fail FAIL"
[ "$fail" = 0 ]
