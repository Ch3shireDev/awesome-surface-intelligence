#!/bin/sh
# Dowod szyfrowania danych w spoczynku w asi-db (SEC-6). Uruchamiane W kontenerze
# asi-db: `make crypto-check` (docker compose exec -T asi-db sh < ten plik).
# Tylko odczyt + CHECKPOINT; niczego nie zmienia w danych.
set -eu

DB="${POSTGRES_DB:-asi}"
U="${POSTGRES_USER:-asi}"
q() { psql -U "$U" -d "$DB" -qAtX -v ON_ERROR_STOP=1 -c "$1"; }
ok=0; fail=0
pass() { echo "  [OK]   $1"; ok=$((ok+1)); }
bad()  { echo "  [FAIL] $1"; fail=$((fail+1)); }

echo "== 1. TDE (pg_tde) w serwerze"
case "$(q 'SHOW shared_preload_libraries')" in
  *pg_tde*) pass "pg_tde w shared_preload_libraries" ;;
  *) bad "pg_tde NIE jest ladowane - asi-db bez docker-compose.crypto.yml? (COMPOSE_FILE w .env)"
     echo; echo "Wynik: $ok OK, $fail FAIL"; exit 1 ;;
esac
[ "$(q "SELECT count(*) FROM pg_extension WHERE extname='pg_tde'")" = 1 ] \
  && pass "rozszerzenie pg_tde w bazie $DB" || bad "brak CREATE EXTENSION pg_tde w $DB"
[ "$(q 'SHOW pg_tde.wal_encrypt')" = on ] && pass "WAL szyfrowany (pg_tde.wal_encrypt=on)" || bad "WAL NIE jest szyfrowany"
[ "$(q 'SHOW pg_tde.enforce_encryption')" = on ] \
  && pass "enforce_encryption=on (nie da sie utworzyc tabeli bez szyfrowania)" || bad "enforce_encryption wylaczone"
[ "$(q 'SHOW default_table_access_method')" = tde_heap ] \
  && pass "domyslny access method: tde_heap" || bad "domyslny access method nie jest tde_heap"
echo "  klucz glowny (domyslny): $(q "SELECT * FROM pg_tde_default_key_info()" 2>/dev/null || echo '?')"

echo
echo "== 2. Tabele aplikacji"
q "SELECT c.relname, a.amname, pg_tde_is_encrypted(c.oid::regclass)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_am a ON a.oid=c.relam
   WHERE n.nspname='public' AND c.relkind='r' ORDER BY 1" > /tmp/tables.txt
total=$(wc -l < /tmp/tables.txt); enc=$(grep -c '|t$' /tmp/tables.txt || true)
if [ "$total" -gt 0 ] && [ "$enc" = "$total" ]; then pass "zaszyfrowane tabele: $enc/$total"
else bad "zaszyfrowane tabele: $enc/$total"; grep -v '|t$' /tmp/tables.txt | sed 's/^/         jawna: /' || true; fi

echo
echo "== 3. Surowe pliki na dysku (szukamy jawnego tekstu z bazy)"
marker=$(q "SELECT asset_key FROM observations WHERE asset_key <> '' LIMIT 1" 2>/dev/null || true)
[ -n "$marker" ] || marker=$(q "SELECT id FROM runs LIMIT 1" 2>/dev/null || true)
if [ -z "$marker" ]; then
  echo "  (brak danych w bazie - zrob najpierw skan, np. make asi-scan, i powtorz)"
else
  q 'CHECKPOINT' >/dev/null
  echo "  wartosc widziana przez SQL: '$marker'"
  hits=0
  for t in $(cut -d'|' -f1 /tmp/tables.txt); do
    for f in $(q "SELECT pg_relation_filepath(oid) FROM pg_class WHERE oid='$t'::regclass
                  UNION ALL SELECT pg_relation_filepath(indexrelid) FROM pg_index WHERE indrelid='$t'::regclass"); do
      if grep -qF -- "$marker" "$PGDATA/$f"* 2>/dev/null; then hits=$((hits+1)); echo "         jawnie w: $f ($t)"; fi
    done
  done
  [ "$hits" = 0 ] && pass "pliki tabel i indeksow aplikacji: 0 trafien" || bad "pliki tabel/indeksow: $hits trafien"
  walhits=$(grep -rlF -- "$marker" "$PGDATA/pg_wal" 2>/dev/null | wc -l)
  [ "$walhits" = 0 ] && pass "WAL: 0 trafien" || bad "WAL: $walhits plikow z jawnym tekstem"
  echo "  caly PGDATA - pliki z ta wartoscia (poza danymi aplikacji):"
  grep -rlF -- "$marker" "$PGDATA" 2>/dev/null | sed "s|^$PGDATA/|         |" || true
  echo "  (np. pg_hba.conf to konfiguracja; katalogi systemowe i statystyki pg_tde nie szyfruje,"
  echo "   patrz docs/guide/encryption.md - ograniczenia)"
fi

echo
echo "== 4. Pola wrazliwe (_enc) szyfrowane w aplikacji (AES-256-GCM, prefiks ASI1)"
q "SELECT table_name || '.' || column_name FROM information_schema.columns
   WHERE table_schema='public' AND column_name LIKE '%\_enc' ORDER BY 1" > /tmp/enc.txt
plain_total=0
while IFS= read -r tc; do
  t=${tc%%.*}; c=${tc#*.}
  r=$(q "SELECT count(*) FILTER (WHERE $c IS NOT NULL AND substring($c from 1 for 4) = 'ASI1'::bytea),
                count(*) FILTER (WHERE $c IS NOT NULL AND substring($c from 1 for 4) <> 'ASI1'::bytea)
         FROM $t")
  s=${r%%|*}; p=${r#*|}; plain_total=$((plain_total+p))
  printf '         %-34s zaszyfrowane: %s  jawne: %s\n' "$tc" "$s" "$p"
done < /tmp/enc.txt
[ "$plain_total" = 0 ] && pass "brak jawnych wartosci w kolumnach _enc" \
  || bad "$plain_total jawnych wartosci w kolumnach _enc (ASI_ENCRYPTION_KEYS nieustawione przy zapisie?)"

echo
echo "Wynik: $ok OK, $fail FAIL"
[ "$fail" = 0 ]
