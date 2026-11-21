-- Ponowne wlaczenie TDE (pg_tde) w istniejacej bazie asi-db.
--
-- Kiedy to potrzebne: `DROP SCHEMA public CASCADE` (odbudowa schematu z dumpa)
-- usuwa rozszerzenie pg_tde razem z obiektami schematu. Keyring i konfiguracja
-- key providera zostaja na dysku (PGDATA/pg_tde, wolumen asi_db_keys), wiec
-- ponowne wywolanie pg_tde_add_global_key_provider_file konczy sie bledem
-- `Key provider "asi-keyring" already exists`. Ten skrypt jest idempotentny:
-- sprawdza stan (provider, klucz domyslny, klucz serwerowy) i robi tylko to,
-- czego brakuje, a tabele pozostawione na heap przełącza na tde_heap.
--
-- Uzycie:
--   docker cp scripts/tde-reenable.sql asi-asi-db-1:/tmp/tde-reenable.sql
--   docker exec asi-asi-db-1 psql -U asi -d asi -v ON_ERROR_STOP=1 -f /tmp/tde-reenable.sql
--   make crypto-check
-- Opis: docs/guide/encryption.md

CREATE EXTENSION IF NOT EXISTS pg_tde;

-- 1. Key provider plikowy (keyring asi_db_keys -> /var/lib/asi-keys/pg_tde.per).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tde_list_all_global_key_providers() WHERE name = 'asi-keyring') THEN
    PERFORM pg_tde_add_global_key_provider_file('asi-keyring', '/var/lib/asi-keys/pg_tde.per');
    RAISE NOTICE 'dodano key provider asi-keyring';
  ELSE
    RAISE NOTICE 'key provider asi-keyring juz jest - pomijam';
  END IF;
END $$;

-- 2. Klucz glowny: domyslny dla baz i serwerowy (WAL). Set jest idempotentny,
--    ale tworzenie klucza o istniejacej nazwie nie jest, wiec sprawdzamy wpisy.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tde_default_key_info() WHERE key_name = 'asi-principal-1') THEN
    PERFORM pg_tde_create_key_using_global_key_provider('asi-principal-1', 'asi-keyring');
    RAISE NOTICE 'utworzono klucz asi-principal-1';
  END IF;
  PERFORM pg_tde_set_default_key_using_global_key_provider('asi-principal-1', 'asi-keyring');
  RAISE NOTICE 'klucz domyslny: asi-principal-1';
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tde_server_key_info() WHERE key_name = 'asi-principal-1') THEN
    PERFORM pg_tde_set_server_key_using_global_key_provider('asi-principal-1', 'asi-keyring');
    RAISE NOTICE 'klucz serwerowy (WAL): asi-principal-1';
  ELSE
    RAISE NOTICE 'klucz serwerowy juz ustawiony - pomijam';
  END IF;
END $$;

-- 3. Ustawienia bazy (migracje tworza wtedy tabele szyfrowane, jawne sa zablokowane).
ALTER DATABASE asi SET default_table_access_method = 'tde_heap';
ALTER DATABASE asi SET pg_tde.enforce_encryption = on;

-- 4. Tabele utworzone, zanim rozszerzenie wrocilo, sa jeszcze na heap.
--    ALTER TABLE ... SET ACCESS METHOD przepisuje tabele i jej indeksy.
DO $$
DECLARE r record; n int := 0;
BEGIN
  FOR r IN SELECT c.oid::regclass AS t FROM pg_class c
             JOIN pg_namespace nsp ON nsp.oid = c.relnamespace
             JOIN pg_am a ON a.oid = c.relam
            WHERE nsp.nspname = 'public' AND c.relkind = 'r' AND a.amname = 'heap'
            ORDER BY 1
  LOOP
    EXECUTE format('ALTER TABLE %s SET ACCESS METHOD tde_heap', r.t);
    RAISE NOTICE 'przelaczono % na tde_heap', r.t;
    n := n + 1;
  END LOOP;
  RAISE NOTICE 'tabel przelaczonych: %', n;
END $$;

-- 5. Podsumowanie.
SELECT c.relname, a.amname, pg_tde_is_encrypted(c.oid) AS encrypted
  FROM pg_class c
  JOIN pg_namespace nsp ON nsp.oid = c.relnamespace
  JOIN pg_am a ON a.oid = c.relam
 WHERE nsp.nspname = 'public' AND c.relkind = 'r'
 ORDER BY 2, 1;
