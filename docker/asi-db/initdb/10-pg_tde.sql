-- Wlaczenie TDE (pg_tde) w asi-db. Uruchamiane RAZ, przy inicjalizacji pustej
-- bazy (docker-entrypoint-initdb.d), jako superuser asi w bazie asi.
-- Serwer startuje z -c shared_preload_libraries=pg_tde (docker-compose.crypto.yml).
--
-- Efekt:
--   * klucz glowny AES-256 w keyringu /var/lib/asi-keys (osobny wolumen, nie PGDATA),
--   * wszystkie tabele tworzone w bazie asi (migracje asi) domyslnie jako tde_heap,
--     a tworzenie niezaszyfrowanych tabel jest zablokowane (enforce_encryption),
--   * WAL szyfrowany (po restarcie serwera, ktory entrypoint robi po init).
-- Weryfikacja: make crypto-check. Opis: docs/guide/encryption.md.

ALTER SYSTEM SET pg_tde.cipher = 'aes_256';
SELECT pg_reload_conf();
SET pg_tde.cipher = 'aes_256';

CREATE EXTENSION IF NOT EXISTS pg_tde;

-- Keyring plikowy (dev/hackathon). Produkcyjnie: OpenBao/Vault albo KMIP
-- (pg_tde_add_global_key_provider_vault_v2 / _kmip) - patrz docs.
SELECT pg_tde_add_global_key_provider_file('asi-keyring', '/var/lib/asi-keys/pg_tde.per');
SELECT pg_tde_create_key_using_global_key_provider('asi-principal-1', 'asi-keyring');
-- ten sam klucz glowny: domyslny dla baz i serwerowy (WAL)
SELECT pg_tde_set_default_key_using_global_key_provider('asi-principal-1', 'asi-keyring');
SELECT pg_tde_set_server_key_using_global_key_provider('asi-principal-1', 'asi-keyring');

ALTER SYSTEM SET pg_tde.wal_encrypt = on;
ALTER DATABASE asi SET default_table_access_method = 'tde_heap';
ALTER DATABASE asi SET pg_tde.enforce_encryption = on;
