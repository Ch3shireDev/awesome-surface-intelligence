# asi-db z szyfrowaniem danych w spoczynku (TDE, pg_tde od Percony).
# Bazowy obraz to Percona Distribution for PostgreSQL 18 (ta sama glowna wersja
# co postgres:18 w docker-compose.yml); pg_tde wymaga ich patchowanego serwera.
# Jedyna zmiana wzgledem obrazu: katalog na keyring pg_tde nalezacy do
# uzytkownika postgres (uid 26), zeby nazwany wolumen z kluczami dziedziczyl
# wlasciciela przy pierwszym utworzeniu. Patrz docs/guide/encryption.md.
FROM percona/percona-distribution-postgresql:18.7.1-1

USER root
RUN mkdir -p /var/lib/asi-keys && chown 26:26 /var/lib/asi-keys && chmod 700 /var/lib/asi-keys
USER 26
