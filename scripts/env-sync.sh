#!/bin/sh
# Dopisuje do ISTNIEJACEGO .env klucze z .env.example, ktorych w nim brakuje (po pullu z nowymi
# funkcjami compose nie startuje bez nowych zmiennych). Istniejacych wartosci NIE zmienia.
# Placeholdery CHANGE_ME* dostaja wygenerowane sekrety, jak w `make env`.
set -eu
[ -f .env ] || { echo "brak .env - uruchom: make env"; exit 1; }
asi_dbp=$(grep -E '^ASI_DB_PASSWORD=' .env | cut -d= -f2- || true)
[ -n "$asi_dbp" ] || asi_dbp=$(openssl rand -hex 16)
added=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  key=${line%%=*}
  grep -q "^${key}=" .env && continue
  val=${line#*=}
  case "$key" in
    DD_SECRET_KEY) val=$(openssl rand -hex 32) ;;
    DD_CREDENTIAL_AES_256_KEY) val=$(openssl rand -hex 16) ;;
    DD_ADMIN_PASSWORD) val=$(openssl rand -hex 12) ;;
    ASI_ENCRYPTION_KEYS) val="k1:$(openssl rand -base64 32)" ;;
  esac
  val=$(printf '%s' "$val" | sed -e "s|CHANGE_ME_ASI_DB|$asi_dbp|g" -e "s|CHANGE_ME_ASI_ADMIN|$(openssl rand -hex 12)|g")
  [ $added -eq 0 ] && printf '\n# --- dopisane przez make env-sync (%s) ---\n' "$(date +%F)" >> .env
  printf '%s=%s\n' "$key" "$val" >> .env
  echo "dopisano $key"
  added=$((added+1))
done < .env.example
[ $added -eq 0 ] && echo ".env kompletny" || echo "dopisano $added kluczy (sprawdz: grep -n 'env-sync' -A$added .env)"
