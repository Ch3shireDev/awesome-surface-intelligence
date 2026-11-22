#!/bin/bash
# Test DEV-11 (zarzadzanie kontami: role, blokada, reset hasla, usuwanie) na dzialajacej
# instancji panelu. Tylko localhost. Tworzy konto test-users-* i je usuwa.
# Uzycie: BASE=http://127.0.0.1:18090 bash scripts/test-users.sh
set -u
BASE=${BASE:-http://127.0.0.1:18090}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
AJ=$(mktemp); UJ=$(mktemp); A2J=$(mktemp); rm -f "$AJ" "$UJ" "$A2J" "$A2J"
set -a; . "$ROOT/.env"; set +a
ok=0; bad=0
chk() { # chk <opis> <oczekiwane> <otrzymane>
  if [ "$2" = "$3" ]; then ok=$((ok+1)); printf '  OK   %-54s %s\n' "$1" "$3";
  else bad=$((bad+1)); printf '  FAIL %-54s oczekiwano=%s otrzymano=%s\n' "$1" "$2" "$3"; fi
}
code() { curl -s -o /tmp/out.json -w '%{http_code}' "$@"; }
jqv() { python3 -c "import json;d=json.load(open('/tmp/out.json'));print($1)" 2>/dev/null; }
LOGIN=$(printf '{"username":"%s","password":"%s"}' "$ASI_ADMIN_USER" "$ASI_ADMIN_PASSWORD")

echo "1. brak uwierzytelnienia / obca rola"
chk "PATCH /users/1 bez sesji" 401 "$(code -X PATCH -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/users/1")"
chk "DELETE /users/1 bez sesji" 401 "$(code -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/users/1")"
chk "POST /api/v1/login admin" 200 "$(code -c "$AJ" -H 'Content-Type: application/json' -d "$LOGIN" "$BASE/api/v1/login")"

echo "2. nowe konto przez admina"
N="test-users-$$"
chk "POST /api/v1/users (viewer)" 200 "$(code -b "$AJ" -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d "{\"username\":\"$N\",\"password\":\"haslo-testowe\",\"role\":\"viewer\"}" "$BASE/api/v1/users")"
UID2=$(jqv 'd["id"]')
echo "   id=$UID2 login=$N"
chk "nowe konto loguje sie" 200 "$(code -c "$UJ" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$N\",\"password\":\"haslo-testowe\"}" "$BASE/api/v1/login")"
chk "viewer nie moze PATCH /users (403)" 403 "$(code -b "$UJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"role":"admin"}' "$BASE/api/v1/users/$UID2")"

echo "3. zmiana roli"
chk "PATCH role=operator" 200 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"role":"operator"}' "$BASE/api/v1/users/$UID2")"
chk "rola zapisana" operator "$(jqv 'd["role"]')"
chk "PATCH zla rola -> 400" 400 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"role":"root"}' "$BASE/api/v1/users/$UID2")"
chk "PATCH nieistniejace konto -> 400" 400 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"role":"viewer"}' "$BASE/api/v1/users/999999")"

echo "4. reset hasla uniewaznia sesje"
chk "PATCH password" 200 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"password":"inne-haslo-123"}' "$BASE/api/v1/users/$UID2")"
chk "stara sesja -> 401" 401 "$(code -b "$UJ" "$BASE/api/v1/me")"
chk "stare haslo -> 401" 401 "$(code -H 'Content-Type: application/json' \
  -d "{\"username\":\"$N\",\"password\":\"haslo-testowe\"}" "$BASE/api/v1/login")"
chk "nowe haslo -> 200" 200 "$(code -c "$UJ" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$N\",\"password\":\"inne-haslo-123\"}" "$BASE/api/v1/login")"
chk "krotkie haslo -> 400" 400 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"password":"krotkie"}' "$BASE/api/v1/users/$UID2")"

echo "5. blokada konta dziala natychmiast"
chk "PATCH disabled=true" 200 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"disabled":true}' "$BASE/api/v1/users/$UID2")"
chk "zablokowany: istniejaca sesja 401" 401 "$(code -b "$UJ" "$BASE/api/v1/me")"
chk "zablokowany: logowanie 401" 401 "$(code -H 'Content-Type: application/json' \
  -d "{\"username\":\"$N\",\"password\":\"inne-haslo-123\"}" "$BASE/api/v1/login")"
chk "lista pokazuje disabled" true "$(code -b "$AJ" "$BASE/api/v1/users" >/dev/null; jqv "str([u['disabled'] for u in d if u['id']==$UID2][0]).lower()")"
chk "PATCH disabled=false" 200 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"disabled":false}' "$BASE/api/v1/users/$UID2")"
chk "odblokowany: logowanie 200" 200 "$(code -c "$UJ" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$N\",\"password\":\"inne-haslo-123\"}" "$BASE/api/v1/login")"

echo "6. ostatni admin jest chroniony"
MEID=$(code -b "$AJ" "$BASE/api/v1/me" >/dev/null; jqv 'd["id"]')
chk "PATCH siebie role=viewer -> 409" 409 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"role":"viewer"}' "$BASE/api/v1/users/$MEID")"
chk "PATCH siebie disabled -> 409" 409 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"disabled":true}' "$BASE/api/v1/users/$MEID")"
chk "DELETE siebie -> 409" 409 "$(code -b "$AJ" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/users/$MEID")"

echo "7. drugi admin zmienia pierwszego (guard nie jest slepy)"
A2="test-admin-$$"
chk "POST drugi admin" 200 "$(code -b "$AJ" -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d "{\"username\":\"$A2\",\"password\":\"haslo-admina-1\",\"role\":\"admin\"}" "$BASE/api/v1/users")"
A2ID=$(jqv 'd["id"]')
chk "degracja siebie przy drugim adminie -> 200" 200 "$(code -b "$AJ" -X PATCH -H 'X-ASI: 1' \
  -H 'Content-Type: application/json' -d '{"role":"operator"}' "$BASE/api/v1/users/$MEID")"
chk "po degradacji: admin-only trasa -> 403" 403 "$(code -b "$AJ" "$BASE/api/v1/users")"
# dalej pracujemy jako drugi admin (to dowod, ze zmiana roli dziala od razu)
chk "login drugiego admina" 200 "$(code -c "$A2J" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$A2\",\"password\":\"haslo-admina-1\"}" "$BASE/api/v1/login")"
chk "drugi admin przywraca role admin" 200 "$(code -b "$A2J" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' \
  -d '{"role":"admin"}' "$BASE/api/v1/users/$MEID")"
chk "DELETE konto testowe" 200 "$(code -b "$A2J" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/users/$UID2")"
chk "DELETE drugi admin (siebie, jest jeszcze inny admin)" 200 "$(code -b "$A2J" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/users/$A2ID")"
chk "usunieta sesja drugiego admina -> 401" 401 "$(code -b "$A2J" "$BASE/api/v1/me")"
chk "DELETE jeszcze raz -> 400" 400 "$(code -b "$AJ" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/users/$UID2")"

echo "8. dziennik audytu"
code -b "$AJ" "$BASE/api/v1/audit" >/dev/null
chk "audit ma user_update" 1 "$(jqv 'int(sum(1 for a in d if a["action"]=="user_update")>0)')"
chk "audit ma user_delete" 1 "$(jqv 'int(sum(1 for a in d if a["action"]=="user_delete")>0)')"

rm -f "$AJ" "$UJ" "$A2J"
echo
echo "Wynik: $ok OK, $bad FAIL"
[ "$bad" -eq 0 ]
