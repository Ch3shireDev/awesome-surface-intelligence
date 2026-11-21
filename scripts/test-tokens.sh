#!/bin/bash
# Test DEV-3 (tokeny API w GUI) na dzialajacej instancji panelu. Tylko localhost.
# Uzycie: BASE=http://127.0.0.1:8099 bash scripts/test-tokens.sh
set -u
BASE=${BASE:-http://127.0.0.1:8090}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
J=$(mktemp); rm -f "$J"
set -a; . "$ROOT/.env"; set +a
ok=0; bad=0
chk() { # chk <opis> <oczekiwane> <otrzymane>
  if [ "$2" = "$3" ]; then ok=$((ok+1)); printf '  OK   %-52s %s\n' "$1" "$3";
  else bad=$((bad+1)); printf '  FAIL %-52s oczekiwano=%s otrzymano=%s\n' "$1" "$2" "$3"; fi
}
code() { curl -s -o /tmp/out.json -w '%{http_code}' "$@"; }
jqv() { python3 -c "import json;d=json.load(open('/tmp/out.json'));print($1)" 2>/dev/null; }

echo "1. brak uwierzytelnienia"
chk "GET /api/v1/tokens bez sesji" 401 "$(code "$BASE/api/v1/tokens")"
chk "POST /api/v1/tokens bez sesji" 401 "$(code -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/tokens")"

echo "2. logowanie admina"
LOGIN=$(printf '{"username":"%s","password":"%s"}' "$ASI_ADMIN_USER" "$ASI_ADMIN_PASSWORD")
chk "POST /api/v1/login" 200 "$(code -c "$J" -H 'Content-Type: application/json' -d "$LOGIN" "$BASE/api/v1/login")"

echo "3. lista tokenow (sesja oznaczona jako current)"
chk "GET /api/v1/tokens" 200 "$(code -b "$J" "$BASE/api/v1/tokens")"
chk "dokladnie jeden current" 1 "$(jqv 'sum(1 for t in d if t["current"])')"

echo "4. utworzenie tokenu API"
chk "POST /api/v1/tokens" 200 "$(code -b "$J" -H 'X-ASI: 1' -H 'Content-Type: application/json' -d '{"name":"test-goose","days":1}' "$BASE/api/v1/tokens")"
TOK=$(jqv 'd["token"]')
case "$TOK" in asi_*) chk "format tokenu asi_ + 64 hex" 68 "${#TOK}";; *) chk "format tokenu asi_..." "asi_*" "$TOK";; esac
code -b "$J" "$BASE/api/v1/tokens" >/dev/null
chk "nowy token nie jest current" 1 "$(jqv 'sum(1 for t in d if t["name"]=="test-goose" and not t["current"])')"
TID=$(jqv '[t["id"] for t in d if t["name"]=="test-goose"][0]')
echo "   id=$TID"

echo "5. token dziala jako Bearer (bez cookie i bez CSRF)"
chk "GET /api/v1/assets z Bearer" 200 "$(code -H "Authorization: Bearer $TOK" "$BASE/api/v1/assets")"
chk "GET /api/v1/me z Bearer" 200 "$(code -H "Authorization: Bearer $TOK" "$BASE/api/v1/me")"
chk "zly token -> 401" 401 "$(code -H "Authorization: Bearer asi_zle" "$BASE/api/v1/me")"

echo "6. CSRF: cookie bez naglowka X-ASI nie tworzy tokenu"
chk "POST /tokens bez X-ASI -> 403" 403 "$(code -b "$J" -H 'Content-Type: application/json' -d '{"name":"x"}' "$BASE/api/v1/tokens")"

echo "7. uniewaznienie tokenu"
chk "DELETE /api/v1/tokens/$TID" 200 "$(code -b "$J" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/tokens/$TID")"
chk "usuniety token -> 401" 401 "$(code -H "Authorization: Bearer $TOK" "$BASE/api/v1/me")"
chk "DELETE jeszcze raz -> 404" 404 "$(code -b "$J" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/tokens/$TID")"
chk "DELETE nieistniejacy -> 404" 404 "$(code -b "$J" -X DELETE -H 'X-ASI: 1' "$BASE/api/v1/tokens/999999")"

echo "8. dziennik audytu"
code -b "$J" "$BASE/api/v1/audit" >/dev/null
chk "audit ma token_create" 1 "$(jqv 'int(sum(1 for a in d if a["action"]=="token_create")>0)')"
chk "audit ma token_revoke" 1 "$(jqv 'int(sum(1 for a in d if a["action"]=="token_revoke")>0)')"

echo "9. walidacja wejscia"
chk "days=-5 -> 200" 200 "$(code -b "$J" -H 'X-ASI: 1' -H 'Content-Type: application/json' -d '{"name":"t2","days":-5}' "$BASE/api/v1/tokens")"
chk "days ujemne zapisane jako 0" 0 "$(jqv 'd["days"]')"
chk "pusta nazwa -> 200" 200 "$(code -b "$J" -H 'X-ASI: 1' -H 'Content-Type: application/json' -d '{"days":0}' "$BASE/api/v1/tokens")"
chk "domyslna nazwa" api "$(jqv 'd["name"]')"
chk "zly JSON -> 400" 400 "$(code -b "$J" -H 'X-ASI: 1' -H 'Content-Type: application/json' -d 'nie-json' "$BASE/api/v1/tokens")"
chk "brak tokenu w bazie po revoke" 0 "$(code -b "$J" "$BASE/api/v1/tokens" >/dev/null; jqv 'sum(1 for t in d if t["name"]=="test-goose")')"

echo
echo "WYNIK: OK=$ok FAIL=$bad"
[ "$bad" -eq 0 ]
