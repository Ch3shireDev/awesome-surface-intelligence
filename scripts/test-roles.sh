#!/bin/bash
# Test DEV-12 (wyrównanie ról z treścią zadania, pkt 13 PDF) na działającej instancji panelu.
# Macierz: viewer = odczyt, analyst = + modyfikacja istniejących wartości, operator =
# + dodawanie/usuwanie/uruchamianie, admin = + konta. Tylko localhost; tworzy i usuwa
# konta test-roles-* oraz zbiór celów test-roles-*.
# Użycie: BASE=http://127.0.0.1:8090 bash scripts/test-roles.sh
set -u
BASE=${BASE:-http://127.0.0.1:8090}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
J=$(mktemp); rm -f "$J"
set -a; . "$ROOT/.env"; set +a
ok=0; bad=0
chk() { # chk <opis> <oczekiwane> <otrzymane>
  if [ "$2" = "$3" ]; then ok=$((ok+1)); printf '  OK   %-58s %s\n' "$1" "$3";
  else bad=$((bad+1)); printf '  FAIL %-58s oczekiwano=%s otrzymano=%s\n' "$1" "$2" "$3"; fi
}
code() { curl -s -o /tmp/out.json -w '%{http_code}' "$@"; }
jqv() { python3 -c "import json;d=json.load(open('/tmp/out.json'));print($1)" 2>/dev/null; }
PW="haslo-testowe-1"
SUF=$$
SET="test-roles-$SUF"
login() { code -c "$1" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$2\",\"password\":\"${3:-$PW}\"}" "$BASE/api/v1/login"; }
POST() { code -b "$J" -X POST -H 'X-ASI: 1' -H 'Content-Type: application/json' -d "$1" "$BASE$2"; }
PUT()  { code -b "$J" -X PUT  -H 'X-ASI: 1' -H 'Content-Type: application/json' -d "$1" "$BASE$2"; }
PATCH(){ code -b "$J" -X PATCH -H 'X-ASI: 1' -H 'Content-Type: application/json' -d "$1" "$BASE$2"; }
DEL()  { code -b "$J" -X DELETE -H 'X-ASI: 1' "$BASE$1"; }

echo "0. administrator i konta testowe (viewer/analyst/operator)"
chk "login admin" 200 "$(login "$J" "$ASI_ADMIN_USER" "$ASI_ADMIN_PASSWORD")"
for r in viewer analyst operator; do
  chk "utworzenie test-roles-$r" 200 "$(POST "{\"username\":\"test-roles-$r-$SUF\",\"password\":\"$PW\",\"role\":\"$r\"}" /api/v1/users)"
  eval "${r^^}ID=\$(jqv 'd[\"id\"]')"
done
chk "utworzenie celu (operator) w zbiorze $SET" 200 \
  "$(POST "{\"set\":\"$SET\",\"text\":\"192.0.2.77\"}" /api/v1/targets)"
chk "lista celów zbioru" 200 "$(code -b "$J" "$BASE/api/v1/targets?set=$SET")"
TID=$(jqv '[t["id"] for t in d if t["target"]=="192.0.2.77"][0]')
echo "   target id=$TID"

echo "1. viewer = odczyt"
login "$J" "test-roles-viewer-$SUF" >/dev/null
chk "GET /assets" 200 "$(code -b "$J" "$BASE/api/v1/assets")"
chk "GET /targets" 200 "$(code -b "$J" "$BASE/api/v1/targets?set=$SET")"
chk "PATCH /asset -> 403" 403 "$(PATCH '{"key":"x","tags":[]}' /api/v1/asset)"
chk "PUT /targets/{id} -> 403" 403 "$(PUT "{\"set\":\"$SET\",\"target\":\"192.0.2.77\",\"enabled\":true}" "/api/v1/targets/$TID")"
chk "POST /targets -> 403" 403 "$(POST "{\"set\":\"$SET\",\"text\":\"192.0.2.78\"}" /api/v1/targets)"
chk "GET /users -> 403" 403 "$(code -b "$J" "$BASE/api/v1/users")"

echo "2. analyst = modyfikacja istniejących wartości"
login "$J" "test-roles-analyst-$SUF" >/dev/null
chk "PUT /targets/{id} (tagi) -> 200" 200 \
  "$(PUT "{\"set\":\"$SET\",\"target\":\"192.0.2.77\",\"enabled\":true,\"tags\":[\"dev12\"],\"note\":\"od analysty\"}" "/api/v1/targets/$TID")"
chk "PUT zmiana wartości -> 400" 400 \
  "$(PUT "{\"set\":\"$SET\",\"target\":\"192.0.2.99\",\"enabled\":true}" "/api/v1/targets/$TID")"
chk "PUT nieistniejący cel -> 404" 404 \
  "$(PUT "{\"set\":\"$SET\",\"target\":\"192.0.2.77\",\"enabled\":true}" "/api/v1/targets/999999")"
chk "POST /targets (dodawanie) -> 403" 403 "$(POST "{\"set\":\"$SET\",\"text\":\"192.0.2.78\"}" /api/v1/targets)"
chk "DELETE /targets/{id} -> 403" 403 "$(DEL "/api/v1/targets/$TID")"
chk "POST /schedules (tworzenie) -> 403" 403 \
  "$(POST "{\"name\":\"x-$SUF\",\"set\":\"$SET\",\"cron\":\"0 3 * * *\",\"window_minutes\":30,\"enabled\":false}" /api/v1/schedules)"
chk "POST /scans (start) -> 403" 403 \
  "$(POST "{\"set\":\"$SET\",\"parallel\":1,\"rate\":50,\"ports\":\"top100\"}" /api/v1/scans)"

echo "3. operator = dodawanie, usuwanie, harmonogramy"
login "$J" "test-roles-operator-$SUF" >/dev/null
chk "POST /targets (dodawanie) -> 200" 200 "$(POST "{\"set\":\"$SET\",\"text\":\"192.0.2.78\"}" /api/v1/targets)"
chk "POST /schedules -> 200" 200 \
  "$(POST "{\"name\":\"test-roles-$SUF\",\"set\":\"$SET\",\"cron\":\"0 3 * * *\",\"window_minutes\":30,\"enabled\":false}" /api/v1/schedules)"
SID=$(jqv 'd["id"]')
chk "PUT /schedules/{id} -> 200" 200 \
  "$(PUT "{\"name\":\"test-roles-$SUF\",\"set\":\"$SET\",\"cron\":\"0 4 * * *\",\"window_minutes\":45,\"enabled\":false}" "/api/v1/schedules/$SID")"
chk "DELETE /schedules/{id} -> 200" 200 "$(DEL "/api/v1/schedules/$SID")"
chk "GET /users -> 403 (nie admin)" 403 "$(code -b "$J" "$BASE/api/v1/users")"

echo "4. admin"
login "$J" "$ASI_ADMIN_USER" "$ASI_ADMIN_PASSWORD" >/dev/null
chk "GET /users -> 200" 200 "$(code -b "$J" "$BASE/api/v1/users")"
chk "GET /audit -> 200" 200 "$(code -b "$J" "$BASE/api/v1/audit")"

echo "5. audyt edycji celu z rolą analyst"
chk "audit ma target_edit" 1 "$(code -b "$J" "$BASE/api/v1/audit" >/dev/null; jqv 'int(sum(1 for a in d if a["action"]=="target_edit")>0)')"

echo "6. sprzątanie"
for r in viewer analyst operator; do
  eval "id=\${${r^^}ID:-}"
  [ -n "${id:-}" ] && DEL "/api/v1/users/$id" >/dev/null
done
code -b "$J" "$BASE/api/v1/targets?set=$SET" >/dev/null
for id in $(jqv '[t["id"] for t in d]' | tr -d '[],'); do DEL "/api/v1/targets/$id" >/dev/null; done
chk "konta testowe usunięte" "" "$(code -b "$J" "$BASE/api/v1/users" >/dev/null; jqv '[u["username"] for u in d if u["username"].startswith("test-roles-")]' | tr -d "[]' ")"
# pusty zbiór celów też po sobie (GUI nie ma usuwania zbiorów, CLI ma: asi db drop-set)
if [ -x "$ROOT/asi" ] && [ -n "${ASI_DATABASE_URL:-}" ]; then
  "$ROOT/asi" db drop-set -db "$ASI_DATABASE_URL" -set "$SET" -force >/dev/null 2>&1 \
    && echo "  OK   zbiór celów $SET usunięty (asi db drop-set)"
else
  echo "  --   zbiór $SET zostaje; usuń: asi db drop-set -set $SET -force"
fi
rm -f "$J"
echo
echo "Wynik: $ok OK, $bad FAIL"
[ "$bad" -eq 0 ]
