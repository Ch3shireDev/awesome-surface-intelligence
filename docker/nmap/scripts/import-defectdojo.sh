#!/bin/bash
# Wgranie wyniku skanu do DefectDojo przez API v2 /reimport-scan/.
# Odpalane w kontenerze nmap-scanner (network_mode: host, env z .env).
#
# Kazdy rodzaj skanu ma w DD jeden staly test ("nmap-fast", "nmap-discover",
# ...) w Engagement DD_ENGAGEMENT. Kolejne przebiegi ida do tego samego testu,
# wiec DD sam liczy diff: nowe / zamkniete (zniknely) / reaktywowane / bez
# zmian. Product Type/Product/Engagement/Test tworza sie przy pierwszym
# imporcie (auto_create_context).
#
# Rodzaj skanu bierzemy z nazwy pliku: <rodzaj>-YYYYMMDD-HHMMSS.xml
# (tak nazywa pliki Makefile). "discover" (-sn) idzie przez konwerter
# nmap-hosts-to-generic.sh jako "Generic Findings Import".
#
# Uzycie: import-defectdojo.sh /scans/results/fast-20261121-120000.xml
set -euo pipefail

FILE="${1:?podaj sciezke do pliku .xml z wynikami}"
DD_URL="${DD_URL:-http://localhost:${DD_PORT:-8080}}"
HERE="$(dirname "$0")"

[ -f "$FILE" ] || { echo "Brak pliku: $FILE" >&2; exit 1; }

KIND="$(basename "$FILE" | sed -E 's/-[0-9]{8}-[0-9]{6}\.[a-z]+$//')"

if [ "$KIND" = "discover" ]; then
  GNMAP="${FILE%.xml}.gnmap"
  UPLOAD="${FILE%.xml}.generic.json"
  "$HERE/nmap-hosts-to-generic.sh" "$GNMAP" > "$UPLOAD"
  SCAN_TYPE="Generic Findings Import"
else
  UPLOAD="$FILE"
  SCAN_TYPE="Nmap Scan"
fi

TOKEN="${DD_API_KEY:-}"
if [ -z "$TOKEN" ]; then
  TOKEN=$(curl -sS --fail-with-body -X POST "$DD_URL/api/v2/api-token-auth/" \
    --form-string "username=$DD_ADMIN_USER" \
    --form-string "password=$DD_ADMIN_PASSWORD" | jq -r .token)
fi

echo "reimport: $(basename "$UPLOAD") -> test 'nmap-$KIND' ($SCAN_TYPE)" >&2
curl -sS --fail-with-body -X POST "$DD_URL/api/v2/reimport-scan/" \
  -H "Authorization: Token $TOKEN" \
  --form-string "scan_type=$SCAN_TYPE" \
  --form-string "auto_create_context=true" \
  --form-string "product_type_name=${DD_PRODUCT_TYPE:-HackNation}" \
  --form-string "product_name=${DD_PRODUCT:-Attack Surface}" \
  --form-string "engagement_name=${DD_ENGAGEMENT:-nmap}" \
  --form-string "test_title=nmap-$KIND" \
  --form-string "close_old_findings=true" \
  -F "file=@$UPLOAD" \
  | jq '{test_id, diff: (.statistics.delta // {} | with_entries(.value |= .total.total)),
         active_after: .statistics.after.total.active}'
