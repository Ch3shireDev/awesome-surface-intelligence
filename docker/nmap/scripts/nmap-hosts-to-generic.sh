#!/bin/bash
# Konwersja wyniku host discovery nmapa (-sn, plik .gnmap) na format
# "Generic Findings Import" DefectDojo: jeden finding Info "Host up" na host.
# Parser Nmapa w DD robi findingi tylko z otwartych portow, wiec bez tego
# sam liveness nie bylby widoczny w DD.
#
# Opis findingu jest stabilny (bez dat), zeby reimport dopasowywal go miedzy
# przebiegami: host znikniety w kolejnym skanie -> finding zamkniety.
#
# Uzycie: nmap-hosts-to-generic.sh plik.gnmap > plik.json
set -euo pipefail

GNMAP="${1:?podaj plik .gnmap}"

# "Host: 10.0.0.5 (nazwa.hosta)	Status: Up"  ->  "10.0.0.5<TAB>nazwa.hosta"
awk -F'\t' '/Status: Up/ {
  split($1, a, " "); ip = a[2]; name = a[3]; gsub(/[()]/, "", name);
  print ip "\t" name
}' "$GNMAP" \
| jq -R -s '
  split("\n") | map(select(length > 0) | split("\t") | {ip: .[0], name: .[1]})
  | {findings: map({
      title: "Host up: \(.ip)",
      severity: "Info",
      description: ("Host \(.ip) odpowiada na host discovery (nmap -sn)."
                    + (if .name != "" then " Nazwa: \(.name)." else "" end)),
      unique_id_from_tool: "host-up-\(.ip)",
      endpoints: [.ip],
      tags: ["liveness"]
    })}'
