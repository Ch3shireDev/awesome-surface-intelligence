# Format celów

Spec (pkt 1, 11) wymaga wczytania listy IP, zakresów CIDR lub domen, ręcznie oraz z pliku CSV/JSON.
`asi` przyjmuje trzy formaty o **tym samym schemacie**; `asi convert` przelicza CSV ↔ JSON.

## Pola

| pole | wymagane | opis |
|---|---|---|
| `target` | tak | IPv4/IPv6, CIDR (`10.0.0.0/24`) albo domena |
| `asset` | nie | logiczna nazwa maszyny (`edge-1`, `db-1`) — łączy IP publiczne, Tailscale i domeny |
| `owner` | nie | właściciel — do decyzji o zgodzie na skan |
| `tags` | nie | tagi; w CSV rozdzielone `;`, w JSON tablica |
| `enabled` | nie (domyślnie `true`) | `false` = zostaje w inwentarzu, nigdy nie jest skanowane |
| `note` | nie | opis; dla `enabled=false` pokazywany jako powód pominięcia |

## CSV

```csv
target,asset,owner,tags,enabled,note
# komentarze zaczynają się od #
203.0.113.10,edge-1,secops,prod;public,true,Edge proxy
10.50.0.0/24,lab-incus,secops,incus;internal,true,
api.example.com,edge-1,secops,domain;api,true,
hpc.arizona.edu,arizona,university-of-arizona,third-party,false,NIE skanować
```

## JSON

```json
{
  "version": 1,
  "targets": [
    { "target": "203.0.113.10", "asset": "edge-1", "owner": "secops",
      "tags": ["prod", "public"], "enabled": true, "note": "Edge proxy" }
  ]
}
```

## TXT

Jeden cel na linię, `#` = komentarz. Wszystko `enabled=true`, bez metadanych — do szybkich testów.

## Jak powstaje plan

1. IP i CIDR trafiają do **inwentarza** (CIDR większy niż 65 536 adresów jest odrzucany — bezpiecznik).
2. Domeny są rozwiązywane (A, 32 zapytania równolegle, timeout 5 s).
3. Adres z domeny:
   - jest w inwentarzu → domena dopisana do tego IP (pojawi się w DefectDojo jako endpoint),
   - jest w zakresach Cloudflare → pominięty („CDN edge, not our host”),
   - jest gdzie indziej → pominięty („resolves outside IP inventory”) — `-only-inventory=false` wyłącza.
4. Duplikaty są scalane: jedno IP = jeden wpis z sumą domen, assetów, tagów.

`asi plan` wypisuje wynik z listą pominiętych i powodami; `asi plan -o plan.json` zapisuje go.

::: tip Format organizatorów
Organizatorzy zapowiedzieli „przykładowy format eksportu/importu JSON/CSV”. Gdy się pojawi,
dopiszemy mapowanie w `internal/targets` — schemat wewnętrzny zostaje.
:::
