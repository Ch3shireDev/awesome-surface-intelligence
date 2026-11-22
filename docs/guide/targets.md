# Format celów

Spec (pkt 1, 11) wymaga wczytania listy IP, zakresów CIDR lub domen, ręcznie oraz z pliku CSV/JSON.
`asi` przyjmuje trzy formaty o **tym samym schemacie**; `asi convert` przelicza CSV ↔ JSON.

## Pola

| pole | wymagane | opis |
|---|---|---|
| `target` | tak | IPv4/IPv6, CIDR (`10.0.0.0/24`) albo domena |
| `ports` | nie | porty TCP tego celu: puste (profil skanu), `top100`, `top1000`, `all` albo lista `22;80;8000-8100` (w JSON też `22,80`) |
| `asset` | nie | logiczna nazwa maszyny (`edge-1`, `db-1`) — łączy IP publiczne, Tailscale i domeny |
| `owner` | nie | właściciel — do decyzji o zgodzie na skan |
| `tags` | nie | tagi; w CSV rozdzielone `;`, w JSON tablica |
| `enabled` | nie (domyślnie `true`) | `false` = zostaje w inwentarzu, nigdy nie jest skanowane |
| `note` | nie | opis; dla `enabled=false` pokazywany jako powód pominięcia |

## CSV

```csv
target,ports,asset,owner,tags,enabled,note
# komentarze zaczynają się od #
203.0.113.10,22;80;443;8000-8100,edge-1,secops,prod;public,true,Edge proxy
10.50.0.0/24,top1000,lab-incus,secops,incus;internal,true,
api.example.com,,edge-1,secops,domain;api,true,
partner.example.net,,partner,partner,third-party,false,NIE skanować
```

## JSON

```json
{
  "version": 1,
  "targets": [
    { "target": "203.0.113.10", "ports": "22,80,443", "asset": "edge-1", "owner": "secops",
      "tags": ["prod", "public"], "enabled": true, "note": "Edge proxy" }
  ]
}
```

## TXT

Jeden cel na linię, `#` = komentarz. Wszystko `enabled=true`, bez metadanych — do szybkich testów.

## Porty per cel {#porty}

W panelu: pole **porty** w „Dodaj ręcznie”, w „Import z pliku” (dla wierszy bez kolumny `ports`) i edycja w tabeli celów.

- Puste pole oznacza profil wybrany w **Nowy skan** (`-ports`, domyślnie `auto`).
- Gdy kilka celów obejmuje to samo IP: cel z wybranymi portami wygrywa z pustym, listy się sumują, a przy profilu
  i liście wygrywa szerszy profil (ostrzeżenie w `plan.json`).
- Przykład: `10.0.0.0/24` bez portów i `10.0.0.5` z `22` oznacza, że `10.0.0.5` ma skanowany tylko port 22.
- Wykrywanie hostów jest wspólne, etap usług puszcza nmapa osobno dla każdego zestawu. `ASI_ALLOWED_PORTS`,
  pomijanie własnych portów i limity tempa obowiązują jak zawsze.
- Port spoza wybranej listy nie jest sondowany i nie dostaje `missing`. W przebiegu po zawężeniu DefectDojo
  nie zamyka starych findingów; kolejne przebiegi odzwierciedlają już nowy zakres.
- Ponowny import z pustym polem nie kasuje portów. Powrót do profilu skanu: wyczyść pole w tabeli.

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

## Gotowe pliki do wgrania

Przykładowe pliki (CSV, JSON, TXT) dla labu i dla localhosta są na stronie
[Lab testowy i demo → Pliki celów do wgrania](/guide/lab#pliki-celow-do-wgrania).
