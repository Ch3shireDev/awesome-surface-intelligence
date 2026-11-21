# Pliki wynikowe

Każdy przebieg: `results/<YYYYMMDD-HHMMSS>/`

| plik | zawartość |
|---|---|
| `plan.json` | hosty do skanu (IP, domeny, assety, właściciele, tagi) + pominięte z powodem |
| `discovery/chunk_NNNN.{targets,xml,log}` | wejście, wynik i stdout każdej paczki discovery |
| `discovery/timings.csv` | czasy paczek discovery |
| `hosts_up.json` | aktywne hosty |
| `services/chunk_NNNN.{targets,xml,log}` | jw. dla fazy usług |
| `services/timings.csv` | czasy paczek usług |
| `services.json` | **znormalizowane usługi** (1 rekord = IP:port) — podstawa diffu i eksportu |
| `findings_defectdojo.json` | Generic Findings Import (to, co idzie do DefectDojo) |
| `merged.xml` | wszystkie aktywne hosty w jednym XML nmapa, z domenami jako `hostname type="user"` |
| `run.json` | podsumowanie: czasy, liczby, fazy, argumenty, link do testu w DefectDojo |
| `events.ndjson` | log zdarzeń + końcowy snapshot |
| `final_state.json` | końcowy stan panelu (dla `asi serve`) |

Globalnie: `results/tuning.json` — zmierzone `s/host` dla faz (start następnego przebiegu).

## Rekord `services.json`

```json
{
  "ip": "203.0.113.20",
  "port": 8888,
  "proto": "tcp",
  "service": "sun-answerbook",
  "domains": ["health.example.org", "os.example.org", "uptime.example.net"],
  "assets": ["sh"],
  "tags": ["prod", "public", "domain", "monitoring", "admin"],
  "interest": "medium",
  "interest_reason": "alt HTTP / dev on a public IP"
}
```
