# Architektura

Jedna binarka w Go (`asi`, ~8 MB, zero zależności poza stdlib), nmap jako silnik skanowania,
DefectDojo jako system zarządzania podatnościami. Spec sugeruje Go/Rust/C++ ze względu na niskie
zużycie zasobów — narzut `asi` jest pomijalny wobec procesów nmap.

```
 targets.csv / .json / .txt
          │  asi plan: parsowanie, rozwijanie CIDR, DNS, dedup, reguły bezpieczeństwa
          ▼
   plan.json  (unikalne IP + domeny, assety, właściciele, tagi; lista pominiętych z powodem)
          │
          ▼  FAZA 1: discovery  (nmap -sn, duże paczki, ~0.1–0.3 s/host)
   ┌─────────────────────────────────────────────┐
   │ worker pool: N procesów nmap                │──▶ hosts_up.json
   │ każdy worker sam bierze kolejną paczkę,     │
   │ rozmiar = cel_czasu / zmierzony_s_na_host   │
   └─────────────────────────────────────────────┘
          │ tylko aktywne hosty
          ▼  FAZA 2: usługi  (nmap -sT -sV --top-ports 1000, małe paczki)
   ┌─────────────────────────────────────────────┐
   │ ten sam worker pool + adaptacja             │──▶ services.json (1 rekord = IP:port)
   │ po każdej paczce: parsowanie XML,           │──▶ upload "live" do DefectDojo
   │ ocena „ciekawości”, zdarzenie do trackera   │
   └─────────────────────────────────────────────┘
          │
          ▼
   findings_defectdojo.json ──reimport (close_old)──▶ DefectDojo: new / closed / reactivated
   merged.xml (surowy nmap), run.json, timings.csv, events.ndjson

   progress.Tracker ──▶ pasek CLI (stderr, 5 fps)
                    ──▶ panel web (SSE /api/events, ≤4 klatki/s)
                    ──▶ events.ndjson + final_state.json
```

## Pakiety

| pakiet | odpowiedzialność |
|---|---|
| `internal/targets` | wczytanie CSV/JSON/TXT, plan skanu, CIDR, DNS, Cloudflare, reguła inwentarza |
| `internal/scanner` | worker pool, `Sizer` (adaptacyjny rozmiar paczki), uruchamianie nmap, parsowanie `--stats-every` |
| `internal/nmapxml` | parser XML nmapa (toleruje urwane pliki po zabiciu procesu) |
| `internal/findings` | model usługi, ocena ciekawości, diff przebiegów, format Generic Findings dla DefectDojo |
| `internal/progress` | stan przebiegu (jedno źródło prawdy dla CLI, web i pliku zdarzeń) |
| `internal/cli` | pasek postępu w terminalu |
| `internal/web` | panel HTML (osadzony w binarce), SSE, historia, diff |
| `internal/dojo` | klient API v2 (`import-scan`, `reimport-scan`) |
| `docker-compose.yml` | DefectDojo 3.5.202 + kontener `nmap-scanner` (nmap + `asi`) |

## Dlaczego tak

- **nmap jako proces, nie biblioteka** — dojrzałe fingerprinty `-sV`, a izolacja procesów daje
  twarde zabijanie paczki po przekroczeniu czasu (`-chunk-timeout`, `-window`).
- **Dwie fazy** — w sieci 10 000 IP zwykle 5–20% hostów odpowiada. Discovery kosztuje ułamek sekundy
  na host, skan usług kilkanaście sekund. Bez rozdzielenia martwe adresy zajmowałyby sloty
  workerów i rozjeżdżały czasy paczek.
- **Pull zamiast stałego podziału** — wolny host nie blokuje kolejki; szybkie workery biorą więcej paczek.
- **Jeden stan postępu** — CLI, panel i plik zdarzeń nie mogą się rozjechać.
