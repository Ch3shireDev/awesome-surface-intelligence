# Postęp: CLI i panel web

Jedno źródło prawdy — `internal/progress.Tracker`. Każda zmiana (start paczki, linia
`--stats-every` z nmapa, koniec paczki, upload) aktualizuje stan; konsumenci dostają
**pełny snapshot**, a nie zdarzenia przyrostowe, więc nie da się „zgubić” stanu.

## Terminal

```
 62.4% ██████████████████░░░░░░░░░░░░ │ services 7/12 hosts, chunk=2 │ up 12 │ open 16 │ 00:48 ETA 00:29
  workers: #3[1]  55%  #5[2]  36%  #6[1]  41% │ dojo: done (4)
13:51:14 services chunk_0000: 3 hosts, 2 up, 4 open, 51.6s
```

- linie logu przewijają się **nad** paskiem, pasek zostaje na dole (odświeżanie 5×/s),
- druga linia: aktywne workery — `#id[hosty] procent`, status DefectDojo,
- bez TTY (CI, `nohup`, przekierowanie) — zwykłe linie logu + status co 10 s.

### Jak liczony jest procent

```
procent = 25% · postęp_discovery + 75% · postęp_usług
postęp_fazy = Σ(hosty_paczki · procent_paczki) / hosty_fazy
ETA = upłynęło / procent · (1 − procent)
```

Wagi odzwierciedlają typowy rozkład czasu (discovery jest tanie). ETA jest liczone od początku
całego runu, więc stabilizuje się po kilku paczkach.

## Panel web

```bash
./asi scan -ui 127.0.0.1:8090          # panel na żywo w trakcie skanu
./asi serve                            # tylko historia + stan ostatniego przebiegu
```

Zakładka **Na żywo**: wielki procent + ETA, kafelki KPI (IP w planie, aktywne hosty, otwarte porty,
paczki, równoległość, DefectDojo), paski faz z bieżącym rozmiarem paczki i s/host,
**siatka paczek** (kółko = discovery, kwadrat = usługi, wypełnienie = postęp, kolor = stan,
tooltip = szczegóły), tabela usług wykrywanych na żywo z oceną ciekawości, log.

Zakładka **Historia i diff**: tabela przebiegów (`run.json`), porównanie dowolnych dwóch.

### API

| endpoint | opis |
|---|---|
| `GET /api/events` | Server-Sent Events, pełny snapshot ≤ 4×/s + ping co 15 s |
| `GET /api/live` | bieżący snapshot (w trybie `serve`: `final_state.json` ostatniego runu) |
| `GET /api/runs` | lista przebiegów |
| `GET /api/runs/{id}` | `run.json` + `services.json` |
| `GET /api/diff?from=A&to=B` | porównanie przebiegów |

Panel jest osadzony w binarce (`go:embed`), bez zewnętrznych zasobów (działa offline, brak CDN).

::: warning Brak uwierzytelniania
Panel domyślnie słucha na `127.0.0.1`. Nie wystawiaj go na `0.0.0.0` przed dodaniem RBAC — patrz
[Status](/status).
:::
