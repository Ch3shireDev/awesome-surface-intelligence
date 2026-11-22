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

## Skąd się bierze procent

Postęp całości to suma etapów z wagami: wykrywanie hostów 15%, porty i usługi 60%, HTTP 15%, sygnatury 10%.
Postęp etapu to suma postępu jego paczek ważona liczbą hostów.

| źródło | kiedy | w panelu |
|---|---|---|
| raport narzędzia (`nmap --stats-every 2s`: ukończone hosty + „About X% done”) | nmap, gdy już coś wypisał | zwykły pasek |
| szacunek z czasu: `czas paczki / oczekiwany czas`, max 90% | httpx i nuclei (nie raportują postępu) oraz nmap przed pierwszą linią statystyk | „≈” przy etapie i bledsze wypełnienie paczki |

Oczekiwany czas paczki to zmierzona szybkość etapu (sekundy na host, uczona między przebiegami) razy
liczba hostów. Jeśli narzędzie podało jakikolwiek postęp, ma pierwszeństwo, nawet gdy jest niższy od
szacunku. Przykład: pełny skan TCP (`-ports auto` przy ≤16 hostach) jest dużo wolniejszy niż top-1000,
więc szacunek pokazywałby 90% przez kilka minut.

Stan wysyłany jest do przeglądarki przez SSE co najmniej raz na sekundę, także gdy nic się nie zmienia.
Zielona kropka „na żywo” w rogu oznacza, że ramki przychodzą. Gdy przez 3 s nic nie przyjdzie, panel
pokazuje, od ilu sekund brak danych, i łączy się ponownie.

**nmap w kontenerze:** nmap 7.95 z Alpine wypisuje `--stats-every` tylko wtedy, gdy jego stdin jest
terminalem i nmap jest procesem pierwszoplanowym. Skaner uruchamia więc nmapa z pseudo-terminalem
(`internal/scanner/tty_linux.go`). Bez tego paczki stały na 0% aż do końca.

## Widok na żywo

- **Pasek segmentowy:** szerokość segmentu to waga etapu, wypełnienie to postęp etapu, a etap w toku jest animowany.
- **„Teraz: etap X/4”:** co robi skaner, ile procesów działa, ile hostów etapu już zrobionych.
- **Etapy:** ✓ zrobione, numer w kółku w toku, wyszarzone czekające. Przy każdym etapie: procent, hosty,
  bieżący rozmiar paczki, czas i sekundy na host.
- **Paczki** pogrupowane per etap: kółko = paczka wykrywania, kwadrat = pozostałe; wypełnienie = postęp,
  zielone = gotowa, czerwone = przerwana. Po najechaniu: hosty, czas, oczekiwany czas, wynik.
- **Wykryte usługi** dochodzą na górę listy z krótkim podświetleniem.

## Panel web

```bash
./asi scan                             # pasek w terminalu; przebieg i wyniki w panelu (asi server, :18090)
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
