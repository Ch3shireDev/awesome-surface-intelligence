# Podział na paczki nmap

Spec: *„podział adresów źródłowych do skanowania na optymalne podgrupy, w zależności od szybkości
skanowania”* oraz *„funkcjonalność sprawdzania czasu trwania skanu”*.

## Problem

Jeden nmap na 10 000 adresów to jeden punkt awarii: brak postępu, brak częściowych wyników,
zabicie procesu = utrata wszystkiego. Z kolei 10 000 procesów po jednym IP to ogromny narzut
startu i fingerprintów. Optimum zależy od sieci: host za firewallem drop-all trwa minuty,
host z 3 portami kilka sekund.

## Rozwiązanie

### 1. Dwie fazy

| faza | nmap | typowy koszt | paczka startowa | min–max | cel czasu paczki |
|---|---|---|---|---|---|
| discovery | `-sn -n -PS21,22,25,80,443,3389,8080,8443` | 0.1–0.3 s/host | 64 | 16–1024 | 20 s |
| usługi | `-sT -sV --version-light -Pn --top-ports 1000 --open` | 5–20 s/host | 4 | 1–64 | 45 s (`-chunk-target`) |

Faza usług dostaje **tylko aktywne hosty**, więc jej czasy są przewidywalne.

### 2. Workery same biorą paczki

Nie ma podziału z góry. Każdy z `-parallel` workerów po skończeniu paczki prosi `Sizer` o następną.
Dzięki temu wolna paczka nie wstrzymuje reszty, a rozmiar kolejnych paczek uwzględnia to,
co już zmierzono.

### 3. Adaptacja rozmiaru (`internal/scanner.Sizer`)

```
s_na_host  = EWMA(czas_paczki / hosty_w_paczce)          # α = 0.4
rozmiar    = clamp(round(cel_czasu / s_na_host), min, max)
rozmiar    = min(rozmiar, ceil(pozostało / workery))      # wyrównanie końcówki
```

- **EWMA** wygładza pojedyncze anomalie, ale szybko reaguje na zmianę charakteru sieci
  (np. przejście z LAN na publiczne IP).
- **Wyrównanie końcówki**: przy 20 pozostałych hostach i 5 workerach każdy dostaje 4,
  zamiast jeden 20 i czterech bezczynnych.
- **Pamięć między przebiegami**: zmierzone `s/host` dla każdej fazy zapisuje się do
  `results/tuning.json` i jest punktem startu następnego skanu — drugi przebieg od razu
  zaczyna z dobrym rozmiarem.
- `-chunk N` / `-discovery-chunk N` wyłączają adaptację (stały rozmiar).

### 4. Pomiar czasu

Każda faza zapisuje `timings.csv` (paczka, hosty, sekundy, s/host, błąd),
`run.json` ma czasy faz i końcowe `sec_per_host`. W panelu i pasku widać bieżący rozmiar
paczki i `s/host` na żywo.

### 5. Postęp wewnątrz paczki

nmap jest uruchamiany z `--stats-every 2s`. Parser czyta z stdout
`N hosts completed (M up)` oraz `About X% done` i liczy postęp paczki:

```
postęp = (ukończone + X% · (hosty − ukończone) · 0.95) / hosty     # monotoniczny, < 100% do końca
```

### 6. Limity i okna

| flaga | działanie |
|---|---|
| `-rate 1000` | **globalny** limit pps, dzielony równo: każdy nmap dostaje `--max-rate rate/parallel` |
| `-chunk-timeout 20m` | zabija pojedynczy nmap (zawieszony host nie blokuje workera) |
| `-window 2h` | po upływie okna: zabicie trwających nmapów, nowe paczki nie startują, run = `interrupted` |
| Ctrl+C | jak `-window` — częściowe wyniki są zapisywane |

## Co jeszcze nie jest zrobione

- Wznawianie przerwanego runu w kolejnym oknie (spec: *„zatrzymany i uruchomiony ponownie w
  kolejnym oknie”*) — dziś kolejny run zaczyna od zera. Plan: `run.json` z listą niezeskanowanych
  IP + `asi scan -resume <run>`.
- Grupowanie paczek po podsieci /24 (sąsiednie IP zwykle zachowują się podobnie — lepsza predykcja).
- Ponawianie hostów, które odpowiedziały niestabilnie (spec: obsługa hostów niestabilnych).
