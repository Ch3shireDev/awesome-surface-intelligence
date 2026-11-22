# Komendy CLI

```
asi <convert|plan|scan|upload|diff|serve> [flagi]      # asi <komenda> -h
```

## `asi plan`

| flaga | domyślnie | opis |
|---|---|---|
| `-targets` | `targets/targets.csv` | plik celów (`.csv`/`.json`/`.txt`) |
| `-skip-cdn` | `true` | pomijaj IP Cloudflare za domenami |
| `-only-inventory` | `true` | domeny tylko podpisują IP z inwentarza |
| `-o` | — | zapisz plan jako JSON |

## `asi scan`

Plus flagi `plan`.

| flaga | domyślnie | opis |
|---|---|---|
| `-parallel` | `1` | procesy nmap naraz |
| `-rate` | `1000` | globalny limit pps |
| `-chunk` | `0` (adaptacyjnie) | stały rozmiar paczki usług |
| `-chunk-target` | `45s` | docelowy czas paczki usług |
| `-discovery-chunk` | `0` (adaptacyjnie) | stały rozmiar paczki discovery |
| `-discovery-args` | `-sn -n -PS21,22,25,80,443,3389,8080,8443 -T4 --max-retries 1` | nmap discovery |
| `-nmap` | `-sT -sV --version-light -Pn --top-ports 1000 -T4 --max-retries 2 --host-timeout 10m --open` | nmap usług |
| `-skip-discovery` | `false` | wszystkie IP traktuj jako aktywne |
| `-chunk-timeout` | `20m` | limit jednej paczki |
| `-window` | `0` | okno czasowe runu |
| `-out` | `results` | katalog wyników |
| `-ui` | — | tylko dev: dodatkowa strona postępu tego skanu; zwykle niepotrzebne, bo panel `asi server` (:18090) pokazuje skany |
| `-upload` | `off` | `off` / `end` / `live` |
| `-product`, `-engagement` | `ASI PoC`, `discovery` | kontekst DefectDojo |

Zmienne środowiskowe: `DD_URL` (domyślnie `http://localhost:8080`), `DD_TOKEN`.

## `asi upload`

| flaga | domyślnie | opis |
|---|---|---|
| `-run` | najnowszy | katalog przebiegu |
| `-format` | `generic` | `generic` (historia zmian) / `nmap` (surowy XML) |
| `-close-old` | `true` | zamknij znaleziska, których nie ma w tym przebiegu |

## `asi diff [A B]`, `asi convert`

Patrz [Porównanie](/guide/diff), [Postęp](/guide/progress), [Format celów](/guide/targets).
