# Adaptery skanerów (kontrakt `Observation`)

Każde narzędzie (nmap, httpx, nuclei, naabu…) podłączamy przez **adapter**, który zamienia swoje wyjście na
`[]obs.Observation`. Rdzeń (paczki, postęp, timeouty, baza, diff, eksport) nie zna formatów narzędzi.
Kod: `internal/obs/obs.go`, przykład: `internal/scanner/nmap/`.

## Interfejs

```go
type Scanner interface {
    Stage() obs.Stage   // discovery | ports | services | http | signatures
    Tool() string       // "httpx"
    // Proces dla paczki. Cele są w c.TargetsFile (jeden na linię), katalog roboczy c.Dir,
    // nazwa pliku c.Name. cfg.RatePPS jest już podzielone przez liczbę równoległych procesów.
    Command(ctx context.Context, c obs.Chunk, cfg obs.StageConfig) (*exec.Cmd, obs.OutputSpec)
    // Surowe wyjście -> obserwacje. MUSI tolerować urwany plik (proces zabity na końcu okna).
    Parse(raw io.Reader) ([]obs.Observation, error)
}

// opcjonalnie - postęp wewnątrz paczki (pasek CLI, panel)
type ProgressParser interface {
    ParseProgress(line string) (completed int, pct float64, ok bool) // -1 = brak wartości
}
```

`OutputSpec.Path` = plik, który pisze narzędzie (np. `-o chunk_0003.jsonl`). Puste = runner zbiera stdout
i podaje go do `Parse`. Plik zostaje w katalogu przebiegu jako dowód (evidence).

## Obserwacja

| pole | znaczenie |
|---|---|
| `kind` | `host`, `port`, `service`, `http`, `signature`, `dns` |
| `asset_key` | host: `192.0.2.10`, port: `192.0.2.10/tcp/443` (`obs.HostKey`, `obs.PortKey`) |
| `data` | JSON; typowane struktury: `HostData`, `PortData`, `ServiceData`, `HTTPData`, `SignatureData` |
| `fp_hash` | hash pól, których zmiana = zdarzenie `changed` (`obs.New(..., fpFields...)`) |
| `confidence` | 0–100 (np. nmap `method=table`, czyli zgadnięte po numerze portu = 30) |
| `tool`, `observed_at` | skąd i kiedy |

Twórz przez `obs.New(kind, key, tool, data, confidence, fpFields...)`. Dobór `fpFields`:
- `service`: nazwa, produkt, wersja,
- `http`: status, tytuł, serwer, posortowana lista technologii (nie nagłówki z datą!),
- `signature`: id sygnatury + wyekstrahowana wersja.

## Jak dodać skaner (np. httpx)

1. `internal/scanner/httpx/httpx.go`: typ implementujący `obs.Scanner` (+ `var _ obs.Scanner = (*Adapter)(nil)`).
2. Test na zapisanym fragmencie wyjścia (`testdata/`), w tym urwana ostatnia linia.
3. Binarka narzędzia w `docker/nmap/Dockerfile`.
4. Podpięcie etapu w `cmd/asi` (wejście: klucze portów/URL-e z poprzedniego etapu).
