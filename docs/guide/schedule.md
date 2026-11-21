# Harmonogram, okna czasowe i wznawianie

Wymaganie z treści zadania: *„możliwość ustawiania konkretnych przedziałów czasowych uruchomienia oraz
częstotliwości wykonywania skanów. W przypadku bardzo długiego czasu skanowania, jeśli przekroczone zostanie
okno czasowe, skan powinien zostać zatrzymany i uruchomiony ponownie w kolejnym oknie.”* (DEV-5)

## Jak to działa

```
 okno 1 (np. 02:00–04:00)                     okno 2 (następna noc 02:00)
 ┌──────────────────────────────┐             ┌──────────────────────────────┐
 │ paczki done ✔ ✔ ✔ ✔ | ✂ koniec │             │ najpierw: wznowienie         │
 │ przerwane → deferred         │  ──────▶    │ niezeskanowanych celów z     │
 │ nierozpoczęte → pending      │             │ okna 1 (resume_of), potem    │
 │ przebieg: partial            │             │ kolejne okna: pełny zbiór    │
 └──────────────────────────────┘             └──────────────────────────────┘
```

1. Harmonogram ma **cron** (5 pól, czas serwera), **okno w minutach** i parametry skanu (równoległość, limit pps,
   porty, eksport do DefectDojo).
2. Serwer (`asi server`) co 20 s sprawdza harmonogramy, których czas startu minął, i uruchamia
   `asi scan -window <okno> -trigger schedule -schedule-id N` jako podproces.
3. Na końcu okna `asi scan` zabija trwające nmapy i nie startuje nowych paczek. Paczki przerwane dostają status
   `deferred`, a przebieg `partial`. Cele, których nie objęła żadna zakończona paczka (discovery lub usługi),
   trafiają do `runs.pending_targets`.
4. Przy następnym odpaleniu harmonogram sprawdza, czy jego poprzednie okno zostawiło `pending`. Jeśli tak,
   **najpierw je wznawia** (`asi scan -resume <run>`: plan poprzedniego przebiegu zawężony do pending, z
   zachowaniem domen i metadanych). Przebiegi są powiązane w obie strony (`resume_of` / `resumed_by`), więc tego
   samego przebiegu nie da się wznowić dwa razy.
5. Przebieg `partial` nie generuje fałszywych zniknięć: liczy się tylko pokrycie paczek `done`
   ([Historia i stany](/guide/history)).
6. Jeśli w momencie startu trwa inny skan, odpalenie jest pomijane, a powód widać w kolumnie „ostatni”
   (`last_error`). Następny termin liczy się normalnie.

Wznawianie nie potrzebuje `nmap --resume`: jednostką pracy jest paczka, więc wystarczy lista niezeskanowanych celów.

## W panelu (zakładka Skany)

| akcja | efekt |
|---|---|
| **Uruchom skan** | ręczny skan z opcjonalnym oknem (`2h`) |
| **Wstrzymaj** | zatrzymanie teraz; wyniki zapisane, przebieg `partial`, przy nim przycisk **Wznów (N)** |
| **Anuluj** | zatrzymanie bez wznawiania; przebieg `cancelled`, pending wyczyszczone |
| **Wznów (N)** | przy przebiegu częściowym: dokończ N niezeskanowanych celów (parametry z formularza) |
| **Harmonogram** | lista (cron, okno, następny i ostatni start, błąd, włącz/wyłącz, usuń) i formularz z gotowymi ustawieniami („codziennie 02:00”, „dni robocze 22:30”…) oraz podglądem 5 najbliższych startów |

Uprawnienia: tworzenie, edycja, start, stop i wznawianie wymagają roli `operator`, a podgląd roli `viewer`.
Wszystko trafia do dziennika audytu (`scan_scheduled`, `scan_pause`, `scan_cancel`, `scan_resume`, `schedule_save`).

## CLI

```bash
asi scan -targets t.csv -window 2h             # okno ręcznie
asi scan -resume 20261121-152210 -window 2h    # dokończ przebieg częściowy
asi db runs                                    # status, schedule_id, pending
```

## Cron

`min godz dzień_mies mies dzień_tyg`, np. `0 2 * * *` (codziennie 02:00), `30 22 * * 1-5` (dni robocze 22:30),
`*/15 * * * *`, `0 3 * * 0` (niedziela, 0 albo 7), skróty `@hourly`, `@daily`, `@weekly`, `@monthly`.
Listy (`1,15`), zakresy (`1-5`) i kroki (`*/10`, `0-30/10`). Gdy ograniczone są oba pola dnia, wystarczy
zgodność jednego (jak w klasycznym cronie). Czas serwera (kontener: UTC) jest pokazany w panelu.

## Testy

- `internal/schedule/cron_test.go`: najbliższe starty dla typowych wyrażeń, błędne wyrażenia, wyrażenie niemożliwe (31 lutego).
- End-to-end na `127.0.0.0/29` (21.11): harmonogram z oknem 1 min → przebieg `partial` (3 cele pending)
  → drugie odpalenie wznowiło je (`resume_of`) i skończyło jako `completed`. Wstrzymaj → `partial` + Wznów z API
  → `completed`; Anuluj → `cancelled`, 0 pending (test regresyjny `TestLatestRunSinceAndCancel`).
