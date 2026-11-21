# Historia i stany assetów

Po każdym przebiegu zapisanym w bazie `asi` przelicza **assety**: trwałe byty śledzone między skanami
(host `192.0.2.10` albo port `192.0.2.10/tcp/443`). Obserwacje są per przebieg, assety żyją dalej
(VISION 4.7, kod `internal/store/reconcile.go`).

## Stany i zdarzenia

```
            obserwowany                    brak × 1                 brak × próg
 (brak) ──────────────▶ new ──▶ active ─────────────▶ missing ─────────────────▶ gone
                                  ▲                     │                          │
                                  └──── reappeared ─────┴──────────────────────────┘
```

| zdarzenie | kiedy |
|---|---|
| `new` | asset pierwszy raz zaobserwowany |
| `changed` | zmienił się odcisk (`fp_hash`): dla portu usługa + produkt + wersja |
| `missing` | pierwszy brak w przebiegu, który ten asset **naprawdę sprawdzał** |
| `gone` | `consecutive_misses ≥ próg` (host: 3, port: 2) i opcjonalnie `-gone-after 24h` od ostatniego widzenia |
| `reappeared` | wrócił ze stanu `missing` albo `gone` |
| `reverted` | odcisk usługi lub HTTP wrócił do stanu sprzed ostatniej zmiany (np. zaplecze za proxy chwilowo nie działało i odpowiadał sam proxy). To nie jest druga zmiana, tylko cofnięcie: liczy się jak 2 przejścia do `flapping`, a w DefectDojo zamyka finding „zmiana” (LAB-T8) |
| `flapping` | ≥ 3 przejścia w ostatnich 10 przebiegach: active↔missing albo cofnięte zmiany odcisku (flaga na assecie) |

Odpowiedź na pytanie z treści zadania *„po jakim czasie braku odpowiedzi raportować host jako nieaktywny?”*:
po `-miss-threshold` kolejnych brakach (domyślnie 3) i opcjonalnie po `-gone-after`. Pojedynczy brak to
tylko `missing`, a nie zniknięcie.

## Trzy zasady, żeby nie produkować fałszywych zniknięć

1. **Pokrycie hostów.** Brak liczy się tylko dla adresów z paczek o statusie `done`. Paczka `failed`,
   `killed` albo przerwana oknem czasowym nie generuje braków, więc przebieg `partial` niczego nie zamyka.
2. **Pokrycie portów.** Port może zniknąć tylko wtedy, gdy był w zbiorze portów faktycznie skanowanych
   w tym przebiegu (nmap `<scaninfo services="…">`, zapisywane w `chunks.ports`). Skan samego portu 22
   nie oznacza 8080 jako brakującego.
3. **Hierarchia.** Port może zniknąć tylko wtedy, gdy jego host w tym przebiegu żył. Jeśli host nie
   odpowiedział (np. filtrowany ping), porty dziedziczą jego stan zamiast dostawać własne braki.

Dodatkowo skan potwierdzający ([Porównanie](/guide/diff)) sprawdza ponownie usługi, które zniknęły na
żywych hostach, zanim w ogóle trafią do bazy jako brak.

## Edycje użytkownika

`user_tags`, `user_note` (zaszyfrowana) i `user_overrides` są polami assetu, a nie obserwacji. Przeliczanie
stanów ich nie dotyka, więc **przetrwają każdy kolejny skan** (pkt 14 treści zadania). Każda edycja trafia do
`audit_log` (bez treści notatki).

## `hours_seen`

Bitmapa 24 godzin (UTC), w których asset był widziany. Podstawa do wykrywania wzorców w stylu
„odpowiada tylko w dzień” (mile widziane w treści zadania). Pokazanie tego w GUI jest w DEV-4/DEV-7.

## Komendy

```bash
asi scan ...                                  # przeliczenie stanów automatycznie po zapisie przebiegu
asi changes [RUN]                             # zdarzenia przebiegu (domyślnie ostatniego)
asi changes -asset 192.0.2.10/tcp/443         # historia jednego assetu
asi assets [-state missing] [-flapping] [-q 192.0.2.]
asi asset edit 192.0.2.10/tcp/22 -tags ssh,crown-jewel -note "właściciel: zespół A"
asi db reconcile RUN [RUN...]                 # przeliczenie starszych przebiegów (chronologicznie)
```

Progi: `-miss-threshold 3 -port-miss-threshold 2 -gone-after 0 -flap-window 10 -flap-transitions 3`
(flagi `asi scan` i `asi db reconcile`). Ten sam przebieg nie zostanie przeliczony dwa razy
(`runs.reconciled_at`).

## Testy

`internal/store/reconcile_test.go` przechodzi 7 syntetycznych przebiegów: zmiana wersji, brak hosta z
dziedziczeniem portów, przebieg częściowy, próg `gone`, powrót, flapping, skan z zawężonym zbiorem portów
oraz trwałość edycji użytkownika.
