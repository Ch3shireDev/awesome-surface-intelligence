# Porównanie przebiegów

Spec pkt 8–9: porównanie wyników między kolejnymi przebiegami i oznaczenie nowych, znikających
i zmienionych usług.

```bash
./asi diff                                   # dwa najnowsze przebiegi
./asi diff 20261121-132002 20261121-135500   # wybrane
./asi diff -json                             # do dalszego przetwarzania
```

Po każdym `asi scan` diff względem poprzedniego **zakończonego** przebiegu wypisuje się
automatycznie. W panelu: zakładka *Historia i diff*.

| znak | warunek (porównanie dwóch przebiegów) |
|---|---|
| `+` | `IP:port/proto` jest w nowszym, nie było w starszym |
| `-` | było w starszym, nie ma w nowszym |
| `~` | jest w obu, ale różni się `usługa + produkt + wersja` |
| `+ host` / `- host` | host aktywny w discovery tylko w jednym z przebiegów |

### Te same słowa co historia (LAB-T5)

Samo porównanie dwóch przebiegów **nie zna progu braków** ani wcześniejszej historii: nie odróżni pierwszego
braku (`missing`, do potwierdzenia) od zniknięcia po progu (`gone`), ani usługi nowej (`new`) od powrotu
(`reappeared`). Dlatego przy każdej różnicy diff pokazuje **zdarzenie z historii nowszego przebiegu**, tak jak
`asi changes`, zakładka Skany i DefectDojo `asi-changes`. Gdy bazy nie ma (sam plik), pisze neutralnie
„pojawiła się” / „brak w tym przebiegu”, nigdy „gone”.

| sytuacja | z bazą (CLI po skanie, `asi diff`, `asi diff -db`, GUI) | bez bazy |
|---|---|---|
| port zniknął w tym przebiegu pierwszy raz | `- missing` | `- brak w tym przebiegu` |
| port nie odpowiada drugi raz (próg portów = 2) | brak w diffie (nie ma go w żadnym z dwóch), `gone` w `asi changes` | — |
| port wrócił po zniknięciu | `+ reappeared` | `+ pojawiła się` |
| port pierwszy raz w historii | `+ new` | `+ pojawiła się` |
| cofnięta zmiana (LAB-T8) | `~ reverted` | `~ changed` |

Przykład z LAB-6 (lab organizatorów, powrót `custom-network` po `modern`), `asi diff -db 20261121-203702 20261121-203925`:

```
zmiany 20261121-203702 -> 20261121-203925: 13 zmian, 6 bez zmian
  - missing                     127.0.0.1:8080/tcp       http Apache httpd 2.4.71
  + reappeared                  127.0.0.1:8787/tcp       http nginx 1.31.9
  …
```

Ten sam diff bez bazy: `- brak w tym przebiegu 127.0.0.1:8080/tcp …`, `+ pojawiła się 127.0.0.1:8787/tcp …`.
W JSON (`-json`, API `/api/v1/diff`) pole `kind` zostaje bez zmian (`new` / `gone` / `changed`, struktura
porównania), a doszły `history` przy każdej różnicy i `host_history` dla hostów.

## Potwierdzanie zniknięć (hosty i usługi niestabilne)

Pojedyncza zgubiona sonda (limit tempa, utrata pakietu) wyglądałaby jak `gone` — a przy reimporcie
z `close_old` DefectDojo zamknąłby prawdziwą usługę jako *mitigated*. Dlatego po fazie usług:

1. usługi obecne w poprzednim przebiegu, a brakujące teraz, **na hostach nadal aktywnych**,
   są skanowane ponownie — tylko te porty, wolniej (`-T3 --max-retries 4`),
2. jeśli port odpowie → usługa zostaje, dostaje tag **`unstable`** (widoczny w DefectDojo),
3. dopiero brak odpowiedzi w obu próbach = `gone`.

To przypadek z realnych danych: `web-2 198.51.100.7:80` „zniknął” w jednym przebiegu, a trzy
kolejne sondy pokazały go jako otwarty.

```
confirm: 1 services vanished since 20261121-135809 on live hosts - re-checking
confirm: 127.0.0.1:8000/tcp still open (missed by first pass) - kept, tagged unstable
zmiany 20261121-135809 -> 20261121-135815: brak (2 usług bez zmian)
```

## Do zrobienia

- Host (a nie usługa) „niestabilny” vs „zniknął”: dziś jeden brak odpowiedzi w discovery = `- host`. Plan: licznik kolejnych
  nieudanych przebiegów i próg (np. 3) zanim host zostanie uznany za nieaktywny; dodatkowe
  powtórzenie discovery dla hostów, które zniknęły (spec: *„po jakim czasie braku odpowiedzi…”*).
- Różnice zależne od pory dnia — wymaga harmonogramu i agregacji po godzinie.
