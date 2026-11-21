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

| rodzaj | warunek |
|---|---|
| `new` | `IP:port/proto` jest w nowszym, nie było w starszym |
| `gone` | było w starszym, nie ma w nowszym |
| `changed` | jest w obu, ale różni się `usługa + produkt + wersja` |
| `+ host` / `- host` | host aktywny w discovery tylko w jednym z przebiegów |

Przykład z testu samosprawdzającego (port 8000 wyłączony między przebiegami):

```
zmiany 20261121-135516 -> 20261121-135523: 1 zmian, 1 bez zmian
  - gone    127.0.0.1:8000/tcp       http SimpleHTTPServer 0.6
```

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
