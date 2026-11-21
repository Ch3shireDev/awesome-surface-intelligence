# Test skali (10 000+ adresów)

Wymaganie: *„obsługa dużych zakresów, np. ponad 10 000 IP”*, a kryterium 30% to skuteczność *„w dużej
infrastrukturze”* (DEV-10). Test 21.11 na maszynie deweloperskiej: 4 rdzenie, 7 GB RAM, z działającym DefectDojo,
`asi-db` i panelem.

## Scenariusz

`127.0.0.0/18`, czyli **16 384 adresy**, wyłącznie loopback (zero ruchu poza maszyną). W Linuksie każdy adres
127.x odpowiada, więc to przypadek najgorszy: 100% hostów żywych, każdy z otwartymi portami.

```bash
asi scan -targets scale.csv -parallel 8 -rate 1000 -http off \
  -nmap "-sT -Pn -p 22,8080 -T4 --max-retries 1 --open"
```

Usługi skanowane bez `-sV` (dwa porty, connect scan): test mierzy **rdzeń** (plan, paczki, zapis do bazy,
przeliczanie stanów, panel), a nie szybkość identyfikacji wersji przez nmapa.

## Wyniki

| | przebieg 1 (wszystko nowe) | przebieg 2 (bez zmian) |
|---|---|---|
| adresy / żywe hosty / usługi | 16 384 / 16 384 / 32 768 | 16 384 / 16 384 / 32 768 |
| całość od startu do końca (z bazą i przeliczeniem stanów) | **86 s** | **85 s** |
| paczki discovery (adaptacyjnie) | 55, rozmiar 7 → 1024 | podobnie |
| paczki usług | 292, rozmiar 1 → 64 | podobnie |
| zdarzenia z przeliczenia stanów | 49 152 `new` | 0 |
| przeliczenie stanów (49 152 assety) | – | ok. 11 s |
| pamięć procesu `asi` (szczyt) | 182 MB | – |

API panelu przy 49 152 assetach:

| endpoint | czas | rozmiar |
|---|---|---|
| dashboard | 0,22 s | 4 kB |
| lista assetów (limit 5000) | 0,06 s | 2 MB |
| filtr assetów | 0,02 s | – |
| eksport CSV wszystkich assetów | 0,31 s | 5 MB |

Globalny limit 1000 pps (twardy limit polityki `ASI_MAX_RATE`) był utrzymany: suma czasów paczek discovery
to 131 s przy 8 równoległych procesach (ok. 16 s ściany).

## Znalezione i poprawione przy teście

- Domyślne porównanie („dwa ostatnie przebiegi”) brało przebiegi **różnych zbiorów celów**, co dawało 32 776
  fałszywych różnic i 5 MB odpowiedzi. Teraz brany jest poprzedni przebieg tego samego zbioru, panel pokazuje
  maks. 500 wierszy (reszta przez `asi diff -db … -json`), a skany z GUI zapisują stałą nazwę zbioru (`-set`).

## Szacunek dla prawdziwej sieci (nie pomiar)

Koszt dominujący to `-sV --version-light` na żywych hostach: w labie i na serwerach Hetznera **20–30 s/host**
przy limicie tempa. Dla 10 000 adresów z 10% żywych (1000 hostów) przy `-parallel 8`: ok. 1000 × 25 s / 8 ≈
**50 min** na etap usług, a discovery (0,1–0,2 s/host) to ok. 2–4 min. Przy `-parallel 20 -rate 2000`: ok. 20 min.
Okno czasowe i wznawianie ([Harmonogram](/guide/schedule)) obsługują dłuższe skany.

## Granice znane i świadome

- Lista assetów w GUI zwraca maks. 5000 wierszy (filtr zawęża). Pełny eksport ma CSV/JSON.
- Przeliczanie stanów trzyma wszystkie assety w pamięci (49 tys. ≈ kilkadziesiąt MB). Do ok. 500 tys. to OK,
  potem przetwarzanie partiami.
