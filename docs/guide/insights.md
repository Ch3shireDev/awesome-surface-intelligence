# Ocena ciekawości, grupy usług, pora dnia

Punkty „mile widziane” z PDF: *ocena „ciekawości” lub priorytetu analitycznego, grupowanie podobnych usług,
wykrywanie różnic zależnych od pory dnia*, a także pkt 9 (*zmienione usługi*). DEV-7.

## Ocena 0–100 z powodami (`findings.Rank`)

Jeden wynik na otwarty port, liczony z wszystkiego, co o nim wiadomo:

| składnik | punkty |
|---|---|
| port wysokiego ryzyka (RDP, bazy, Redis, Docker API, Telnet…) na publicznym IP / w sieci wewnętrznej | 80 / 50 |
| port administracyjny (8080, 8443, 9000, Webmin…) na publicznym IP | 50 |
| najsilniejsza sygnatura: high / medium / low | 85 / 60 / 35 (zastępuje bazę, jeśli wyższa) |
| każda kolejna istotna sygnatura | +5 (maks. +15) |
| certyfikat self-signed albo niezgodny z nazwą na publicznym IP | +10 |
| certyfikat wygasły | +10 |
| HTTP 401/403 (zasób chroniony) | +5 |
| nowa ekspozycja w ostatnim przebiegu | +10 |
| usługa niestabilna (flapping) | +5 |

Poziom: ≥ 75 high, ≥ 45 medium, poniżej low. **Ocena analityka zawsze wygrywa**: fałszywy alarm i
zaakceptowane ryzyko znikają z listy, a nadpisany poziom ustala wynik. Dashboard pokazuje 100 najwyżej ocenionych
portów z wynikiem i listą powodów, np.:

```
80 high    192.0.2.14/tcp/23     telnet          Telnet exposed on a public IP
70 medium  192.0.2.10/tcp/443    nginx 1.27.5    Nieaktualny PHP (7.4.33) · certyfikat self-signed na publicznym IP
60 medium  192.0.2.16/tcp/8080   nginx 1.27.5    alt HTTP / admin on a public IP · Jenkins (2.401.1)
```

## Grupy podobnych usług

Aktywne porty grupowane po **produkcie i wersji** (z `-sV`) oraz po **technologii** (z httpx/Wappalyzera).
Grupa to ≥ 2 hosty. Przykład z labu: `nginx 1.27.5` na 5 hostach, `PHP 7.4.33` na 2. „pokaż →” otwiera listę
assetów przefiltrowaną po usłudze (`GET /api/v1/assets?svc=…`). Jedna podatność w wersji albo jedna decyzja
analityka dotyczy wtedy całej grupy.

## Wzorce pory dnia

Każdy asset ma `hours_seen`: bitmapę 24 godzin (UTC), w których był widziany. Panel zestawia ją z godzinami, w
których **w ogóle były skany** (ostatnie 14 dni). Host widziany np. tylko w `08-17 UTC`, a nieobecny w skanach o
`02 UTC`, trafia do karty „Wzorce pory dnia” (warunki: ≥ 2 obserwacje, są godziny skanu bez odpowiedzi, host
miał braki albo jest niestabilny). Żeby to działało, harmonogram powinien skanować o różnych porach (np. dwa
harmonogramy: dzień i noc).

## Zmiana treści HTTP jako zdarzenie `changed`

Port ma dwa odciski: usługi (nmap: nazwa, produkt, wersja) i **HTTP** (status, tytuł, serwer, technologie,
favicon, nazwy ciasteczek, certyfikat, przekierowanie). Zmiana strony albo certyfikatu daje zdarzenie `changed`
z „przed” i „po”. Porównanie odbywa się tylko wtedy, gdy etap http w danym przebiegu obserwował ten port, więc skan
bez `httpx` nie produkuje fałszywych zmian. Mniej szczegółowa obserwacja usługi (brak wersji) też nie jest zmianą.

Testy: `internal/findings/score_test.go`, `TestReconcileHTTPChange`.
