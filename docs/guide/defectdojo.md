# Integracja z DefectDojo

## Uruchomienie

DefectDojo **3.5.202** stoi w głównym `docker-compose.yml` (oficjalne obrazy: django, nginx,
postgres 18, valkey 9, compose wyrównany do upstreamu, patrz `DECISIONS.md`, decyzja 3):

```bash
make env && make up
```

UI: `http://localhost:8080`, login `admin`, hasło: `grep DD_ADMIN_PASSWORD .env`.

`asi` bierze token z `DD_TOKEN` albo `DD_API_KEY`, a gdy oba są puste, loguje się
`DD_ADMIN_USER`/`DD_ADMIN_PASSWORD` (`/api/v2/api-token-auth/`). Produkt i typ produktu biorą się
z `DD_PRODUCT` i `DD_PRODUCT_TYPE` w `.env`, engagement to `discovery`, a test `ASI discovery`.
Stary PoC (`make poc`) pisze do engagementu `nmap` w tym samym produkcie.

## Dlaczego nie surowy XML nmapa

Parser „Nmap Scan” w DefectDojo tworzy **jedno znalezisko na port** i dokleja do niego wszystkie
hosty jako endpointy (pierwszy test: 6 znalezisk na 11 hostów). Nie da się wtedy śledzić,
że *na tym konkretnym hoście* port się pojawił lub zniknął, ani nadać różnej ważności RDP
w LAN i RDP w internecie.

Dlatego `asi` pakuje wyniki jako **Generic Findings Import** (`findings_defectdojo.json`):

| pole | wartość |
|---|---|
| `title` | `Open port 443/tcp on 203.0.113.10 (http)` — stabilny między przebiegami |
| `unique_id_from_tool` | `asi:203.0.113.10:443/tcp` |
| `severity` | z oceny ciekawości: high→Medium, medium→Low, low→Info |
| `description` | tabela: usługa, produkt, wersja, TLS, asset, domeny, powód oceny |
| `component_name` / `_version` | produkt i wersja z `-sV` |
| `endpoints` | IP + każda domena wskazująca na to IP, z portem i schematem (`https`, `ssh`, `rdp`…) |
| `tags` | `asi`, `interest-high/medium/low`, `svc-<usługa>`, tagi z pliku celów |

Surowy XML nadal można wysłać: `./asi upload -format nmap` (osobny test, bez historii).

## Historia zmian po stronie DefectDojo

Wszystkie przebiegi trafiają do **jednego testu** `ASI discovery` (produkt `ASI PoC`, engagement
`discovery`) przez `/api/v2/reimport-scan/`:

- `-upload live` — po każdej paczce usług reimport z `close_old_findings=false`
  (znaleziska pojawiają się w DefectDojo w trakcie skanu),
- na końcu pełny reimport z `close_old_findings=true` — DefectDojo **zamyka jako mitigated**
  usługi, których już nie ma, **reaktywuje** te, które wróciły, i liczy deltę
  (`created / closed / reactivated / untouched`), widoczną w logu i panelu,
- **przebieg przerwany** (okno, Ctrl+C) nigdy nie zamyka znalezisk — niezeskanowane hosty
  zostałyby błędnie oznaczone jako naprawione.

`-upload end` wysyła tylko końcowy reimport, `-upload off` (domyślnie) — nic;
`./asi upload` wysyła istniejący przebieg ręcznie.

## Znane ograniczenia

- Pole `protocol` endpointu ma w DefectDojo max 10 znaków — nazwy usług nmapa są mapowane na
  schematy (`ms-wbt-server`→`rdp`), nieznane są pomijane (zostaje `host:port`).
  Wcześniej powodowało to HTTP 500 przy reimporcie.
- Reimport porównuje znaleziska po hashu (tytuł + opis). Zmiana wersji usługi zmienia opis →
  DefectDojo widzi to jako zamknięcie starego i utworzenie nowego znaleziska. Dla nas to
  pożądane („zmieniona usługa”), ale w DefectDojo nie jest oznaczone wprost jako „changed”.
