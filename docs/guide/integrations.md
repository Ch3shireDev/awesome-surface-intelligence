# Źródła pasywne, eksport wybranych, SIEM

## Źródła pasywne

Panel: **Cele → Źródła pasywne** (API: `POST /api/v1/passive`, rola `operator`). Dla podanej domeny:

| źródło | co daje | dokąd wychodzi zapytanie |
|---|---|---|
| Certificate Transparency | nazwy z certyfikatów w obrębie domeny | Cert Spotter, zapasowo crt.sh (domena) |
| DNS | adresy nazw | resolver hosta ASI (nazwy) |
| inwentarz pasywny (opcja, domyślnie wyłączona) | porty widziane wcześniej przez Shodan | InternetDB (tylko publiczne IP) |

Nic nie jest skanowane. **Dodaj jako wyłączone** zapisuje nowe nazwy z tagiem `passive` i `enabled=false`, istniejących
celów nie zmienia. Limity: 200 nazw, 50 adresów w inwentarzu. Porty z inwentarza nie są weryfikowane. InternetDB jest
bezpłatny tylko do użytku niekomercyjnego.

## Eksport wybranych

Panel: **Assety**, zaznacz wiersze (API: `POST /api/v1/export/selected` `{"keys":[...],"to":"csv|json|dojo|siem"}`).

- `csv`, `json`: każda rola,
- `dojo`: rola `operator`, porty trafiają do osobnego testu `asi-selected` z `close_old=false`,
- `siem`: rola `operator`.

Każdy eksport trafia do dziennika audytu.

## Powiadomienia SIEM

`ASI_SIEM_URL` w `.env` (puste = wyłączone), potem `make up`:

- `https://host/webhook`: POST JSON `{"source":"asi","events":[...]}`,
- `udp://host:514`, `tcp://host:514`: syslog RFC 5424 bez TLS, używać w zaufanej sieci.

Po każdym skanie wychodzą zdarzenia (`new`, `changed`, `reverted`, `missing`, `gone`, `reappeared`, `flapping`,
`filtered`): typ, klucz `ip/proto/port`, przebieg, czas. Bez notatek, nagłówków i ciasteczek. Wysyłka bez ponawiania:
błąd trafia do logu skanu i nie przerywa go. Import wyników powiadomień nie wysyła.
