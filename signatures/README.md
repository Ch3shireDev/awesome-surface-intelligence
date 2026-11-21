# Sygnatury ASI (nuclei)

Własne sygnatury detekcyjne etapu `signatures` (SEC-5). Uruchamia je `asi scan` przez nuclei **tylko z tego
katalogu**, na URL-ach, które odpowiedziały w etapie `http`, oraz na `host:port` usług z sygnaturami sieciowymi
(np. Redis). Wynik to obserwacja `signature` na assecie `IP/tcp/port`, widoczna w panelu (szuflada assetu,
„Najważniejsze znaleziska” dla severity ≥ low).

## Zasady (sprawdzane testem `internal/scanner/nuclei`)

- `id` zaczyna się od `asi-`.
- **Tylko detekcja**: żadnych `POST`/`PUT`/`DELETE`, payloadów, `attack:`, haseł, interactsh.
  Ścieżki typu `/login` czy `/admin` wolno tylko odczytać przez GET.
- Tagi `intrusive, dos, fuzz, brute-force, exploit, rce, sqli, xss, lfi` są wykluczone w adapterze (`-etags`),
  więc taka sygnatura i tak się nie uruchomi.
- `severity`: `info` to fakt (technologia, wersja), `low` to warto spojrzeć (panel, staging), `medium` to
  prawdopodobny problem (nieaktualne oprogramowanie, wystawiony CI, `.git`), `high` to poważna ekspozycja (Redis bez hasła).

## Jak dodać sygnaturę

1. Plik `signatures/http/asi-<nazwa>.yaml` (albo `network/` dla TCP).
2. Szkielet, np. wykrycie nagłówka:

```yaml
id: asi-grafana
info:
  name: Grafana
  author: twoje-imie
  severity: info
  description: Nagłówek/tytuł Grafany.
  tags: asi,tech,grafana
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words: ["<title>Grafana</title>"]
    extractors:
      - type: regex
        part: body
        group: 1
        regex: ['"version":"([0-9.]+)"']
```

3. Sprawdź: `nuclei -t signatures/http/asi-grafana.yaml -validate`, potem
   `nuclei -t signatures/http/asi-grafana.yaml -u http://192.0.2.12:8080 -nc -duc -ni` na labie.
4. `go test ./internal/scanner/nuclei` (lint bezpieczeństwa wszystkich szablonów).
5. Commit. Kontener czyta katalog z repo (`./signatures` jest podpięty), więc wystarczy kolejny skan.

Typy dopasowań: nagłówek (`part: header`, regex), ciasteczko (`set-cookie`), fragment HTML (`part: body`),
ścieżka (`path`), wersja (extractor `group: 1`), hash favicony (`dsl: mmh3(base64_py(body)) == "…"`),
TCP (`tcp: inputs/data`).

## Obecne sygnatury

| id | severity | co wykrywa |
|---|---|---|
| `asi-tech-php-version` | info | wersja PHP z `X-Powered-By` |
| `asi-php-outdated` | medium | PHP 5.x / 7.x / 8.0 (bez wsparcia bezpieczeństwa) |
| `asi-session-cookies` | info | nazwa ciasteczka sesji zdradza framework lub środowisko |
| `asi-staging-environment` | low | `X-Environment: staging/dev/test` albo tytuł ze „staging” |
| `asi-html-generator` | info | `<meta name="generator">` (CMS i wersja) |
| `asi-cms-wordpress` | info | WordPress po `/wp-login.php`, `/readme.html`, nagłówku `Link` |
| `asi-admin-panel` | low | `/admin/`, `/administrator/`, `/login`, `/wp-admin/`, `/manager/html` ze stroną logowania |
| `asi-login-redirect` | info | `/login`, `/admin` przekierowują do logowania |
| `asi-version-endpoint` | low | `/version`, `/api/version`, `/actuator/info` z wersją |
| `asi-footer-version` | info | nazwa i wersja w stopce strony |
| `asi-jenkins` | medium | Jenkins (`X-Jenkins`) |
| `asi-favicon-known` | info | znane hashe favicony (Jenkins, Tomcat, Spring Boot) |
| `asi-git-exposed` | medium | publiczny `/.git/HEAD` |
| `asi-redis-noauth` | high | Redis odpowiada na `PING` bez hasła (tylko PING) |
| `asi-iot-camera-hikvision` | low | kamera/rejestrator Hikvision (treść albo nagłówek `App-webs`/`DNVRS-Webs`) |
| `asi-iot-camera-dahua` | low | kamera/rejestrator Dahua (nagłówek `DNVRS-Webs`, model `DH-…`) |
| `asi-iot-camera-generic` | low | „IP camera” / DVR / NVR / system nadzoru z ekranem logowania |
| `asi-iot-router-mikrotik` | low | RouterOS / WebFig |
| `asi-iot-router-openwrt` | low | LuCI na OpenWrt |
| `asi-iot-printer` | low | panel drukarki (HP, Epson, Brother, Xerox, Konica, Kyocera, Ricoh, Lexmark) |
| `asi-iot-nas` | low | Synology DSM, QNAP QTS, TrueNAS/FreeNAS, OpenMediaVault |
| `asi-iot-embedded-server` | info | wbudowany serwer WWW firmware'u (`GoAhead-Webs`, `Boa`, `uc-httpd`, `thttpd`, `mini_httpd`…) |
| `asi-iot-upnp-description` | info | opis urządzenia UPnP (`/rootDesc.xml`): producent i model |
