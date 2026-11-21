# Fingerprint HTTP i sygnatury

Lejek etapów (VISION 4.3): każdy etap dostaje tylko to, co znalazł poprzedni.

```
discovery (nmap -sn) → services (nmap -sV, top 1000 + porty wysokiego ryzyka)
   → http (httpx: porty webowe z services) → signatures (nuclei: URL-e, które odpowiedziały + host:port Redisa)
```

## Etap `http` (SEC-4, httpx)

Wejście: porty z nazwą usługi `http*` albo typowe porty webowe (80, 443, 8000, 8080, 8443, 8888, 3000, 5000,
9000, 9090…), nawet jeśli nmap ich nie nazwał (np. 8888 jako `sun-answerbook`). Schemat `https`, gdy nmap
widział TLS albo port to 443/8443/9443.

| zbierane | pole obserwacji `http` |
|---|---|
| tytuł strony, kod odpowiedzi | `title`, `status` |
| nagłówki (bez `Date`) | `headers` |
| ciasteczka (same nazwy, bez wartości sesji) | `cookies` |
| przekierowanie (`Location`, bez podążania) | `redirects` |
| certyfikat TLS: CN, SAN, wystawca, ważność, self-signed, niezgodność nazwy, SHA-256 | `tls_*` |
| technologie (Wappalyzer), serwer, hash favicony (mmh3) | `tech`, `webserver`, `favicon_mmh3` |
| czas odpowiedzi HTTP (ms, flaga `-rt`, próg `ASI_HTTP_SLOW_MS`, dom. 500 ms) | `response_time_ms` |

Bezpieczeństwo: jeden GET na URL, `-rl` (żądania/s na proces, ≤ 100) z globalnego limitu, timeout 8 s,
1 ponowienie, `-nfs` (bez przeskakiwania http↔https), bez podążania za przekierowaniami, żeby obserwacja
zawsze dotyczyła tego IP:portu.

Odcisk (`fp_hash`) obejmuje status, tytuł, serwer, technologie, favicon, nazwy ciasteczek, certyfikat i
`Location`, bez dat, wartości ciasteczek ani `response_time_ms` (zmiana opóźnienia nie generuje fałszywego zdarzenia `changed`).

## Etap `signatures` (SEC-5, nuclei)

Uruchamia **wyłącznie nasze szablony** z `signatures/`, bez pobierania publicznej bazy. Opis, lista i
instrukcja „jak dodać sygnaturę” są w `signatures/README.md` w repo.
Flagi: `-ni` (bez interactsh i zewnętrznych callbacków), `-etags intrusive,dos,fuzz,brute-force,exploit,rce,sqli,xss,lfi`,
`-rl ≤ 50`, `-timeout 5`, `-mhe 3`.

### Sygnatury IoT (SEC-10)

Punkt 6 zadania wymienia **urządzenie IoT** obok CMS, frameworka i serwera aplikacyjnego. Doszło 9 sygnatur
detekcyjnych (tylko GET, bez prób logowania) w `signatures/http/`:

| id | wykrywa |
|---|---|
| `asi-iot-camera-hikvision` | kamera/rejestrator Hikvision (treść strony albo nagłówek `App-webs`/`Hikvision-Webs`/`webs`) |
| `asi-iot-camera-dahua` | kamera/rejestrator Dahua (nagłówek `DNVRS-Webs`, model `DH-…`) |
| `asi-iot-camera-generic` | ogólne urządzenie wizyjne: „IP camera”, DVR/NVR, system nadzoru + ekran logowania |
| `asi-iot-router-mikrotik` | RouterOS / WebFig |
| `asi-iot-router-openwrt` | LuCI na OpenWrt |
| `asi-iot-printer` | drukarka z panelem WWW (HP, Epson, Brother, Xerox, Konica, Kyocera, Ricoh, Lexmark) |
| `asi-iot-nas` | Synology DSM, QNAP QTS, TrueNAS/FreeNAS, OpenMediaVault |
| `asi-iot-embedded-server` | wbudowany serwer WWW firmware'u (`GoAhead-Webs`, `Boa`, `uc-httpd`, `thttpd`, `mini_httpd`, …) |
| `asi-iot-upnp-description` | publiczny opis urządzenia UPnP (`/rootDesc.xml`) z producentem i modelem |

### Sygnatury usług, paneli i labu organizatorów (LAB-T3)

Dodatkowe 10 bezpiecznych sygnatur (wyłącznie GET, bez prób logowania) pod usługi i panele spotykane w
infrastrukturze i w [labie organizatorów](/guide/lab-organizers):

| id | severity | wykrywa |
|---|---|---|
| `asi-phpmyadmin` | low | panel baz danych phpMyAdmin (ciasteczko, tytuł, pola formularza, wersja) |
| `asi-adminer` | low | panel baz danych Adminer (tytuł, formularz, wersja) |
| `asi-dvwa` | medium | Damn Vulnerable Web Application (aplikacja testowa/labowa) |
| `asi-gitea` | info | serwer repozytoriów Gitea (`i_like_gitea`, stopka, wersja) |
| `asi-rabbitmq-management` | low | panel RabbitMQ Management (tytuł lub `WWW-Authenticate`) |
| `asi-nginx-proxy-manager` | low | panel Nginx Proxy Manager (`/` lub `/api/` z wersją) |
| `asi-traefik-dashboard` | medium | niezabezpieczony dashboard/API Traefika (`--api.insecure`) |
| `asi-toxiproxy-api` | medium | otwarte API sterowania proxy Toxiproxy (`/proxies`) |
| `asi-httpbin` | info | usługa diagnostyczna/testowa httpbin |
| `asi-wordpress-outdated` | medium | nieaktualna wersja WordPressa (< 6.0, np. 4.7 w `vulnerable`) |

Dlaczego tak: same nazwy modeli/producentów to fakt techniczny (severity `low`/`info`), a nie podatność —
panel urządzenia to sygnał „sprawdź to ręcznie”, bo IoT często ma domyślne konta i nieaktualny firmware.
Wzorce są zawężone (np. „printer” **i** nazwa producenta), żeby nie łapać zwykłych stron o druku.
Sprawdzone na atrapie 7 urządzeń pod `127.0.0.1` (`nuclei -validate` + przebieg na atrapie: 6/9 trafień
pozytywnych, brak fałszywych trafień Dahua/MikroTik/NAS), a lint `go test ./internal/scanner/nuclei`
pilnuje, że żadna sygnatura nie wysyła POST-a i nie ma wykluczonych tagów.

## Porty wysokiego ryzyka spoza top 1000

Lista „top 1000” nmapa **nie zawiera** m.in. Redis 6379, MongoDB 27017, Memcached 11211, Docker API 2375/2376,
Kibany 5601, RabbitMQ 15672, CouchDB 5984, Cassandry 9042, etcd 2379, kubeleta 10250, Kubernetes API 6443,
Consula 8500 ani ActiveMQ 61616. Adapter nmapa zamienia więc `--top-ports N` na jawne `-p` = lista top-N
odczytana z zainstalowanego nmapa + te porty (`RiskyPorts` w `internal/scanner/nmap`). Bez tego otwarty
Redis z labu w ogóle nie był wykrywany. Jawne `-p` albo lista dozwolonych portów z polityki ma pierwszeństwo.

## Wynik na labie (21.11)

| host | wykryte |
|---|---|
| 192.0.2.10 web-prod | TLS self-signed `intranet.lab.example`, nginx 1.27.5, **PHP 7.4.33 (nieaktualny, medium)**, `PHPSESSID`, `/login` → przekierowanie, „LabPortal 1.8.2” w stopce |
| 192.0.2.11 wordpress | **WordPress 6.4.2** (generator, `wp-login.php`, `readme.html`, nagłówek `Link`), MySQL/PHP z Wappalyzera |
| 192.0.2.12 staging-admin | **staging** (nagłówek `X-Environment`, tytuł `[STAGING]`, ciasteczko `staging_session`), **panel `/admin/`**, `/version` → 2.3.1-rc1 |
| 192.0.2.13 cache | **Redis 7.2.4 bez hasła (high)** |
| 192.0.2.17 flaky | host migający: `reappeared` / `changed` między przebiegami |

Czas na labie: http < 1 s na paczkę, sygnatury 1–8 s. Wszystko trafia do `asi-db` (obserwacje `http` i
`signature`), do panelu (szuflada assetu: sekcja „HTTP i sygnatury”; dashboard: sygnatury ≥ low w
„Najważniejszych znaleziskach”) i do plików przebiegu (`http/`, `signatures/` jako dowody).

## Wyłączanie

`asi scan -http off` (bez obu etapów), `-signatures ""` (bez sygnatur). Bez httpx/nuclei w PATH etapy są
pomijane z informacją w logu.
