# Lab testowy i demo

Własna mała „infrastruktura” do testów i prezentacji (zadanie SEC-3). Imituje to, co w PDF jury opisuje
jako swoje środowisko: hosty z różnymi usługami, technologie webowe, panel admina, staging, ciekawe
nagłówki i ciasteczka, hosty niestabilne. Jury testuje „co najmniej dwa przebiegi skanu”, dlatego
lab ma dwa stany.

## Uruchomienie

```bash
make up          # stack asi (skaner musi działać)
make demo        # lab od zera -> przebieg 1 -> zmiany w labie -> przebieg 2 -> diff, upload do DD
make lab-ps      # stan kontenerów labu
make lab-down    # usuń lab
```

`make demo` skanuje z kontenera `nmap-scanner` cele z `targets/lab.csv`. Wyniki trafiają do `results/lab/`,
a w DefectDojo do produktu **ASI lab** (engagement `demo`). Porty są zawężone do tych, które lab wystawia,
więc jeden przebieg trwa ok. 20–30 s.

## Pliki celów do wgrania

Gotowe pliki do formularza **Cele → Import** w panelu (`asi server`, :18090) albo do CLI
(`asi scan -targets …`). Wszystkie trzy formaty opisują ten sam zakres labu: 12 adresów,
192.0.2.8–.15 i .16–.19.

| plik | format | do czego |
|---|---|---|
| <a href="/cele/lab.csv" download>lab.csv</a> | CSV | lab: zakresy CIDR z tagami i notatkami (kopia `targets/lab.csv`) |
| <a href="/cele/lab.json" download>lab.json</a> | JSON | to samo w formacie JSON (`asi convert`) |
| <a href="/cele/lab.txt" download>lab.txt</a> | TXT | to samo jako lista: jeden cel w linii |
| <a href="/cele/localhost.csv" download>localhost.csv</a> | CSV | tylko `127.0.0.1`, czyli test samej VM (kopia `targets/example.csv`) |

`lab.csv`:

<<< @/public/cele/lab.csv

`lab.json`:

<<< @/public/cele/lab.json

Format kolumn i pól opisuje strona [Format celów](/guide/targets). Przed wgraniem uruchom lab
(`make lab-up`), bo inaczej skan zwróci 0 aktywnych hostów.

## Sieć i bezpieczeństwo

- Osobny projekt compose `asi-lab` (`docker/lab/compose.yml`), niezależny od stacku `asi`.
- Sieć `192.0.2.0/24` to **TEST-NET-1 (RFC 5737)**. Adresy nie są routowane w internecie, więc gdy lab nie
  stoi, pakiety skanu nigdzie nie wychodzą.
- Bramka `192.0.2.1` to sama VM i jest celowo **poza zakresem** celów (`192.0.2.8/29`, `192.0.2.16/30`).
- Lab nie zawiera prawdziwych podatności ani powłok. Telnet na `legacy` odrzuca każde logowanie
  (`-l /bin/false`), a „WordPress” i „Jenkins” to statyczne strony z odciskami.
- Certyfikat TLS w `docker/lab/tls/` to self-signed **tylko do labu** (CN `intranet.lab.example`).

## Hosty i co powinien wykryć skaner

| IP | host | usługi | artefakty do wykrycia |
|---|---|---|---|
| 192.0.2.10 | `web-prod` | 80, 443 (TLS) | `Server: nginx/1.27.x`, `X-Powered-By: PHP/7.4.33` (stary PHP), cookie `PHPSESSID`, tytuł „Intranet AGH-LAB”, `/login` → przekierowanie, cert self-signed, wersja w stopce „LabPortal 1.8.2” |
| 192.0.2.11 | `wordpress` | 80 | CMS: `<meta name="generator" content="WordPress 6.4.2">`, `/wp-login.php` (cookie `wordpress_test_cookie`), `/readme.html`, `/wp-content/themes/…`, nagłówek `Link: …api.w.org` |
| 192.0.2.12 | `staging-admin` | 8080 | **staging**: `X-Environment: staging`, tytuł „[STAGING]”, cookie `staging_session`; **panel admina** `/admin/` („Admin Panel - Login”); `/version` (JSON, `2.3.1-rc1`) |
| 192.0.2.13 | `cache` | 6379 | redis/valkey **bez hasła** wystawiony w sieci |
| 192.0.2.14 | `legacy` | 23, 8000 | telnet (BusyBox telnetd), stary httpd; **znika w przebiegu 2** |
| 192.0.2.15 | `app` | 80 | przebieg 1: nginx, przebieg 2: BusyBox httpd na tym samym IP:port → **zmieniona usługa** |
| 192.0.2.16 | `jenkins` | 8080 | **nowy host w przebiegu 2**; `X-Jenkins: 2.401.1`, `X-Hudson`, cookie `JSESSIONID.*`, tytuł „Dashboard [Jenkins]” |
| 192.0.2.17 | `flaky` | 80 | port na przemian 30 s włączony / 30 s wyłączony → **host niestabilny** (`unstable` / `flapping` po kilku przebiegach) |

Adresy .8, .9, .18 i .19 są w zakresie, ale nic na nich nie ma: skaner powinien je pominąć jako nieaktywne.

## Oczekiwany wynik `make demo`

Sprawdzone 21.11 na VM B, w kontenerze skanera i z hosta:

```
przebieg 1: 7/12 hosts up, 9 open services (2 high, 1 medium)
przebieg 2: 7/12 hosts up, 7-8 open services
zmiany:
  + host    192.0.2.16
  - host    192.0.2.14
  ~ changed 192.0.2.15:80/tcp        http nginx 1.27.5 -> http
  - gone    192.0.2.14:23/tcp        telnet
  - gone    192.0.2.14:8000/tcp      http-alt
  + new     192.0.2.16:8080/tcp      http nginx 1.27.5
  (- gone   192.0.2.17:80/tcp        zależnie od fazy hosta flaky)
```

Etapy **http** (httpx) i **signatures** (nuclei + nasze szablony) idą automatycznie w każdym przebiegu.
Sprawdzone 21.11, 17:00, `make demo` na pełnym stacku:

| host | co wykrył fingerprint i sygnatury |
|---|---|
| .10 web-prod | PHP 7.4.33 (`asi-php-outdated`, medium), `PHPSESSID`, cert TLS self-signed `intranet.lab.example`, `/login` → przekierowanie, „LabPortal 1.8.2” w stopce |
| .11 wordpress | WordPress 6.4.2: `asi-html-generator`, `asi-cms-wordpress:readme`, `:api-link`, `:wp-login` |
| .12 staging-admin | staging (`X-Environment`, tytuł, `staging_session`), panel `/admin/`, `/version` 2.3.1-rc1 |
| .13 cache | Redis bez hasła (`asi-redis-noauth`, high) |
| .16 jenkins (przebieg 2) | httpx: Jenkins 2.401.1; `asi-jenkins` (medium), `asi-footer-version`, `asi-session-cookies:java` |

W DefectDojo przebieg 2 daje reimport `created 2, closed 4, untouched 5` oraz test `asi-changes`
z 4 warunkami (zniknięcia, zmiana, nowy host).

Wynik .17 zależy od chwili skanu, i o to chodzi: przy kilku przebiegach co chwilę
(`make asi ARGS="scan -targets targets/lab.csv -out results/lab"`) reconcile w bazie powinien oznaczyć go
jako `flapping`.

## Rozszerzanie

Nowy host to nowa usługa w `docker/lab/compose.yml` z kolejnym `ipv4_address` w 192.0.2.8–.19. Treść
stron leży w `docker/lab/html/<host>/`, a konfiguracja nginx w `docker/lab/nginx/<host>.conf`. Jeśli
host wychodzi poza zakres celów, dopisz go do `targets/lab.csv`. Do testów sygnatur (SEC-5) dokładaj
artefakty w HTML i nagłówkach, nigdy prawdziwe podatności.
