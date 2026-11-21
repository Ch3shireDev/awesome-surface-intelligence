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

Bezpieczeństwo: jeden GET na URL, `-rl` (żądania/s na proces, ≤ 100) z globalnego limitu, timeout 8 s,
1 ponowienie, `-nfs` (bez przeskakiwania http↔https), bez podążania za przekierowaniami, żeby obserwacja
zawsze dotyczyła tego IP:portu.

Odcisk (`fp_hash`) obejmuje status, tytuł, serwer, technologie, favicon, nazwy ciasteczek, certyfikat i
`Location`, bez dat i wartości ciasteczek.

## Etap `signatures` (SEC-5, nuclei)

Uruchamia **wyłącznie nasze szablony** z `signatures/`, bez pobierania publicznej bazy. Opis, lista i
instrukcja „jak dodać sygnaturę” są w `signatures/README.md` w repo.
Flagi: `-ni` (bez interactsh i zewnętrznych callbacków), `-etags intrusive,dos,fuzz,brute-force,exploit,rce,sqli,xss,lfi`,
`-rl ≤ 50`, `-timeout 5`, `-mhe 3`.

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
