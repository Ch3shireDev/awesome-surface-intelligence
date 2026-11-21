# Status projektu

Stan na 21.11.2026. Legenda: ✅ zrobione i przetestowane · 🟡 częściowo · ❌ nie zrobione · ❓ wymaga decyzji.

## Wymagania ze specyfikacji

| # | wymaganie | stan | jak / co brakuje |
|---|---|---|---|
| 1 | wczytanie IP, CIDR, domen | ✅ | CSV/JSON/TXT, wspólny schemat, `asi convert`; [Format celów](/guide/targets) |
| 2 | bezpieczny, wielowątkowy skan nmap | ✅ | worker pool, `-sT`, `--version-light`, globalny `-rate`; [Bezpieczeństwo](/guide/safety) |
| 2 | czas trwania skanu | ✅ | `timings.csv` per faza, `run.json`, ETA na żywo |
| 2 | podział na optymalne podgrupy | ✅ | 2 fazy + adaptacyjny `Sizer` (EWMA s/host) + pamięć `tuning.json`; [Podział](/guide/chunking) |
| 3 | wykrycie aktywnych hostów | ✅ | faza discovery (`-sn`, TCP SYN/connect ping na 8 portów) |
| 3 | …w sieciach blokujących sondy | 🟡 | `-skip-discovery`; brak ICMP bez roota ❓ (uruchamiać nmap z `CAP_NET_RAW`?) |
| 4 | identyfikacja usług | ✅ | `-sV --version-light`, top 1000 TCP |
| 4 | UDP | ❌ | nie skanujemy UDP (wolne); ❓ czy potrzebne (DNS/SNMP/NTP)? |
| 5 | HTTP: tytuł, kod, nagłówki, cookies, TLS, przekierowania | ❌ | **następny krok** — moduł Go `net/http` na usługach http/https z fazy 2 |
| 6 | wykrywanie technologii / CMS / IoT | ❌ | po module HTTP: reguły na nagłówkach, cookies, HTML, favicon hash |
| 7 | staging / panel admina | 🟡 | tagi z wejścia (`staging`, `admin`) + ocena portów admin; brak detekcji z treści |
| 8 | porównanie przebiegów | ✅ | `asi diff`, panel, automatycznie po skanie; [Porównanie](/guide/diff) |
| 9 | nowe / znikające / zmienione usługi | ✅ | `new / gone / changed`, plus `created/closed/reactivated` w DefectDojo |
| 10 | własne sygnatury | ❌ | plan: YAML (nagłówek, cookie, regex HTML, ścieżka GET, favicon mmh3) — po module HTTP |
| 11 | formularz: ręcznie + CSV/JSON | ✅ | GUI: formularz ręczny + import CSV/JSON/TXT do bazy, walidacja wejścia ([Panel web](/guide/gui)) |
| 12–13 | RBAC, 4 role | ✅ | lokalne role viewer/analyst/operator/admin na każdej trasie API, użytkownicy w GUI, audit log |
| 14 | edycja wartości niezależnie od skanu, trwała | ✅ | GUI + CLI: tagi, notatka, nadpisania na assecie (trwałe), edycja celów; audit log |
| 15 | czytelny interfejs + dashboard | ✅ | dashboard: kafelki, najważniejsze znaleziska, zmiany, niestabilne, wykres zmian w czasie; postęp skanu na żywo |
| 16 | szyfrowanie at-rest | ✅ | 2 warstwy: TDE `pg_tde` w `asi-db` (tabele, indeksy, WAL; AES-256) + pola `_enc` AES-256-GCM w aplikacji (`ASI_ENCRYPTION_KEYS`, rotacja); dowód `make crypto-check`; [Szyfrowanie](/guide/encryption) |
| — | harmonogram, okna czasowe | ✅ | cron + okno w GUI, wznawianie niezeskanowanych celów w kolejnym oknie, wstrzymaj/wznów/anuluj ([Harmonogram](/guide/schedule)) |
| — | ograniczanie tempa | ✅ | `-rate` globalny, `-parallel`, timeouty |
| — | eksport JSON/CSV | ✅ | assety CSV/JSON z GUI/API; `services.json`, `findings_defectdojo.json` |
| — | import wyników skanów JSON/CSV | ❌ | baza jest; brak importera cudzych wyników (DEV-6) |
| — | hosty / usługi niestabilne | ✅ | stany `new/active/missing/gone`, `reappeared`, `flapping`, progi braków, zasady pokrycia i hierarchii ([Historia](/guide/history)); skan potwierdzający |
| — | integracja DefectDojo | ✅ | Generic Findings, reimport do stałego testu, upload na żywo; [DefectDojo](/guide/defectdojo) |
| — | ocena „ciekawości” | ✅ | `high/medium/low` + powód; mapowanie na severity w DefectDojo |
| — | tagi | ✅ | tagi celów (formularz/import) i assetów (edycja w GUI, trwałe między skanami) |
| — | dokumentacja | ✅ | ta strona (VitePress) |

## Lab i demo (SEC-3, 21.11)

✅ `make demo`: własny lab w compose (`docker/lab`, 8 hostów w 192.0.2.0/24) i 2 przebiegi ze zmianami
pomiędzy. Wykrywa nowy host, zniknięty host, zmienioną usługę, zniknięte i nowe porty oraz host niestabilny.
Sprawdzone z hosta i w kontenerze skanera. Lab ma też artefakty pod fingerprint i sygnatury (WordPress,
staging, panel admina, stary PHP, Jenkins, cert TLS). Opis: [Lab testowy i demo](/guide/lab).

## Elementy tej iteracji (co i jak przetestowano)

| element | test |
|---|---|
| dwufazowy skan + adaptacja | prawdziwy skan 37 IP: discovery 16+16+5 hostów, usługi 1–3 hosty; testy jednostkowe `Sizer` (adaptacja, clamp, wyrównanie końcówki, tryb stały) |
| pasek CLI | uruchomiony pod `script` (TTY) i bez TTY; widoczne procenty workerów, ETA, status DefectDojo |
| panel web + SSE | `/api/live`, `/api/events` w trakcie skanu; historia i diff z `asi serve` |
| upload na żywo | 8 reimportów w trakcie skanu + końcowy z `close_old` |
| cykl zmian w DefectDojo | selftest localhost: `created → closed → reactivated` |
| potwierdzanie zniknięć | selftest: port „zgubiony” w 1. przejściu → zachowany z tagiem `unstable`; port naprawdę zamknięty → `gone` |
| okno czasowe | `-window 5s`: nmapy zabite, `interrupted`, brak zamykania znalezisk |
| parsery wejścia | CSV, JSON, TXT + CIDR, dedup, `enabled=false` (test jednostkowy) |

## Decyzje do podjęcia

1. **Architektura UI / RBAC / baza.** Opcje:
   (a) rozbudować panel w Go + PostgreSQL z `pgcrypto`/szyfrowaniem pól w aplikacji, własny RBAC;
   (b) oprzeć RBAC na DefectDojo (ma użytkowników, role, uprawnienia per produkt) i trzymać
   w `asi` tylko skaner + panel postępu;
   (c) hybryda: logowanie do panelu `asi` przez token DefectDojo i mapowanie jego ról.
   Spec wymaga 4 konkretnych ról i **własnego** formularza — (b) sam nie wystarczy.
   **Rekomendacja: (a)** — jedna binarka, SQLite/PostgreSQL, role w kodzie, szyfrowanie pól AES-GCM
   kluczem z env; DefectDojo jako cel eksportu.
2. **Zgoda na skan cudzych hostów**: wiersze bez zgody właściciela mają `enabled=false`.
3. **Punkt obserwacji.** Skan z `blackarch` nie widzi tailnetu Daniela ani sieci Incus. Czy
   skanujemy z węzła w tailnecie Daniela / z `vision`? Czy wspieramy wiele sond?
4. **Uprawnienia nmapa.** Bez roota: connect scan, brak ICMP i SYN. Z `CAP_NET_RAW`: szybciej i
   lepsze discovery, ale skaner wymaga uprawnień. Na zawodach środowisko testowe w kontenerach —
   prawdopodobnie OK.
5. **Licencje (regulamin §4.2: rozwiązanie wolne od wad prawnych; prawa przechodzą na AGH).**
   nmap ma licencję NPSL (ograniczenia redystrybucji w produktach komercyjnych) — wołamy go jako
   zewnętrzny program, nie dołączamy. DefectDojo — BSD-3. Kod `asi` — tylko stdlib Go.
   Do potwierdzenia z mentorami, że wywołanie nmapa jest OK.
6. **Format organizatorów** — czekamy na „przykładowy format eksportu/importu JSON/CSV”,
   „listę dozwolonych portów” i „limity ruchu” (sekcja 7 spec). `-rate` i `-nmap` są gotowe na te limity.
7. ~~**Współpraca z repo zespołu**~~ — rozstrzygnięte 21.11: jedno repo, własny system w Go z eksportem
   do DD (`DECISIONS.md` 8 i 10, `VISION.md`).

## Następne kroki (kolejność)

1. Moduł HTTP/HTTPS (tytuł, kod, nagłówki, cookies, certyfikat, przekierowania, favicon hash) — 10% oceny wprost i podstawa sygnatur.
2. Sygnatury YAML + detekcja CMS/staging/admin.
3. Baza (SQLite → PostgreSQL) + szyfrowanie pól + RBAC + formularz w panelu.
4. Harmonogram + wznawianie w kolejnym oknie + hosty niestabilne.
5. Eksport CSV, import cudzych wyników.
