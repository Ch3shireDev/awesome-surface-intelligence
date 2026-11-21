# Roadmap - Attack Surface Intelligence

Plan rozwoju etapami: najpierw dzialajacy PoC, potem dokladamy po jednym
klocku tak, zeby po kazdym etapie stack dalej dzialal i bylo widac efekt w
DefectDojo.

Zasada: **gotowe narzedzia + DefectDojo zamiast wlasnego kodu**. Wlasny kod
tylko tam, gdzie nic istniejacego nie spelnia wymagania albo gdzie nasze
rozwiazanie jest wyraznie lepsze (to jest nasze pole do innowacji).

Zrodlo wymagan: opis wyzwania "Attack Surface Intelligence" (CBI AGH) na
https://hacknation.pl/zadania (PDF "Szczegoly").

## Co mowi brief (skrot)

Prototyp do **cyklicznego discovery scanu duzej infrastruktury (>10 000 IP)**:
aktywne hosty, uslugi, fingerprint HTTP/HTTPS (tytul, kod, naglowki,
ciasteczka, cert TLS, przekierowania), technologie/CMS/IoT, panele admina i
srodowiska staging, **zmiany w czasie** (nowe / znikajace / zmienione uslugi,
hosty niestabilne), **wlasne sygnatury detekcyjne** (bezpieczne, bez
exploitacji), integracja z **DefectDojo**.

Dodatkowo wymagane: formularz celow (recznie + CSV/JSON), RBAC z 4 rolami,
edycja danych zachowywana miedzy skanami, dashboard, szyfrowanie danych w
spoczynku, harmonogram z oknami czasowymi (skan przerwany po oknie wznawia sie
w kolejnym), limit tempa, podzial celow na podgrupy, pomiar czasu skanu,
import/eksport JSON/CSV.

Test jury: lab z hostami, **min. 2 przebiegi skanu** (wykrywanie zmian),
edycja znalezisk, import, role. Wagi: discovery i uslugi 30%, zmiany w czasie
i niestabilne hosty 15%, jakosc/dokumentacja/DefectDojo 20%, bezpieczenstwo i
kontrola intensywnosci 15%, fingerprint/CMS/sygnatury 10%, role i ochrona
danych 10%. Sugerowane jezyki o niskim zuzyciu zasobow (Go, Rust, C++).

## Mapa: wymaganie -> czym to pokrywamy

Sprawdzone na naszej instancji DefectDojo 3.5.202: parsery `Nmap Scan`,
`Masscan Scan`, `Naabu Scan`, `httpx Scan`, `Nuclei Scan`, `WhatWeb Scan`,
`Testssl Scan` i `Generic Findings Import` sa dostepne. `reimport-scan` zwraca
diff `created / closed / reactivated / untouched`.

| Wymaganie | Pokrywa | Wlasny kod |
|---|---|---|
| Aktywne hosty | nmap `-sn` / naabu | konwerter na findingi (patrz etap 1) |
| Uslugi | nmap `-sV` -> `Nmap Scan` | nie |
| >10k IP, tempo, podgrupy | naabu/masscan (`--rate`), nmap `--min-hostgroup`, `--max-rate` | podzial listy celow na chunki (kilka linii) |
| HTTP: tytul, kod, naglowki, TLS, redirecty, tech | httpx (`-title -sc -td -tls-grab -fr -favicon`) -> `httpx Scan` | sprawdzic, co parser DD z tego zachowuje |
| CMS/technologie, panele, staging | nuclei (szablony `tech`, `panels`), ew. WhatWeb | nie |
| Wlasne sygnatury | **szablony nuclei (YAML)** w repo: naglowek, cookie, hash favicony, fragment HTML, sciezka, wersja | tylko szablony |
| Porownanie skanow, nowe/znikajace | DD `reimport-scan` (diff, historia importow) | nie |
| Zmienione uslugi | DD reimport (zmiana wersji w opisie) | do zweryfikowania |
| Hosty niestabilne (N brakow -> nieaktywny) | DD zamyka finding od razu przy `close_old_findings` | **tak - nasza logika, pole do innowacji** |
| Harmonogram + okna czasowe | kontener-scheduler (np. ofelia/supercronic) + `timeout` + `nmap --resume` / `nuclei -resume` | cienki wrapper |
| Formularz celow (recznie, CSV/JSON) | DD: Product -> Endpoints (dodawanie w UI) + import CSV; skaner pobiera cele z API DD | pobranie celow z API |
| Import wynikow JSON/CSV | DD `Generic Findings Import` | nie |
| Eksport JSON/CSV | DD (CSV/Excel w UI, JSON przez API) | nie |
| RBAC, 4 role | DD: Owner/Maintainer/Writer/Reader (+ superuser) | nie, tylko mapowanie i konfiguracja |
| Edycja zachowana miedzy skanami | DD reimport nie nadpisuje recznych zmian findingu | do zweryfikowania |
| Dashboard | DD dashboard, metryki, raporty | nie |
| Szyfrowanie w spoczynku | do wyboru: Postgres z TDE (np. Percona `pg_tde`) albo szyfrowany wolumen (LUKS) | konfiguracja |

## Etapy

### Etap 0 - stack + pierwszy import (ZROBIONE)
`make env && make up`, `make scan-fast`, `make import-latest` na `127.0.0.1`.
Findingi `Open Port: 22/TCP`, `8080/TCP` widoczne w DD.
Ustalenie: import samego `-sn` (liveness) przechodzi, ale daje **0 findingow**,
bo parser Nmapa w DD tworzy findingi tylko z otwartych portow.

### Etap 1 - PoC petli "discovery -> DD -> drugi przebieg -> diff" (ZROBIONE)
- `make poc`: `nmap -sn` + `nmap -F`, oba wyniki przez `reimport-scan` do
  stalych testow `nmap-discover` / `nmap-fast` (rodzaj z nazwy pliku).
- Liveness: `docker/nmap/scripts/nmap-hosts-to-generic.sh` (.gnmap ->
  `Generic Findings Import`, finding Info "Host Up" per host, tag `liveness`).
- Zweryfikowane na 127.0.0.1 (3 przebiegi): wlaczony port 8888 ->
  `created 1`, wylaczony -> `closed 1` (finding mitigated), reszta
  `untouched`. Host discovery: `untouched 1`.
- Ograniczenie: zamkniecie nastepuje juz po jednym braku - hosty niestabilne
  to etap 6.

### Etap 2 - identyfikacja uslug i skala
- `nmap -sV` na znalezionych portach; szybkie odkrywanie portow naabu/masscan
  z limitem `--rate`.
- Podzial celow na podgrupy + rownolegle uruchomienia, czas trwania z
  `runstats` nmapa / pol start-end testu w DD.

### Etap 3 - fingerprint HTTP/HTTPS
- httpx na uslugach HTTP -> `httpx Scan`. Sprawdzic, czy naglowki/cookies/cert
  laduja w DD; jesli nie - nuclei/nmap NSE (`http-headers`, `ssl-cert`,
  `http-cookie-flags`) jako uzupelnienie.

### Etap 4 - technologie, panele, wlasne sygnatury
- nuclei tylko z bezpiecznymi szablonami (`-tags tech,panel`, wykluczone
  `intrusive,dos,fuzz`), katalog `signatures/` z naszymi szablonami.
- Przyklady sygnatur od organizatora przepisujemy na szablony nuclei.

### Etap 5 - harmonogram, okna czasowe, limity
- Scheduler w compose, `timeout` do konca okna, wznowienie w kolejnym oknie.

### Etap 6 - niestabilne hosty i zmiany w czasie (innowacja)
- Host/usluga "nieaktywny" dopiero po N kolejnych brakach (np. tagi w DD,
  wlasny reconciler przez API), roznice zalezne od pory dnia, ocena
  "ciekawosci" findingow.

### Etap 7 - role, cele z DD, szyfrowanie, prezentacja
- Mapowanie 4 rol z briefu na role DD + uzytkownicy demo.
- Cele zarzadzane w DD (endpointy produktu) zamiast `scans/targets.txt`.
- Szyfrowanie w spoczynku, dokumentacja, prezentacja do 10 slajdow.

## Do potwierdzenia z mentorami (wazne dla architektury)
- Czy UI DefectDojo (formularze, RBAC, dashboard) moze byc "interfejsem
  rozwiazania", czy jury oczekuje wlasnego UI. Od tego zalezy, czy etap 7
  to konfiguracja DD, czy wlasna aplikacja.
- Lista dozwolonych portow, limity ruchu, zakres labu (patrz zasoby z briefu).
- Wymaganie szyfrowania: czy wystarczy szyfrowany wolumen, czy chca TDE w bazie.
