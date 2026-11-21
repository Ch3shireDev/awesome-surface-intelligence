# Roadmapa: gdzie jesteśmy

**Ostatnia aktualizacja: 21.11.2026, 16:00** (agent blackarch). Zasada: kto kończy zadanie z
[`TASKS.md`](TASKS.md), aktualizuje tu wiersz etapu i pasek postępu, a w [`status.md`](status.md) wymagania.

Legenda: ✅ zrobione · 🔨 w toku · ⏳ następne · ⬜ nie zaczęte · ⏸ odłożone.

```
M0 Stack + PoC            ██████████ 100%  ✅
M1 Silnik skanowania      ██████████ 100%  ✅
M2 Fundament (kontrakt+DB)████████░░  80%  🔨  brak: SEC-1 arm64, SEC-2 materiały, SEC-3 lab
M3 Historia i stany       ░░░░░░░░░░   0%  ⏳  DEV-2
M4 Web GUI                ██░░░░░░░░  20%  ⏳  DEV-4 (panel postępu jest, brak formularza/dashboardu)
M5 Fingerprint i sygnatury░░░░░░░░░░   0%  ⬜  SEC-4, SEC-5
M6 Ochrona danych i role  █░░░░░░░░░  10%  ⬜  SEC-6, DEV-3 (Sealer w bazie gotowy)
M7 Harmonogram i eksport  ███░░░░░░░  30%  ⬜  DEV-5, DEV-6, SEC-7, SEC-8
M8 Finisz dla jury        ██░░░░░░░░  20%  ⬜  SEC-9, ALL-1, ALL-2 (dokumentacja w VitePress jest)
```

## Etapy

| etap | cel (co widać w demo) | zadania | stan |
|---|---|---|---|
| **M0** Stack + PoC | DefectDojo 3.5.202 w compose, pierwszy import nmapa, pętla reimportu | Etap 0–1 PoC fatusi | ✅ |
| **M1** Silnik skanowania | `asi scan`: plan celów (CSV/JSON/TXT, CIDR, domeny, reguły zakresu), 2 fazy nmapa, adaptacyjne paczki, globalny limit pps, okno czasowe, pasek CLI + panel SSE, diff, skan potwierdzający, reimport Generic Findings (`created/closed/reactivated`) | silnik z `~/asi-poc` | ✅ |
| **M2** Fundament | kontrakt `Observation` + interfejs `Scanner` (adaptery), Postgres `asi-db` z migracjami, przebiegi i obserwacje w bazie, diff z bazy, cały stack przez `make up` | DEV-0 ✅, DEV-1 ✅, SEC-1, SEC-2, SEC-3 | 🔨 |
| **M3** Historia i stany | assety ze stanami `new/active/missing/gone`, `reappeared`, `flapping`, próg braków dla hostów, zasada pokrycia (`partial` nie zamyka), edycje użytkownika trwałe między skanami | DEV-2 | ⏳ |
| **M4** Web GUI (najwyżej punktowane) | logowanie (na start 1 admin), formularz celów (ręcznie + CSV/JSON), start skanu z panelu, lista assetów z edycją, dashboard: najważniejsze znaleziska, zmiany, niestabilne hosty | DEV-4 | ⏳ |
| **M5** Fingerprint i sygnatury | httpx: tytuł, kod, nagłówki, cookies, TLS, przekierowania, technologie, favicon; nuclei z naszymi szablonami (CMS, panel, staging, wersja) | SEC-4, SEC-5, DEV-7 | ⬜ |
| **M6** Ochrona danych i role | AES-256-GCM dla pól `_enc` + szyfrowanie Postgresa w spoczynku (mentor: „darmowe 5%”), RBAC lokalny (4 role, jeśli starczy czasu), audit log | SEC-6, DEV-3 | ⬜ |
| **M7** Harmonogram i eksport | cron + okno + wznawianie paczek `deferred`, eksport JSON/CSV, import cudzych wyników, eksport do DD natywnymi parserami, twarde limity skanera | DEV-5, DEV-6, SEC-7, SEC-8 | ⬜ |
| **M8** Finisz | publiczne repo bez sekretów, czyste uruchomienie od zera, prezentacja ≤10 slajdów, nagranie demo, dokumentacja 100% | SEC-9, ALL-1, ALL-2 | ⬜ |

## Ścieżka krytyczna

```
DEV-0 ✅ → DEV-1 ✅ → DEV-2 ⏳ → DEV-4 ⏳ ──────────────→ demo (2 przebiegi + GUI)
                         ↘ SEC-4 → SEC-5 (fingerprint)  ↗
                         ↘ SEC-6 (szyfrowanie)         ↗
```

Plan awaryjny (z `TASKS.md`): jeśli GUI nie zdąży, demo idzie na CLI + obecnym panelu postępu
i DefectDojo; RBAC zostaje jednym kontem admina (mentor to akceptuje).

## Dziennik postępu

| kiedy | co się zmieniło |
|---|---|
| 21.11 ~13:00 | PoC: chunkowany nmap → DefectDojo (`~/asi-poc`) |
| 21.11 ~14:00 | 2 fazy, adaptacyjne paczki, postęp CLI + web, diff, potwierdzanie zniknięć, Generic Findings |
| 21.11 14:44 | konsultacja z mentorem: GUI wymagane, Postgres + szyfrowanie, RBAC 10% ([MENTOR](MENTOR.md)) |
| 21.11 ~15:30 | scalenie repo `~/asi`; DEV-0 kontrakt `Observation`, adaptery nmap |
| 21.11 ~15:50 | DEV-1 baza `asi-db`, zapis przebiegów, `asi diff -db`; obraz skanera z pgx |
| 21.11 ~16:00 | stary DefectDojo z `~/asi-poc` usunięty; cały stack przez `make up`; skan z kontenera → baza + DD sprawdzony |

---

# Archiwum: pierwotna mapa wymagań (przed decyzją 8)

Plan rozwoju etapami: najpierw dzialajacy PoC, potem dokladamy po jednym
klocku tak, zeby po kazdym etapie stack dalej dzialal i bylo widac efekt w
DefectDojo.

**Kierunek od 21.11: wlasny system ASI (Go) z eksportem do DefectDojo** -
architektura i rdzen w [`VISION.md`](VISION.md). Mapa wymagan nizej
powstala, gdy zakladalismy DD jako UI; wiersze o RBAC, formularzu,
dashboardzie i diffie realizuje teraz ASI (DD dostaje eksport).

Zasada: **gotowe narzedzia zamiast wlasnego kodu**. Wlasny kod
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

Etapy 0-1 to PoC na Makefile + skryptach (zostaje jako test dymny).
Dalej budujemy ASI wg `VISION.md`:

### Etap 2 - rdzen ASI
- `asi-postgres`, migracje, model danych (VISION 4.2), szkielet `asi`
  (server / worker / CLI), tokeny + pierwszy admin.
- Import celow (CSV/JSON/recznie), rozwijanie zakresu, wykluczenia,
  chunking (staly rozmiar), kolejka River.
- Worker: etapy `discovery` + `ports` na nmapie, obserwacje w bazie.
- Postep runu (`asi run status --watch`).
- Eksport do DD (przeniesiona logika z `import-defectdojo.sh`).
- Demo: to samo co `make poc`, ale przez `asi` i na chunkach.

### Etap 3 - historia i diff
- Assety, reconcile (VISION 4.7): new/missing/gone/reappeared/changed,
  zasada pokrycia i hierarchii, flapping, `asi changes` / `asi diff`.
- Eksport eventow do DD jako `Generic Findings` (`asi-changes`).

### Etap 4 - RBAC i audit
- 4 role, uprawnienia per trasa API, audit log, edycja assetow (tagi,
  notatki) zachowywana miedzy runami.

### Etap 5 - wiecej skanerow
- naabu (`ports`), `nmap -sV` (`services`), httpx (`http`), nuclei + nasze
  sygnatury (`signatures`).

### Etap 6 - harmonogram i limity
- Profile z cronem i oknem czasowym, `deferred` chunki, globalny limit pps,
  dozwolone porty, adaptacyjny rozmiar chunkow.

### Etap 7 - szyfrowanie, web UI, prezentacja
- Szyfrowanie pol (VISION 6), web UI na API, dokumentacja, slajdy.

## Do potwierdzenia z mentorami (wazne dla architektury)
- ~~Czy UI DefectDojo moze byc interfejsem rozwiazania~~ - rozstrzygniete:
  DD to cel eksportu, budujemy wlasny system (DECISIONS 8).
- Lista dozwolonych portow, limity ruchu, zakres labu (patrz zasoby z briefu).
- Kiedy i gdzie (Discord / stanowisko AGH) dostaniemy materialy z briefu:
  konfiguracje labu, przykladowe sygnatury, format eksportu/importu JSON/CSV,
  wyniki referencyjne, liste "ciekawych artefaktow".
- Wymaganie szyfrowania: czy wystarczy szyfrowany wolumen, czy chca TDE w bazie.
