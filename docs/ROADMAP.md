# Roadmapa: gdzie jesteśmy

**Ostatnia aktualizacja: 21.11.2026, 17:30** (agent blackarch, przegląd wymagań PDF vs kod). Zasada: kto kończy zadanie z
[`TASKS.md`](TASKS.md), aktualizuje tu wiersz etapu i pasek postępu, a w [`status.md`](status.md) wymagania.

Legenda: ✅ zrobione · 🔨 w toku · ⏳ następne · ⬜ nie zaczęte · ⏸ odłożone.

```
M0 Stack + PoC            ██████████ 100%  ✅
M1 Silnik skanowania      ██████████ 100%  ✅
M2 Fundament (kontrakt+DB)█████████░  90%  🔨  DEV-0/1 ✅, SEC-1 ✅, SEC-3 lab ✅; brak: SEC-2 materiały od organizatorów
M3 Historia i stany       ██████████ 100%  ✅  DEV-2
M4 Web GUI                ██████████ 100%  ✅  DEV-4 ✅, DEV-8 ✅, DEV-9 ✅ (porównanie przebiegów, ocena analityka, edycja harmonogramu), HTTP/sygnatury w assecie ✅
M5 Fingerprint i sygnatury██████████ 100%  ✅  SEC-4 httpx, SEC-5 nuclei + 14 sygnatur (DEV-7 osobno)
M6 Ochrona danych i role  █████████░  95%  ✅  SEC-6 ✅ (pg_tde + AES-GCM), role+audit ✅; brak: tokeny API w GUI (DEV-3)
M7 Harmonogram i eksport  █████████░  90%  🔨  DEV-5 ✅, SEC-8 ✅, SEC-7 🟡 (asi-changes ✅; parsery httpx/nuclei do DD: do zrobienia, M5 gotowe), DEV-6 ✅ (eksport + import)
M8 Finisz dla jury        ███░░░░░░░  30%  🔨  test skali ✅ (DEV-10); SEC-9, ALL-1, ALL-2 nie zaczęte
```

## Etapy

| etap | cel (co widać w demo) | zadania | stan |
|---|---|---|---|
| **M0** Stack + PoC | DefectDojo 3.5.202 w compose, pierwszy import nmapa, pętla reimportu | Etap 0–1 PoC fatusi | ✅ |
| **M1** Silnik skanowania | `asi scan`: plan celów (CSV/JSON/TXT, CIDR, domeny, reguły zakresu), 2 fazy nmapa, adaptacyjne paczki, globalny limit pps, okno czasowe, pasek CLI + panel SSE, diff, skan potwierdzający, reimport Generic Findings (`created/closed/reactivated`) | silnik z `~/asi-poc` | ✅ |
| **M2** Fundament | kontrakt `Observation` + interfejs `Scanner` (adaptery), Postgres `asi-db` z migracjami, przebiegi i obserwacje w bazie, diff z bazy, cały stack przez `make up` | DEV-0 ✅, DEV-1 ✅, SEC-1 ✅, SEC-2, SEC-3 ✅ | 🔨 |
| **M3** Historia i stany | assety ze stanami `new/active/missing/gone`, `reappeared`, `flapping`, próg braków dla hostów, zasada pokrycia (`partial` nie zamyka), edycje użytkownika trwałe między skanami | DEV-2 | ✅ |
| **M4** Web GUI (najwyżej punktowane) | logowanie (na start 1 admin), formularz celów (ręcznie + CSV/JSON), start skanu z panelu, lista assetów z edycją, dashboard: najważniejsze znaleziska, zmiany, niestabilne hosty | DEV-4 ✅, DEV-8 ✅ | ✅ |
| **M5** Fingerprint i sygnatury | httpx: tytuł, kod, nagłówki, cookies, TLS, przekierowania, technologie, favicon; nuclei z naszymi szablonami (CMS, panel, staging, wersja) | SEC-4 ✅, SEC-5 ✅, DEV-7 |  ✅ |
| **M6** Ochrona danych i role | AES-256-GCM dla pól `_enc` + szyfrowanie Postgresa w spoczynku (mentor: „darmowe 5%”), RBAC lokalny (4 role, jeśli starczy czasu), audit log | SEC-6 ✅, DEV-3 🟡 | ✅ |
| **M7** Harmonogram i eksport | cron + okno + wznawianie paczek `deferred`, eksport JSON/CSV, import cudzych wyników, eksport do DD natywnymi parserami, twarde limity skanera | DEV-5 ✅, DEV-6 🟡, SEC-7 🟡, SEC-8 ✅ | 🔨 |
| **M8** Finisz | publiczne repo bez sekretów, czyste uruchomienie od zera, prezentacja ≤10 slajdów, nagranie demo, dokumentacja 100% | SEC-9, ALL-1, ALL-2 | ⬜ |

## Ścieżka krytyczna

```
DEV-0 ✅ → DEV-1 ✅ → DEV-2 ✅ → DEV-4 ✅ ─────────────────────────────→ demo (2 przebiegi + GUI) ✅ działa
                         ↘ SEC-4 ✅ → SEC-5 ✅ → sekcja w GUI ✅ → SEC-7 parsery httpx/nuclei ↗
                         ↘ SEC-6 ✅ (szyfrowanie)                                    ↗
M8: SEC-9 (czyste repo + uruchomienie od zera) → ALL-1 (prezentacja + nagranie) → oddanie
```

## Pokrycie wymagań PDF (przegląd 21.11, 17:30)

Każdy punkt sprawdzony w kodzie, nie tylko w dokumentacji. Szczegóły: [`status.md`](status.md).

| wymaganie z PDF | stan | brakuje |
|---|---|---|
| 1. wczytanie IP / CIDR / domen | ✅ | – |
| 2. bezpieczny, wielowątkowy skan; czas trwania; podział na podgrupy | ✅ | – |
| 3–4. aktywne hosty, identyfikacja usług | ✅ | – |
| 5. HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | ✅ | – |
| 6. CMS, framework, serwer aplikacyjny, **urządzenia IoT** | 🟡 | brak sygnatur IoT (kamery, routery, drukarki) → **SEC-10** |
| 7. staging, panel administracyjny | ✅ | – |
| 8–9. porównanie przebiegów; nowe / znikające / zmienione | ✅ | porównanie w GUI (DEV-9); zmiana usługi i treści HTTP (tytuł, certyfikat, technologie) jako `changed` (DEV-7) |
| 10. własne sygnatury | ✅ | (opcja) wgrywanie sygnatur z GUI |
| 11. formularz celów, ręcznie + CSV/JSON | ✅ | – |
| 12–13. RBAC, 4 role | ✅ | tokeny API w GUI (DEV-3, mała) |
| 14. edycja wartości niezależnie od skanu, trwała | ✅ | tagi, notatki, ocena analityka (FP / zaakceptowane / ocena) eksportowana do DD, edycja harmonogramu (DEV-9) |
| 15. czytelny interfejs, dashboard | ✅ | – |
| 16. szyfrowanie w spoczynku | ✅ | – |
| min.: import wyników skanów JSON/CSV | ✅ | DEV-6: nmap XML, CSV, JSON, JSONL; GUI i CLI |
| min.: obsługa >10 000 IP | ✅ | DEV-10: 16 384 adresy w 86 s (z bazą i przeliczeniem stanów), dashboard 0,22 s przy 49 tys. assetów ([Test skali](/guide/scale)) |
| min.: porównanie dwóch skanów | ✅ | GUI i CLI (DEV-9) |
| min.: edycja danych istniejących skanów, wyników i konfiguracji | ✅ | wyniki: ocena analityka, tagi, notatki; konfiguracja: cele, harmonogramy (DEV-9) |
| mile widziane: pora dnia, ocena ciekawości, grupowanie usług | ✅ | DEV-7: ocena 0–100 z powodami, grupy usług/technologii, wzorce pory dnia ([Ocena, grupy, pora dnia](/guide/insights)) |
| mile widziane: eksport wybranych obserwacji do DD | 🟡 | eksport jest całościowy; natywne parsery httpx/nuclei → **SEC-7** |
| formalne: repozytorium, dokumentacja, prezentacja ≤10 slajdów + demo | 🟡 | publiczne repo (**SEC-9**), prezentacja (**ALL-1**), uruchomienie od zera (**ALL-2**) |

## Co zostało do wzięcia (kolejność wg wagi w ocenie)

| zadanie | etap | co konkretnie | kto | waga |
|---|---|---|---|---|
| **DEV-6** | M7 | import wyników skanów (nmap XML, JSON/CSV) z GUI i CLI do bazy jako przebieg, z przeliczeniem stanów | ✅ agent blackarch | minimum PDF, test jury „import” |
| **DEV-9** | M4 | GUI: porównanie dwóch dowolnych przebiegów; oznaczanie wyników (fałszywy alarm, zaakceptowane, nadpisana ocena), honorowane przez dashboard i eksport; edycja harmonogramu | ✅ agent blackarch | minimum PDF, test jury „edycja znalezisk” |
| **DEV-10** | M8 | test skali: ≥10 000 adresów lokalnie (127.0.0.0/18, wyłącznie loopback), pomiar skanu, zapisu, przeliczania stanów i dashboardu; poprawki wydajności | ✅ agent blackarch | 30% („w dużej infrastrukturze”) |
| **DEV-7** | M5 | zmiana treści HTTP jako `changed`, ocena ciekawości z portów, HTTP i sygnatur razem, grupowanie podobnych usług, wzorce pory dnia z `hours_seen` | ✅ agent blackarch | 10–15% + „mile widziane” |
| **SEC-10** | M5 | sygnatury IoT (kamery, routery, drukarki, panele urządzeń) | wolne (SEC) | pkt 6 PDF |
| **SEC-7** | M7 | natywne parsery httpx/nuclei do DD | wolne (SEC) | 20% (integracja DD) |
| **SEC-9** | M8 | publiczne repo bez sekretów i realnych IP; `git clone && make env && make up && make demo` | wolne | formalny wymóg |
| **ALL-1** | M8 | prezentacja ≤10 slajdów + nagranie demo | wszyscy | formalny wymóg |
| **ALL-2** | M8 | `status.md` 100%, quickstart przetestowany przez drugą osobę | wszyscy | 20% |
| **DEV-3** | M6 | tokeny API w GUI | wolne | mała |
| **SEC-2** | M2 | materiały organizatorów (lab, porty, limity, format JSON/CSV) | człowiek na miejscu | ryzyko testu jury |
| drobne | docs | `vitepress preview` ignoruje `--host` i słucha na wszystkich interfejsach (`make docs`) | wolne | bezpieczeństwo |

## Dziennik postępu

| kiedy | co się zmieniło |
|---|---|
| 21.11 ~18:45 | DEV-7: ocena 0–100 z powodami (port, sygnatury, TLS, świeżość, flapping, ocena analityka), grupy podobnych usług i technologii, wzorce pory dnia, zmiana treści HTTP jako `changed` |
| 21.11 ~18:30 | DEV-10: test skali 16 384 adresów (loopback) w 86 s, dashboard 0,22 s przy 49 tys. assetów; poprawione domyślne porównanie (ten sam zbiór celów), `-set` dla skanów z GUI, ponawianie `apk add` w Dockerfile |
| 21.11 ~18:10 | DEV-9: porównanie dwóch przebiegów w GUI, ocena analityka (FP / zaakceptowane / ocena) trwała i eksportowana do DD jako false_p / risk_accepted, edycja harmonogramu; ocena usunięta z opisu znaleziska DD (stabilny hash) |
| 21.11 ~17:50 | DEV-6: import wyników (nmap XML, CSV, JSON, JSONL httpx/nuclei) w GUI i `asi import`, pokrycie auto/none, import historyczny; mniej szczegółowa obserwacja usługi nie jest już „zmianą” |
| 21.11 ~17:30 | przegląd wymagań PDF vs kod: M4 85% (brak porównania przebiegów i edycji wyników w GUI), brak importu wyników, brak testu 10k, brak sygnatur IoT; nowe zadania DEV-9, DEV-10, SEC-10 |
| 21.11 ~17:10 | M5: SEC-4 httpx (etap `http`), SEC-5 nuclei + 14 sygnatur (etap `signatures`), porty wysokiego ryzyka spoza top 1000 (Redis wykryty), szuflada „HTTP i sygnatury” i sygnatury na dashboardzie; blokery: `make env-sync`, restart nginx, import scala tagi |
| 21.11 ~13:00 | PoC: chunkowany nmap → DefectDojo (`~/asi-poc`) |
| 21.11 ~14:00 | 2 fazy, adaptacyjne paczki, postęp CLI + web, diff, potwierdzanie zniknięć, Generic Findings |
| 21.11 14:44 | konsultacja z mentorem: GUI wymagane, Postgres + szyfrowanie, RBAC 10% ([MENTOR](MENTOR.md)) |
| 21.11 ~15:30 | scalenie repo `~/asi`; DEV-0 kontrakt `Observation`, adaptery nmap |
| 21.11 ~15:50 | DEV-1 baza `asi-db`, zapis przebiegów, `asi diff -db`; obraz skanera z pgx |
| 21.11 ~16:00 | stary DefectDojo z `~/asi-poc` usunięty; cały stack przez `make up`; skan z kontenera → baza + DD sprawdzony |
| 21.11 ~16:10 | DEV-2: assety ze stanami, flapping, zasady pokrycia (hosty i porty) i hierarchii, edycje trwałe; `asi changes/assets/asset edit` |
| 21.11 ~16:20 | DEV-4: panel web `asi server` (login, dashboard, assety z edycją, formularz/import celów, skany z GUI + postęp na żywo, role, audit, eksport CSV/JSON); kontener skanera startuje panel na :8090 |
| 21.11 ~16:25 | SEC-3: lab `docker/lab` (8 hostów, 192.0.2.0/24) + `make demo`: new/gone/changed/unstable w 2 przebiegach |
| 21.11 ~16:30 | DEV-5: harmonogram (cron + okno) w panelu, wznawianie niezeskanowanych celów w kolejnym oknie, wstrzymaj/wznów/anuluj, `asi scan -resume` |
| 21.11 ~16:47 | DEV-8: cele z dowolnego tekstu (DeepSeek / regex) w panelu i `asi targets-extract`, serwer MCP `asi mcp` |
| 21.11 ~16:50 | SEC-8: polityka skanera `internal/safety` (zakres, wykluczenia wbudowane i własne, allowlista portów i flag nmapa, twardy limit pps), sprawdzana w planie i w workerze; profile `raw`/`unprivileged`, decyzja UDP |
| 21.11 ~16:50 | SEC-6: `asi-db` na `pg_tde` (tabele, indeksy, WAL; AES-256) + pola `_enc` AES-256-GCM, rotacja kluczy, `make env-keys`, `make crypto-check` 9/9 OK ([Szyfrowanie](guide/encryption.md)) |
| 21.11 ~16:55 | panel: oś „Zmiany w czasie” z godziną i datą przebiegów, klikalne KPI (np. „otwarte usługi” → Assety z filtrem), filtr oceny; pliki celów do pobrania w dokumentacji |
| 21.11 ~17:00 | SEC-7: test `asi-changes` w DD (missing/gone/flapping/zmiana, zamykane, gdy warunek mija), brak `close_old` dla przebiegów częściowych też w `asi upload`, `-format nmap` do stałego `asi-nmap`; lab: 4 przebiegi, missing → gone ([DefectDojo](guide/defectdojo.md)) |

