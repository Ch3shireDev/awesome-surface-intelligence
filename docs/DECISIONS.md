# Decyzje i ustalenia - Attack Surface Intelligence (HackNation 2026)

Stan na: 21.11.2026 (dzien startu Wydarzenia). Ten plik to zywy log decyzji -
aktualizuj go, nie zgaduj na nowo przy kazdej sesji.

## Kontekst wyzwania

- Wyzwanie: **Attack Surface Intelligence**, partner: AGH / Centrum
  Bezpieczenstwa Informacji AGH (CBI AGH), hackathon HackNation 2026
  (21-22.11.2026, Bydgoszcz).
- Cel wg briefu: kompleksowe rozwiazanie do automatycznego skanowania
  bezpieczenstwa - integracja narzedzi pentestowych (m.in. Nmap), pipeline
  skanowania podatnosci, dashboard do wizualizacji wynikow, raportowanie.
- Dostarczone przez organizatora: DefectDojo (API v2, swagger dostepny),
  dokumentacja Nmap, SecureCodeBox (framework orkiestracji skanow), srodowisko
  sandbox z danymi testowymi.
- Kryteria oceny: funkcjonalnosc skanowania, jakosc integracji z dostarczonymi
  narzedziami/API, UX/czytelnosc dashboardu, jakosc i dokumentacja kodu,
  innowacyjnosc ponad wymagany zakres.

## Prawa autorskie / zasady konkursu (sprawdzone w pelnym regulaminie CBI AGH)

- Tylko **zwycieski zespol** podpisuje Umowe o dzielo i przenosi na AGH pelne
  autorskie prawa majatkowe do rozwiazania (laczne wynagrodzenie 25 000 zl
  brutto, dzielone rowno miedzy czlonkow zespolu, chyba ze zlozą inny podzial
  na pismie przed podpisaniem).
- Brak NDA, brak klauzuli zakazu konkurencji w regulaminie.
- Ten sam szablon prawny (slowo w slowo) wystepuje w regulaminie UZP
  (Odwolania2json) - najpewniej identyczny we wszystkich 15 wyzwaniach.
- Jesli zespol NIE podpisze umowy w 7 dni, traci prawo do nagrody (idzie do
  kolejnej druzyny z rankingu) - ale zachowuje pelne prawa do wlasnego kodu.
- Nic nie stoi na przeszkodzie, zeby repo bylo publiczne/open source JUZ
  teraz, w trakcie zgloszenia (regulamin tego wymaga/dopuszcza - link do repo
  w materialach konkursowych) - kwestia cesji dotyczy wylacznie wygranej.

## Decyzje architektoniczne

1. **Docker Compose, nie VM/K8s jako platforma orkiestracji.** Szybsze do
   postawienia w 24h, reprodukowalne, zgodne z tym jak jury testuje repo
   ("praktyczne przetestowanie dzialania (...) przeglad struktury kodu").
   Docelowo uruchamiane na dedykowanej VM (nie lokalnie), bo kontener
   nmapa potrzebuje uprawnien (NET_ADMIN/NET_RAW) do skanow SYN/wersji.

2. **SecureCodeBox swiadomie ODRZUCONY.** SCB jest naciwnie K8s-owy
   (operator + CRD-y ScanType/Scan/ScheduledScan) - postawienie go
   wymagaloby lokalnego klastra (kind/k3d) w srodku hackathonu, co jest
   zbyt duzym ryzykiem czasowym jak na 24h. Robimy "po swojemu": wlasny
   maly kontener z nmapem + Makefile zamiast frameworka orkiestracji.
   (Mozliwy stretch goal pozniej, patrz "Zaleglosci / TODO".)

3. **DefectDojo z oficjalnych obrazow Docker Hub** (`defectdojo/defectdojo-django`,
   `defectdojo/defectdojo-nginx`), NIE build lokalny z zrodel - oszczednosc
   czasu na starcie. `docker-compose.yml` w repo NIE byl uruchamiany/testowany
   w tej sesji - przed pierwszym `make up` zweryfikuj nazwy zmiennych
   srodowiskowych wzgledem aktualnej dokumentacji DefectDojo (bywaja
   aktualizowane miedzy wersjami).

4. **DefectDojo = dashboard.** Nie budujemy wlasnego UI/frontendu -
   DefectDojo juz ma pelny interfejs (findings, severity, engagements,
   metryki, raporty). Nasz wklad to pipeline: skan -> XML -> import do
   DefectDojo (`/api/v2/import-scan/`, `scan_type=Nmap Scan` - wbudowany
   parser, nic nie trzeba pisac recznie).

5. **Nmap w osobnym, malym kontenerze** (alpine + nmap + curl + jq),
   sterowany z `Makefile` (cele `scan-discover` / `scan-fast` / `scan-full`
   / `scan-service` / `scan-udp`), wyniki ladowane do `scans/results/*.xml`
   (zamontowany wolumen), gotowe do importu.

## Otwarte pytania / do potwierdzenia z CBI AGH

- [ ] **Dokladny zakres skanu** (CIDR/hostname'y sandboxa) - bez tego nie ma
      czego wpisac do `scans/targets.txt`.
- [ ] Czy zalozenie "plaski intranet bez firewalli/segmentacji do omijania"
      jest poprawne, czy jest tam cos, co moze zmylic wyniki skanu.
- [ ] Czy sandbox jest dostepny z poziomu VM od razu, czy wymaga VPN/dostepu
      specjalnego.

## Zaleglosci / TODO (kolejnosc wedlug priorytetu)

1. Postawic stack na VM, przejsc pierwsze logowanie do DefectDojo, wygenerowac
   API key, utworzyc Product + Engagement, wpisac `DD_API_KEY` /
   `DD_ENGAGEMENT_ID` do `.env`.
2. Potwierdzic zakres skanu z mentorami, uzupelnic `scans/targets.txt`.
3. Przejsc petle: `make scan-fast` -> `make import-defectdojo FILE=...` ->
   sprawdzic findings w UI DefectDojo. To jest core MVP.
4. Jak dziala podstawowa petla: dodac `scan-service` do wzbogacenia wynikow
   (wersje uslug), ew. CVSS/CVE jesli DefectDojo tego nie robi automatycznie
   z samego Nmapa.
5. Stretch goal (tylko jesli zostanie czas): drugi typ skanera na inna
   warstwe attack surface (np. Nikto pod warstwe webowa) - DefectDojo ma
   gotowy parser, wiec koszt dodania jest niski a podnosi "kompletnosc"
   wzgledem kryteriow oceny.
6. Stretch goal (opcjonalny, niski priorytet): k3d + prawdziwe SecureCodeBox,
   tylko jesli MVP dziala i zostaje czas do konca.
