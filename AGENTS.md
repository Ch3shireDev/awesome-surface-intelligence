# AGENTS.md

Kontekst dla agentow AI pracujacych w tym repo (Claude Code / inne).

## Co to jest

Projekt hackathonowy na HackNation 2026, wyzwanie **Attack Surface
Intelligence** (partner: AGH/CBI AGH). Cel: pipeline do automatycznego
skanowania bezpieczenstwa (Nmap) z importem wynikow do DefectDojo
(dostarczone przez organizatora narzedzie do zarzadzania podatnosciami).
Pelny kontekst decyzji: `docs/DECISIONS.md` - przeczytaj go PRZED
wprowadzaniem zmian architektonicznych, zawiera uzasadnienia (np. dlaczego
SecureCodeBox zostal swiadomie odrzucony na rzecz wlasnego rozwiazania).

## Twarde zasady

- **Stack uruchamiamy tylko na dedykowanej VM** (nmap potrzebuje
  NET_ADMIN/NET_RAW i `network_mode: host`). Na innej maszynie tylko
  walidacja skladni (`docker compose config`, `make -n <cel>`).
- **Wszystko zamyka sie w repo.** Konfiguracja jako pliki w repo podpinane
  bind-mountami do kontenerow, narzedzia (nmap, curl, jq) tylko w
  kontenerach. Na hoscie wymagane wylacznie: docker + compose plugin, make,
  openssl. Nie instaluj niczego innego na hoscie.
- **Nie skanuj niczego poza `scans/targets.txt`.** Do czasu potwierdzenia
  zakresu z mentorami CBI AGH (patrz "Otwarte pytania" w
  `docs/DECISIONS.md`) jedynym dozwolonym celem jest `127.0.0.1` (sama VM,
  do testow pipeline'u). Nie wpisuj przykladowych adresow IP jako
  "defaultowych" celow skanu.
- **Nie commituj `.env`, `scans/targets.txt` ani plikow wynikowych
  `scans/results/*.xml`** - sa w `.gitignore` celowo (dane ze srodowiska
  sandbox, API key DefectDojo).
- DefectDojo jest dashboardem docelowym - nie buduj wlasnego frontendu/UI
  do wizualizacji wynikow, to zdublowana praca wzgledem tego, co juz daje
  DefectDojo.
- `docker-compose.yml` jest wyrownany do upstreamowego compose DefectDojo
  3.5.202. Jesli cos w nim poprawiasz, zaktualizuj rowniez
  `docs/DECISIONS.md` (sekcja decyzji nr 3).

## Konwencje

- Wszystkie inwokacje nmapa ida przez `Makefile` - to jedyne miejsce, gdzie
  trzymamy konkretne flagi/opcje skanu. Nie dodawaj ad-hoc wywolan nmapa w
  skryptach obok.
- Nowe cele `make` dopisuj w sekcji odpowiadajacej istniejacemu wzorcowi
  (patrz `scan-fast` jako referencja) i dodaj je do listy w `help:`.
- Sekrety/klucze (`DD_API_KEY`, hasla) tylko w `.env` (gitignored), nigdy w
  `docker-compose.yml`, `Makefile` ani kodzie.

## Gdzie co jest

- `docker-compose.yml` - caly stack (DefectDojo + nmap-scanner).
- `docker/nmap/Dockerfile` - obraz skanera (alpine + nmap + curl + jq).
- `docker/nmap/scripts/` - skrypty montowane do skanera w `/opt/asi`
  (`import-defectdojo.sh` - import wynikow przez API v2).
- `docker/defectdojo/extra_settings/` - nadpisania settings DefectDojo.
- `Makefile` - sterowanie skanami i importem do DefectDojo.
- `scans/targets.example.txt` - szablon listy celow (skopiuj do
  `scans/targets.txt` PO potwierdzeniu zakresu).
- `docs/ROADMAP.md` - streszczenie briefu, mapa wymaganie -> narzedzie,
  plan etapow. Przed nowym etapem sprawdz, co pokrywa gotowe narzedzie/DD.
- `docs/DECISIONS.md` - log decyzji, otwarte pytania, TODO wedlug
  priorytetu. Aktualizuj na biezaco zamiast trzymac ustalenia tylko w
  rozmowie.
