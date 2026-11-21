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

- **Nie uruchamiaj `docker compose up` ani zadnego celu `make scan-*` w tym
  srodowisku.** Stack docelowo dziala na dedykowanej VM (nmap potrzebuje
  NET_ADMIN/NET_RAW), nie na maszynie, na ktorej pracuje agent. Mozesz
  walidowac skladnie (`docker compose config`, `make -n <cel>`), ale nie
  faktyczne uruchomienie.
- **Nie skanuj niczego poza `scans/targets.txt`, a ten plik nie istnieje w
  repo dopoki zakres nie zostanie potwierdzony z mentorami CBI AGH** (patrz
  "Otwarte pytania" w `docs/DECISIONS.md`). Nie wpisuj przykladowych
  adresow IP jako "defaultowych" celow skanu.
- **Nie commituj `.env`, `scans/targets.txt` ani plikow wynikowych
  `scans/results/*.xml`** - sa w `.gitignore` celowo (dane ze srodowiska
  sandbox, API key DefectDojo).
- DefectDojo jest dashboardem docelowym - nie buduj wlasnego frontendu/UI
  do wizualizacji wynikow, to zdublowana praca wzgledem tego, co juz daje
  DefectDojo.
- `docker-compose.yml` bazuje na typowej, znanej strukturze DefectDojo
  (oficjalne obrazy z Docker Hub), ale nie byl uruchamiany/testowany w tej
  sesji. Jesli coś w nim poprawiasz na podstawie faktycznego uruchomienia,
  zaktualizuj rowniez `docs/DECISIONS.md` (sekcja decyzji nr 3).

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
- `Makefile` - sterowanie skanami i importem do DefectDojo.
- `scans/targets.example.txt` - szablon listy celow (skopiuj do
  `scans/targets.txt` PO potwierdzeniu zakresu).
- `docs/DECISIONS.md` - log decyzji, otwarte pytania, TODO wedlug
  priorytetu. Aktualizuj na biezaco zamiast trzymac ustalenia tylko w
  rozmowie.
