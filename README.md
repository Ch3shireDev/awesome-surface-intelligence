# Attack Surface Intelligence - HackNation 2026

Pipeline do automatycznego skanowania bezpieczenstwa: Nmap (wlasny kontener,
sterowany z Makefile) -> import wynikow do DefectDojo (dostarczony przez
CBI AGH, pelni role dashboardu/zarzadzania podatnosciami).

Decyzje i uzasadnienia architektury: [`docs/DECISIONS.md`](docs/DECISIONS.md).
Kontekst dla agentow AI pracujacych w repo: [`AGENTS.md`](AGENTS.md).

## Zanim cokolwiek odpalisz

1. **Potwierdz zakres skanu z mentorami CBI AGH** (adresy/CIDR sandboxa).
   Bez tego nie skanuj niczego "na sprobe".
2. Skopiuj `.env.example` -> `.env` i uzupelnij `DD_SECRET_KEY` /
   `DD_CREDENTIAL_AES_256_KEY` (patrz komentarze w pliku) oraz haslo admina.
3. Odpal to na VM z Linuksem (nmap w kontenerze potrzebuje uprawnien
   NET_ADMIN/NET_RAW) - nie na laptopie przez Docker Desktop.

## Start

```bash
cp .env.example .env            # i uzupelnij wartosci
make up                         # stawia DefectDojo + kontener skanera
```

Pierwsze logowanie do DefectDojo: http://localhost:8080 (login/haslo z
`DD_ADMIN_USER` / `DD_ADMIN_PASSWORD` w `.env`). Po zalogowaniu:
Configuration -> API -> API key, utworz Product + Engagement, wpisz
`DD_API_KEY` i `DD_ENGAGEMENT_ID` do `.env`.

## Skanowanie

```bash
cp scans/targets.example.txt scans/targets.txt   # i uzupelnij PO potwierdzeniu zakresu
make scan-fast                                    # szybki skan top-portow
make scan-service                                 # + wykrywanie wersji/uslug
make import-defectdojo FILE=scans/results/fast-<timestamp>.xml
```

Pelna lista celow: `make help`.

## Status / co dalej

Zobacz sekcje "Otwarte pytania" i "Zaleglosci / TODO" w
[`docs/DECISIONS.md`](docs/DECISIONS.md).
