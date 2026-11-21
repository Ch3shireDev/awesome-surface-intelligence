# Attack Surface Intelligence - HackNation 2026

Pipeline do automatycznego skanowania bezpieczenstwa: Nmap (wlasny kontener,
sterowany z Makefile) -> import wynikow do DefectDojo (dostarczony przez
CBI AGH, pelni role dashboardu/zarzadzania podatnosciami).

Decyzje i uzasadnienia architektury: [`docs/DECISIONS.md`](docs/DECISIONS.md).
Plan etapow i mapa wymagan z briefu: [`docs/ROADMAP.md`](docs/ROADMAP.md).
Kontekst dla agentow AI pracujacych w repo: [`AGENTS.md`](AGENTS.md).

## Wymagania na hoscie (VM z Linuksem)

Tylko: docker + compose plugin, `make`, `openssl`. Wszystko inne (nmap, curl,
jq) siedzi w kontenerach, konfiguracja w repo.

## Start

```bash
make env     # .env z .env.example + wygenerowane sekrety i haslo admina
make up      # DefectDojo + kontener skanera
make ps      # initializer powinien skonczyc z "Exited (0)" (1. start: kilka minut)
```

UI: http://localhost:8080, login `admin`, haslo: `grep DD_ADMIN_PASSWORD .env`.
Na VM forwardujesz z hosta tylko port **8080/tcp**.

## Skanowanie

Zakres skanu potwierdzamy z mentorami CBI AGH - do tego czasu tylko
`127.0.0.1` (test pipeline'u).

```bash
echo 127.0.0.1 > scans/targets.txt
make poc                # host discovery + szybki skan portow + wgranie obu do DD
```

W DefectDojo: Product `Attack Surface` -> Engagement `nmap` -> testy
`nmap-discover` (findingi "Host Up", tag `liveness`) i `nmap-fast` (otwarte
porty). Kolejne przebiegi ida do tych samych testow (`reimport-scan`), wiec DD
pokazuje diff: nowe / zamkniete / bez zmian (zakladka historii importow
testu, a w terminalu podsumowanie `diff`).

Szybki test wykrywania zmian na VM:

```bash
make poc                                              # przebieg 1
docker compose exec -d nmap-scanner nc -lk -p 8888    # nowa "usluga"
make poc                                              # przebieg 2: created 1
docker compose exec nmap-scanner pkill -f 'nc -lk'
make poc                                              # przebieg 3: closed 1
```

Product/Engagement/testy tworza sie przy pierwszym imporcie same. Pelna lista celow: `make help`.

## Status / co dalej

Zobacz sekcje "Otwarte pytania" i "Zaleglosci / TODO" w
[`docs/DECISIONS.md`](docs/DECISIONS.md).
