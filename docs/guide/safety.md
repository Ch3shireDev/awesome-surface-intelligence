# Bezpieczeństwo skanowania

Kryterium oceny (15%): *bezpieczeństwo działania, kontrola intensywności skanowania*.
Zasada: skaner ma **wykrywać obecność**, nie eksploatować — i nigdy nie wychodzić poza
zatwierdzony inwentarz.

## Zakres

| mechanizm | domyślnie | efekt |
|---|---|---|
| `enabled=false` w pliku celów | — | cel zostaje w inwentarzu, nigdy nie jest skanowany (powód w `plan.json`) |
| `-only-inventory` | **włączone** | domena nie dodaje nowych IP — tylko podpisuje IP już zatwierdzone |
| `-skip-cdn` | **włączone** | IP Cloudflare nie są skanowane portowo (to nie nasza infrastruktura) |
| limit CIDR | 65 536 adresów | literówka `/8` zamiast `/24` nie odpali skanu 16 mln adresów |

Przykład z realnych danych: `preciselab.space` wskazywało na Vercel, `api.zentra.tax` na obcy hosting,
18 domen na Cloudflare — wszystkie pominięte z podanym powodem.

## Intensywność

| mechanizm | domyślnie |
|---|---|
| globalny limit pakietów `-rate` | 300 pps łącznie, dzielone na procesy |
| równoległość `-parallel` | 5 procesów nmap |
| `--max-retries` | 1 (discovery) / 2 (usługi) |
| `--host-timeout` | 10 min na host |
| `-chunk-timeout` | 20 min na paczkę |
| `-window` | twarde okno czasowe całego runu |
| `-sV --version-light` | lekkie sondy wersji (intensywność 2 zamiast 7) |
| `-sT` (connect) | bez surowych pakietów i bez roota |

Brak skryptów NSE z kategorii `intrusive`, `exploit`, `brute`, `dos` — w ogóle nie są uruchamiane.

## Dane

- Wyniki leżą lokalnie w `results/` (do zrobienia: szyfrowanie at-rest — patrz [Status](/status)).
- `.env` i `.dd_token` mają prawa `600` i są w `.gitignore`.
- Panel web słucha tylko na `127.0.0.1`.
