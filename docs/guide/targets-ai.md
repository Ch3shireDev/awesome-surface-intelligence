# Cele z dowolnego tekstu (LLM, MCP)

Często lista celów nie istnieje jako CSV, tylko jako inwentarz w wiki, tabela z notatek, mail albo zrzut
z konfiguracji serwerów. ASI zamienia taki tekst na cele w [naszym formacie](/guide/targets)
(`target, asset, owner, tags, enabled, note`).

Są trzy drogi do tej samej funkcji (wzorzec MISP: GUI i MCP są nakładką na to, co robi CLI):

| gdzie | jak |
|---|---|
| Panel web | **Cele → Wklej dowolny tekst → Wyciągnij cele**, podgląd, odznaczenie zbędnych, **Dodaj zaznaczone do zbioru** albo **Pobierz CSV** |
| CLI | `asi targets-extract -in notatki.txt -out targets/targets.csv` (albo `-format json`, stdin/stdout) |
| MCP | `asi mcp`: narzędzia `extract_targets`, `list_target_sets`, `list_targets`, `add_targets` |
| API | `POST /api/v1/targets/extract` `{"text": "...", "engine": "auto"}` (rola `operator`), niczego nie zapisuje |

## Silniki

- **`llm`**: model zgodny z API OpenAI, domyślnie DeepSeek **`deepseek-flash`**. Rozumie kontekst: nazwy
  hostów z tabeli trafiają do `asset`, dostawca i rodzaj do `tags`, rozwija skróty subdomen
  (`example.com (api., www.)` → `api.example.com`, `www.example.com`), skleja adresy połamane przez zawijanie
  wierszy, opisuje cel w `note` i wyłącza to, czego nie należy skanować (urządzenia osobiste, cudza
  infrastruktura).
- **`regex`**: bez sieci i bez klucza. Wyciąga same IP, CIDR i domeny, bez kontekstu.
- **`auto`** (domyślnie): LLM, jeśli jest klucz; bez klucza albo przy błędzie API regex z ostrzeżeniem.

## Zabezpieczenia (zawsze, niezależnie od silnika)

Wynik modelu to tylko propozycja. Zanim trafi do podglądu, przechodzi deterministyczne sprawdzenie:

1. **Tylko cele obecne w tekście.** Cel, którego nie ma w tekście (także po złączeniu zawiniętych wierszy
   albo rozwinięciu skrótu subdomeny), jest odrzucany z ostrzeżeniem. Model nie może „dopisać” hosta do skanu.
2. **Adresy wewnętrzne nigdy nie są włączone**: RFC 1918, CGNAT/Tailscale `100.64.0.0/10`, loopback,
   link-local, ULA IPv6. Dostają `enabled=false` i tag `wewnetrzny`.
3. **Co model pominął, nie ginie**: adresy znalezione przez regex, których nie ma w odpowiedzi modelu, są
   dodawane jako wyłączone z tagiem `do-sprawdzenia`.
4. Walidacja formatu (IP, CIDR, domena), nazwy plików (`fleet.md`) nie są domenami, duplikaty są scalane.
5. Zapis do bazy dopiero po zatwierdzeniu w panelu (albo `add_targets` w MCP), przez to samo scalanie co
   import: puste pola nie kasują istniejących tagów i notatek. Audit log zapisuje rozmiar tekstu i liczbę
   celów, **nie sam tekst**.

> **Prywatność.** W trybie `llm` wklejony tekst jest wysyłany do API DeepSeek. Jeśli zawiera dane, których
> nie wolno wysyłać na zewnątrz, wybierz silnik `regex` albo ustaw `ASI_LLM_BASE_URL` na lokalny model
> zgodny z OpenAI (np. Ollama: `http://host:11434/v1`).

## Konfiguracja (`.env`)

```bash
DEEPSEEK_API_KEY=sk-...                    # puste = tylko regex
ASI_LLM_MODEL=deepseek-flash               # domyślnie
ASI_LLM_BASE_URL=https://api.deepseek.com  # albo inny dostawca zgodny z OpenAI
# ASI_LLM_API_KEY=...                      # klucz innego dostawcy (ma pierwszeństwo przed DEEPSEEK_API_KEY)
```

Panel w kontenerze czyta `.env` (`env_file`), więc po dopisaniu klucza wystarczy `make up`.

## Przykład

Wejście:

```
 Host  │ Publiczny IP  │ Tailscale IP   │ Zadania
 edge  │ 192.0.2.10    │ 100.101.1.2    │ proxy api.example.com
 db    │ 198.51.100.7  │ —              │ Postgres
Domeny: example.com (api., www.), shop.example.org
```

Wynik (`asi targets-extract`, silnik `llm`):

```csv
target,asset,owner,tags,enabled,note
192.0.2.10,edge,,hetzner;publiczny,true,proxy
198.51.100.7,db,,publiczny,true,Postgres
api.example.com,edge,,domena,true,API
example.com,,,domena,true,
shop.example.org,,,domena,true,
www.example.com,,,domena,true,
100.101.1.2,edge,,tailscale;wewnetrzny,false,adres wewnętrzny, wyłączony
```

## MCP (Claude Code, Claude Desktop i inne)

```bash
make build   # albo go build -o asi ./cmd/asi
claude mcp add asi -- "$PWD/asi" mcp -env "$PWD/.env"
```

`-env` wczytuje `ASI_DATABASE_URL` i klucz LLM z `.env` (bez nadpisywania zmiennych już ustawionych).
Potem można napisać do agenta: *„zamień ten inwentarz na cele ASI i po moim OK dodaj je do zbioru prod”*.
Narzędzia:

| narzędzie | co robi |
|---|---|
| `extract_targets` | `{text, engine}` → `{engine, warnings, targets, csv}`, niczego nie zapisuje |
| `list_target_sets` | nazwy zbiorów celów |
| `list_targets` | `{set}` → cele w zbiorze |
| `add_targets` | `{set, targets}` → zapis do bazy (scalanie, walidacja, wpis w audit log) |
