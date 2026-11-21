// Package targetsai turns free text (an inventory, notes, an e-mail, a pasted table)
// into scan targets in the ASI format (targets.Target: target, asset, owner, tags,
// enabled, note).
//
// With an API key it asks an OpenAI-compatible chat model (default: DeepSeek
// "deepseek-flash") to read the text. Without a key it falls back to a regex
// extractor. Either way the result goes through the same deterministic checks:
//   - a target must be a valid IP, CIDR or domain,
//   - it must come from the text (an LLM cannot add hosts that are not there),
//   - internal addresses (RFC 1918, CGNAT/Tailscale, loopback, link-local) are
//     never enabled for scanning by default,
//   - duplicates are merged.
//
// The result is only a proposal: the GUI shows it for review before saving.
package targetsai

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"asi/internal/targets"
)

// MaxInput is the largest text accepted (bytes).
const MaxInput = 64 << 10

// Config selects the model. Empty APIKey means regex only.
type Config struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
}

// FromEnv reads ASI_LLM_BASE_URL (default https://api.deepseek.com),
// ASI_LLM_API_KEY or DEEPSEEK_API_KEY, and ASI_LLM_MODEL (default deepseek-flash).
func FromEnv() Config {
	key := os.Getenv("ASI_LLM_API_KEY")
	if key == "" {
		key = os.Getenv("DEEPSEEK_API_KEY")
	}
	c := Config{BaseURL: os.Getenv("ASI_LLM_BASE_URL"), APIKey: key, Model: os.Getenv("ASI_LLM_MODEL")}
	if c.BaseURL == "" {
		c.BaseURL = "https://api.deepseek.com"
	}
	if c.Model == "" {
		c.Model = "deepseek-flash"
	}
	return c
}

// Enabled reports whether an LLM can be used.
func (c Config) Enabled() bool { return c.APIKey != "" }

// Result is what Extract returns.
type Result struct {
	Engine   string           `json:"engine"` // model name or "regex"
	Targets  []targets.Target `json:"targets"`
	Warnings []string         `json:"warnings,omitempty"`
}

// Extract reads text and proposes targets. engine: "auto" (LLM if configured,
// else regex), "llm" or "regex". If the LLM call fails in "auto" mode, the regex
// result is returned with a warning.
func Extract(ctx context.Context, c Config, text, engine string) (Result, error) {
	if len(text) > MaxInput {
		return Result{}, fmt.Errorf("tekst za długi (%d B, limit %d B)", len(text), MaxInput)
	}
	if strings.TrimSpace(text) == "" {
		return Result{}, errors.New("pusty tekst")
	}
	switch engine {
	case "", "auto":
		if !c.Enabled() {
			r := Regex(text)
			r.Warnings = append([]string{"brak klucza LLM (DEEPSEEK_API_KEY): użyto prostego wyszukiwania adresów"}, r.Warnings...)
			return r, nil
		}
		r, err := llm(ctx, c, text)
		if err != nil {
			rr := Regex(text)
			rr.Warnings = append([]string{"LLM niedostępny (" + err.Error() + "): użyto prostego wyszukiwania adresów"}, rr.Warnings...)
			return rr, nil
		}
		return r, nil
	case "llm":
		if !c.Enabled() {
			return Result{}, errors.New("brak klucza LLM: ustaw DEEPSEEK_API_KEY (albo ASI_LLM_API_KEY) w .env")
		}
		return llm(ctx, c, text)
	case "regex":
		return Regex(text), nil
	}
	return Result{}, fmt.Errorf("nieznany silnik %q (auto, llm, regex)", engine)
}

// ---------------------------------------------------------------- regex

var (
	reIPv4 = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:/(?:3[0-2]|[12]?\d))?\b`)
	reIPv6 = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?`)
	reDom  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,22}[a-z0-9]\b`)
	reHost = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// "TLDs" that in practice are file names (fleet.md, Caddyfile.conf, main.go).
var fileExt = map[string]bool{"md": true, "txt": true, "json": true, "csv": true, "yml": true, "yaml": true,
	"go": true, "py": true, "js": true, "ts": true, "sh": true, "conf": true, "log": true, "html": true,
	"toml": true, "xml": true, "sql": true, "env": true, "lock": true, "mts": true, "pdf": true, "png": true,
	"jpg": true, "zip": true, "gz": true, "tar": true, "pem": true, "key": true, "crt": true, "ini": true,
	"service": true, "socket": true, "local": true, "internal": true, "lan": true, "home": true, "m4a": true}

// Regex extracts IPs, CIDRs and domains without any model.
func Regex(text string) Result {
	var ts []targets.Target
	for _, m := range reIPv4.FindAllString(text, -1) {
		ts = append(ts, targets.Target{Target: m, Enabled: true})
	}
	for _, m := range reIPv6.FindAllString(text, -1) {
		if _, err := targets.ParseAddrOrPrefix(m); err == nil {
			ts = append(ts, targets.Target{Target: m, Enabled: true})
		}
	}
	for _, m := range reDom.FindAllString(text, -1) {
		if isIPish(m) {
			continue
		}
		ts = append(ts, targets.Target{Target: m, Enabled: true})
	}
	r := Result{Engine: "regex"}
	r.Targets, r.Warnings = Normalize(ts, text)
	return r
}

func isIPish(s string) bool {
	return strings.Trim(s, "0123456789./") == ""
}

// ---------------------------------------------------------------- LLM

const systemPrompt = `Jesteś parserem inwentarza infrastruktury dla systemu skanowania powierzchni ataku (ASI).
Z tekstu użytkownika wypisz WSZYSTKIE cele skanowania: adresy IPv4/IPv6, zakresy CIDR i domeny/subdomeny.
Zasady:
- Bierz tylko to, co jest w tekście. Niczego nie wymyślaj. Gdy tekst skraca subdomeny (np. "example.com (api., www.)"), rozwiń je do pełnych nazw (api.example.com, www.example.com).
- Napraw nazwy i adresy połamane przez zawijanie wierszy lub tabelę, jeśli jest to jednoznaczne.
- Nie wypisuj nazw plików (np. fleet.md), ścieżek, portów osobno ani adresów URL ze ścieżką: z URL weź sam host.
- Jeden cel = jeden wpis. Ten sam host pod adresem publicznym i prywatnym/Tailscale to dwa wpisy.
Pola każdego wpisu:
- "target": IP, CIDR albo domena (małe litery, bez schematu, portu i kropki na końcu),
- "asset": krótka nazwa hosta/aliasu, do którego należy cel (np. nazwa serwera z tabeli), albo "",
- "owner": osoba lub klient, jeśli wynika z tekstu, albo "",
- "tags": 1-4 krótkie tagi małymi literami bez spacji (np. dostawca: hetzner/oracle/cloudflare, rodzaj: publiczny/tailscale/wewnetrzny/domena/klient/stacja-robocza/telefon),
- "enabled": true tylko dla publicznych adresów i domen, które wyglądają na infrastrukturę autora tekstu; false dla adresów prywatnych, Tailscale (100.64.0.0/10), urządzeń osobistych (telefony, laptopy, router), cudzej infrastruktury (np. uczelnia, zewnętrzny dostawca) i wszystkiego niepewnego,
- "note": krótki opis po polsku (do 80 znaków): co to jest; przy enabled=false dlaczego.
Odpowiedz wyłącznie JSON-em: {"targets":[{"target":"...","asset":"...","owner":"...","tags":["..."],"enabled":true,"note":"..."}]}`

func llm(ctx context.Context, c Config, text string) (Result, error) {
	body, _ := json.Marshal(map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": text},
		},
		"response_format": map[string]string{"type": "json_object"},
		"temperature":     0,
		"max_tokens":      8000,
		"stream":          false,
	})
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return Result{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return Result{}, fmt.Errorf("nieoczekiwana odpowiedź modelu: %s", truncate(string(raw), 200))
	}
	content := strings.TrimSpace(out.Choices[0].Message.Content)
	content = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(content, "```json"), "```"), "```")
	var parsed struct {
		Targets []struct {
			Target  string   `json:"target"`
			Asset   string   `json:"asset"`
			Owner   string   `json:"owner"`
			Tags    []string `json:"tags"`
			Enabled *bool    `json:"enabled"`
			Note    string   `json:"note"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return Result{}, fmt.Errorf("model nie zwrócił poprawnego JSON-a: %v", err)
	}
	var ts []targets.Target
	for _, p := range parsed.Targets {
		t := targets.Target{Target: p.Target, Asset: p.Asset, Owner: p.Owner, Tags: p.Tags, Note: p.Note}
		t.Enabled = p.Enabled == nil || *p.Enabled
		ts = append(ts, t)
	}
	r := Result{Engine: c.Model}
	r.Targets, r.Warnings = Normalize(ts, text)
	if out.Choices[0].FinishReason == "length" {
		r.Warnings = append(r.Warnings, "odpowiedź modelu ucięta (limit długości): lista może być niepełna, podziel tekst")
	}
	// anything the regex sees that the model skipped is added for review
	seen := map[string]bool{}
	for _, t := range r.Targets {
		seen[t.Target] = true
	}
	var missed []string
	for _, t := range Regex(text).Targets {
		if !seen[t.Target] {
			t.Tags = appendUniq(t.Tags, "do-sprawdzenia")
			t.Enabled = false
			t.Note = joinNote(t.Note, "pominięty przez model, dodany z tekstu")
			r.Targets = append(r.Targets, t)
			missed = append(missed, t.Target)
		}
	}
	if len(missed) > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("model pominął %d cel(e), dodane jako wyłączone do sprawdzenia: %s", len(missed), strings.Join(firstN(missed, 8), ", ")))
	}
	sortTargets(r.Targets)
	return r, nil
}

// ---------------------------------------------------------------- normalize

// internal ranges: never enabled by default
var internal = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, Tailscale
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"), // Tailscale IPv6
}

// Normalize cleans, validates and deduplicates proposed targets against the
// source text. It returns the kept targets and human-readable warnings.
func Normalize(in []targets.Target, source string) ([]targets.Target, []string) {
	hay := strings.ToLower(source)
	flat := flatten(hay)
	var warns, invented, invalid []string
	idx := map[string]int{}
	var out []targets.Target
	for _, t := range in {
		v := cleanTarget(t.Target)
		if v == "" {
			continue
		}
		pfx, ipErr := targets.ParseAddrOrPrefix(v)
		isIP := ipErr == nil
		if !isIP && !reHost.MatchString(v) {
			invalid = append(invalid, t.Target)
			continue
		}
		if !isIP && fileExt[v[strings.LastIndexByte(v, '.')+1:]] {
			continue // a file name, not a domain
		}
		if !fromText(v, hay, flat) {
			invented = append(invented, v)
			continue
		}
		t.Target = v
		t.Tags = cleanTags(t.Tags)
		t.Note = truncate(strings.TrimSpace(t.Note), 200)
		t.Asset = strings.TrimSpace(t.Asset)
		t.Owner = strings.TrimSpace(t.Owner)
		if isIP && isInternal(pfx) {
			if t.Enabled {
				t.Note = joinNote(t.Note, "adres wewnętrzny, wyłączony")
			}
			t.Enabled = false
			t.Tags = appendUniq(t.Tags, "wewnetrzny")
		}
		if i, ok := idx[v]; ok { // merge duplicates
			o := &out[i]
			o.Tags = appendUniq(o.Tags, t.Tags...)
			o.Enabled = o.Enabled && t.Enabled
			if o.Asset == "" {
				o.Asset = t.Asset
			}
			if o.Owner == "" {
				o.Owner = t.Owner
			}
			if o.Note == "" {
				o.Note = t.Note
			}
			continue
		}
		idx[v] = len(out)
		out = append(out, t)
	}
	if len(invented) > 0 {
		warns = append(warns, fmt.Sprintf("odrzucono %d cel(e), których nie ma w tekście: %s", len(invented), strings.Join(firstN(invented, 8), ", ")))
	}
	if len(invalid) > 0 {
		warns = append(warns, fmt.Sprintf("odrzucono %d niepoprawne wpisy: %s", len(invalid), strings.Join(firstN(invalid, 8), ", ")))
	}
	sortTargets(out)
	return out, warns
}

func cleanTarget(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	// strip a URL path, but keep the /NN of a CIDR
	if i := strings.IndexByte(v, '/'); i >= 0 {
		if _, err := strconv.Atoi(v[i+1:]); err != nil {
			v = v[:i]
		}
	}
	if !strings.Contains(v, "/") && strings.Count(v, ":") == 1 { // host:port
		v = v[:strings.IndexByte(v, ':')]
	}
	v = strings.TrimPrefix(v, "*.")
	return strings.Trim(v, ".,;()[]<>\"'` ")
}

// fromText: the target occurs in the text, also when the text was broken by line
// wrapping, or when the text abbreviates subdomains ("example.com (api., www.)").
func fromText(v, hay, flat string) bool {
	if strings.Contains(hay, v) || strings.Contains(flat, v) {
		return true
	}
	if p, err := netip.ParsePrefix(v); err == nil && strings.Contains(hay, p.Addr().String()) {
		return true
	}
	if i := strings.IndexByte(v, '.'); i > 0 && !isIPish(v) {
		label, parent := v[:i], v[i+1:]
		if strings.Count(parent, ".") >= 1 && fromText(parent, hay, flat) && containsWord(hay, label) {
			return true
		}
	}
	return false
}

// flatten removes whitespace and table drawing so "cv.\n   example.com" matches.
func flatten(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '│', '|', '┃', '•':
			return -1
		}
		return r
	}, s)
}

func containsWord(hay, w string) bool {
	re, err := regexp.Compile(`(^|[^a-z0-9-])` + regexp.QuoteMeta(w) + `([^a-z0-9-]|$)`)
	return err == nil && re.MatchString(hay)
}

func isInternal(p netip.Prefix) bool {
	a := p.Addr().Unmap()
	for _, r := range internal {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

func cleanTags(in []string) []string {
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		t = strings.ReplaceAll(t, " ", "-")
		t = strings.ReplaceAll(t, ";", "-")
		t = strings.ReplaceAll(t, ",", "-")
		if t != "" && len(t) <= 40 {
			out = appendUniq(out, t)
		}
	}
	return out
}

func appendUniq(s []string, vals ...string) []string {
	for _, v := range vals {
		dup := false
		for _, x := range s {
			if x == v {
				dup = true
				break
			}
		}
		if !dup {
			s = append(s, v)
		}
	}
	return s
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "…")
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// sortTargets: enabled first, then IPs before domains, then alphabetically.
func sortTargets(ts []targets.Target) {
	sort.SliceStable(ts, func(i, j int) bool {
		if ts[i].Enabled != ts[j].Enabled {
			return ts[i].Enabled
		}
		ii, ji := isIPish(ts[i].Target) || strings.Contains(ts[i].Target, ":"), isIPish(ts[j].Target) || strings.Contains(ts[j].Target, ":")
		if ii != ji {
			return ii
		}
		if ts[i].Asset != ts[j].Asset {
			return ts[i].Asset < ts[j].Asset
		}
		return ts[i].Target < ts[j].Target
	})
}

// CSV renders targets in the ASI CSV format (same header as targets/example.csv).
func CSV(ts []targets.Target) string {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"target", "asset", "owner", "tags", "enabled", "note"})
	for _, t := range ts {
		w.Write([]string{t.Target, t.Asset, t.Owner, strings.Join(t.Tags, ";"), strconv.FormatBool(t.Enabled), t.Note})
	}
	w.Flush()
	return b.String()
}

// Valid reports whether v is an IP, CIDR or domain accepted as a target.
func Valid(v string) error {
	if _, err := targets.ParseAddrOrPrefix(v); err == nil {
		return nil
	}
	if reHost.MatchString(v) {
		return nil
	}
	return fmt.Errorf("%q nie jest adresem IP, zakresem CIDR ani domeną", v)
}
