// Package httpx is the HTTP/HTTPS fingerprint adapter (SEC-4, stage "http"):
// title, status, headers, cookies, TLS certificate, redirects, technologies,
// favicon hash - one obs.KindHTTP per IP:port, from ProjectDiscovery httpx.
//
// Safety: one plain GET per URL (no paths, no forms), rate-limited (-rl),
// redirects are recorded (Location) but not followed, so a port is never
// attributed to another host/port.
package httpx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"asi/internal/findings"
	"asi/internal/obs"
)

type Adapter struct {
	Timeout int // seconds per request (default 8)
}

func (a *Adapter) Stage() obs.Stage { return obs.StageHTTP }
func (a *Adapter) Tool() string     { return "httpx" }

func (a *Adapter) Command(ctx context.Context, c obs.Chunk, cfg obs.StageConfig) (*exec.Cmd, obs.OutputSpec) {
	out := filepath.Join(c.Dir, c.Name+".jsonl")
	rl := cfg.RatePPS
	if rl <= 0 || rl > 100 {
		rl = 100 // requests/s per process; global pps is divided by the runner already
	}
	t := a.Timeout
	if t <= 0 {
		t = 8
	}
	threads := min(10, max(1, len(c.Targets)))
	args := []string{"-l", c.TargetsFile, "-json", "-o", out, "-silent", "-nc", "-duc",
		"-nfs", // keep the scheme we give (no https->http fallback on another port)
		"-title", "-sc", "-td", "-server", "-cl", "-location", "-tls-grab", "-favicon", "-irh",
		"-rl", strconv.Itoa(rl), "-t", strconv.Itoa(threads), "-timeout", strconv.Itoa(t), "-retries", "1",
		"-maxr", "0"}
	args = append(args, cfg.Args...)
	return exec.CommandContext(ctx, "httpx", args...), obs.OutputSpec{Path: out, Format: "jsonl"}
}

// raw httpx JSON line (only what we use)
type line struct {
	Input      string         `json:"input"`
	URL        string         `json:"url"`
	Host       string         `json:"host"`
	HostIP     string         `json:"host_ip"`
	Port       string         `json:"port"`
	Scheme     string         `json:"scheme"`
	Status     int            `json:"status_code"`
	Title      string         `json:"title"`
	Webserver  string         `json:"webserver"`
	Tech       []string       `json:"tech"`
	Location   string         `json:"location"`
	Favicon    string         `json:"favicon"`
	ContentLen int            `json:"content_length"`
	Header     map[string]any `json:"header"`
	TLS        *struct {
		SubjectCN  string   `json:"subject_cn"`
		SubjectAN  []string `json:"subject_an"`
		IssuerCN   string   `json:"issuer_cn"`
		IssuerOrg  []string `json:"issuer_org"`
		NotAfter   string   `json:"not_after"`
		SelfSigned bool     `json:"self_signed"`
		Mismatched bool     `json:"mismatched"`
		Version    string   `json:"tls_version"`
		FP         struct {
			SHA256 string `json:"sha256"`
		} `json:"fingerprint_hash"`
	} `json:"tls"`
	Failed bool `json:"failed"`
}

// HTTPData extends obs.HTTPData with TLS flags the scoring uses.
type HTTPData struct {
	obs.HTTPData
	TLSSelfSigned bool   `json:"tls_self_signed,omitempty"`
	TLSMismatched bool   `json:"tls_mismatched,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	TLSSHA256     string `json:"tls_sha256,omitempty"`
}

func (a *Adapter) Parse(raw io.Reader) ([]obs.Observation, error) {
	var out []obs.Observation
	sc := bufio.NewScanner(raw)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		var l line
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.Failed || l.Status == 0 {
			continue // truncated last line (killed at window end) or failed probe
		}
		o, ok := toObservation(l)
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

func toObservation(l line) (obs.Observation, bool) {
	ip := l.HostIP
	if ip == "" {
		ip = l.Host
	}
	port, _ := strconv.Atoi(l.Port)
	if port == 0 { // fall back to the input URL
		if u, err := url.Parse(l.Input); err == nil {
			port, _ = strconv.Atoi(u.Port())
			if port == 0 && u.Scheme == "https" {
				port = 443
			} else if port == 0 {
				port = 80
			}
		}
	}
	if ip == "" || port == 0 {
		return obs.Observation{}, false
	}
	d := HTTPData{HTTPData: obs.HTTPData{URL: l.URL, Status: l.Status, Title: strings.TrimSpace(l.Title),
		WebServer: l.Webserver, Tech: l.Tech, FaviconMMH3: l.Favicon}}
	if l.Location != "" {
		d.Redirects = []string{l.Location}
	}
	d.Headers = map[string][]string{}
	for k, v := range l.Header {
		name := strings.ReplaceAll(k, "_", "-")
		switch x := v.(type) {
		case string:
			d.Headers[name] = []string{x}
		case []any:
			for _, e := range x {
				d.Headers[name] = append(d.Headers[name], fmt.Sprint(e))
			}
		}
	}
	d.Cookies = cookieNames(d.Headers["set-cookie"])
	delete(d.Headers, "date") // volatile
	if l.TLS != nil {
		d.TLSSubject, d.TLSIssuer, d.TLSNotAfter, d.TLSSANs = l.TLS.SubjectCN, l.TLS.IssuerCN, l.TLS.NotAfter, l.TLS.SubjectAN
		d.TLSSelfSigned, d.TLSMismatched, d.TLSVersion, d.TLSSHA256 = l.TLS.SelfSigned, l.TLS.Mismatched, l.TLS.Version, l.TLS.FP.SHA256
	}
	tech := append([]string(nil), l.Tech...)
	sort.Strings(tech)
	// fingerprint = what an analyst would call "the same site" (no dates, no cookie values)
	fp := []string{strconv.Itoa(l.Status), d.Title, l.Webserver, strings.Join(tech, ","), l.Favicon,
		strings.Join(d.Cookies, ","), d.TLSSHA256, l.Location}
	conf := 90
	if len(tech) == 0 {
		conf = 70
	}
	return obs.New(obs.KindHTTP, obs.PortKey(ip, "tcp", port), "httpx", d, conf, fp...), true
}

// cookieNames: names only (values are session secrets and change every request).
func cookieNames(setCookie []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, sc := range setCookie {
		// httpx may join several Set-Cookie headers with ", " - split carefully on "name="
		for _, part := range strings.Split(sc, ",") {
			kv := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			name, _, ok := strings.Cut(kv, "=")
			name = strings.TrimSpace(name)
			if !ok || name == "" || strings.ContainsAny(name, " \t") || isAttr(name) || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func isAttr(n string) bool {
	switch strings.ToLower(n) {
	case "path", "domain", "expires", "max-age", "samesite", "secure", "httponly":
		return true
	}
	return false
}

// webPorts are probed even when nmap did not name the service http (e.g. 8888 "sun-answerbook").
var webPorts = map[int]bool{80: true, 443: true, 8000: true, 8008: true, 8080: true, 8081: true, 8088: true,
	8443: true, 8888: true, 3000: true, 5000: true, 9000: true, 9090: true, 9443: true}

// URLs builds the http stage input from services found by nmap: one URL per web port.
func URLs(svcs []findings.Service) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range svcs {
		if s.Proto != "tcp" {
			continue
		}
		name := strings.ToLower(s.Name)
		web := strings.Contains(name, "http") || webPorts[s.Port]
		if !web {
			continue
		}
		scheme := "http"
		if s.TLS || strings.Contains(name, "https") || strings.HasPrefix(name, "ssl/") || s.Port == 443 || s.Port == 8443 || s.Port == 9443 {
			scheme = "https"
		}
		u := fmt.Sprintf("%s://%s:%d", scheme, s.IP, s.Port)
		if (scheme == "http" && s.Port == 80) || (scheme == "https" && s.Port == 443) {
			u = fmt.Sprintf("%s://%s", scheme, s.IP)
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

var _ obs.Scanner = (*Adapter)(nil)
