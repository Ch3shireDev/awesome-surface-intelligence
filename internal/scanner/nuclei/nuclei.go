// Package nuclei is the custom-signature adapter (SEC-5, stage "signatures"):
// ProjectDiscovery nuclei run ONLY with our templates from signatures/
// (detection only: headers, cookies, favicon hash, HTML fragments, paths without
// login attempts, versions, CMS, staging). One obs.KindSignature per hit.
//
// Safety: -etags intrusive,dos,fuzz,brute-force; no interactsh (-ni); no template
// download; rate limit; templates live in the repo and are reviewed like code.
package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"asi/internal/findings"
	"asi/internal/obs"
)

// ExcludedTags never run, whatever a template says (PDF: detection, not exploitation).
const ExcludedTags = "intrusive,dos,fuzz,brute-force,exploit,rce,sqli,xss,lfi"

type Adapter struct {
	Templates string // directory with our templates (signatures/)
	Timeout   int
}

func (a *Adapter) Stage() obs.Stage { return obs.StageSignatures }
func (a *Adapter) Tool() string     { return "nuclei" }

func (a *Adapter) Command(ctx context.Context, c obs.Chunk, cfg obs.StageConfig) (*exec.Cmd, obs.OutputSpec) {
	out := filepath.Join(c.Dir, c.Name+".jsonl")
	rl := cfg.RatePPS
	if rl <= 0 || rl > 50 {
		rl = 50
	}
	t := a.Timeout
	if t <= 0 {
		t = 5
	}
	args := []string{"-l", c.TargetsFile, "-t", a.Templates, "-jsonl", "-o", out,
		"-silent", "-nc", "-duc", "-ni", // no colors, no update check, no interactsh (no external callbacks)
		"-etags", ExcludedTags,
		"-rl", strconv.Itoa(rl), "-c", "10", "-bs", "10", "-timeout", strconv.Itoa(t), "-retries", "1",
		"-mhe", "3", // give up on hosts that keep failing
		"-stats", "-si", "2", // progress lines on stderr->log
	}
	args = append(args, cfg.Args...)
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	return cmd, obs.OutputSpec{Path: out, Format: "jsonl"}
}

type hit struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Type      string   `json:"type"`
	Host      string   `json:"host"`
	IP        string   `json:"ip"`
	Port      string   `json:"port"`
	MatchedAt string   `json:"matched-at"`
	Matcher   string   `json:"matcher-name"`
	Extracted []string `json:"extracted-results"`
}

func (a *Adapter) Parse(raw io.Reader) ([]obs.Observation, error) {
	var out []obs.Observation
	seen := map[string]bool{}
	sc := bufio.NewScanner(raw)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		var h hit
		if json.Unmarshal(sc.Bytes(), &h) != nil || h.TemplateID == "" {
			continue // truncated last line or noise
		}
		ip, port := where(h)
		if ip == "" || port == 0 {
			continue
		}
		id := h.TemplateID
		if h.Matcher != "" {
			id += ":" + h.Matcher
		}
		key := obs.PortKey(ip, "tcp", port)
		ex := uniq(h.Extracted)
		dedup := key + "|" + id + "|" + strings.Join(ex, ",")
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		name := h.Info.Name
		if h.Matcher != "" {
			name += " (" + h.Matcher + ")"
		}
		d := obs.SignatureData{ID: id, Name: name, Severity: strings.ToLower(h.Info.Severity), Tags: h.Info.Tags,
			Matched: h.MatchedAt, Extract: ex}
		out = append(out, obs.New(obs.KindSignature, key, "nuclei", d, 95, append([]string{id}, ex...)...))
	}
	return out, nil
}

// where resolves IP and port of a hit (http: from the URL; network: host:port).
func where(h hit) (string, int) {
	ip := h.IP
	port, _ := strconv.Atoi(h.Port)
	for _, s := range []string{h.MatchedAt, h.Host} {
		if port != 0 && ip != "" {
			break
		}
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			if ip == "" {
				ip = u.Hostname()
			}
			if port == 0 {
				port, _ = strconv.Atoi(u.Port())
				if port == 0 && u.Scheme == "https" {
					port = 443
				} else if port == 0 && u.Scheme == "http" {
					port = 80
				}
			}
			continue
		}
		if hst, p, err := net.SplitHostPort(s); err == nil {
			if ip == "" {
				ip = hst
			}
			if port == 0 {
				port, _ = strconv.Atoi(p)
			}
		}
	}
	return ip, port
}

func uniq(s []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if x = strings.TrimSpace(x); x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// networkPorts: non-HTTP services that have network signatures (signatures/network).
var networkPorts = map[string]int{"redis": 6379}

// Targets: URLs that answered in the http stage + host:port of services with
// network signatures (e.g. redis). Nothing else reaches nuclei.
func Targets(httpObs []obs.Observation, svcs []findings.Service) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, o := range httpObs {
		var d obs.HTTPData
		if o.Kind == obs.KindHTTP && o.Decode(&d) == nil && d.URL != "" {
			add(d.URL)
		}
	}
	for _, s := range svcs {
		if _, ok := networkPorts[strings.ToLower(s.Name)]; ok || s.Port == 6379 {
			add(net.JoinHostPort(s.IP, strconv.Itoa(s.Port)))
		}
	}
	return out
}

var _ obs.Scanner = (*Adapter)(nil)
