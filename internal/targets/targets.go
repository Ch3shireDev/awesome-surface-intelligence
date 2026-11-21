// Package targets loads scan targets (IP, CIDR, domain) from CSV/JSON/TXT
// and resolves them into a deduplicated per-IP scan plan.
package targets

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Target is one input row. The same schema is used for CSV and JSON.
type Target struct {
	Target  string   `json:"target"`          // IP, CIDR or domain
	Asset   string   `json:"asset,omitempty"` // logical host name / alias
	Owner   string   `json:"owner,omitempty"` // who owns it
	Tags    []string `json:"tags,omitempty"`  // free tags
	Enabled bool     `json:"enabled"`         // false = never scan
	Note    string   `json:"note,omitempty"`
}

type File struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

func Load(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		var tf File
		if err := json.NewDecoder(f).Decode(&tf); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		return tf.Targets, nil
	case ".csv":
		return loadCSV(f)
	default: // plain list, one target per line
		b, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		var out []Target
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, Target{Target: l, Enabled: true})
			}
		}
		return out, nil
	}
}

func loadCSV(r io.Reader) ([]Target, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.Comment = '#'
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	if _, ok := col["target"]; !ok {
		return nil, fmt.Errorf("csv: missing 'target' column")
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	var out []Target
	for _, row := range rows[1:] {
		t := Target{Target: get(row, "target"), Asset: get(row, "asset"), Owner: get(row, "owner"), Note: get(row, "note"), Enabled: true}
		if t.Target == "" {
			continue
		}
		if e := get(row, "enabled"); e != "" {
			t.Enabled, _ = strconv.ParseBool(e)
		}
		for _, tag := range strings.Split(get(row, "tags"), ";") {
			if tag = strings.TrimSpace(tag); tag != "" {
				t.Tags = append(t.Tags, tag)
			}
		}
		out = append(out, t)
	}
	return out, nil
}

func SaveJSON(path string, ts []Target) error {
	b, _ := json.MarshalIndent(File{Version: 1, Targets: ts}, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Host is one IP to scan, with everything we know about it from the inputs.
type Host struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains,omitempty"`
	Assets  []string `json:"assets,omitempty"`
	Owners  []string `json:"owners,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

type Skipped struct {
	Target string   `json:"target"`
	Reason string   `json:"reason"`
	IPs    []string `json:"ips,omitempty"`
}

type Plan struct {
	Created time.Time `json:"created"`
	Hosts   []Host    `json:"hosts"`
	Skipped []Skipped `json:"skipped,omitempty"`
}

type PlanOptions struct {
	SkipCDN bool // don't port-scan IPs belonging to CDNs (Cloudflare) - it's not our infra
	// OnlyInventory: a domain only attaches names to IPs explicitly listed as IP/CIDR targets.
	// Domains pointing anywhere else (Vercel, shared hosting...) are reported, not scanned.
	OnlyInventory bool
	MaxCIDR       int // max addresses per single CIDR (safety)
	DNSTimeout    time.Duration
}

func BuildPlan(ts []Target, o PlanOptions) Plan {
	if o.MaxCIDR == 0 {
		o.MaxCIDR = 65536
	}
	if o.DNSTimeout == 0 {
		o.DNSTimeout = 5 * time.Second
	}
	p := Plan{Created: time.Now()}
	hosts := map[string]*Host{}
	var mu sync.Mutex
	add := func(ip string, t Target, domain string) {
		mu.Lock()
		defer mu.Unlock()
		h := hosts[ip]
		if h == nil {
			h = &Host{IP: ip}
			hosts[ip] = h
		}
		h.Domains = appendUniq(h.Domains, domain)
		h.Assets = appendUniq(h.Assets, t.Asset)
		h.Owners = appendUniq(h.Owners, t.Owner)
		h.Tags = appendUniq(h.Tags, t.Tags...)
	}
	skip := func(s Skipped) { mu.Lock(); p.Skipped = append(p.Skipped, s); mu.Unlock() }

	type resolved struct {
		t   Target
		ips []netip.Addr
	}
	var domains []resolved
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for _, t := range ts {
		if !t.Enabled {
			skip(Skipped{Target: t.Target, Reason: "disabled: " + t.Note})
			continue
		}
		if a, err := netip.ParseAddr(t.Target); err == nil {
			add(a.String(), t, "")
			continue
		}
		if pfx, err := netip.ParsePrefix(t.Target); err == nil {
			pfx = pfx.Masked()
			bits := pfx.Addr().BitLen() - pfx.Bits()
			if bits > 30 || 1<<bits > o.MaxCIDR {
				skip(Skipped{Target: t.Target, Reason: fmt.Sprintf("CIDR larger than max %d addresses", o.MaxCIDR)})
				continue
			}
			for a := pfx.Addr(); pfx.Contains(a); a = a.Next() {
				add(a.String(), t, "")
			}
			continue
		}
		// domain
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), o.DNSTimeout)
			defer cancel()
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", t.Target)
			if err != nil || len(ips) == 0 {
				skip(Skipped{Target: t.Target, Reason: fmt.Sprintf("dns: %v", err)})
				return
			}
			mu.Lock()
			domains = append(domains, resolved{t, ips})
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	inventory := map[string]bool{}
	for ip := range hosts {
		inventory[ip] = true
	}
	for _, d := range domains {
		var cdnIPs, foreign []string
		for _, ip := range d.ips {
			ip = ip.Unmap()
			switch {
			case inventory[ip.String()]:
				add(ip.String(), d.t, d.t.Target)
			case o.SkipCDN && IsCloudflare(ip):
				cdnIPs = append(cdnIPs, ip.String())
			case o.OnlyInventory:
				foreign = append(foreign, ip.String())
			default:
				add(ip.String(), d.t, d.t.Target)
			}
		}
		if len(cdnIPs) > 0 {
			skip(Skipped{Target: d.t.Target, Reason: "behind Cloudflare (CDN edge, not our host)", IPs: cdnIPs})
		}
		if len(foreign) > 0 {
			skip(Skipped{Target: d.t.Target, Reason: "resolves outside IP inventory (third-party hosting?)", IPs: foreign})
		}
	}

	for _, h := range hosts {
		sort.Strings(h.Domains)
		p.Hosts = append(p.Hosts, *h)
	}
	sort.Slice(p.Hosts, func(i, j int) bool {
		a, _ := netip.ParseAddr(p.Hosts[i].IP)
		b, _ := netip.ParseAddr(p.Hosts[j].IP)
		return a.Less(b)
	})
	sort.Slice(p.Skipped, func(i, j int) bool { return p.Skipped[i].Target < p.Skipped[j].Target })
	return p
}

func appendUniq(s []string, vals ...string) []string {
outer:
	for _, v := range vals {
		if v == "" {
			continue
		}
		for _, x := range s {
			if x == v {
				continue outer
			}
		}
		s = append(s, v)
	}
	return s
}

// https://www.cloudflare.com/ips-v4
var cloudflare = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func IsCloudflare(ip netip.Addr) bool {
	for _, p := range cloudflare {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
