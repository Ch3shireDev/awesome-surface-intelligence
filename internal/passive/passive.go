// Package passive finds candidate targets without scanning them: certificate transparency logs,
// DNS resolution and, opt-in, a public passive inventory (Shodan InternetDB).
// Nothing here probes a target. Results are candidates: saved disabled, never scanned by themselves.
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxNames = 200 // names resolved per domain
	maxIPs   = 50  // addresses looked up in the inventory
)

// Client queries the sources. The zero value is not usable: use New.
type Client struct {
	HTTP                           *http.Client
	CertSpotter, CRTSh, InternetDB string
	Lookup                         func(ctx context.Context, host string) ([]string, error)
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Second},
		CertSpotter: "https://api.certspotter.com", CRTSh: "https://crt.sh", InternetDB: "https://internetdb.shodan.io",
		Lookup: net.DefaultResolver.LookupHost}
}

// Record is one candidate name.
type Record struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips,omitempty"`
	Ports   []int    `json:"ports,omitempty"` // reported by the passive inventory, not verified
	Sources []string `json:"sources"`
}

type Result struct {
	Domain   string   `json:"domain"`
	Records  []Record `json:"records"`
	Warnings []string `json:"warnings,omitempty"`
}

var reName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Find lists names of domain. inventory = also ask InternetDB about the public addresses.
func (c *Client) Find(ctx context.Context, domain string, inventory bool) (Result, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !reName.MatchString(domain) || net.ParseIP(domain) != nil {
		return Result{}, fmt.Errorf("%q nie jest domeną", domain)
	}
	res := Result{Domain: domain}
	src := map[string]string{domain: "dns"}
	add := func(n string) {
		n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "*.")
		// only names inside the domain: a shared certificate also lists other people's hosts
		if (n == domain || strings.HasSuffix(n, "."+domain)) && reName.MatchString(n) {
			src[n] = "ct"
		}
	}
	var cs []struct {
		Names []string `json:"dns_names"`
	}
	err := c.get(ctx, c.CertSpotter+"/v1/issuances?include_subdomains=true&expand=dns_names&domain="+url.QueryEscape(domain), &cs)
	if err == nil {
		for _, i := range cs {
			for _, n := range i.Names {
				add(n)
			}
		}
	} else {
		var crt []struct {
			Names string `json:"name_value"`
		}
		if err2 := c.get(ctx, c.CRTSh+"/?output=json&q="+url.QueryEscape("%."+domain), &crt); err2 != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("logi CT niedostępne (%v; %v), wynik tylko z DNS", err, err2))
		}
		for _, i := range crt {
			for _, n := range strings.Fields(i.Names) {
				add(n)
			}
		}
	}
	var names []string
	for n := range src {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxNames {
		res.Warnings = append(res.Warnings, fmt.Sprintf("znaleziono %d nazw, pokazano pierwsze %d", len(names), maxNames))
		names = names[:maxNames]
	}
	res.Records = make([]Record, len(names))
	each(len(names), func(i int) {
		r := &res.Records[i]
		r.Name, r.Sources = names[i], []string{src[names[i]]}
		lc, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if ips, err := c.Lookup(lc, r.Name); err == nil && len(ips) > 0 {
			sort.Strings(ips)
			r.IPs = ips
			if r.Sources[0] != "dns" {
				r.Sources = append(r.Sources, "dns")
			}
		}
	})
	if inventory {
		c.inventory(ctx, &res)
	}
	return res, nil
}

func (c *Client) inventory(ctx context.Context, res *Result) {
	seen := map[string]bool{}
	var ips []string
	for _, r := range res.Records {
		for _, ip := range r.IPs {
			a, err := netip.ParseAddr(ip)
			if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) || seen[ip] {
				continue // internal addresses are never sent to a third party
			}
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	if len(ips) > maxIPs {
		res.Warnings = append(res.Warnings, fmt.Sprintf("inwentarz pasywny: sprawdzono %d z %d adresów", maxIPs, len(ips)))
		ips = ips[:maxIPs]
	}
	ports := make([][]int, len(ips))
	each(len(ips), func(i int) {
		var v struct {
			Ports []int `json:"ports"`
		}
		if c.get(ctx, c.InternetDB+"/"+ips[i], &v) == nil {
			ports[i] = v.Ports
		}
	})
	byIP := map[string][]int{}
	for i, ip := range ips {
		byIP[ip] = ports[i]
	}
	for i := range res.Records {
		r, have := &res.Records[i], map[int]bool{}
		for _, ip := range r.IPs {
			for _, p := range byIP[ip] {
				if !have[p] {
					have[p] = true
					r.Ports = append(r.Ports, p)
				}
			}
		}
		if len(r.Ports) > 0 {
			sort.Ints(r.Ports)
			r.Sources = append(r.Sources, "inventory")
		}
	}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func each(n int, f func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f(i)
		}()
	}
	wg.Wait()
}

func (c *Client) get(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s: brak odpowiedzi", req.URL.Host)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}
