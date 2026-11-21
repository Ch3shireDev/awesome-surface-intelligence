// Package findings turns nmap results into normalized services, compares runs
// and packages them for DefectDojo ("Generic Findings Import" JSON).
package findings

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"asi/internal/nmapxml"
	"asi/internal/targets"
)

// Service = one open port on one IP. Key() is stable across runs.
type Service struct {
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Proto     string   `json:"proto"`
	Name      string   `json:"service,omitempty"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	ExtraInfo string   `json:"extrainfo,omitempty"`
	TLS       bool     `json:"tls,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	Assets    []string `json:"assets,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Interest  string   `json:"interest"` // high | medium | low
	Reason    string   `json:"interest_reason,omitempty"`
}

func (s Service) Key() string { return fmt.Sprintf("%s:%d/%s", s.IP, s.Port, s.Proto) }

// Fingerprint changes when what runs on the port changes.
func (s Service) Fingerprint() string {
	return strings.TrimSpace(strings.Join([]string{s.Name, s.Product, s.Version}, " "))
}

// FromHosts extracts open services from parsed nmap hosts, enriched with plan metadata.
func FromHosts(hosts []nmapxml.Host, meta map[string]targets.Host) []Service {
	var out []Service
	for _, h := range hosts {
		if !h.Up() {
			continue
		}
		ip := h.IP()
		m := meta[ip]
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			s := Service{
				IP: ip, Port: p.PortID, Proto: p.Protocol,
				Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo, TLS: p.Service.Tunnel == "ssl",
				Domains: m.Domains, Assets: m.Assets, Tags: m.Tags,
			}
			s.Interest, s.Reason = score(s)
			out = append(out, s)
		}
	}
	Sort(out)
	return out
}

func Sort(s []Service) {
	sort.Slice(s, func(i, j int) bool {
		a, _ := netip.ParseAddr(s[i].IP)
		b, _ := netip.ParseAddr(s[j].IP)
		if a != b {
			return a.Less(b)
		}
		return s[i].Port < s[j].Port
	})
}

// Ports that should never be reachable from the Internet.
var risky = map[int]string{
	21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API (no TLS)",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
	8086: "InfluxDB", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

// Typical admin / monitoring / dev ports.
var admin = map[int]string{
	2222: "alt SSH", 4848: "GlassFish admin", 5601: "Kibana", 8080: "alt HTTP / admin",
	8081: "alt HTTP", 8088: "alt HTTP", 8090: "alt HTTP / panel", 8443: "alt HTTPS / admin",
	8888: "alt HTTP / dev", 9000: "dev / Portainer", 9090: "Prometheus / Cockpit", 9443: "Portainer",
	10000: "Webmin", 15672: "RabbitMQ mgmt",
}

func score(s Service) (string, string) {
	public := isPublic(s.IP)
	if why, ok := risky[s.Port]; ok {
		if public {
			return "high", why + " exposed on a public IP"
		}
		return "medium", why + " reachable internally"
	}
	if why, ok := admin[s.Port]; ok {
		if public {
			return "medium", why + " on a public IP"
		}
		return "low", why
	}
	if s.Port == 25 && public {
		return "medium", "SMTP on a public IP (check for open relay)"
	}
	return "low", ""
}

func isPublic(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10") // Tailscale
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a))
}

func Save(path string, s []Service) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func Load(path string) ([]Service, error) {
	var s []Service
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, &s)
}

// ---- diff between runs (spec 8, 9) ----

type Change struct {
	Kind   string   `json:"kind"` // new | gone | changed
	Key    string   `json:"key"`
	Before *Service `json:"before,omitempty"`
	After  *Service `json:"after,omitempty"`
}

type Diff struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	HostsNew  []string `json:"hosts_new"`
	HostsGone []string `json:"hosts_gone"`
	Changes   []Change `json:"changes"`
	Unchanged int      `json:"unchanged"`
}

func Compare(from, to string, a, b []Service, upA, upB []string) Diff {
	d := Diff{From: from, To: to}
	ma, mb := index(a), index(b)
	for k, sb := range mb {
		sb := sb
		if sa, ok := ma[k]; !ok {
			d.Changes = append(d.Changes, Change{Kind: "new", Key: k, After: &sb})
		} else if sa.Fingerprint() != sb.Fingerprint() {
			sa := sa
			d.Changes = append(d.Changes, Change{Kind: "changed", Key: k, Before: &sa, After: &sb})
		} else {
			d.Unchanged++
		}
	}
	for k, sa := range ma {
		sa := sa
		if _, ok := mb[k]; !ok {
			d.Changes = append(d.Changes, Change{Kind: "gone", Key: k, Before: &sa})
		}
	}
	sort.Slice(d.Changes, func(i, j int) bool {
		if d.Changes[i].Kind != d.Changes[j].Kind {
			return d.Changes[i].Kind < d.Changes[j].Kind
		}
		return d.Changes[i].Key < d.Changes[j].Key
	})
	d.HostsNew, d.HostsGone = setDiff(upB, upA), setDiff(upA, upB)
	return d
}

func index(s []Service) map[string]Service {
	m := make(map[string]Service, len(s))
	for _, x := range s {
		m[x.Key()] = x
	}
	return m
}

func setDiff(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	out := []string{}
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// ---- DefectDojo packaging ----

type ddEndpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type ddFinding struct {
	Title            string       `json:"title"`
	Description      string       `json:"description"`
	Severity         string       `json:"severity"`
	UniqueID         string       `json:"unique_id_from_tool"`
	Component        string       `json:"component_name,omitempty"`
	ComponentVersion string       `json:"component_version,omitempty"`
	Service          string       `json:"service,omitempty"`
	Endpoints        []ddEndpoint `json:"endpoints"`
	Tags             []string     `json:"tags,omitempty"`
	Active           bool         `json:"active"`
	Verified         bool         `json:"verified"`
	StaticFinding    bool         `json:"static_finding"`
	DynamicFinding   bool         `json:"dynamic_finding"`
}

// nmap service names -> URL schemes accepted by DefectDojo endpoints (max 10 chars).
var schemes = map[string]string{
	"http": "http", "https": "https", "ssl/http": "https", "http-proxy": "http", "http-alt": "http",
	"ssh": "ssh", "ftp": "ftp", "smtp": "smtp", "submission": "smtp", "imap": "imap", "imaps": "imaps",
	"pop3": "pop3", "pop3s": "pop3s", "ms-wbt-server": "rdp", "vnc": "vnc", "telnet": "telnet",
	"mysql": "mysql", "postgresql": "postgresql", "redis": "redis", "mongodb": "mongodb", "ldap": "ldap",
	"domain": "dns", "microsoft-ds": "smb", "snmp": "snmp", "rtsp": "rtsp", "sip": "sip",
}

func urlScheme(s Service) string {
	sc := schemes[s.Name]
	if s.TLS && sc == "http" {
		sc = "https"
	}
	return sc // "" -> endpoint without protocol (host:port only)
}

var severity = map[string]string{"high": "Medium", "medium": "Low", "low": "Info"}

// NOTE: the DefectDojo "service" field is deliberately NOT set. On reimport DefectDojo
// only closes findings whose service equals the import-level service (or is empty),
// so per-finding service values would make disappeared ports never close.
// The service name goes to the description and the svc-<name> tag instead.
//
// GenericJSON builds a DefectDojo "Generic Findings Import" document: one finding
// per IP:port (nmap parser would merge all hosts with the same port into one).
// Title/description contain only stable data so re-import can match findings
// between runs and DefectDojo itself reports new / closed / reactivated.
func GenericJSON(svcs []Service) []byte {
	out := struct {
		Findings []ddFinding `json:"findings"`
	}{Findings: []ddFinding{}}
	for _, s := range svcs {
		scheme := urlScheme(s)
		eps := []ddEndpoint{{Host: s.IP, Port: s.Port, Protocol: scheme}}
		for _, d := range s.Domains {
			eps = append(eps, ddEndpoint{Host: d, Port: s.Port, Protocol: scheme})
		}
		var desc strings.Builder
		fmt.Fprintf(&desc, "**Open port** `%d/%s` on `%s`\n\n", s.Port, s.Proto, s.IP)
		fmt.Fprintf(&desc, "| field | value |\n|---|---|\n")
		row := func(k, v string) {
			if v != "" {
				fmt.Fprintf(&desc, "| %s | %s |\n", k, v)
			}
		}
		row("service", s.Name)
		row("product", s.Product)
		row("version", s.Version)
		row("extra", s.ExtraInfo)
		if s.TLS {
			row("tls", "yes")
		}
		row("asset", strings.Join(s.Assets, ", "))
		row("domains", strings.Join(s.Domains, ", "))
		row("interest", s.Interest+" "+s.Reason)
		tags := append([]string{"asi", "interest-" + s.Interest}, s.Tags...)
		if s.Name != "" {
			tags = append(tags, "svc-"+s.Name)
		}
		title := fmt.Sprintf("Open port %d/%s on %s", s.Port, s.Proto, s.IP)
		if s.Name != "" {
			title += " (" + s.Name + ")"
		}
		out.Findings = append(out.Findings, ddFinding{
			Title: title, Description: desc.String(), Severity: severity[s.Interest],
			UniqueID: "asi:" + s.Key(), Component: s.Product, ComponentVersion: s.Version,
			Endpoints: eps, Tags: tags, Active: true, DynamicFinding: true,
		})
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}
