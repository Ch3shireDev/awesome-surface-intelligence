// Package safety is the scanner safety policy (SEC-8).
//
// The policy is enforced twice: once when the plan is built (excluded targets land in
// plan.json "skipped" with a reason) and again in every worker right before a tool process
// starts (defense in depth: a resumed run, a hand-edited plan or a bug in the planner
// must still not reach an excluded address). The worker also validates the final tool
// command line: only allow-listed nmap flags, no targets smuggled in the arguments,
// a mandatory per-process rate limit under the hard cap, ports inside the allow-list.
//
// Configuration comes from the environment (.env) only, so the operator of the
// deployment sets the hard limits and a GUI user or CLI flag cannot raise them.
// See docs/guide/safety.md.
package safety

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Profiles: what kind of packets the scanner may send.
const (
	// ProfileRaw: raw sockets (container with NET_RAW): -sS, ICMP echo ping, ARP.
	ProfileRaw = "raw"
	// ProfileUnprivileged: TCP connect only (-sT, connect "ping"), works without root
	// and without NET_RAW. nmap gets --unprivileged.
	ProfileUnprivileged = "unprivileged"
)

// Builtin exclusions: never scanned, whatever the inventory says.
var builtinExclude = []string{
	"0.0.0.0/8",      // "this network"
	"169.254.0.0/16", // link-local, incl. cloud metadata 169.254.169.254
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved + limited broadcast 255.255.255.255
	"::/128",         // unspecified
	"fe80::/10",      // IPv6 link-local
	"ff00::/8",       // IPv6 multicast
}

// DefaultUDPPorts: UDP services worth discovering (DNS, NTP, SNMP) - used only when UDP is allowed.
const DefaultUDPPorts = "53,123,161"

type Policy struct {
	Scope     []netip.Prefix // allow-list; empty = no extra restriction (inventory only)
	Exclude   []netip.Prefix // user exclusions + builtin
	Ports     PortSet        // allowed TCP ports; nil = all
	UDPPorts  PortSet        // allowed UDP ports (only with AllowUDP)
	AllowUDP  bool
	MaxRate   int // hard cap on the GLOBAL packet rate (pps) of one run
	MaxPar    int // hard cap on concurrent tool processes
	Profile   string
	Self      []netip.Prefix // addresses of the scanner host (LAB-T2, self.go)
	SelfPorts PortSet        // ports of our own stack, never scanned on Self

	userExclude int // how many of Exclude came from the user (for the summary)
}

// Default policy: builtin exclusions, 1000 pps, 32 processes, raw profile, no UDP.
func Default() *Policy {
	p := &Policy{MaxRate: 1000, MaxPar: 32, Profile: ProfileRaw}
	p.UDPPorts, _ = ParsePorts(DefaultUDPPorts)
	for _, s := range builtinExclude {
		p.Exclude = append(p.Exclude, netip.MustParsePrefix(s))
	}
	return p
}

// FromEnv reads the policy from the environment:
//
//	ASI_SCOPE / ASI_SCOPE_FILE (default targets/scope.txt)        allowed prefixes
//	ASI_EXCLUDE / ASI_EXCLUDE_FILE (default targets/exclude.txt)  never scanned
//	ASI_ALLOWED_PORTS   allowed TCP ports, e.g. 1-1024,8000-8999 (empty = all)
//	ASI_MAX_RATE        hard global pps cap (default 1000)
//	ASI_MAX_PARALLEL    hard cap on nmap processes (default 32)
//	ASI_SCAN_PROFILE    raw | unprivileged (default raw)
//	ASI_ALLOW_UDP       1/true enables -sU, only on ASI_UDP_PORTS (default 53,123,161)
func FromEnv() (*Policy, error) {
	p := Default()
	var err error
	scope := splitList(os.Getenv("ASI_SCOPE"))
	if s, e := readList(envOr("ASI_SCOPE_FILE", "targets/scope.txt")); e != nil {
		return nil, e
	} else {
		scope = append(scope, s...)
	}
	if p.Scope, err = parsePrefixes(scope); err != nil {
		return nil, fmt.Errorf("ASI_SCOPE: %w", err)
	}
	excl := splitList(os.Getenv("ASI_EXCLUDE"))
	if s, e := readList(envOr("ASI_EXCLUDE_FILE", "targets/exclude.txt")); e != nil {
		return nil, e
	} else {
		excl = append(excl, s...)
	}
	user, err := parsePrefixes(excl)
	if err != nil {
		return nil, fmt.Errorf("ASI_EXCLUDE: %w", err)
	}
	p.Exclude, p.userExclude = append(user, p.Exclude...), len(user)
	if v := os.Getenv("ASI_ALLOWED_PORTS"); v != "" {
		if p.Ports, err = ParsePorts(v); err != nil {
			return nil, fmt.Errorf("ASI_ALLOWED_PORTS: %w", err)
		}
	}
	if v := os.Getenv("ASI_UDP_PORTS"); v != "" {
		if p.UDPPorts, err = ParsePorts(v); err != nil {
			return nil, fmt.Errorf("ASI_UDP_PORTS: %w", err)
		}
	}
	if p.MaxRate, err = envInt("ASI_MAX_RATE", p.MaxRate, 1, 100000); err != nil {
		return nil, err
	}
	if p.MaxPar, err = envInt("ASI_MAX_PARALLEL", p.MaxPar, 1, 256); err != nil {
		return nil, err
	}
	switch v := strings.ToLower(envOr("ASI_SCAN_PROFILE", ProfileRaw)); v {
	case ProfileRaw, ProfileUnprivileged:
		p.Profile = v
	default:
		return nil, fmt.Errorf("ASI_SCAN_PROFILE: %q (raw | unprivileged)", v)
	}
	switch strings.ToLower(os.Getenv("ASI_ALLOW_UDP")) {
	case "1", "true", "yes", "on":
		p.AllowUDP = true
	}
	if err := loadSelf(p); err != nil {
		return nil, fmt.Errorf("ASI_SELF_PORTS / ASI_SELF_IPS: %w", err)
	}
	return p, nil
}

// Check says whether one IP may be scanned; reason is set when it may not.
func (p *Policy) Check(ip string) (ok bool, reason string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false, "not an IP address"
	}
	a = a.Unmap()
	for _, x := range p.Exclude {
		if x.Contains(a) {
			return false, "excluded (" + x.String() + ")"
		}
	}
	if len(p.Scope) > 0 {
		for _, s := range p.Scope {
			if s.Contains(a) {
				return true, ""
			}
		}
		return false, "outside scope (ASI_SCOPE)"
	}
	return true, ""
}

type Blocked struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// Filter splits IPs into allowed and blocked.
func (p *Policy) Filter(ips []string) (allowed []string, blocked []Blocked) {
	for _, ip := range ips {
		if ok, why := p.Check(ip); ok {
			allowed = append(allowed, ip)
		} else {
			blocked = append(blocked, Blocked{ip, why})
		}
	}
	return
}

// Limits clamps the requested global rate and parallelism to the hard caps.
// notes describe what was lowered (for the run log).
func (p *Policy) Limits(rate, parallel int) (int, int, []string) {
	var notes []string
	if rate < 1 {
		rate = 1
	}
	if rate > p.MaxRate {
		notes = append(notes, fmt.Sprintf("rate %d pps > hard cap ASI_MAX_RATE=%d - lowered", rate, p.MaxRate))
		rate = p.MaxRate
	}
	if parallel < 1 {
		parallel = 1
	}
	if parallel > p.MaxPar {
		notes = append(notes, fmt.Sprintf("parallel %d > hard cap ASI_MAX_PARALLEL=%d - lowered", parallel, p.MaxPar))
		parallel = p.MaxPar
	}
	if parallel > rate { // every process needs at least 1 pps
		notes = append(notes, fmt.Sprintf("parallel %d > rate %d pps - lowered to %d", parallel, rate, rate))
		parallel = rate
	}
	return rate, parallel, notes
}

// Summary is recorded in run.json and the run log, so every run says under which rules it ran.
func (p *Policy) Summary() map[string]any {
	ports := "all"
	if p.Ports != nil {
		ports = p.Ports.String()
	}
	udp := "off"
	if p.AllowUDP {
		udp = p.UDPPorts.String()
	}
	scope := make([]string, len(p.Scope))
	for i, s := range p.Scope {
		scope[i] = s.String()
	}
	self := "off"
	if len(p.SelfPorts) > 0 {
		self = p.SelfPorts.String()
	}
	return map[string]any{"profile": p.Profile, "max_rate_pps": p.MaxRate, "max_parallel": p.MaxPar,
		"scope": scope, "exclusions_user": p.userExclude, "exclusions_builtin": len(p.Exclude) - p.userExclude,
		"tcp_ports": ports, "udp": udp, "self_ports": self, "self_addrs": len(p.Self)}
}

func (p *Policy) String() string {
	s := p.Summary()
	return fmt.Sprintf("profile=%v max_rate=%vpps max_parallel=%v scope=%v exclusions=%v+%v builtin tcp_ports=%v udp=%v self_ports=%v",
		s["profile"], s["max_rate_pps"], s["max_parallel"], len(p.Scope), s["exclusions_user"], s["exclusions_builtin"],
		s["tcp_ports"], s["udp"], s["self_ports"])
}

// ---- helpers ----

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def, lo, hi int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s=%q: expected %d-%d", k, v, lo, hi)
	}
	return n, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		out = append(out, f)
	}
	return out
}

// readList reads one prefix per line (# comments). A missing file is not an error.
func readList(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		out = append(out, splitList(l)...)
	}
	return out, sc.Err()
}

func parsePrefixes(vals []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range vals {
		var pfx netip.Prefix
		if a, err := netip.ParseAddr(v); err == nil {
			pfx = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		} else if pfx, err = netip.ParsePrefix(v); err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", v)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

// ---- ports ----

type portRange struct{ lo, hi int }

// PortSet is a set of ports as sorted, non-overlapping ranges.
type PortSet []portRange

// ParsePorts parses "22,80,8000-8100". "-" alone or "1-65535" means all ports.
func ParsePorts(s string) (PortSet, error) {
	var ps PortSet
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f == "-" {
			ps = append(ps, portRange{1, 65535})
			continue
		}
		lo, hi, ok := strings.Cut(f, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if ok {
			if hi == "" {
				b = 65535
			} else {
				b, err2 = strconv.Atoi(hi)
			}
		}
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			if ok && lo == "" && err2 == nil && b >= 1 && b <= 65535 { // "-1024"
				ps = append(ps, portRange{1, b})
				continue
			}
			return nil, fmt.Errorf("bad port %q", f)
		}
		ps = append(ps, portRange{a, b})
	}
	if len(ps) == 0 {
		return nil, fmt.Errorf("empty port list")
	}
	return ps.normalize(), nil
}

func (ps PortSet) normalize() PortSet {
	sort.Slice(ps, func(i, j int) bool { return ps[i].lo < ps[j].lo })
	var out PortSet
	for _, r := range ps {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

func (ps PortSet) Contains(port int) bool {
	for _, r := range ps {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// Intersect returns ports present in both sets (nil allow-list = everything).
func (ps PortSet) Intersect(allow PortSet) PortSet {
	if allow == nil {
		return ps
	}
	var out PortSet
	for _, a := range ps {
		for _, b := range allow {
			lo, hi := max(a.lo, b.lo), min(a.hi, b.hi)
			if lo <= hi {
				out = append(out, portRange{lo, hi})
			}
		}
	}
	return out.normalize()
}

func (ps PortSet) String() string {
	parts := make([]string, len(ps))
	for i, r := range ps {
		if r.lo == r.hi {
			parts[i] = strconv.Itoa(r.lo)
		} else {
			parts[i] = fmt.Sprintf("%d-%d", r.lo, r.hi)
		}
	}
	return strings.Join(parts, ",")
}
