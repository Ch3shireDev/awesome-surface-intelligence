package safety

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// LAB-T2: the scanner must not scan its own stack. When a target is the scanner host
// (loopback, an address of a local interface - the scanner runs with network_mode: host -
// or ASI_SELF_IPS), the ports of ASI and DefectDojo are left out: otherwise the run would
// report our own panel, DefectDojo and asi-db as "findings" and hit them with -sV probes.
//
//	ASI_SELF_PORTS   explicit list of own ports; "off" disables; default: derived from .env
//	                 (DD_PORT, ASI_WEB_ADDR, ASI_LIVE_ADDR, ASI_DB_PORT) + the -ui port of the current scan
//	ASI_SELF_IPS     extra addresses of the scanner host (e.g. a public IP behind NAT)

// Default ports of the stack when .env does not say otherwise.
var defaultSelfPorts = []struct{ env, def string }{
	{"DD_PORT", "8080"},
	{"ASI_WEB_ADDR", "18090"},
	{"ASI_LIVE_ADDR", "8091"},
	{"ASI_DB_PORT", "5433"},
}

func loadSelf(p *Policy) error {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv("ASI_SELF_PORTS"))); v {
	case "off", "none", "0", "false":
		p.SelfPorts = nil
	case "", "auto":
		var list []string
		for _, d := range defaultSelfPorts {
			if port := portOf(envOr(d.env, d.def)); port != "" {
				list = append(list, port)
			}
		}
		p.SelfPorts, _ = ParsePorts(strings.Join(list, ","))
	default:
		ps, err := ParsePorts(v)
		if err != nil {
			return err
		}
		p.SelfPorts = ps
	}
	p.Self = append(p.Self, localAddrs()...)
	extra, err := parsePrefixes(splitList(os.Getenv("ASI_SELF_IPS")))
	if err != nil {
		return err
	}
	p.Self = append(p.Self, extra...)
	return nil
}

// portOf returns the port of "8080", ":18090" or "127.0.0.1:18090" ("" if none).
func portOf(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
		return v
	}
	return ""
}

// localAddrs: loopback plus every address of the local interfaces.
func localAddrs() []netip.Prefix {
	out := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	as, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range as {
		var raw net.IP
		switch v := a.(type) {
		case *net.IPNet:
			raw = v.IP
		case *net.IPAddr:
			raw = v.IP
		}
		if raw == nil {
			continue
		}
		if ip, ok := netip.AddrFromSlice(raw); ok {
			ip = ip.Unmap()
			if !ip.IsUnspecified() {
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}
	return out
}

// AddSelfPorts adds ports of the current process (e.g. the -ui panel of this scan).
func (p *Policy) AddSelfPorts(ports ...string) {
	if p.SelfPorts == nil && os.Getenv("ASI_SELF_PORTS") != "" { // explicitly off
		return
	}
	var list []string
	for _, v := range ports {
		if port := portOf(v); port != "" {
			list = append(list, port)
		}
	}
	if len(list) == 0 {
		return
	}
	ps, _ := ParsePorts(strings.Join(list, ","))
	p.SelfPorts = append(p.SelfPorts, ps...).normalize()
}

// IsSelf says whether ip is the scanner host.
func (p *Policy) IsSelf(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, s := range p.Self {
		if s.Contains(a) {
			return true
		}
	}
	return false
}

// IsSelfPort reports whether (ip, proto, port) is a port of our own stack on the scanner host.
func (p *Policy) IsSelfPort(ip, proto string, port int) bool {
	if p == nil || len(p.SelfPorts) == 0 || port <= 0 {
		return false
	}
	if proto != "" && !strings.EqualFold(proto, "tcp") {
		return false
	}
	return p.IsSelf(ip) && p.SelfPorts.Contains(port)
}

// SplitSelf separates scanner-host addresses (they get their own chunk without the
// stack ports) from the rest. With no own ports configured nothing is split.
func (p *Policy) SplitSelf(ips []string) (self, rest []string) {
	if len(p.SelfPorts) == 0 {
		return nil, ips
	}
	for _, ip := range ips {
		if p.IsSelf(ip) {
			self = append(self, ip)
		} else {
			rest = append(rest, ip)
		}
	}
	return
}

// Subtract returns ports of ps that are not in ex.
func (ps PortSet) Subtract(ex PortSet) PortSet {
	out := append(PortSet(nil), ps...)
	for _, e := range ex {
		var next PortSet
		for _, r := range out {
			if e.hi < r.lo || e.lo > r.hi {
				next = append(next, r)
				continue
			}
			if r.lo < e.lo {
				next = append(next, portRange{r.lo, e.lo - 1})
			}
			if r.hi > e.hi {
				next = append(next, portRange{e.hi + 1, r.hi})
			}
		}
		out = next
	}
	return out
}
