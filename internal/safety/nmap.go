package safety

import (
	"fmt"
	"strconv"
	"strings"
)

// nmap flag allow-list. Anything not listed is rejected: an unknown flag could add
// targets, write files, spoof packets or bypass the rate limit.
type flagSpec struct {
	value bool                 // takes a separate value
	raw   bool                 // needs raw sockets (profile raw)
	check func(v string) error // optional value validation
}

func intIn(lo, hi int) func(string) error {
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("expected %d-%d", lo, hi)
		}
		return nil
	}
}

func timeSpec(v string) error {
	v = strings.TrimRight(v, "smhd")
	if strings.HasSuffix(v, "m") { // "ms" after trimming "s"
		v = strings.TrimSuffix(v, "m")
	}
	if _, err := strconv.ParseFloat(v, 64); err != nil {
		return fmt.Errorf("expected time, e.g. 500ms, 10m")
	}
	return nil
}

func anyValue(string) error { return nil }

var nmapFlags = map[string]flagSpec{
	// scan / discovery types
	"-sn": {}, "-sT": {}, "-sV": {}, "-Pn": {}, "-n": {}, "-R": {},
	"-sS": {raw: true}, "-sU": {raw: true}, "-O": {raw: true},
	"-PE": {raw: true}, "-PP": {raw: true}, "-PM": {raw: true},
	"--unprivileged": {}, "--privileged": {raw: true}, "--send-ip": {raw: true},
	"--disable-arp-ping": {}, "--system-dns": {}, "-F": {}, "-4": {}, "-6": {},
	// output / verbosity (only XML, the runner sets the path)
	"--open": {}, "--reason": {}, "-v": {}, "-vv": {}, "-d": {},
	"-oX": {value: true, check: anyValue}, "-iL": {value: true, check: anyValue},
	"--stats-every": {value: true, check: timeSpec},
	// ports
	"-p": {value: true, check: anyValue}, "--top-ports": {value: true, check: intIn(1, 65535)}, "-r": {},
	// version detection
	"--version-light": {}, "--version-intensity": {value: true, check: intIn(0, 9)},
	// timing and limits (no --min-rate: it would push past the rate limit)
	"--max-rate":            {value: true, check: intIn(1, 100000)},
	"--max-retries":         {value: true, check: intIn(0, 10)},
	"--host-timeout":        {value: true, check: timeSpec},
	"--script-timeout":      {value: true, check: timeSpec},
	"--min-rtt-timeout":     {value: true, check: timeSpec},
	"--max-rtt-timeout":     {value: true, check: timeSpec},
	"--initial-rtt-timeout": {value: true, check: timeSpec},
	"--scan-delay":          {value: true, check: timeSpec},
	"--max-scan-delay":      {value: true, check: timeSpec},
	"--max-parallelism":     {value: true, check: intIn(1, 1024)},
	"--min-hostgroup":       {value: true, check: intIn(1, 4096)},
	"--max-hostgroup":       {value: true, check: intIn(1, 4096)},
	"--exclude":             {value: true, check: anyValue},
	"--excludefile":         {value: true, check: anyValue},
	"--exclude-ports":       {value: true, check: func(v string) error { _, _, err := parseNmapPorts(v); return err }},
	"--dns-servers":         {value: true, check: anyValue},
	// NSE: only the scripts from allowedScripts (checked separately)
	"--script":      {value: true},
	"--script-args": {value: true, check: scriptArgs},
}

// Explicitly forbidden flags, with the reason shown to the operator.
var nmapDenied = map[string]string{
	"-iR": "random targets outside the inventory", "-A": "aggressive (runs default NSE scripts, OS, traceroute)",
	"-sC": "default NSE scripts include intrusive ones", "-T5": "insane timing", "--min-rate": "bypasses the rate limit",
	"--allports": "-sV would probe printer ports 9100-9107 (they print the probes)",
	"-D":         "decoys (evasion)", "-S": "spoofed source address", "-e": "interface selection", "--spoof-mac": "spoofed MAC",
	"-f": "fragmentation (evasion)", "--mtu": "fragmentation (evasion)", "--data": "custom payload",
	"--data-string": "custom payload", "--data-length": "padding (evasion)", "--badsum": "bad checksums (evasion)",
	"-g": "source port (evasion)", "--source-port": "source port (evasion)", "--ttl": "custom TTL",
	"--ip-options": "IP options", "--proxies": "proxies", "-b": "FTP bounce", "-sI": "idle/zombie scan",
	"-oN": "writes files outside the run dir", "-oG": "writes files outside the run dir",
	"-oA": "writes files outside the run dir", "-oS": "writes files outside the run dir",
	"--resume": "resumes an arbitrary scan file", "--datadir": "loads foreign nmap data files",
	"--servicedb": "loads foreign nmap data files", "--versiondb": "loads foreign nmap data files",
	"--script-updatedb": "modifies the script DB", "--script-args-file": "loads arbitrary files",
	"--traceroute": "not needed for discovery", "--send-eth": "raw ethernet frames",
	"-sA": "not needed for discovery", "-sW": "not needed for discovery", "-sM": "not needed for discovery",
	"-sN": "not needed for discovery", "-sF": "not needed for discovery", "-sX": "not needed for discovery",
	"-sO": "IP protocol scan", "-sY": "SCTP", "-sZ": "SCTP", "--scanflags": "custom TCP flags",
}

// Only detection scripts that read banners/headers/certificates.
// Categories like "discovery" or "safe" are NOT allowed: categories are unions, "discovery"
// contains brute-forcers (dns-brute) and broadcast scripts that hit the whole LAN.
var allowedScripts = map[string]bool{
	"version": true, "banner": true, "http-title": true, "http-headers": true, "http-server-header": true,
	"http-favicon": true, "http-generator": true, "http-robots.txt": true, "ssl-cert": true, "ssh-hostkey": true,
	"rdp-ntlm-info": false, // reveals AD names, but sends NTLM auth - keep it out
}

func scriptArgs(v string) error {
	if strings.Contains(strings.ToLower(v), "newtargets") {
		return fmt.Errorf("newtargets would add targets outside the plan")
	}
	return nil
}

// Opts of Enforce.
type Opts struct {
	// Final: the complete command line of one chunk. Then -iL must be TargetsFile,
	// -oX must appear at most once and --max-rate must be set and <= MaxProcRate.
	Final       bool
	TargetsFile string
	MaxProcRate int
	// ExcludePorts (LAB-T2): the chunk targets the scanner host - these ports (our own stack)
	// are cut from -p and ping probes and passed to nmap as --exclude-ports.
	ExcludePorts PortSet
}

// Enforce validates nmap arguments against the policy and returns them rewritten:
// -F becomes --top-ports 100, ports are cut to the allow-list (-p added when needed),
// ping ports (-PS/-PA) are cut too, the unprivileged profile adds --unprivileged.
// Any token that is not a known flag or its value (e.g. a target address) is an error.
func (p *Policy) Enforce(args []string, o Opts) ([]string, error) {
	var (
		out             []string
		pSpec           string
		hasP, hasTop    bool
		hasUDP, hasSn   bool
		hasUnpriv       bool
		exclTCP         PortSet
		exclUDP         PortSet
		exclUnprefixed  PortSet
		iL, oX          []string
		rate            = -1
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := ""
		hasVal := false
		if strings.HasPrefix(a, "--") {
			if k, v, ok := strings.Cut(a, "="); ok {
				a, val, hasVal = k, v, true
			}
		}
		if why, bad := nmapDenied[a]; bad {
			return nil, fmt.Errorf("nmap %s is not allowed: %s", a, why)
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return nil, fmt.Errorf("nmap argument %q is not a flag: targets come only from the plan (-iL)", a)
		}
		spec, known := nmapFlags[a]
		if !known {
			// attached forms: -T4, -PS22,80, -PA80, -PU53, -p22,80
			switch {
			case len(a) == 3 && strings.HasPrefix(a, "-T") && a[2] >= '0' && a[2] <= '9':
				if a[2] > '4' {
					return nil, fmt.Errorf("nmap %s is not allowed: max timing is -T4", a)
				}
				out = append(out, a)
				continue
			case strings.HasPrefix(a, "-PS") || strings.HasPrefix(a, "-PA") || strings.HasPrefix(a, "-PU"):
				kind, list := a[:3], a[3:]
				if kind == "-PU" {
					if !p.AllowUDP {
						return nil, fmt.Errorf("nmap -PU (UDP ping) needs ASI_ALLOW_UDP=1")
					}
					if p.Profile != ProfileRaw {
						return nil, fmt.Errorf("nmap -PU needs raw sockets (ASI_SCAN_PROFILE=raw)")
					}
				}
				allow := p.Ports
				if kind == "-PU" {
					allow = p.UDPPorts
				}
				if list == "" {
					if kind != "-PU" && o.ExcludePorts.Contains(80) {
						continue // bare -PS/-PA defaults to port 80
					}
					out = append(out, a)
					continue
				}
				if allow == nil && (kind == "-PU" || o.ExcludePorts == nil) {
					out = append(out, a)
					continue
				}
				ps, err := ParsePorts(list)
				if err != nil {
					return nil, fmt.Errorf("nmap %s: %w", a, err)
				}
				ps = ps.Intersect(allow)
				if kind != "-PU" {
					ps = ps.Subtract(o.ExcludePorts) // LAB-T2: no probes to our own stack
				}
				if len(ps) > 0 {
					out = append(out, kind+ps.String())
				} // else: ping ports all outside the allow-list -> drop the probe
				continue
			case strings.HasPrefix(a, "-p") && len(a) > 2:
				a, val, hasVal = "-p", a[2:], true
				spec = nmapFlags["-p"]
			default:
				return nil, fmt.Errorf("nmap %s is not on the allow-list (internal/safety)", a)
			}
		}
		if spec.raw && p.Profile != ProfileRaw {
			return nil, fmt.Errorf("nmap %s needs raw sockets, profile is %s (ASI_SCAN_PROFILE)", a, p.Profile)
		}
		if spec.value && !hasVal {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("nmap %s needs a value", a)
			}
			i++
			val = args[i]
		}
		if spec.value && spec.check != nil {
			if err := spec.check(val); err != nil {
				return nil, fmt.Errorf("nmap %s %q: %w", a, val, err)
			}
		}
		switch a {
		case "-sU":
			if !p.AllowUDP {
				return nil, fmt.Errorf("nmap -sU: UDP scanning is off (ASI_ALLOW_UDP=1 enables it, only on %s)", p.UDPPorts)
			}
			hasUDP = true
		case "-sn":
			hasSn = true
		case "--unprivileged":
			hasUnpriv = true
		case "-p":
			hasP, pSpec = true, val
			continue // re-added below, cut to the allow-list
		case "--exclude-ports":
			t, u, err := parseNmapPorts(val)
			if err != nil {
				return nil, fmt.Errorf("nmap --exclude-ports %q: %w", val, err)
			}
			if u == nil && !strings.Contains(strings.ToUpper(val), "T:") {
				exclUnprefixed = append(exclUnprefixed, t...).normalize()
			} else {
				exclTCP = append(exclTCP, t...).normalize()
				exclUDP = append(exclUDP, u...).normalize()
			}
			continue // merged into one --exclude-ports below (nmap aborts on duplicates)
		case "--top-ports":
			hasTop = true
		case "-iL":
			iL = append(iL, val)
		case "-oX":
			oX = append(oX, val)
		case "--max-rate":
			rate, _ = strconv.Atoi(val)
		case "--script":
			for _, s := range strings.Split(val, ",") {
				if !allowedScripts[strings.TrimSpace(s)] {
					return nil, fmt.Errorf("nmap --script %s is not allowed (allowed: %s)", s, scriptList())
				}
			}
		}
		out = append(out, a)
		if spec.value {
			out = append(out, val)
		}
	}
	// -F is a shortcut for the 100 most common ports; as --top-ports it combines with -p.
	for i, a := range out {
		if a == "-F" {
			out[i] = "--top-ports"
			out = append(out[:i+1], append([]string{"100"}, out[i+1:]...)...)
			hasTop = true
			break
		}
	}

	// ports: cut to the allow-list
	if !hasSn && (hasP || p.Ports != nil || hasUDP) {
		var tcp, udp PortSet
		if hasP {
			var err error
			if tcp, udp, err = parseNmapPorts(pSpec); err != nil {
				return nil, fmt.Errorf("nmap -p %q: %w", pSpec, err)
			}
			if hasUDP && udp == nil {
				udp = tcp // ports without T:/U: apply to both protocols in nmap
			}
		} else {
			tcp, udp = p.Ports, p.UDPPorts
			if tcp == nil {
				tcp = PortSet{{1, 65535}}
			}
			if !hasTop { // keep nmap's default (top 1000) instead of scanning the whole allow-list
				out = append(out, "--top-ports", "1000")
			}
		}
		tcp = tcp.Intersect(p.Ports).Subtract(o.ExcludePorts)
		if hasUDP {
			udp = udp.Intersect(p.UDPPorts)
		} else {
			udp = nil
		}
		var parts []string
		if len(tcp) > 0 {
			parts = append(parts, "T:"+tcp.String())
		}
		if len(udp) > 0 {
			parts = append(parts, "U:"+udp.String())
		}
		if len(parts) == 0 {
			return nil, fmt.Errorf("nmap ports %q: nothing left inside the allow-list (TCP %s, UDP %s) minus own stack ports (%s)",
				pSpec, p.Ports, p.UDPPorts, o.ExcludePorts)
		}
		spec := strings.Join(parts, ",")
		if !hasUDP {
			spec = strings.TrimPrefix(spec, "T:")
		}
		out = append(out, "-p", spec)
	}
	if !hasSn {
		// Merge user --exclude-ports with chunk o.ExcludePorts into a single flag:
		// nmap aborts ("Only 1 --exclude-ports option allowed") if passed twice.
		if len(exclUnprefixed) > 0 {
			exclTCP = append(exclTCP, exclUnprefixed...).normalize()
			if hasUDP {
				exclUDP = append(exclUDP, exclUnprefixed...).normalize()
			}
		}
		if len(o.ExcludePorts) > 0 {
			exclTCP = append(exclTCP, o.ExcludePorts...).normalize()
		}
		if len(exclTCP) > 0 || len(exclUDP) > 0 {
			var parts []string
			if len(exclTCP) > 0 {
				parts = append(parts, "T:"+exclTCP.String())
			}
			if len(exclUDP) > 0 {
				parts = append(parts, "U:"+exclUDP.String())
			}
			spec := strings.Join(parts, ",")
			if !hasUDP && len(exclUDP) == 0 {
				spec = strings.TrimPrefix(spec, "T:")
			}
			out = append(out, "--exclude-ports", spec)
		}
	}
	if p.Profile == ProfileUnprivileged && !hasUnpriv {
		out = append(out, "--unprivileged")
	}

	if o.Final {
		if len(iL) != 1 || (o.TargetsFile != "" && iL[0] != o.TargetsFile) {
			return nil, fmt.Errorf("nmap: expected exactly one -iL %s, got %v", o.TargetsFile, iL)
		}
		if len(oX) > 1 {
			return nil, fmt.Errorf("nmap: more than one -oX")
		}
		if o.MaxProcRate > 0 && (rate < 1 || rate > o.MaxProcRate) {
			return nil, fmt.Errorf("nmap: --max-rate %d missing or above the per-process limit %d pps", rate, o.MaxProcRate)
		}
	} else if len(iL) > 0 {
		return nil, fmt.Errorf("nmap -iL in profile arguments: targets come only from the plan")
	}
	return out, nil
}

// parseNmapPorts parses nmap -p syntax: "22,80", "1-1024", "-", "T:80,U:53".
// Ports without a T:/U: prefix go to tcp; nmap would also use them for UDP with -sU,
// which Enforce handles. udp stays nil when no U: was given.
func parseNmapPorts(s string) (tcp, udp PortSet, err error) {
	cur := "T"
	var t, u []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if k, v, ok := strings.Cut(f, ":"); ok {
			switch strings.ToUpper(k) {
			case "T", "U":
				cur, f = strings.ToUpper(k), v
			default:
				return nil, nil, fmt.Errorf("protocol %q not allowed (T: or U: only)", k)
			}
		}
		if f == "" {
			continue
		}
		if cur == "U" {
			u = append(u, f)
		} else {
			t = append(t, f)
		}
	}
	if len(t) > 0 {
		if tcp, err = ParsePorts(strings.Join(t, ",")); err != nil {
			return
		}
	}
	if len(u) > 0 {
		if udp, err = ParsePorts(strings.Join(u, ",")); err != nil {
			return
		}
	}
	if tcp == nil && udp == nil {
		err = fmt.Errorf("empty port list")
	}
	return
}

func scriptList() string {
	var s []string
	for k, ok := range allowedScripts {
		if ok {
			s = append(s, k)
		}
	}
	return strings.Join(sortStrings(s), ",")
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
