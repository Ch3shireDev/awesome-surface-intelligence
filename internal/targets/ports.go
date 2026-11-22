package targets

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Ports of a target (decision 25). "" = no choice, the profile of the scan applies. Otherwise
// "all", "top100", "top1000" or a canonical TCP list such as "22,80,8000-8100".
const (
	PortsDefault = ""
	PortsAll     = "all"
	PortsTop100  = "top100"
	PortsTop1000 = "top1000"
)

var profileWidth = map[string]int{PortsTop100: 1, PortsTop1000: 2, PortsAll: 3}

// NormalizePorts validates the ports of a target. Lists accept ',', ';' or spaces as separators
// (';' needs no quoting in CSV, like tags).
func NormalizePorts(spec string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	switch s {
	case "", "default", "auto":
		return PortsDefault, nil
	case "all", "full", "lab", "allowed", "policy", "-":
		return PortsAll, nil
	case PortsTop100, PortsTop1000:
		return s, nil
	}
	rs, err := parseRanges(s)
	if err != nil {
		return "", fmt.Errorf("porty %q: %w (top100, top1000, all albo lista 1-65535, np. 22,80,8000-8100)", spec, err)
	}
	return formatRanges(rs), nil
}

func parseRanges(s string) ([][2]int, error) {
	num := func(v string) (int, error) {
		if v == "" || strings.Trim(v, "0123456789") != "" {
			return 0, fmt.Errorf("%q nie jest numerem portu", v)
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %s poza zakresem", v)
		}
		return n, nil
	}
	var out [][2]int
	for _, part := range strings.FieldsFunc(s, func(c rune) bool { return strings.ContainsRune(",; \t\r\n", c) }) {
		a, b, isRange := strings.Cut(part, "-")
		lo, err := num(a)
		if err != nil {
			return nil, err
		}
		hi := lo
		if isRange {
			if hi, err = num(b); err != nil {
				return nil, err
			}
			if hi < lo {
				return nil, fmt.Errorf("odwrócony zakres %s", part)
			}
		}
		out = append(out, [2]int{lo, hi})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pusta lista")
	}
	return out, nil
}

func formatRanges(rs [][2]int) string {
	sort.Slice(rs, func(i, j int) bool { return rs[i][0] < rs[j][0] })
	var merged [][2]int
	for _, r := range rs {
		n := len(merged)
		// join overlaps and existing ranges, keep "22,23" readable as two ports
		if n > 0 && (r[0] <= merged[n-1][1] || (r[0] == merged[n-1][1]+1 && (r[1] > r[0] || merged[n-1][1] > merged[n-1][0]))) {
			merged[n-1][1] = max(merged[n-1][1], r[1])
			continue
		}
		merged = append(merged, r)
	}
	out := make([]string, len(merged))
	for i, r := range merged {
		out[i] = strconv.Itoa(r[0])
		if r[1] > r[0] {
			out[i] += "-" + strconv.Itoa(r[1])
		}
	}
	return strings.Join(out, ",")
}

// mergePorts combines the (normalized) ports of two targets covering the same IP: a target
// without a choice yields to one with a choice, lists add up, and when a profile meets
// something else the wider profile wins (lost=true when that drops an explicit list).
func mergePorts(a, b string) (ports string, lost bool) {
	switch {
	case a == b || b == PortsDefault:
		return a, false
	case a == PortsDefault:
		return b, false
	}
	wa, wb := profileWidth[a], profileWidth[b]
	switch {
	case wa == 0 && wb == 0:
		ra, errA := parseRanges(a)
		rb, errB := parseRanges(b)
		if errA != nil || errB != nil {
			return a, true
		}
		return formatRanges(append(ra, rb...)), false
	case wa >= wb:
		return a, wb == 0 && a != PortsAll
	default:
		return b, wa == 0 && b != PortsAll
	}
}

// InPorts reports whether port is inside a custom list; profiles and "" always say true.
func InPorts(spec string, port int) bool {
	if spec == PortsDefault || profileWidth[spec] > 0 {
		return true
	}
	rs, err := parseRanges(spec)
	if err != nil {
		return true
	}
	for _, r := range rs {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}
