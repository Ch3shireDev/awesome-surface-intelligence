package nmap

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// nmap drops ALL results of a host that exceeds --host-timeout, and the clock of every host in a
// process runs while the others are probed. At R pps a process needs at least hosts*ports/R
// seconds, so e.g. full TCP at 60 pps (18 min) could never finish within 10 min: zero services.
const defaultHostTimeout = 10 * time.Minute

// FitTimeout adapts service args to the rate of one process: maxHosts keeps the probing of a
// chunk within half of the default host timeout; when a single host needs more than that, the
// default --host-timeout is raised and returned (0 = unchanged). An explicit other value is kept.
func FitTimeout(args string, pps int) (fitted string, maxHosts int, timeout time.Duration) {
	f := strings.Fields(args)
	ports := portCount(f)
	if ports == 0 || pps <= 0 {
		return args, 0, 0
	}
	perHost := time.Duration(float64(ports) / float64(pps) * float64(time.Second))
	budget := defaultHostTimeout / 2
	if perHost <= budget {
		return args, int(budget / max(perHost, time.Millisecond)), 0
	}
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "--host-timeout" && f[i+1] == "10m" {
			timeout = 2*perHost + defaultHostTimeout // probing with retries + time for -sV
			f[i+1] = fmt.Sprintf("%ds", int(timeout.Seconds()))
		}
	}
	return strings.Join(f, " "), 1, timeout
}

func portCount(args []string) int {
	spec := ""
	for i, a := range args {
		switch {
		case a == "-p" && i+1 < len(args):
			spec = args[i+1]
		case a == "-p-":
			return 65535
		case strings.HasPrefix(a, "-p") && len(a) > 2:
			spec = a[2:]
		}
	}
	if spec == "" {
		if n := flagValue(args, "--top-ports"); n > 0 {
			return n + len(RiskyPorts)
		}
		return 1000 // nmap's default
	}
	total := 0
	for _, part := range strings.Split(spec, ",") {
		if _, after, ok := strings.Cut(part, ":"); ok {
			part = after
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			continue
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(b); err != nil {
				continue
			}
		}
		total += max(0, hi-lo+1)
	}
	return total
}
