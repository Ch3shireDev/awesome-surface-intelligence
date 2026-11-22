package main

import (
	"fmt"
	"sort"

	"asi/internal/obs"
	nmapad "asi/internal/scanner/nmap"
	"asi/internal/targets"
)

// targetPorts splits the services stage by the ports chosen per target (decision 25).
type targetPorts struct {
	of    map[string]string // ip -> spec; missing = profile of the scan
	args  map[string]string // spec -> nmap args
	count map[string]int    // spec -> number of hosts
}

func portGroups(baseArgs string, hosts []targets.Host) (targetPorts, error) {
	p := targetPorts{of: map[string]string{}, args: map[string]string{}, count: map[string]int{}}
	for _, h := range hosts {
		spec, err := targets.NormalizePorts(h.Ports) // again: plan.json of a resumed run is an input too
		if err != nil {
			return p, fmt.Errorf("%s: %w", h.IP, err)
		}
		if spec == targets.PortsDefault {
			continue
		}
		if _, ok := p.args[spec]; !ok {
			args, _, err := nmapad.ApplyPorts(baseArgs, spec, 0)
			if err != nil {
				return p, fmt.Errorf("%s: %w", h.IP, err)
			}
			p.args[spec] = args
		}
		p.of[h.IP] = spec
		p.count[spec]++
	}
	return p, nil
}

func (p targetPorts) specs() []string {
	out := make([]string, 0, len(p.args))
	for s := range p.args {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// group is nil when no target has its own ports: the scan then runs exactly as without the feature.
func (p targetPorts) group() func(string) string {
	if len(p.of) == 0 {
		return nil
	}
	return func(ip string) string { return p.of[ip] }
}

func (p targetPorts) adapter(def obs.Scanner) func(string) obs.Scanner {
	return func(spec string) obs.Scanner {
		if args, ok := p.args[spec]; ok {
			return nmapad.Services(args)
		}
		return def
	}
}
