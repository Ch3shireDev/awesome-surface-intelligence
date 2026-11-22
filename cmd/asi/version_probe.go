package main

import (
	"net/netip"
	"sort"
)

// versionProbeMax caps the deeper version probe (LAB-T10): each probed host costs up to its
// --host-timeout (2m), so an unbounded pass on a large network could outlast the scan window.
const versionProbeMax = 512

// capWeak keeps at most max host:port pairs of the deeper version probe, deterministically:
// hosts in address order, ports ascending. Returns the kept map and its size.
func capWeak(weak map[string][]int, max int) (map[string][]int, int) {
	ips := make([]string, 0, len(weak))
	for ip := range weak {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		a, ea := netip.ParseAddr(ips[i])
		b, eb := netip.ParseAddr(ips[j])
		if ea != nil || eb != nil {
			return ips[i] < ips[j]
		}
		return a.Less(b)
	})
	out, n := map[string][]int{}, 0
	for _, ip := range ips {
		ports := append([]int(nil), weak[ip]...)
		sort.Ints(ports)
		for _, p := range ports {
			if n == max {
				return out, n
			}
			out[ip] = append(out[ip], p)
			n++
		}
	}
	return out, n
}
