package nmap

import (
	"asi/internal/nmapxml"
	"asi/internal/obs"
)

// Filtered returns the re-probed ports that nmap saw as filtered: a firewall drops the probe,
// so nothing is known about the service (LAB-T11, decision 20). Reconcile never counts them as
// missing or new. want: ip -> TCP ports given to the confirmation pass (run without --open).
func Filtered(hosts []nmapxml.Host, want map[string][]int) []obs.Observation {
	var out []obs.Observation
	for _, h := range hosts {
		if h.TimedOut || !h.Up() {
			continue
		}
		ip := h.IP()
		for _, port := range want[ip] {
			state, reason := h.TCPState(port)
			if state != "filtered" {
				continue
			}
			o := obs.New(obs.KindPort, obs.PortKey(ip, "tcp", port), "nmap", obs.PortData{State: state, Reason: reason}, 60)
			o.FPHash = "" // not a fingerprint
			out = append(out, o)
		}
	}
	return out
}
