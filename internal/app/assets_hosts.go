package app

import (
	"encoding/json"
	"net/netip"
	"sort"

	"asi/internal/store"
)

type assetRow struct {
	store.Asset
	Interest string `json:"interest,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Service  string `json:"service,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	HTTPMs   int    `json:"http_ms,omitempty"`
	SlowHTTP bool   `json:"slow_http,omitempty"`
}

func hostStateFromPorts(ports []store.Asset) string {
	best := "gone"
	rank := map[string]int{"active": 4, "new": 3, "missing": 2, "gone": 1}
	for _, p := range ports {
		if rank[p.State] > rank[best] {
			best = p.State
		}
	}
	return best
}

func synthHostFromPorts(ip string, ports []store.Asset) store.Asset {
	h := store.Asset{
		Key:     ip,
		Kind:    "host",
		IP:      ip,
		State:   hostStateFromPorts(ports),
		Current: json.RawMessage(`{"up":true}`),
	}
	for _, p := range ports {
		if h.FirstSeen.IsZero() || (!p.FirstSeen.IsZero() && p.FirstSeen.Before(h.FirstSeen)) {
			h.FirstSeen = p.FirstSeen
		}
		if p.LastSeen.After(h.LastSeen) {
			h.LastSeen = p.LastSeen
			h.LastSeenRun = p.LastSeenRun
		}
		if p.SeenCount > h.SeenCount {
			h.SeenCount = p.SeenCount
		}
		h.HoursSeen |= p.HoursSeen
		if p.Flapping {
			h.Flapping = true
		}
	}
	return h
}

// ensureHostsForAssetRows makes sure that whenever port rows are shown in the
// combined Assets view (kind == ""), each port's host IP is also present right
// before its ports — either from existing DB hosts or synthesized from its ports.
func ensureHostsForAssetRows(rows []assetRow, hostByIP map[string]store.Asset) []assetRow {
	hasHost := map[string]bool{}
	portsByIP := map[string][]store.Asset{}
	for _, r := range rows {
		if r.Kind == "host" {
			hasHost[r.IP] = true
		} else if r.Kind == "port" && r.IP != "" {
			portsByIP[r.IP] = append(portsByIP[r.IP], r.Asset)
		}
	}
	missing := map[string]bool{}
	for ip := range portsByIP {
		if !hasHost[ip] {
			missing[ip] = true
		}
	}
	if len(missing) == 0 {
		return rows
	}
	out := make([]assetRow, 0, len(rows)+len(missing))
	inserted := map[string]bool{}
	for _, r := range rows {
		if r.Kind == "port" && missing[r.IP] && !inserted[r.IP] {
			h, ok := hostByIP[r.IP]
			if !ok {
				h = synthHostFromPorts(r.IP, portsByIP[r.IP])
			}
			out = append(out, assetRow{Asset: h})
			inserted[r.IP] = true
		}
		out = append(out, r)
	}
	return out
}

// ensureHostsFromOrphanPorts adds synthesized host assets for IPs that have
// detected ports in DB without a corresponding kind="host" row.
func ensureHostsFromOrphanPorts(hosts []store.Asset, ports []store.Asset) []store.Asset {
	hasHost := map[string]bool{}
	for _, h := range hosts {
		hasHost[h.IP] = true
	}
	byIP := map[string][]store.Asset{}
	for _, p := range ports {
		if p.IP != "" && !hasHost[p.IP] {
			byIP[p.IP] = append(byIP[p.IP], p)
		}
	}
	if len(byIP) == 0 {
		return hosts
	}
	out := make([]store.Asset, len(hosts), len(hosts)+len(byIP))
	copy(out, hosts)
	for ip, ps := range byIP {
		out = append(out, synthHostFromPorts(ip, ps))
	}
	sort.Slice(out, func(i, j int) bool {
		ai, ei := netip.ParseAddr(out[i].IP)
		aj, ej := netip.ParseAddr(out[j].IP)
		if ei == nil && ej == nil {
			return ai.Compare(aj) < 0
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// countSyntheticHosts ensures Dashboard host KPIs include any IP that has
// detected port assets even if no kind="host" row exists for it yet.
func countSyntheticHosts(all []store.Asset, counts map[string]map[string]int) {
	hasHost := map[string]bool{}
	portsByIP := map[string][]store.Asset{}
	for _, as := range all {
		if as.Kind == "host" {
			hasHost[as.IP] = true
		} else if as.Kind == "port" && as.IP != "" {
			portsByIP[as.IP] = append(portsByIP[as.IP], as)
		}
	}
	for ip, ps := range portsByIP {
		if hasHost[ip] {
			continue
		}
		h := synthHostFromPorts(ip, ps)
		counts["host"][h.State]++
		if h.Flapping {
			counts["host"]["flapping"]++
		}
	}
}
