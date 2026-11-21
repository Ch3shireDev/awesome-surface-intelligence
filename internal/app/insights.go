package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"time"

	"asi/internal/findings"
	"asi/internal/obs"
	"asi/internal/store"
)

// DEV-7: ranking (one 0-100 score with reasons), groups of similar services,
// time-of-day patterns. Computed from assets + the newest http/signature observations.

type rankedItem struct {
	Key      string   `json:"key"`
	Service  string   `json:"service"`
	Score    int      `json:"score"`
	Interest string   `json:"interest"`
	Reason   string   `json:"reason"`
	Reasons  []string `json:"reasons"`
	State    string   `json:"state"`
	Tags     []string `json:"tags"`
}

type group struct {
	Label string   `json:"label"`
	Kind  string   `json:"kind"` // service | tech
	Count int      `json:"count"`
	Keys  []string `json:"keys"`  // up to 8 examples
	Query string   `json:"query"` // assets filter that shows the group
}

type timePattern struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	SeenAt   string `json:"seen_at"`   // e.g. "08-17 UTC"
	MissedAt string `json:"missed_at"` // hours when scanned but not seen
	State    string `json:"state"`
}

type insights struct {
	Ranked   []rankedItem  `json:"ranked"`
	Groups   []group       `json:"groups"`
	Patterns []timePattern `json:"time_patterns"`
}

func (a *App) buildInsights(ctx context.Context, all []store.Asset) insights {
	httpBy := map[string]*findings.WebInfo{}
	if hs, err := a.St.LatestKind(ctx, obs.KindHTTP); err == nil {
		for _, o := range hs {
			var w findings.WebInfo
			if json.Unmarshal(o.Data, &w) == nil {
				httpBy[o.AssetKey] = &w
			}
		}
	}
	sigsBy := map[string][]obs.SignatureData{}
	if _, sigs, err := a.St.LatestSignatures(ctx); err == nil {
		for _, o := range sigs {
			var d obs.SignatureData
			if o.Decode(&d) == nil {
				sigsBy[o.AssetKey] = append(sigsBy[o.AssetKey], d)
			}
		}
	}
	now := time.Now()
	var out insights
	svcGroups := map[string]*group{}
	techGroups := map[string]*group{}
	addTo := func(m map[string]*group, label, kind, key, q string) {
		g := m[label]
		if g == nil {
			g = &group{Label: label, Kind: kind, Query: q}
			m[label] = g
		}
		g.Count++
		if len(g.Keys) < 8 {
			g.Keys = append(g.Keys, key)
		}
	}
	scanned, _ := a.St.ScannedHours(ctx, 14)

	for _, as := range all {
		live := as.State == "active" || as.State == "new"
		if as.Kind == "port" && live {
			s := portService(as)
			r := findings.Rank(findings.ScoreInput{Service: s, HTTP: httpBy[as.Key], Sigs: sigsBy[as.Key],
				State: as.State, Flapping: as.Flapping, Verdict: verdictOf(as)}, now)
			fp := strings.TrimSpace(s.Fingerprint())
			if !r.Dismissed && r.Level != "low" {
				out.Ranked = append(out.Ranked, rankedItem{Key: as.Key, Service: fp, Score: r.Score, Interest: r.Level,
					Reason: strings.Join(r.Reasons, " · "), Reasons: r.Reasons, State: as.State, Tags: as.UserTags})
			}
			if s.Product != "" {
				label := strings.TrimSpace(s.Product + " " + s.Version)
				addTo(svcGroups, label, "service", as.Key, label)
			}
			if h := httpBy[as.Key]; h != nil {
				for _, t := range h.Tech {
					addTo(techGroups, strings.ReplaceAll(t, ":", " "), "tech", as.Key, as.Key)
				}
			}
		}
		// time of day: seen at some hours, scanned but absent at others (hosts only, >=2 sightings)
		if as.Kind == "host" && as.SeenCount >= 2 && as.HoursSeen != 0 {
			missed := scanned &^ as.HoursSeen
			if missed != 0 && bits.OnesCount(uint(as.HoursSeen)) < bits.OnesCount(uint(scanned)) && (as.State != "active" || as.ConsecutiveMisses > 0 || as.Flapping) {
				out.Patterns = append(out.Patterns, timePattern{Key: as.Key, Kind: as.Kind, SeenAt: hoursLabel(as.HoursSeen),
					MissedAt: hoursLabel(missed), State: as.State})
			}
		}
	}
	sort.Slice(out.Ranked, func(i, j int) bool {
		if out.Ranked[i].Score != out.Ranked[j].Score {
			return out.Ranked[i].Score > out.Ranked[j].Score
		}
		return out.Ranked[i].Key < out.Ranked[j].Key
	})
	if len(out.Ranked) > 100 {
		out.Ranked = out.Ranked[:100]
	}
	for _, m := range []map[string]*group{svcGroups, techGroups} {
		for _, g := range m {
			if g.Count >= 2 { // a "group" is at least two hosts running the same thing
				out.Groups = append(out.Groups, *g)
			}
		}
	}
	sort.Slice(out.Groups, func(i, j int) bool {
		if out.Groups[i].Count != out.Groups[j].Count {
			return out.Groups[i].Count > out.Groups[j].Count
		}
		return out.Groups[i].Label < out.Groups[j].Label
	})
	if len(out.Groups) > 30 {
		out.Groups = out.Groups[:30]
	}
	if len(out.Patterns) > 50 {
		out.Patterns = out.Patterns[:50]
	}
	return out
}

// hoursLabel: 0b111 at 8..10 -> "08-10 UTC"; ranges joined with commas.
func hoursLabel(mask int) string {
	var parts []string
	for h := 0; h < 24; h++ {
		if mask&(1<<h) == 0 {
			continue
		}
		e := h
		for e+1 < 24 && mask&(1<<(e+1)) != 0 {
			e++
		}
		if e == h {
			parts = append(parts, fmt.Sprintf("%02d", h))
		} else {
			parts = append(parts, fmt.Sprintf("%02d-%02d", h, e))
		}
		h = e
	}
	return strings.Join(parts, ", ") + " UTC"
}
