package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/obs"
)

// ReconcileConfig: thresholds for state transitions (profile settings, VISION 4.7).
type ReconcileConfig struct {
	HostMissThreshold int           // consecutive misses before a host is "gone" (default 3)
	PortMissThreshold int           // same for host:port (default 2)
	GoneAfter         time.Duration // and at least this long since last_seen (default 0)
	FlapWindow        int           // look at transitions within the last N runs (default 10)
	FlapTransitions   int           // >= this many transitions -> flapping (default 3)
}

func (c *ReconcileConfig) defaults() {
	if c.HostMissThreshold <= 0 {
		c.HostMissThreshold = 3
	}
	if c.PortMissThreshold <= 0 {
		c.PortMissThreshold = 2
	}
	if c.FlapWindow <= 0 {
		c.FlapWindow = 10
	}
	if c.FlapTransitions <= 0 {
		c.FlapTransitions = 3
	}
}

type Event struct {
	Key    string          `json:"key"`
	Kind   string          `json:"asset_kind"` // host | port
	Type   string          `json:"type"`       // new | changed | reverted | missing | gone | reappeared | flapping
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
	RunID  string          `json:"run_id"`
	At     time.Time       `json:"at"`
}

type ReconcileResult struct {
	RunID        string         `json:"run_id"`
	CoveredHosts int            `json:"covered_hosts"`
	LiveHosts    int            `json:"live_hosts"`
	Counts       map[string]int `json:"counts"` // event type -> n
	Events       []Event        `json:"events"`
}

type assetRow struct {
	id                                int64
	key, kind, parent, state, lastRun string
	ip                                netip.Addr
	port                              int
	flapping                          bool
	firstSeen, lastSeen               time.Time
	misses, seen, hours               int
	fp                                string
	current                           []byte // sealed
	httpFP                            string
	httpCur                           []byte // sealed
	prevFP, prevHTTPFP                string // fingerprints before the last change (LAB-T8)
	transitions                       []string
	dirty, isNew                      bool
}

// observed state of one asset in this run
type seen struct {
	kind    string
	ip      netip.Addr
	port    int
	fp      string
	current []byte // plain JSON
}

// Reconcile turns the observations of a run into asset states and events.
//
// Coverage rule: only targets of chunks with status done count as scanned - a
// failed/killed/deferred chunk never produces "missing".
// Hierarchy rule: a port can only be missing if its host was alive in this run.
// User edits (user_tags, user_note_enc, user_overrides) are never touched.
func (s *Store) Reconcile(ctx context.Context, runID string, cfg ReconcileConfig) (ReconcileResult, error) {
	cfg.defaults()
	res := ReconcileResult{RunID: runID, Counts: map[string]int{}}

	var runStart time.Time
	var done *time.Time
	if err := s.DB.QueryRow(ctx, `SELECT started_at, reconciled_at FROM runs WHERE id=$1`, runID).Scan(&runStart, &done); err != nil {
		return res, fmt.Errorf("run %s: %w", runID, err)
	}
	if done != nil {
		return res, fmt.Errorf("run %s already reconciled at %s", runID, done.Format(time.DateTime))
	}
	hourBit := 1 << runStart.UTC().Hour()

	// coverage
	covHosts, covSvc := map[string]bool{}, map[string]bool{}
	svcPorts := map[string][]PortSet{} // ip -> port sets of done services chunks covering it
	rows, err := s.DB.Query(ctx, `SELECT stage, targets, ports FROM chunks WHERE run_id=$1 AND status='done'`, runID)
	if err != nil {
		return res, err
	}
	hasDiscovery := false
	for rows.Next() {
		var stage, ports string
		var tg []string
		rows.Scan(&stage, &tg, &ports)
		ps := ParsePorts(ports)
		for _, t := range tg {
			switch stage {
			case "discovery":
				covHosts[t] = true
				hasDiscovery = true
			case "services":
				covSvc[t] = true
				svcPorts[t] = append(svcPorts[t], ps)
			}
		}
	}
	rows.Close()
	if !hasDiscovery { // -skip-discovery: services chunks define host coverage
		for t := range covSvc {
			covHosts[t] = true
		}
	}
	res.CoveredHosts = len(covHosts)

	// what was observed
	os, err := s.Observations(ctx, runID, obs.KindHost, obs.KindPort, obs.KindService, obs.KindHTTP)
	if err != nil {
		return res, err
	}
	now := map[string]*seen{}
	httpNow := map[string]obs.Observation{}
	live := map[string]bool{}
	for _, o := range os {
		ip, _, port := obs.SplitKey(o.AssetKey)
		addr, _ := netip.ParseAddr(ip)
		switch o.Kind {
		case obs.KindHost:
			live[ip] = true
			if now[o.AssetKey] == nil {
				now[o.AssetKey] = &seen{kind: "host", ip: addr, fp: "up", current: []byte(`{"up":true}`)}
			}
		case obs.KindPort:
			live[ip] = true // a host with an open port is alive
			if now[o.AssetKey] == nil {
				now[o.AssetKey] = &seen{kind: "port", ip: addr, port: port, fp: o.FPHash, current: o.Data}
			}
		case obs.KindService: // service fingerprint wins over the bare port
			live[ip] = true // a host with a detected service is alive
			now[o.AssetKey] = &seen{kind: "port", ip: addr, port: port, fp: o.FPHash, current: o.Data}
		case obs.KindHTTP:
			if ip != "" {
				live[ip] = true
			}
			httpNow[o.AssetKey] = o
		}
	}
	for ip := range live {
		if now[ip] == nil {
			addr, _ := netip.ParseAddr(ip)
			now[ip] = &seen{kind: "host", ip: addr, fp: "up", current: []byte(`{"up":true}`)}
		}
	}
	res.LiveHosts = len(live)

	// last FlapWindow run ids (for flapping)
	var window []string
	wr, err := s.DB.Query(ctx, `SELECT id FROM runs WHERE started_at <= $1 ORDER BY started_at DESC LIMIT $2`, runStart, cfg.FlapWindow)
	if err != nil {
		return res, err
	}
	window, err = pgx.CollectRows(wr, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	inWindow := map[string]bool{}
	for _, id := range window {
		inWindow[id] = true
	}

	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		// load all assets (10k hosts * few ports fits in memory)
		ar, err := tx.Query(ctx, `SELECT id, key, kind, parent_key, ip, port, state, flapping, first_seen, last_seen,
			last_seen_run, consecutive_misses, seen_count, hours_seen, current_fp_hash, current_enc, transition_runs,
			http_fp, http_enc, prev_fp_hash, prev_http_fp
			FROM assets FOR UPDATE`)
		if err != nil {
			return err
		}
		assets := map[string]*assetRow{}
		for ar.Next() {
			a := &assetRow{}
			if err := ar.Scan(&a.id, &a.key, &a.kind, &a.parent, &a.ip, &a.port, &a.state, &a.flapping, &a.firstSeen,
				&a.lastSeen, &a.lastRun, &a.misses, &a.seen, &a.hours, &a.fp, &a.current, &a.transitions,
				&a.httpFP, &a.httpCur, &a.prevFP, &a.prevHTTPFP); err != nil {
				ar.Close()
				return err
			}
			assets[a.key] = a
		}
		ar.Close()

		var events []Event
		emit := func(a *assetRow, typ string, before, after []byte) {
			events = append(events, Event{Key: a.key, Kind: a.kind, Type: typ, Before: before, After: after, RunID: runID, At: runStart})
		}
		transition := func(a *assetRow) {
			a.transitions = append(a.transitions, runID)
		}
		// a reverted change counts like a disappearance + return: 2 transitions (the change and
		// its revert), so repeated short outages raise "flapping" just like a port that blinks
		reverted := map[string]bool{}
		revert := func(a *assetRow) {
			if !reverted[a.key] { // service and HTTP revert in the same run = one outage
				reverted[a.key] = true
				transition(a)
				transition(a)
			}
		}
		open := func(b []byte) []byte {
			if b == nil {
				return nil
			}
			p, err := s.Sealer.Open(b)
			if err != nil {
				return nil
			}
			return p
		}

		// observed assets
		keys := make([]string, 0, len(now))
		for k := range now {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			o := now[k]
			sealed, err := s.Sealer.Seal(o.current)
			if err != nil {
				return err
			}
			a := assets[k]
			if a == nil {
				parent := ""
				if o.kind == "port" {
					parent = o.ip.String()
				}
				a = &assetRow{key: k, kind: o.kind, parent: parent, ip: o.ip, port: o.port, state: "new",
					firstSeen: runStart, lastSeen: runStart, lastRun: runID, seen: 1, hours: hourBit,
					fp: o.fp, current: sealed, isNew: true, dirty: true}
				if h, ok := httpNow[k]; ok {
					if a.httpCur, err = s.Sealer.Seal(h.Data); err != nil {
						return err
					}
					a.httpFP = h.FPHash
				}
				assets[k] = a
				emit(a, "new", nil, o.current)
				continue
			}
			if a.lastRun == runID { // reconcile re-run for the same run: idempotent
				continue
			}
			switch a.state {
			case "missing", "gone":
				emit(a, "reappeared", open(a.current), o.current)
				transition(a)
				a.state = "active"
			case "new":
				a.state = "active"
			}
			if a.fp != "" && a.fp != o.fp {
				if old := open(a.current); lessDetailed(old, o.current) {
					// same service seen with less detail (no version this time, an import
					// without product...): not a change - keep the richer fingerprint
					o.fp, sealed = a.fp, a.current
				} else if a.prevFP != "" && o.fp == a.prevFP {
					// back to the fingerprint before the last change: the change did not hold
					// (e.g. backend behind a proxy was down) - instability, not a new change
					emit(a, "reverted", old, o.current)
					revert(a)
					a.prevFP = a.fp
				} else {
					emit(a, "changed", old, o.current)
					a.prevFP = a.fp
				}
			}
			a.fp, a.current = o.fp, sealed
			// web content: compared only when the http stage observed this port in this run
			if h, ok := httpNow[k]; ok {
				if a.httpFP != "" && a.httpFP != h.FPHash {
					if a.prevHTTPFP != "" && h.FPHash == a.prevHTTPFP {
						emit(a, "reverted", open(a.httpCur), h.Data)
						revert(a)
					} else {
						emit(a, "changed", open(a.httpCur), h.Data)
					}
					a.prevHTTPFP = a.httpFP
				}
				hs, err := s.Sealer.Seal(h.Data)
				if err != nil {
					return err
				}
				a.httpFP, a.httpCur = h.FPHash, hs
			}
			a.lastSeen, a.lastRun = runStart, runID
			a.misses = 0
			a.seen++
			a.hours |= hourBit
			a.dirty = true
		}

		// not observed, but covered
		for _, a := range assets {
			if now[a.key] != nil || a.isNew || a.lastRun == runID {
				continue
			}
			ip := a.ip.String()
			threshold := cfg.HostMissThreshold
			if a.kind == "host" {
				if !covHosts[ip] {
					continue // not scanned in this run (other set, partial run, failed chunk)
				}
			} else {
				threshold = cfg.PortMissThreshold
				if !live[ip] || !covSvc[ip] {
					continue // hierarchy: host down or ports not scanned -> port inherits, no miss
				}
				scanned := false
				for _, ps := range svcPorts[ip] {
					if ps.Has(a.port) {
						scanned = true
					}
				}
				if !scanned {
					continue // this port was not in the scanned port set of this run
				}
			}
			a.misses++
			a.dirty = true
			if a.misses == 1 && (a.state == "active" || a.state == "new") {
				a.state = "missing"
				transition(a)
				emit(a, "missing", open(a.current), nil)
			}
			if a.misses >= threshold && a.state != "gone" && runStart.Sub(a.lastSeen) >= cfg.GoneAfter {
				a.state = "gone"
				emit(a, "gone", open(a.current), nil)
			}
		}

		// flapping: transitions within the window
		for _, a := range assets {
			var recent []string
			for _, r := range a.transitions {
				if inWindow[r] {
					recent = append(recent, r)
				}
			}
			if len(recent) != len(a.transitions) {
				a.transitions, a.dirty = recent, true
			}
			flap := len(recent) >= cfg.FlapTransitions
			if flap != a.flapping {
				a.flapping, a.dirty = flap, true
				if flap {
					emit(a, "flapping", nil, nil)
				}
			}
		}

		// write
		ids := map[string]int64{}
		for _, a := range assets {
			if !a.dirty {
				continue
			}
			if a.isNew {
				if err := tx.QueryRow(ctx, `INSERT INTO assets (key, kind, parent_key, ip, port, state, flapping, first_seen,
					last_seen, last_seen_run, consecutive_misses, seen_count, hours_seen, current_fp_hash, current_enc, transition_runs,
					http_fp, http_enc, prev_fp_hash, prev_http_fp)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) RETURNING id`,
					a.key, a.kind, a.parent, a.ip, a.port, a.state, a.flapping, a.firstSeen, a.lastSeen, a.lastRun,
					a.misses, a.seen, a.hours, a.fp, a.current, nonNil(a.transitions), a.httpFP, a.httpCur,
					a.prevFP, a.prevHTTPFP).Scan(&a.id); err != nil {
					return fmt.Errorf("insert asset %s: %w", a.key, err)
				}
			} else if _, err := tx.Exec(ctx, `UPDATE assets SET state=$2, flapping=$3, last_seen=$4, last_seen_run=$5,
					consecutive_misses=$6, seen_count=$7, hours_seen=$8, current_fp_hash=$9, current_enc=$10,
					transition_runs=$11, http_fp=$12, http_enc=$13, prev_fp_hash=$14, prev_http_fp=$15, updated_at=now() WHERE id=$1`,
				a.id, a.state, a.flapping, a.lastSeen, a.lastRun, a.misses, a.seen, a.hours, a.fp, a.current,
				nonNil(a.transitions), a.httpFP, a.httpCur, a.prevFP, a.prevHTTPFP); err != nil {
				return fmt.Errorf("update asset %s: %w", a.key, err)
			}
			ids[a.key] = a.id
		}
		for i := range events {
			e := &events[i]
			id := ids[e.Key]
			if id == 0 {
				id = assets[e.Key].id
			}
			before, err := sealOrNil(s.Sealer, e.Before)
			if err != nil {
				return err
			}
			after, err := sealOrNil(s.Sealer, e.After)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO asset_events (asset_id, key, run_id, type, before_enc, after_enc, at)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, e.Key, runID, e.Type, before, after, e.At); err != nil {
				return err
			}
			res.Counts[e.Type]++
		}
		res.Events = events
		_, err = tx.Exec(ctx, `UPDATE runs SET reconciled_at=now() WHERE id=$1`, runID)
		return err
	})
	return res, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sealOrNil(s Sealer, b []byte) ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	return s.Seal(b)
}

// lessDetailed: the new service observation only omits fields the old one had
// (same name; product/version empty or equal). E.g. nmap failed to read the version
// in one run, or an imported CSV has no version column.
func lessDetailed(oldJSON, newJSON []byte) bool {
	var o, n obs.ServiceData
	if json.Unmarshal(oldJSON, &o) != nil || json.Unmarshal(newJSON, &n) != nil || o.Name == "" {
		return false
	}
	same := func(a, b string) bool { return b == "" || a == b }
	return n.Name == o.Name && same(o.Product, n.Product) && same(o.Version, n.Version) &&
		(n.Product != o.Product || n.Version != o.Version)
}
