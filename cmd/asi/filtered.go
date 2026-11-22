package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"asi/internal/findings"
	"asi/internal/obs"
	"asi/internal/store"
)

func orStr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// knownServices: TCP services the database does not consider gone (LAB-T11 re-probe list).
// The caller narrows it to live hosts of this run and to the ports chosen for their targets.
func (d *dbRecorder) knownServices() []findings.Service {
	if d == nil {
		return nil
	}
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	as, err := d.st.Assets(c, store.AssetFilter{Kind: "port", Limit: 1_000_000})
	if err != nil {
		d.logf("db: known services: %v", err)
		return nil
	}
	var out []findings.Service
	for _, a := range as {
		if a.State == "gone" {
			continue
		}
		if ip, proto, port := obs.SplitKey(a.Key); proto == "tcp" {
			out = append(out, findings.Service{IP: ip, Proto: proto, Port: port})
		}
	}
	return out
}

// runIsFiltered reads results/<run>/run.json: a firewall hid known ports.
func runIsFiltered(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return false
	}
	var r struct {
		N int `json:"filtered_ports"`
	}
	return json.Unmarshal(b, &r) == nil && r.N > 0
}
