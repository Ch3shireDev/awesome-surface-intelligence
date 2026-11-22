package main

import (
	"testing"
	"time"

	"asi/internal/findings"
	"asi/internal/obs"
)

// LAB-T12: services.json / DefectDojo use the panel's Rank, not the nmap-only score.
func TestRankServicesUsesSignaturesAndVerdicts(t *testing.T) {
	svcs := []findings.Service{
		{IP: "192.0.2.20", Port: 8088, Proto: "tcp", Name: "http", Product: "Apache httpd"},
		{IP: "192.0.2.21", Port: 3001, Proto: "tcp", Name: "http"},
		{IP: "192.0.2.22", Port: 80, Proto: "tcp", Name: "http"},
	}
	k0 := obs.PortKey("192.0.2.20", "tcp", 8088)
	k1 := obs.PortKey("192.0.2.21", "tcp", 3001)
	all := []obs.Observation{
		obs.New(obs.KindSignature, k0, "nuclei", obs.SignatureData{ID: "asi-wordpress-outdated", Name: "WordPress nieaktualny", Severity: "high", Extract: []string{"4.7"}}, 95, "x"),
		obs.New(obs.KindSignature, k1, "nuclei", obs.SignatureData{ID: "asi-gitea-install", Name: "Gitea - niedokończona instalacja", Severity: "high"}, 95, "y"),
	}
	verdicts := map[string]findings.Verdict{k1: {Status: "accepted", Interest: "low", Reason: "lab"}}
	rankServices(svcs, all, verdicts, time.Now())

	if svcs[0].Interest != "high" || svcs[0].Score < 85 {
		t.Fatalf("signature high must make the service high in the run files: %+v", svcs[0])
	}
	if svcs[1].Interest != "low" {
		t.Fatalf("analyst verdict must still win: %+v", svcs[1])
	}
	if svcs[2].Interest != "low" || svcs[2].Score == 0 && svcs[2].Interest == "" {
		t.Fatalf("plain http without signatures stays low: %+v", svcs[2])
	}
}
