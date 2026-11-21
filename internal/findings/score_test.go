package findings

import (
	"testing"
	"time"

	"asi/internal/obs"
)

func TestRank(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	web := Service{IP: "8.8.8.8", Port: 443, Proto: "tcp", Name: "http", TLS: true}
	plain := Rank(ScoreInput{Service: web, State: "active"}, now)
	if plain.Level != "low" {
		t.Fatalf("plain https on public IP: %+v", plain)
	}
	sig := Rank(ScoreInput{Service: web, State: "active", Sigs: []obs.SignatureData{{Name: "PHP 7.4", Severity: "medium"}, {Name: "staging", Severity: "low"}}}, now)
	if sig.Level != "medium" || sig.Score != 65 {
		t.Fatalf("signatures: %+v", sig)
	}
	cert := Rank(ScoreInput{Service: web, State: "new", HTTP: &WebInfo{TLSSelfSigned: true, HTTPData: obs.HTTPData{TLSNotAfter: "2025-01-01T00:00:00Z"}},
		Sigs: []obs.SignatureData{{Name: "PHP 7.4", Severity: "medium"}}}, now)
	if cert.Level != "high" || len(cert.Reasons) < 4 {
		t.Fatalf("self-signed + expired + new + medium sig must be high: %+v", cert)
	}
	redis := Rank(ScoreInput{Service: Service{IP: "10.0.0.5", Port: 6379, Proto: "tcp", Name: "redis"}, State: "active",
		Sigs: []obs.SignatureData{{Name: "Redis bez hasła", Severity: "high"}}}, now)
	if redis.Level != "high" {
		t.Fatalf("redis noauth: %+v", redis)
	}
	acc := Rank(ScoreInput{Service: Service{IP: "10.0.0.5", Port: 6379, Proto: "tcp"}, Verdict: Verdict{Status: "accepted"},
		Sigs: []obs.SignatureData{{Name: "Redis bez hasła", Severity: "high"}}}, now)
	if !acc.Dismissed {
		t.Fatal("accepted must be dismissed")
	}
	low := Rank(ScoreInput{Service: Service{IP: "10.0.0.5", Port: 6379, Proto: "tcp"}, Verdict: Verdict{Interest: "low", Reason: "lab"},
		Sigs: []obs.SignatureData{{Name: "Redis bez hasła", Severity: "high"}}}, now)
	if low.Level != "low" || low.Score > 44 {
		t.Fatalf("analyst override: %+v", low)
	}
}
