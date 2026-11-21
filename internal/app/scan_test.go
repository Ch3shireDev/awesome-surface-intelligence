package app

import (
	"encoding/json"
	"strings"
	"testing"

	"asi/internal/store"
)

func TestScanRequestArgsPorts(t *testing.T) {
	for _, tc := range []struct {
		ports string
		want  string
	}{
		{"", "-ports auto"},
		{"auto", "-ports auto"},
		{"all", "-ports all"},
		{"lab", "-ports lab"},
		{"allowed", "-ports allowed"},
		{"top100", "-ports top100"},
		{"top1000", "-ports top1000"},
		{"22,80,443,8787", "-ports 22,80,443,8787"},
	} {
		args, err := (ScanRequest{Parallel: 4, Rate: 300, Ports: tc.ports}).args("/t.json", "/r", "127.0.0.1:8091")
		if err != nil {
			t.Fatalf("ports=%q: %v", tc.ports, err)
		}
		if !strings.Contains(strings.Join(args, " "), tc.want) {
			t.Errorf("ports=%q: args %v missing %q", tc.ports, args, tc.want)
		}
	}
	if _, err := (ScanRequest{Parallel: 4, Rate: 300, Ports: "bad;port"}).args("/t.json", "/r", "127.0.0.1:8091"); err == nil {
		t.Fatal("expected error for invalid ports")
	}
}

func TestSlowHTTPThresholdAndExtract(t *testing.T) {
	t.Setenv("ASI_HTTP_SLOW_MS", "")
	if got := slowHTTPThresholdMs(); got != defaultSlowHTTPMs {
		t.Fatalf("default threshold: got %d, want %d", got, defaultSlowHTTPMs)
	}
	t.Setenv("ASI_HTTP_SLOW_MS", "250")
	if got := slowHTTPThresholdMs(); got != 250 {
		t.Fatalf("env threshold: got %d, want 250", got)
	}
	t.Setenv("ASI_HTTP_SLOW_MS", "nope")
	if got := slowHTTPThresholdMs(); got != defaultSlowHTTPMs {
		t.Fatalf("invalid env threshold: got %d, want %d", got, defaultSlowHTTPMs)
	}

	a := store.Asset{HTTP: json.RawMessage(`{"url":"http://127.0.0.1:8085","status":200,"response_time_ms":542}`)}
	if got := assetHTTPMs(a); got != 542 {
		t.Fatalf("assetHTTPMs: got %d, want 542", got)
	}
	if got := assetHTTPMs(store.Asset{}); got != 0 {
		t.Fatalf("empty assetHTTPMs: got %d, want 0", got)
	}
}
