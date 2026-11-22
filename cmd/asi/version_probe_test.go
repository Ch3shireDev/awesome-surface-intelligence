package main

import "testing"

func TestCapWeak(t *testing.T) {
	weak := map[string][]int{
		"192.0.2.10": {15432, 22},
		"192.0.2.9":  {8000, 7000, 6000},
		"192.0.2.11": {1},
	}
	got, n := capWeak(weak, 4)
	if n != 4 {
		t.Fatalf("n = %d, want 4", n)
	}
	// address order (192.0.2.9 < .10 numerically), ports ascending
	if len(got["192.0.2.9"]) != 3 || got["192.0.2.9"][0] != 6000 || len(got["192.0.2.10"]) != 1 || got["192.0.2.10"][0] != 22 {
		t.Fatalf("not deterministic address/port order: %v", got)
	}
	if _, ok := got["192.0.2.11"]; ok {
		t.Fatalf("over the cap must be left out: %v", got)
	}
	if all, n := capWeak(weak, 100); n != 6 || len(all) != 3 {
		t.Fatalf("under the cap keeps everything: %d %v", n, all)
	}
}
