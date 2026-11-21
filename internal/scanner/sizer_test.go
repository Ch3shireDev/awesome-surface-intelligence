package scanner

import (
	"testing"
	"time"
)

func TestSizerAdaptive(t *testing.T) {
	z := &Sizer{Target: 60 * time.Second, Min: 1, Max: 64, Start: 4}
	if n := z.Next(1000, 5); n != 4 {
		t.Fatalf("start size: got %d want 4", n)
	}
	z.Observe(4, 8*time.Second) // 2 s/host -> 30 hosts per 60s chunk
	if n := z.Next(1000, 5); n != 30 {
		t.Fatalf("adaptive size: got %d want 30", n)
	}
	z.Observe(30, 300*time.Second) // slow chunk (10 s/host) pulls EWMA up -> smaller chunks
	if n := z.Next(1000, 5); n >= 30 {
		t.Fatalf("should shrink after slow chunk, got %d", n)
	}
}

func TestSizerTailBalancing(t *testing.T) {
	z := &Sizer{Target: 60 * time.Second, Min: 1, Max: 64, Start: 4}
	z.Seed(0.5) // would want 120 -> capped 64
	if n := z.Next(1000, 5); n != 64 {
		t.Fatalf("max clamp: got %d", n)
	}
	if n := z.Next(20, 5); n != 4 { // 20 left, 5 workers -> 4 each
		t.Fatalf("tail balancing: got %d want 4", n)
	}
	if n := z.Next(3, 5); n != 1 {
		t.Fatalf("tail with min 1: got %d want 1", n)
	}
}

func TestSizerFixed(t *testing.T) {
	z := &Sizer{Fixed: 7}
	z.Observe(7, time.Hour)
	if n := z.Next(100, 5); n != 7 {
		t.Fatalf("fixed: got %d", n)
	}
	if n := z.Next(3, 5); n != 3 {
		t.Fatalf("fixed remainder: got %d", n)
	}
}
