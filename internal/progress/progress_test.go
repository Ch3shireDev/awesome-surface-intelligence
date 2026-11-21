package progress

import (
	"testing"
	"time"
)

// A running chunk whose tool reports nothing gets a time-based estimate (capped at 90%),
// and the phase partial / overall percent follow it.
func TestSnapshotEstimatesSilentChunks(t *testing.T) {
	tr := New("r", 2, "")
	tr.Update(func(s *State) {
		s.Status = "running"
		p := tr.Phase("discovery")
		p.State, p.Hosts = "running", 10
		s.Chunks = append(s.Chunks,
			&Chunk{ID: 0, Phase: "discovery", Hosts: 4, State: "running", Started: time.Now().Add(-5 * time.Second), Expected: 10},
			&Chunk{ID: 1, Phase: "discovery", Hosts: 6, State: "running", Started: time.Now().Add(-time.Hour), Expected: 10},
		)
	})
	s := tr.Snapshot()
	c0, c1 := s.Chunks[0], s.Chunks[1]
	if !c0.Estimated || c0.Percent < 45 || c0.Percent > 60 {
		t.Fatalf("chunk 0: want ~50%% estimated, got %.1f%% estimated=%v", c0.Percent, c0.Estimated)
	}
	if c1.Percent != 90 {
		t.Fatalf("chunk 1: estimate must cap at 90%%, got %.1f", c1.Percent)
	}
	want := 4*c0.Percent/100 + 6*0.9
	if d := s.Phases[0].Partial - want; d > 0.01 || d < -0.01 {
		t.Fatalf("phase partial %.2f, want %.2f", s.Phases[0].Partial, want)
	}
	if s.Percent <= 0 {
		t.Fatalf("overall percent must move, got %.2f", s.Percent)
	}
	// tool-reported progress above the estimate wins and is not marked as estimated
	tr.Update(func(s *State) { s.Chunks[0].Percent = 80 })
	if c := tr.Snapshot().Chunks[0]; c.Estimated || c.Percent != 80 {
		t.Fatalf("reported 80%% must win: %.1f estimated=%v", c.Percent, c.Estimated)
	}
}
