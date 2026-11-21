package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStageCoverage(t *testing.T) {
	d := t.TempDir()
	if _, ran, _ := stageCoverage(filepath.Join(d, "none", "timings.csv")); ran {
		t.Fatal("missing timings.csv must mean: stage did not run")
	}
	ok := filepath.Join(d, "ok", "timings.csv")
	write(t, ok, "chunk,hosts,seconds,sec_per_host,error\nchunk_0001,4,1.0,0.25,\nchunk_0002,4,1.0,0.25,\n")
	if complete, ran, _ := stageCoverage(ok); !ran || !complete {
		t.Fatalf("all chunks without error: complete=%v ran=%v", complete, ran)
	}
	bad := filepath.Join(d, "bad", "timings.csv")
	write(t, bad, "chunk,hosts,seconds,sec_per_host,error\nchunk_0001,4,1.0,0.25,\nchunk_0002,4,9.0,2.25,signal: killed\n")
	if complete, ran, why := stageCoverage(bad); !ran || complete || !strings.Contains(why, "1 chunk") {
		t.Fatalf("a failed chunk must block close_old: complete=%v ran=%v why=%q", complete, ran, why)
	}
	// a stage that ran but found nothing is complete (and may close in DD)
	empty := filepath.Join(d, "empty", "timings.csv")
	write(t, empty, "chunk,hosts,seconds,sec_per_host,error\n")
	if complete, ran, _ := stageCoverage(empty); !ran || !complete {
		t.Fatalf("stage with no chunks: complete=%v ran=%v", complete, ran)
	}
}

func TestConcatJSONL(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "chunk_0002.jsonl"), `{"url":"http://192.0.2.2"}`+"\n\n")
	write(t, filepath.Join(d, "chunk_0001.jsonl"), `{"url":"http://192.0.2.1"}`+"\n"+`{"url":"https://192.0.2.1"}`)
	write(t, filepath.Join(d, "chunk_0001.targets"), "192.0.2.1\n") // not output
	b, n := concatJSONL(d)
	want := `{"url":"http://192.0.2.1"}` + "\n" + `{"url":"https://192.0.2.1"}` + "\n" + `{"url":"http://192.0.2.2"}` + "\n"
	if n != 2 || string(b) != want {
		t.Fatalf("got %d files:\n%s", n, b)
	}
}
