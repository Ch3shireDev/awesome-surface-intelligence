package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"asi/internal/dojo"
)

// Raw tool output sent to DefectDojo's NATIVE parsers (SEC-7), each into its own
// stable test, so DefectDojo tracks new/closed between runs per tool:
//
//	results/<run>/http/*.jsonl        httpx -json   -> "httpx Scan"  test asi-httpx
//	results/<run>/signatures/*.jsonl  nuclei -jsonl -> "Nuclei Scan" test asi-nuclei
//
// DefectDojo hashes httpx findings by title (URL + HTTP status) + endpoint and nuclei
// findings by template name + cwe + severity + component, and neither parser sets
// `service`, so a reimport with close_old_findings closes exactly what disappeared.
var nativeStages = []struct{ dir, scanType, test, file string }{
	{"http", "httpx Scan", "asi-httpx", "httpx.jsonl"},
	{"signatures", "Nuclei Scan", "asi-nuclei", "nuclei.jsonl"},
}

// exportNative reimports the http and signatures stages of runDir. allowClose is false
// for partial runs. Even then close_old is used only when the stage really ran
// (timings.csv exists) and every chunk finished without error: a stage that was skipped
// (no httpx), failed or cut short must never close findings in DefectDojo.
func exportNative(dd *dojo.Client, t dojo.Target, runDir string, allowClose bool, logf func(string, ...any)) {
	if dd == nil {
		return
	}
	for _, s := range nativeStages {
		sd := filepath.Join(runDir, s.dir)
		complete, ran, why := stageCoverage(filepath.Join(sd, "timings.csv"))
		if !ran {
			continue // stage did not run in this run: nothing to say about it
		}
		data, files := concatJSONL(sd)
		closeOld := allowClose && complete
		if len(data) == 0 && !closeOld {
			logf("dojo: %s: no results and close_old not allowed (%s) - nothing to send", s.test, why)
			continue
		}
		tt := t
		tt.ScanType, tt.TestTitle = s.scanType, s.test
		tt.Tags = append(append([]string{}, t.Tags...), s.test)
		res, err := dd.Reimport(s.file, data, tt, closeOld)
		if err != nil {
			logf("dojo: %s: %v", s.test, err)
			continue
		}
		note := ""
		if !closeOld {
			note = " (" + why + ")"
		}
		logf("dojo: %s %d lines from %d files (close_old=%v%s) -> %s/test/%d, delta %v",
			s.test, bytes.Count(data, []byte("\n")), files, closeOld, note, dd.URL, res.Test, res.Delta)
	}
}

// stageCoverage reads a stage's timings.csv (written by scanner.RunPhase):
// ran = the file exists, complete = every chunk finished with an empty error.
func stageCoverage(path string) (complete, ran bool, why string) {
	f, err := os.Open(path)
	if err != nil {
		return false, false, "stage did not run"
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return false, true, "unreadable timings.csv"
	}
	bad := 0
	for i, r := range rows {
		if i == 0 || len(r) < 5 {
			continue
		}
		if r[4] != "" {
			bad++
		}
	}
	if bad > 0 {
		return false, true, fmt.Sprintf("%d chunk(s) with errors", bad)
	}
	return true, true, "partial run"
}

// concatJSONL joins the stage's chunk outputs into one JSON Lines report.
func concatJSONL(dir string) ([]byte, int) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	sort.Strings(paths)
	var out bytes.Buffer
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if line = bytes.TrimSpace(line); len(line) > 0 {
				out.Write(line)
				out.WriteByte('\n')
			}
		}
	}
	return out.Bytes(), len(paths)
}
