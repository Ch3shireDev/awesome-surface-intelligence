package main

import (
	"encoding/json"
	"strings"
	"time"

	"asi/internal/findings"
	"asi/internal/obs"
)

// rankServices sets Interest / Reason / Score of each service with findings.Rank - the same
// 0-100 score the panel and dashboard show - from this run's HTTP and signature observations
// and the analyst's verdicts (LAB-T12). Before, services.json and the DefectDojo Generic report
// used the nmap-only score, so e.g. WordPress 4.7 was "low" in the run files but "high" in the
// panel. Not included here (needs the asset history in the database): +10 "new exposure" and
// +5 "flapping"; those are added by the panel only.
func rankServices(svcs []findings.Service, all []obs.Observation, verdicts map[string]findings.Verdict, now time.Time) {
	httpBy := map[string]*findings.WebInfo{}
	sigsBy := map[string][]obs.SignatureData{}
	for _, o := range all {
		switch o.Kind {
		case obs.KindHTTP:
			var w findings.WebInfo
			if json.Unmarshal(o.Data, &w) == nil {
				httpBy[o.AssetKey] = &w
			}
		case obs.KindSignature:
			var d obs.SignatureData
			if o.Decode(&d) == nil {
				sigsBy[o.AssetKey] = append(sigsBy[o.AssetKey], d)
			}
		}
	}
	for i := range svcs {
		key := obs.PortKey(svcs[i].IP, svcs[i].Proto, svcs[i].Port)
		r := findings.Rank(findings.ScoreInput{Service: svcs[i], HTTP: httpBy[key], Sigs: sigsBy[key],
			Verdict: verdicts[key]}, now)
		svcs[i].Interest, svcs[i].Score = r.Level, r.Score
		svcs[i].Reason = strings.Join(r.Reasons, " · ")
	}
}
