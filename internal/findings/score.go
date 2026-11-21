package findings

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"asi/internal/obs"
)

// ScoreInput: everything known about one open port (DEV-7, PDF: "ocena ciekawości").
type ScoreInput struct {
	Service  Service
	HTTP     *WebInfo
	Sigs     []obs.SignatureData
	State    string // new | active | missing | gone
	Flapping bool
	Verdict  Verdict
}

// WebInfo: the http observation fields scoring uses (httpx adapter adds TLS flags).
type WebInfo struct {
	obs.HTTPData
	TLSSelfSigned bool `json:"tls_self_signed,omitempty"`
	TLSMismatched bool `json:"tls_mismatched,omitempty"`
}

type Scored struct {
	Score     int      `json:"score"` // 0-100
	Level     string   `json:"level"` // high | medium | low
	Reasons   []string `json:"reasons"`
	Dismissed bool     `json:"dismissed,omitempty"` // analyst: false positive / accepted
}

var sevScore = map[string]int{"critical": 95, "high": 85, "medium": 60, "low": 35}

// Rank combines port exposure, custom signatures, HTTP/TLS signals, novelty and
// stability into one 0-100 score with human-readable reasons. The analyst's
// verdict always wins.
func Rank(in ScoreInput, now time.Time) Scored {
	r := Scored{}
	lvl, why := score(in.Service)
	base := map[string]int{"high": 80, "medium": 50, "low": 10}[lvl]
	if why != "" {
		r.Reasons = append(r.Reasons, why)
	}
	// signatures: the strongest sets the floor, each further relevant hit adds a little
	sigs := append([]obs.SignatureData(nil), in.Sigs...)
	sort.Slice(sigs, func(i, j int) bool { return sevScore[sigs[i].Severity] > sevScore[sigs[j].Severity] })
	extra := 0
	for i, sg := range sigs {
		v := sevScore[sg.Severity]
		if v == 0 {
			continue
		}
		label := sg.Name
		if len(sg.Extract) > 0 {
			label += " (" + strings.Join(sg.Extract, ", ") + ")"
		}
		r.Reasons = append(r.Reasons, label)
		if i == 0 && v > base {
			base = v
		} else if extra < 15 {
			extra += 5
		}
	}
	s := base + extra
	if h := in.HTTP; h != nil {
		public := isPublic(in.Service.IP)
		if public && (h.TLSSelfSigned || h.TLSMismatched) {
			s += 10
			r.Reasons = append(r.Reasons, "certyfikat self-signed albo niezgodny z nazwą na publicznym IP")
		}
		if t, err := time.Parse(time.RFC3339, h.TLSNotAfter); err == nil && t.Before(now) {
			s += 10
			r.Reasons = append(r.Reasons, "certyfikat TLS wygasł "+t.Format("2006-01-02"))
		}
		if h.Status == 401 || h.Status == 403 {
			s += 5
			r.Reasons = append(r.Reasons, fmt.Sprintf("HTTP %d: zasób chroniony (panel?)", h.Status))
		}
	}
	if in.State == "new" {
		s += 10
		r.Reasons = append(r.Reasons, "nowa ekspozycja w ostatnim przebiegu")
	}
	if in.Flapping {
		s += 5
		r.Reasons = append(r.Reasons, "usługa niestabilna (flapping)")
	}
	if s > 100 {
		s = 100
	}
	r.Score = s
	switch {
	case s >= 75:
		r.Level = "high"
	case s >= 45:
		r.Level = "medium"
	default:
		r.Level = "low"
	}
	if v := in.Verdict; v.Interest != "" {
		r.Level = v.Interest
		r.Score = map[string]int{"high": max(s, 75), "medium": min(max(s, 45), 74), "low": min(s, 44)}[v.Interest]
		reason := "ocena analityka"
		if v.Reason != "" {
			reason += ": " + v.Reason
		}
		r.Reasons = append([]string{reason}, r.Reasons...)
	}
	if in.Verdict.Dismissed() {
		r.Dismissed = true
		label := map[string]string{"false_positive": "fałszywy alarm", "accepted": "zaakceptowane ryzyko"}[in.Verdict.Status]
		r.Reasons = append([]string{"analityk: " + label}, r.Reasons...)
	}
	return r
}
