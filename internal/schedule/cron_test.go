package schedule

import (
	"testing"
	"time"
)

func TestNext(t *testing.T) {
	base := time.Date(2026, 11, 21, 15, 7, 30, 0, time.UTC) // Saturday
	cases := map[string]string{
		"*/15 * * * *":  "2026-11-21 15:15",
		"0 2 * * *":     "2026-11-22 02:00",
		"@hourly":       "2026-11-21 16:00",
		"30 22 * * 1-5": "2026-11-23 22:30", // next weekday evening (Monday)
		"0 0 1 * *":     "2026-12-01 00:00",
		"0 9 * * 0":     "2026-11-22 09:00", // Sunday
		"0 9 * * 7":     "2026-11-22 09:00", // 7 = Sunday too
		"5,35 15 * * *": "2026-11-21 15:35",
	}
	for expr, want := range cases {
		s, err := Parse(expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if got := s.Next(base).Format("2006-01-02 15:04"); got != want {
			t.Errorf("%s: got %s want %s", expr, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "*/0 * * * *", "a * * * *", "5-1 * * * *"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestImpossible(t *testing.T) {
	s, _ := Parse("0 0 31 2 *")
	if !s.Next(time.Now()).IsZero() {
		t.Error("Feb 31 must never match")
	}
}
