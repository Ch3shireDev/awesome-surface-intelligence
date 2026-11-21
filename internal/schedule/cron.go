// Package schedule: a small 5-field cron parser (minute hour day-of-month month
// day-of-week) for scan schedules. Supports *, lists (1,5), ranges (1-5),
// steps (*/15, 0-30/10) and @hourly/@daily/@weekly. Day-of-week 0 or 7 = Sunday.
// When both day fields are restricted, a day matches if either does (classic cron).
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Spec struct {
	Expr                     string
	min, hour, dom, mon, dow uint64 // bit sets
	domStar, dowStar         bool
}

var aliases = map[string]string{
	"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
	"@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *",
}

func Parse(expr string) (Spec, error) {
	e := strings.TrimSpace(expr)
	if a, ok := aliases[e]; ok {
		e = a
	}
	f := strings.Fields(e)
	if len(f) != 5 {
		return Spec{}, fmt.Errorf("cron: oczekiwano 5 pól (min godz dzień mies dzień_tyg), jest %d", len(f))
	}
	s := Spec{Expr: expr}
	var err error
	if s.min, err = field(f[0], 0, 59); err != nil {
		return s, fmt.Errorf("cron minuta: %w", err)
	}
	if s.hour, err = field(f[1], 0, 23); err != nil {
		return s, fmt.Errorf("cron godzina: %w", err)
	}
	if s.dom, err = field(f[2], 1, 31); err != nil {
		return s, fmt.Errorf("cron dzień miesiąca: %w", err)
	}
	if s.mon, err = field(f[3], 1, 12); err != nil {
		return s, fmt.Errorf("cron miesiąc: %w", err)
	}
	if s.dow, err = field(f[4], 0, 7); err != nil {
		return s, fmt.Errorf("cron dzień tygodnia: %w", err)
	}
	if s.dow&(1<<7) != 0 {
		s.dow |= 1
	}
	s.domStar, s.dowStar = f[2] == "*", f[4] == "*"
	return s, nil
}

func field(f string, lo, hi int) (uint64, error) {
	var set uint64
	for _, part := range strings.Split(f, ",") {
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 {
				return 0, fmt.Errorf("zły krok %q", part)
			}
			step, part = n, part[:i]
		}
		a, b := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			x := strings.SplitN(part, "-", 2)
			var e1, e2 error
			a, e1 = strconv.Atoi(x[0])
			b, e2 = strconv.Atoi(x[1])
			if e1 != nil || e2 != nil {
				return 0, fmt.Errorf("zły zakres %q", part)
			}
		default:
			n, err := strconv.Atoi(part)
			if err != nil {
				return 0, fmt.Errorf("zła wartość %q", part)
			}
			a, b = n, n
			if step > 1 {
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("%q poza zakresem %d-%d", part, lo, hi)
		}
		for v := a; v <= b; v += step {
			set |= 1 << v
		}
	}
	return set, nil
}

// Next returns the first matching minute strictly after t (in t's location).
// Zero time if nothing matches within 5 years (e.g. "0 0 31 2 *").
func (s Spec) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	end := t.AddDate(5, 0, 0)
	for t.Before(end) {
		switch {
		case s.mon&(1<<int(t.Month())) == 0: // skip the month
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
		case !s.dayMatch(t): // skip the day
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
		case s.hour&(1<<t.Hour()) == 0: // skip the hour
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
		case s.min&(1<<t.Minute()) == 0:
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return time.Time{}
}

func (s Spec) dayMatch(t time.Time) bool {
	dom := s.dom&(1<<t.Day()) != 0
	dow := s.dow&(1<<int(t.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dow
	case s.dowStar:
		return dom
	default:
		return dom || dow
	}
}
