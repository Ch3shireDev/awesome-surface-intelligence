package app

import (
	"regexp"
	"testing"
)

// getElementById returns the first match: a duplicated id silently hijacked the "Dodaj cele"
// button with the handler of "Utwórz token".
func TestUIUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`\sid="([a-z0-9-]+)"`).FindAllStringSubmatch(string(uiHTML), -1) {
		if m[1] == "dr-x" { // drawer templates: only one is rendered at a time
			continue
		}
		if seen[m[1]] {
			t.Errorf("duplicate id %q in ui.html", m[1])
		}
		seen[m[1]] = true
	}
}
