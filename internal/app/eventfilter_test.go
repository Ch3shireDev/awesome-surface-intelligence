package app

import (
	"reflect"
	"testing"
)

// parseEventTypes: tylko typy z CHECK w asset_events, puste/nieznane pomijane.
// Dzięki temu ?events=new,bzdura nie wywraca zapytania i nie poszerza filtra.
func TestParseEventTypes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"new,reappeared", []string{"new", "reappeared"}},
		{" new , gone ", []string{"new", "gone"}},
		{"new,bzdura,changed", []string{"new", "changed"}},
		{"", []string{}},
		{"bzdura", []string{}},
	}
	for _, c := range cases {
		if got := parseEventTypes(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseEventTypes(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
