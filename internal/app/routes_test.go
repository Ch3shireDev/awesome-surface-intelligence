package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Adresy widoków panelu (DEV-14) muszą zwracać SPA, żeby link do /assets/<klucz> albo /scans/<id>
// dał się wysłać i działał po odświeżeniu; nieznane ścieżki i API zostają bez zmian.
func TestSPARoutes(t *testing.T) {
	h := (&App{}).Handler()
	spa := []string{
		"/",
		"/assets",
		"/assets/",
		"/assets/192.0.2.15",
		"/assets/192.0.2.15%2Ftcp%2F80", // klucz portu: "/" zakodowany jako %2F
		"/targets",
		"/scans",
		"/scans/20261121-193230",
		"/account",
		"/admin",
	}
	for _, p := range spa {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: kod %d, oczekiwano 200", p, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: Content-Type %q, oczekiwano text/html", p, ct)
		}
		if body := w.Body.String(); !strings.Contains(body, `id="v-app"`) || !strings.Contains(body, "function applyRoute()") {
			t.Errorf("GET %s: odpowiedź nie wygląda jak panel SPA", p)
		}
		if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
			t.Errorf("GET %s: brak nagłówka CSP", p)
		}
	}

	for _, p := range []string{"/nope", "/assetsx", "/assetsfoo/bar"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: kod %d, oczekiwano 404 (tylko znane widoki zwracają SPA)", p, w.Code)
		}
	}

	// /api/ i /live/ nie mogą być przechwycone przez SPA
	for _, p := range []string{"/api/v1/nie-ma", "/live/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if ct := w.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: SPA przechwyciło żądanie API/proxy", p)
		}
	}
}
