package app

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// Decision 24: the live panel of a scan sits behind the main panel on a unix socket, no extra TCP port.
func TestLiveProxyUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "live.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "live "+r.URL.Path)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	rec := httptest.NewRecorder()
	liveProxy("unix:"+sock).ServeHTTP(rec, httptest.NewRequest("GET", "/api/live", nil))
	if rec.Code != 200 || rec.Body.String() != "live /api/live" {
		t.Fatalf("unix: %d %q", rec.Code, rec.Body.String())
	}

	tcp := httptest.NewServer(srv.Handler) // older .env: ASI_LIVE_ADDR=127.0.0.1:8091 still works
	defer tcp.Close()
	rec = httptest.NewRecorder()
	liveProxy(tcp.Listener.Addr().String()).ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 200 || rec.Body.String() != "live /x" {
		t.Fatalf("tcp: %d %q", rec.Code, rec.Body.String())
	}
}
