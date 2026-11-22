package siem

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	ev := []Event{{At: time.Now(), Type: "gone", Key: "192.0.2.1/tcp/80"}}
	var got string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	}))
	defer s.Close()
	if err := Send(context.Background(), s.URL, ev); err != nil || !strings.Contains(got, `"type":"gone"`) {
		t.Fatalf("webhook: %v %s", err, got)
	}
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := Send(context.Background(), "udp://"+p.LocalAddr().String(), ev); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	p.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := p.ReadFrom(b)
	if err != nil || !strings.HasPrefix(string(b[:n]), "<134>1 ") {
		t.Fatalf("syslog: %v %s", err, b[:n])
	}
	if err := Send(context.Background(), "http://127.0.0.1:1/hook?token=s3cret", ev); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("token leaked or no error: %v", err)
	}
}
