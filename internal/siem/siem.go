// Package siem sends ASI events to a SIEM: an HTTP(S) webhook (JSON) or syslog (RFC 5424, UDP/TCP).
// The destination comes only from ASI_SIEM_URL on the server, never from a request.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Event carries identifiers only: no notes, headers, cookies or other sealed fields.
type Event struct {
	At       time.Time `json:"at"`
	Type     string    `json:"type"`
	Key      string    `json:"key"`
	RunID    string    `json:"run_id,omitempty"`
	State    string    `json:"state,omitempty"`
	Service  string    `json:"service,omitempty"`
	Severity string    `json:"severity,omitempty"`
}

var ErrNotConfigured = errors.New("SIEM nie jest skonfigurowany (ASI_SIEM_URL)")

func URL() string { return os.Getenv("ASI_SIEM_URL") }

// Send delivers the events. Errors never contain the URL (it may hold a token).
func Send(ctx context.Context, dest string, evs []Event) error {
	if dest == "" {
		return ErrNotConfigured
	}
	if len(evs) == 0 {
		return nil
	}
	u, err := url.Parse(dest)
	if err != nil || u.Host == "" {
		return errors.New("ASI_SIEM_URL: zły adres")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	switch u.Scheme {
	case "http", "https":
		b, err := json.Marshal(map[string]any{"source": "asi", "events": evs})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, bytes.NewReader(b))
		if err != nil {
			return errors.New("ASI_SIEM_URL: zły adres")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.New("SIEM webhook: brak odpowiedzi")
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("SIEM webhook: HTTP %d", resp.StatusCode)
		}
		return nil
	case "udp", "tcp":
		var d net.Dialer
		conn, err := d.DialContext(ctx, u.Scheme, u.Host)
		if err != nil {
			return errors.New("SIEM syslog: brak połączenia")
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		for _, e := range evs {
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			// <134> = local0.info
			line := fmt.Sprintf("<134>1 %s - asi - - - %s", e.At.UTC().Format(time.RFC3339), b)
			if u.Scheme == "tcp" {
				line += "\n"
			}
			if _, err := conn.Write([]byte(line)); err != nil {
				return errors.New("SIEM syslog: błąd wysyłki")
			}
		}
		return nil
	}
	return errors.New("ASI_SIEM_URL: obsługiwane http(s)://, udp://, tcp://")
}
