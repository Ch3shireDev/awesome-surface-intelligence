// Package dojo is a minimal DefectDojo API v2 client.
package dojo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

type Client struct {
	URL, Token string
	HTTP       *http.Client
}

type Target struct {
	ProductType, Product, Engagement, TestTitle string
	ScanType                                    string // "Generic Findings Import" | "Nmap Scan"
	Tags                                        []string
}

type Result struct {
	Test       int            `json:"test"`
	Engagement int            `json:"engagement_id"`
	Product    int            `json:"product_id"`
	Delta      map[string]int `json:"-"`
	Raw        string         `json:"-"`
}

// Reimport sends a report to /api/v2/reimport-scan/ into a stable test
// (created on first use). With closeOld=true findings missing from the report
// are closed as mitigated - DefectDojo then tracks new/closed/reactivated itself.
func (c *Client) Reimport(filename string, data []byte, t Target, closeOld bool) (Result, error) {
	return c.post("reimport-scan", filename, data, t, map[string]string{
		"close_old_findings": strconv.FormatBool(closeOld),
		"do_not_reactivate":  "false",
	})
}

// Import creates a new test every time (no change tracking).
func (c *Client) Import(filename string, data []byte, t Target) (Result, error) {
	return c.post("import-scan", filename, data, t, map[string]string{"close_old_findings": "false"})
}

func (c *Client) post(endpoint, filename string, data []byte, t Target, extra map[string]string) (Result, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fields := map[string]string{
		"scan_type":           t.ScanType,
		"product_type_name":   t.ProductType,
		"product_name":        t.Product,
		"engagement_name":     t.Engagement,
		"test_title":          t.TestTitle,
		"auto_create_context": "true",
		"scan_date":           time.Now().Format("2006-01-02"),
		"active":              "true",
		"verified":            "false",
		"minimum_severity":    "Info",
	}
	for k, v := range extra {
		fields[k] = v
	}
	for k, v := range fields {
		w.WriteField(k, v)
	}
	for _, tag := range t.Tags {
		w.WriteField("tags", tag)
	}
	fw, _ := w.CreateFormFile("file", filename)
	fw.Write(data)
	w.Close()

	req, _ := http.NewRequest("POST", c.URL+"/api/v2/"+endpoint+"/", &body)
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Minute}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	r := Result{Raw: string(rb)}
	if resp.StatusCode >= 300 {
		return r, fmt.Errorf("%s: HTTP %d: %.300s", endpoint, resp.StatusCode, rb)
	}
	json.Unmarshal(rb, &r)
	r.Delta = parseDelta(rb)
	return r, nil
}

func parseDelta(b []byte) map[string]int {
	var v struct {
		Statistics struct {
			// delta.{created,closed,reactivated,untouched}.{info,low,...,total}.total
			Delta map[string]map[string]struct {
				Total int `json:"total"`
			} `json:"delta"`
			After struct {
				Total struct {
					Total int `json:"total"`
				} `json:"total"`
			} `json:"after"`
		} `json:"statistics"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	out := map[string]int{}
	for k, bySev := range v.Statistics.Delta {
		out[k] = bySev["total"].Total
	}
	out["total_after"] = v.Statistics.After.Total.Total
	return out
}

// Login exchanges username/password for an API token (/api/v2/api-token-auth/).
func (c *Client) Login(user, pass string) (string, error) {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Post(c.URL+"/api/v2/api-token-auth/", "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, rb)
	}
	var r struct{ Token string }
	if err := json.Unmarshal(rb, &r); err != nil || r.Token == "" {
		return "", fmt.Errorf("no token in response: %.200s", rb)
	}
	return r.Token, nil
}
