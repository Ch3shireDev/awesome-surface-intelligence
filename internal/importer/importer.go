// Package importer loads results of scans made elsewhere (DEV-6, PDF: "import
// wyników skanów w formie JSON lub CSV") and turns them into observations, so an
// imported file becomes a normal run: stored, reconciled (new/missing/changed...),
// shown in the GUI and exportable.
//
// Supported (auto-detected):
//   - nmap XML (-oX)                       coverage: exact (hosts + <scaninfo> ports)
//   - ASI observations.json / services.json
//   - JSON array or {"results"|"services"|"findings": [...]} of rows with ip/port/... keys
//   - CSV with a header (ip|host|address, port, proto|protocol, service|name, product, version, state)
//     including ASI's own assets export (key, kind, ip, port, service...)
//   - httpx JSONL, nuclei JSONL
package importer

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"asi/internal/nmapxml"
	"asi/internal/obs"
	"asi/internal/scanner/httpx"
	nmapad "asi/internal/scanner/nmap"
	"asi/internal/scanner/nuclei"
)

// Result of parsing one file.
type Result struct {
	Format       string            `json:"format"`
	Observations []obs.Observation `json:"-"`
	Hosts        []string          `json:"hosts"` // IPs the file says something about
	Ports        string            `json:"ports"` // scanned port set ("" = unknown)
	Exact        bool              `json:"exact"` // coverage is known exactly (nmap XML)
	Rows         int               `json:"rows"`  // input records read
	Skipped      []string          `json:"skipped,omitempty"`
}

const maxSkipped = 20

func (r *Result) skip(format string, a ...any) {
	if len(r.Skipped) < maxSkipped {
		r.Skipped = append(r.Skipped, fmt.Sprintf(format, a...))
	}
}

// Parse auto-detects the format from the file name and content.
func Parse(name string, data []byte) (Result, error) {
	ext := strings.ToLower(filepath.Ext(name))
	trim := bytes.TrimSpace(data)
	switch {
	case ext == ".xml" || bytes.HasPrefix(trim, []byte("<?xml")) || bytes.HasPrefix(trim, []byte("<nmaprun")):
		return parseNmap(data)
	case ext == ".csv":
		return parseCSV(data)
	case ext == ".jsonl" || ext == ".ndjson" || (len(trim) > 0 && trim[0] == '{' && bytes.Contains(trim, []byte("}\n{"))):
		return parseJSONL(data)
	case len(trim) > 0 && (trim[0] == '[' || trim[0] == '{'):
		return parseJSON(trim)
	}
	return Result{}, fmt.Errorf("nieznany format (obsługiwane: nmap XML, JSON, JSONL httpx/nuclei, CSV z nagłówkiem)")
}

func parseNmap(data []byte) (Result, error) {
	run, err := nmapxml.Parse(bytes.NewReader(data))
	if err != nil {
		return Result{}, err
	}
	r := Result{Format: "nmap-xml", Observations: nmapad.FromHosts(run.Hosts), Ports: run.Ports("tcp"), Exact: true}
	for _, h := range run.Hosts {
		if ip := h.IP(); ip != "" {
			r.Hosts = append(r.Hosts, ip) // also hosts that were down: they WERE scanned
		}
	}
	r.Rows = len(run.Hosts)
	if r.Rows == 0 {
		return r, fmt.Errorf("w pliku nmap nie ma żadnych hostów")
	}
	return finish(r), nil
}

func parseJSONL(data []byte) (Result, error) {
	first := bytes.SplitN(bytes.TrimSpace(data), []byte("\n"), 2)[0]
	var probe map[string]any
	json.Unmarshal(first, &probe)
	var (
		os  []obs.Observation
		err error
		f   string
	)
	switch {
	case probe["template-id"] != nil:
		f = "nuclei-jsonl"
		os, err = (&nuclei.Adapter{}).Parse(bytes.NewReader(data))
	case probe["status_code"] != nil || probe["webserver"] != nil:
		f = "httpx-jsonl"
		os, err = (&httpx.Adapter{}).Parse(bytes.NewReader(data))
	default: // JSONL of generic rows
		var rows []map[string]any
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 1<<20), 32<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				rows = append(rows, m)
			}
		}
		return fromRows("jsonl", rows)
	}
	if err != nil {
		return Result{}, err
	}
	r := Result{Format: f, Observations: os, Rows: bytes.Count(data, []byte("\n"))}
	// http/signature observations imply the host is up and the port open
	seenHost, seenPort := map[string]bool{}, map[string]bool{}
	for _, o := range os {
		ip, _, port := obs.SplitKey(o.AssetKey)
		if !seenHost[ip] {
			seenHost[ip] = true
			r.Observations = append(r.Observations, obs.New(obs.KindHost, ip, "import", obs.HostData{Up: true, Reason: f}, 80, "up"))
		}
		if port > 0 && !seenPort[o.AssetKey] {
			seenPort[o.AssetKey] = true
			r.Observations = append(r.Observations, obs.New(obs.KindPort, o.AssetKey, "import", obs.PortData{State: "open", Reason: f}, 80, "open"))
		}
	}
	return finish(r), nil
}

func parseJSON(data []byte) (Result, error) {
	// ASI observations.json: [{"kind":..., "asset_key":..., "data":...}]
	var os []obs.Observation
	if json.Unmarshal(data, &os) == nil && len(os) > 0 && os[0].Kind != "" && os[0].AssetKey != "" {
		r := Result{Format: "asi-observations", Rows: len(os)}
		for _, o := range os {
			if _, err := netip.ParseAddr(ipOf(o.AssetKey)); err != nil {
				r.skip("niepoprawny klucz %q", o.AssetKey)
				continue
			}
			if o.FPHash == "" {
				o.FPHash = obs.FP(string(o.Data))
			}
			if o.Confidence == 0 {
				o.Confidence = 80
			}
			if o.Tool == "" {
				o.Tool = "import"
			}
			r.Observations = append(r.Observations, o)
		}
		return finish(r), nil
	}
	var rows []map[string]any
	if json.Unmarshal(data, &rows) != nil {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(data, &wrap); err != nil {
			return Result{}, fmt.Errorf("JSON: %w", err)
		}
		for _, k := range []string{"results", "services", "findings", "hosts", "assets", "data"} {
			if raw, ok := wrap[k]; ok && json.Unmarshal(raw, &rows) == nil {
				break
			}
		}
	}
	if len(rows) == 0 {
		return Result{}, fmt.Errorf("JSON: nie znaleziono listy wyników (tablica albo klucz results/services/findings/hosts)")
	}
	return fromRows("json", rows)
}

func parseCSV(data []byte) (Result, error) {
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.Comment = '#'
	cr.TrimLeadingSpace = true
	recs, err := cr.ReadAll()
	if err != nil {
		return Result{}, fmt.Errorf("CSV: %w", err)
	}
	if len(recs) < 2 {
		return Result{}, fmt.Errorf("CSV: potrzebny nagłówek i co najmniej jeden wiersz")
	}
	head := recs[0]
	var rows []map[string]any
	for _, rec := range recs[1:] {
		m := map[string]any{}
		for i, h := range head {
			if i < len(rec) {
				m[strings.ToLower(strings.TrimSpace(h))] = strings.TrimSpace(rec[i])
			}
		}
		rows = append(rows, m)
	}
	return fromRows("csv", rows)
}

// fromRows: generic table rows -> host/port/service observations.
func fromRows(format string, rows []map[string]any) (Result, error) {
	r := Result{Format: format, Rows: len(rows)}
	hostSeen := map[string]bool{}
	for i, m := range rows {
		get := func(keys ...string) string {
			for _, k := range keys {
				if v, ok := m[k]; ok && v != nil {
					if s := strings.TrimSpace(fmt.Sprint(v)); s != "" && s != "<nil>" {
						return s
					}
				}
			}
			return ""
		}
		ip := get("ip", "host", "address", "addr", "ip_address", "host_ip")
		key := get("key", "asset_key")
		if ip == "" && key != "" {
			ip = ipOf(key)
		}
		if a, err := netip.ParseAddr(ip); err != nil {
			r.skip("wiersz %d: brak poprawnego IP (%q)", i+2, ip)
			continue
		} else {
			ip = a.String()
		}
		state := strings.ToLower(get("state", "status"))
		if state == "down" || state == "gone" || state == "closed" || state == "missing" {
			continue // explicit negatives are not observations
		}
		if !hostSeen[ip] {
			hostSeen[ip] = true
			r.Observations = append(r.Observations, obs.New(obs.KindHost, ip, "import", obs.HostData{Up: true, Reason: "import"}, 80, "up"))
		}
		portS := get("port", "portid")
		if portS == "" && key != "" {
			_, _, p := obs.SplitKey(key)
			portS = strconv.Itoa(p)
		}
		port, _ := strconv.Atoi(portS)
		if port <= 0 || port > 65535 || get("kind") == "host" {
			continue // host-only row
		}
		proto := strings.ToLower(get("proto", "protocol", "transport"))
		if proto == "" {
			proto = "tcp"
		}
		k := obs.PortKey(ip, proto, port)
		r.Observations = append(r.Observations, obs.New(obs.KindPort, k, "import", obs.PortData{State: "open", Reason: "import"}, 80, "open"))
		name, product, version := get("service", "name", "service_name"), get("product"), get("version")
		if product == "" && strings.Contains(name, " ") { // ASI export: "ssh OpenSSH 10.6"
			parts := strings.Fields(name)
			name = parts[0]
			if len(parts) > 2 {
				product, version = strings.Join(parts[1:len(parts)-1], " "), parts[len(parts)-1]
			} else if len(parts) == 2 {
				product = parts[1]
			}
		}
		if name != "" || product != "" {
			sd := obs.ServiceData{Name: name, Product: product, Version: version, Method: "import"}
			r.Observations = append(r.Observations, obs.New(obs.KindService, k, "import", sd, 70, sd.Name, sd.Product, sd.Version))
		}
	}
	if len(r.Observations) == 0 {
		return r, fmt.Errorf("brak poprawnych wierszy (pominięte: %s)", strings.Join(r.Skipped, "; "))
	}
	return finish(r), nil
}

// finish fills Hosts (if not set by the format) and, for non-exact formats, Ports
// = union of the ports present (conservative coverage: an import never makes
// unlisted ports of unlisted hosts "missing").
func finish(r Result) Result {
	hosts := map[string]bool{}
	for _, h := range r.Hosts {
		hosts[h] = true
	}
	ports := map[int]bool{}
	for _, o := range r.Observations {
		ip, _, p := obs.SplitKey(o.AssetKey)
		hosts[ip] = true
		if p > 0 {
			ports[p] = true
		}
	}
	r.Hosts = r.Hosts[:0]
	for h := range hosts {
		r.Hosts = append(r.Hosts, h)
	}
	sort.Strings(r.Hosts)
	if !r.Exact {
		var ps []int
		for p := range ports {
			ps = append(ps, p)
		}
		sort.Ints(ps)
		var b strings.Builder
		for i, p := range ps {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Itoa(p))
		}
		r.Ports = b.String()
		if r.Ports == "" {
			r.Ports = "0" // host-only data: no port may go missing
		}
	}
	obs.Sort(r.Observations)
	return r
}

func ipOf(key string) string { ip, _, _ := obs.SplitKey(key); return ip }

// ReadAll with a size cap.
func ReadAll(rd io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(rd, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("plik większy niż %d MB", max>>20)
	}
	return b, nil
}
