// Package obs is the contract between scanners and the core (VISION 4.1-4.3).
//
// Every scanner adapter (nmap, httpx, nuclei, ...) turns its raw output into
// []Observation. The core never looks at tool-specific formats: it stores
// observations, reconciles them into assets and exports them.
//
// Writing a new adapter = implement Scanner (and optionally ProgressParser),
// then register it in the stage pipeline. See docs/guide/adapters.md.
package obs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Stage of the scanning funnel. Each stage only gets what the previous one found.
type Stage string

const (
	StageDiscovery  Stage = "discovery"  // is the host alive?
	StagePorts      Stage = "ports"      // which ports are open? (optional, e.g. naabu)
	StageServices   Stage = "services"   // what runs on the port? (nmap -sV)
	StageHTTP       Stage = "http"       // HTTP/TLS fingerprint (httpx)
	StageSignatures Stage = "signatures" // custom detections (nuclei templates)
)

// Kind of an observation.
type Kind string

const (
	KindHost      Kind = "host"      // AssetKey "10.0.0.5"; Data: HostData
	KindPort      Kind = "port"      // AssetKey "10.0.0.5/tcp/443"; Data: PortData
	KindService   Kind = "service"   // AssetKey "10.0.0.5/tcp/443"; Data: ServiceData
	KindHTTP      Kind = "http"      // AssetKey "10.0.0.5/tcp/443"; Data: HTTPData
	KindSignature Kind = "signature" // AssetKey "10.0.0.5/tcp/443"; Data: SignatureData
	KindDNS       Kind = "dns"       // AssetKey "10.0.0.5"; Data: {"name": "...", "type": "A"}
)

// Observation is one normalized fact from one run.
type Observation struct {
	Kind       Kind            `json:"kind"`
	AssetKey   string          `json:"asset_key"`
	Data       json.RawMessage `json:"data"`
	FPHash     string          `json:"fp_hash"`    // fingerprint of the stable part of Data
	Confidence int             `json:"confidence"` // 0-100
	Tool       string          `json:"tool"`
	ObservedAt time.Time       `json:"observed_at"`
}

// ---- asset keys ----

func HostKey(ip string) string { return ip }

func PortKey(ip, proto string, port int) string {
	return fmt.Sprintf("%s/%s/%d", ip, strings.ToLower(proto), port)
}

// SplitKey returns ip, proto, port ("" and 0 for host keys).
func SplitKey(key string) (ip, proto string, port int) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return key, "", 0
	}
	fmt.Sscanf(parts[2], "%d", &port)
	return parts[0], parts[1], port
}

// ---- typed payloads (Data). Adapters may add fields; the core relies only on these. ----

type HostData struct {
	Up        bool     `json:"up"`
	Reason    string   `json:"reason,omitempty"` // e.g. syn-ack, echo-reply
	Hostnames []string `json:"hostnames,omitempty"`
}

type PortData struct {
	State  string `json:"state"` // open
	Reason string `json:"reason,omitempty"`
}

type ServiceData struct {
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extrainfo,omitempty"`
	TLS       bool   `json:"tls,omitempty"`
	Method    string `json:"method,omitempty"` // probed | table (nmap guessed from port number)
}

type HTTPData struct {
	URL         string              `json:"url"`
	Status      int                 `json:"status"`
	Title       string              `json:"title,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	Cookies     []string            `json:"cookies,omitempty"` // cookie names
	Redirects   []string            `json:"redirects,omitempty"`
	TLSSubject  string              `json:"tls_subject,omitempty"`
	TLSIssuer   string              `json:"tls_issuer,omitempty"`
	TLSNotAfter string              `json:"tls_not_after,omitempty"`
	TLSSANs     []string            `json:"tls_sans,omitempty"`
	Tech        []string            `json:"tech,omitempty"`
	FaviconMMH3    string `json:"favicon_mmh3,omitempty"`
	ContentHash    string `json:"content_hash,omitempty"`
	WebServer      string `json:"webserver,omitempty"`
	ResponseTimeMs int    `json:"response_time_ms,omitempty"` // metric only, excluded from fp_hash
}

type SignatureData struct {
	ID       string   `json:"id"` // template / signature id
	Name     string   `json:"name"`
	Severity string   `json:"severity,omitempty"` // info | low | medium | high
	Tags     []string `json:"tags,omitempty"`
	Matched  string   `json:"matched,omitempty"` // URL or matcher detail
	Extract  []string `json:"extract,omitempty"` // e.g. extracted version
}

// New builds an observation; fpFields are the values that define "the same thing"
// across runs (a change in any of them = event "changed").
func New(kind Kind, key, tool string, data any, confidence int, fpFields ...string) Observation {
	b, _ := json.Marshal(data)
	return Observation{Kind: kind, AssetKey: key, Data: b, FPHash: FP(fpFields...),
		Confidence: confidence, Tool: tool, ObservedAt: time.Now().UTC()}
}

// FP is a short stable hash of the given fields.
func FP(fields ...string) string {
	h := sha256.Sum256([]byte(strings.Join(fields, "\x1f")))
	return hex.EncodeToString(h[:8])
}

// Decode unmarshals Data into v.
func (o Observation) Decode(v any) error { return json.Unmarshal(o.Data, v) }

func Sort(os []Observation) {
	sort.SliceStable(os, func(i, j int) bool {
		if os[i].AssetKey != os[j].AssetKey {
			return os[i].AssetKey < os[j].AssetKey
		}
		return os[i].Kind < os[j].Kind
	})
}

// ---- scanner adapter contract ----

// Chunk is one unit of work: a slice of targets for one stage of one run.
type Chunk struct {
	ID      int
	RunID   string
	Stage   Stage
	Targets []string // IPs for discovery/services, "ip/proto/port" keys or URLs for later stages
	Dir     string   // working directory for this chunk's files
	Name    string   // file base name, e.g. chunk_0003
	// TargetsFile holds Targets one per line (written by the runner) - pass it to
	// tools that read target lists from a file (nmap -iL, httpx -l, nuclei -l).
	TargetsFile string
}

// StageConfig carries profile settings for one stage.
type StageConfig struct {
	RatePPS int      // per-process rate limit (already divided by concurrency)
	Ports   []int    // allowed/selected ports (empty = adapter default)
	Args    []string // extra tool arguments from the profile
}

// OutputSpec tells the runner where the tool writes its machine-readable output.
type OutputSpec struct {
	Path   string // file written by the tool; empty = read stdout
	Format string // nmap-xml | jsonl | json
}

type Scanner interface {
	Stage() Stage
	Tool() string
	// Command builds the process for a chunk. Rate limits and ports come from cfg.
	Command(ctx context.Context, c Chunk, cfg StageConfig) (*exec.Cmd, OutputSpec)
	// Parse turns raw output into observations. Must tolerate truncated output
	// (process killed at the end of a scan window).
	Parse(raw io.Reader) ([]Observation, error)
}

// ProgressParser is optional: adapters whose tool prints progress implement it.
// completed = targets finished, pct = progress of the current sub-phase (0-100).
type ProgressParser interface {
	ParseProgress(line string) (completed int, pct float64, ok bool)
}
