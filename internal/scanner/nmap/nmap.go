// Package nmap holds the nmap adapters (discovery, services) implementing obs.Scanner.
package nmap

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"asi/internal/nmapxml"
	"asi/internal/obs"
)

const (
	DefaultDiscoveryArgs = "-sn -n -PS21,22,25,80,443,3389,8080,8443 -T4 --max-retries 1"
	DefaultServicesArgs  = "-sT -sV --version-light -Pn --top-ports 1000 -T4 --max-retries 2 --host-timeout 10m --open"
)

// Adapter runs nmap for one stage. Args are the base nmap flags of the profile.
type Adapter struct {
	StageName obs.Stage
	Args      []string
}

func Discovery(args string) *Adapter {
	return &Adapter{StageName: obs.StageDiscovery, Args: strings.Fields(args)}
}

func Services(args string) *Adapter {
	return &Adapter{StageName: obs.StageServices, Args: strings.Fields(args)}
}

func (a *Adapter) Stage() obs.Stage { return a.StageName }
func (a *Adapter) Tool() string     { return "nmap" }

func (a *Adapter) Command(ctx context.Context, c obs.Chunk, cfg obs.StageConfig) (*exec.Cmd, obs.OutputSpec) {
	out := filepath.Join(c.Dir, c.Name+".xml")
	args := append([]string{}, a.Args...)
	args = append(args, cfg.Args...)
	if len(cfg.Ports) > 0 && a.StageName != obs.StageDiscovery {
		ps := make([]string, len(cfg.Ports))
		for i, p := range cfg.Ports {
			ps[i] = strconv.Itoa(p)
		}
		args = dropFlag(args, "--top-ports", true)
		args = dropFlag(args, "-p", true)
		args = append(args, "-p", strings.Join(ps, ","))
	}
	if a.StageName == obs.StageServices && len(cfg.Ports) == 0 && !hasFlag(args, "-p") {
		if n := flagValue(args, "--top-ports"); n > 0 {
			if list := TopPortsPlusRisky(n); list != "" {
				args = append(dropFlag(args, "--top-ports", true), "-p", list)
			}
		}
	}
	if cfg.RatePPS > 0 {
		args = append(dropFlag(args, "--max-rate", true), "--max-rate", strconv.Itoa(cfg.RatePPS))
	}
	args = append(args, "--stats-every", "2s", "-oX", out, "-iL", c.TargetsFile)
	return exec.CommandContext(ctx, "nmap", args...), obs.OutputSpec{Path: out, Format: "nmap-xml"}
}

// RiskyPorts are services that should never be exposed but are NOT in nmap's top-1000
// list (checked against nmap 7.9x): without them a services scan misses e.g. an open Redis.
var RiskyPorts = []int{
	2375, 2376, // Docker API
	2379,  // etcd
	5601,  // Kibana
	5984,  // CouchDB
	6379,  // Redis
	6443,  // Kubernetes API
	8500,  // Consul
	9042,  // Cassandra
	9300,  // Elasticsearch transport
	10250, // kubelet
	11211, // Memcached
	15672, // RabbitMQ management
	27017, // MongoDB
	61616, // ActiveMQ
}

var (
	topMu    sync.Mutex
	topCache = map[int]string{}
)

// TopPortsPlusRisky returns nmap's own top-N TCP port list (asked from nmap, so it
// follows the installed nmap-services) plus RiskyPorts, as a -p argument. "" if
// nmap cannot tell (the caller then keeps --top-ports).
func TopPortsPlusRisky(n int) string {
	topMu.Lock()
	defer topMu.Unlock()
	if v, ok := topCache[n]; ok {
		return v
	}
	// -sL-like trick: scaninfo is printed before any probe; host-timeout 1ms ends it at once
	out, err := exec.Command("nmap", "-sT", "--top-ports", strconv.Itoa(n), "-oX", "-", "-n", "-Pn",
		"--max-retries", "0", "--host-timeout", "1ms", "127.0.0.1").Output()
	list := ""
	if err == nil {
		if m := reServices.FindSubmatch(out); m != nil {
			list = string(m[1])
			for _, p := range RiskyPorts {
				list += "," + strconv.Itoa(p)
			}
		}
	}
	topCache[n] = list
	return list
}

var reServices = regexp.MustCompile(` services="([0-9,\-]+)"`)

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

func flagValue(args []string, f string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == f {
			n, _ := strconv.Atoi(args[i+1])
			return n
		}
	}
	return 0
}

func dropFlag(args []string, flag string, hasValue bool) []string {
	out := args[:0:0]
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			if hasValue {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func (a *Adapter) Parse(raw io.Reader) ([]obs.Observation, error) {
	run, err := nmapxml.Parse(raw)
	return FromHosts(run.Hosts), err
}

// FromHosts converts parsed nmap hosts to observations (host + port + service).
func FromHosts(hosts []nmapxml.Host) []obs.Observation {
	var out []obs.Observation
	for _, h := range hosts {
		if !h.Up() {
			continue
		}
		ip := h.IP()
		var names []string
		for _, n := range h.Hostnames {
			names = append(names, n.Name)
		}
		out = append(out, obs.New(obs.KindHost, obs.HostKey(ip), "nmap",
			obs.HostData{Up: true, Reason: h.Status.Reason, Hostnames: names}, 100, "up"))
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			key := obs.PortKey(ip, p.Protocol, p.PortID)
			out = append(out, obs.New(obs.KindPort, key, "nmap",
				obs.PortData{State: "open", Reason: p.State.Reason}, 100, "open"))
			if p.Service.Name == "" {
				continue
			}
			sd := obs.ServiceData{Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo, TLS: p.Service.Tunnel == "ssl", Method: p.Service.Method}
			conf := p.Service.Conf * 10 // nmap conf 0-10
			if sd.Method == "table" {
				conf = 30 // guessed from the port number only
			}
			out = append(out, obs.New(obs.KindService, key, "nmap", sd, conf, sd.Name, sd.Product, sd.Version))
		}
	}
	return out
}

var (
	reCompleted = regexp.MustCompile(`(\d+) hosts? completed \((\d+) up\)`)
	reAbout     = regexp.MustCompile(`About ([\d.]+)% done`)
)

// ParseProgress reads nmap --stats-every lines.
func (a *Adapter) ParseProgress(line string) (int, float64, bool) {
	if m := reCompleted.FindStringSubmatch(line); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n, -1, true
	}
	if m := reAbout.FindStringSubmatch(line); m != nil {
		p, _ := strconv.ParseFloat(m[1], 64)
		return -1, p, true
	}
	return 0, 0, false
}

var (
	_ obs.Scanner        = (*Adapter)(nil)
	_ obs.ProgressParser = (*Adapter)(nil)
)
