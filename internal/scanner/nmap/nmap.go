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
	if cfg.RatePPS > 0 {
		args = append(dropFlag(args, "--max-rate", true), "--max-rate", strconv.Itoa(cfg.RatePPS))
	}
	args = append(args, "--stats-every", "2s", "-oX", out, "-iL", c.TargetsFile)
	return exec.CommandContext(ctx, "nmap", args...), obs.OutputSpec{Path: out, Format: "nmap-xml"}
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
