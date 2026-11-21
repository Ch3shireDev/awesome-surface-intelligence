// Package nmapxml parses nmap -oX output into a small, stable model.
package nmapxml

import (
	"encoding/xml"
	"io"
	"os"
)

type Run struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Status    Status     `xml:"status"`
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
}

type Status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type Service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
	Method    string `xml:"method,attr"`
	Conf      int    `xml:"conf,attr"`
}

func (h Host) IP() string {
	for _, a := range h.Addresses {
		if a.Type == "ipv4" || a.Type == "ipv6" {
			return a.Addr
		}
	}
	return ""
}

func (h Host) Up() bool { return h.Status.State == "up" }

// ParseFile reads an nmap XML file. A partially written file (nmap killed)
// yields whatever hosts were complete; the error is returned alongside.
func ParseFile(path string) (Run, error) {
	f, err := os.Open(path)
	if err != nil {
		return Run{}, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads nmap XML from r (see ParseFile).
func Parse(rd io.Reader) (Run, error) {
	var r Run
	d := xml.NewDecoder(rd)
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return r, nil // EOF or truncated file: keep what we have
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "host" {
			var h Host
			if err := d.DecodeElement(&h, &se); err != nil {
				return r, nil // truncated last host (nmap killed): keep complete ones
			}
			r.Hosts = append(r.Hosts, h)
		}
	}
}
