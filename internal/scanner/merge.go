package scanner

import (
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	reHost      = regexp.MustCompile(`(?s)<host[ >].*?</host>`)
	reAddr      = regexp.MustCompile(`<address addr="([^"]+)" addrtype="ipv[46]"`)
	reHostnames = regexp.MustCompile(`(?s)<hostnames>.*?</hostnames>|<hostnames/>`)
	reHeader    = regexp.MustCompile(`(?s)^.*?<nmaprun[^>]*>`)
)

// MergeXML joins per-chunk nmap XML files into one nmaprun document, so one run
// becomes one DefectDojo test. Domains from the input are injected as
// <hostname type="user"> so findings show the real service names, not only IPs.
func MergeXML(out string, files []string, domains map[string][]string) (int, error) {
	var header string
	var b strings.Builder
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue // chunk killed before writing anything
		}
		s := string(data)
		if header == "" {
			header = reHeader.FindString(s)
		}
		for _, h := range reHost.FindAllString(s, -1) {
			if !strings.Contains(h, `<status state="up"`) {
				continue
			}
			if m := reAddr.FindStringSubmatch(h); m != nil && len(domains[m[1]]) > 0 {
				h = injectHostnames(h, domains[m[1]])
			}
			b.WriteString(h)
			b.WriteString("\n")
			n++
		}
	}
	if header == "" {
		return 0, fmt.Errorf("no valid nmap XML found")
	}
	doc := header + "\n" + b.String() +
		fmt.Sprintf(`<runstats><finished time="%d"/><hosts up="%d" down="0" total="%d"/></runstats>`+"\n</nmaprun>\n",
			time.Now().Unix(), n, n)
	return n, os.WriteFile(out, []byte(doc), 0o644)
}

func injectHostnames(host string, domains []string) string {
	existing := reHostnames.FindString(host)
	var add strings.Builder
	for _, d := range domains {
		if !strings.Contains(existing, `name="`+d+`"`) {
			fmt.Fprintf(&add, `<hostname name="%s" type="user"/>`, html.EscapeString(d))
		}
	}
	switch {
	case existing == "":
		return host
	case existing == "<hostnames/>":
		return strings.Replace(host, existing, "<hostnames>"+add.String()+"</hostnames>", 1)
	default:
		return strings.Replace(host, "<hostnames>", "<hostnames>"+add.String(), 1)
	}
}
