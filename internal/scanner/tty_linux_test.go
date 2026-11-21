//go:build linux

package scanner

import (
	"os/exec"
	"strings"
	"testing"
)

func TestOpenTTYGivesTerminalStdin(t *testing.T) {
	m, s, err := openTTY()
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	defer m.Close()
	defer s.Close()
	// foreground process of its own terminal: what nmap checks before printing --stats-every
	cmd := exec.Command("sh", "-c", `test -t 0 && [ "$(ps -o tpgid= -p $$ 2>/dev/null | tr -d ' ')" = "$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')" ] && echo tty || echo notty`)
	attachTTY(cmd, s)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "tty" {
		t.Fatalf("child stdin is not a terminal: %q %v", out, err)
	}
}
