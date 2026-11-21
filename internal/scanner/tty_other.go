//go:build !linux

package scanner

import (
	"errors"
	"os"
	"os/exec"
)

func openTTY() (master, slave *os.File, err error) { return nil, nil, errors.New("pty: linux only") }

func attachTTY(cmd *exec.Cmd, slave *os.File) {}
