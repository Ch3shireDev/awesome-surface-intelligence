//go:build linux

package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// openTTY returns a pseudo-terminal pair. Some nmap builds (e.g. Alpine 7.95, used in the scanner
// image) print --stats-every lines only when stdin is a terminal; without them the progress of a
// running chunk stays at 0% until it finishes. The scanner gives nmap the slave side as stdin
// (stdout stays a pipe we parse) and never writes to the master, so nmap sees no key presses.
func openTTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		master.Close()
		return nil, nil, e
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		master.Close()
		return nil, nil, e
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// attachTTY makes slave the child's stdin AND controlling terminal in a new session, so the
// child is the terminal's foreground process (nmap reads keys / prints --stats-every only then).
func attachTTY(cmd *exec.Cmd, slave *os.File) {
	cmd.Stdin = slave
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Ctty = 0 // fd number in the child = stdin
}
