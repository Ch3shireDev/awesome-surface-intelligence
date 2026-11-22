package targets

import (
	"fmt"
	"regexp"
)

var hostName = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Valid reports whether v is an IP, a CIDR or a host name.
func Valid(v string) error {
	if _, err := ParseAddrOrPrefix(v); err == nil || hostName.MatchString(v) {
		return nil
	}
	return fmt.Errorf("%q nie jest adresem IP, zakresem CIDR ani domeną", v)
}
