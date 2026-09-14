//go:build linux

package inspect

import (
	"fmt"
)

// New returns the inspector for Linux, backed by procfs.
func New() (HostInspector, error) {
	return newProcfsInspector("/proc"), nil
}

// ElevatedInspectCommand returns a command that identifies the listener when
// it belongs to another user.
func ElevatedInspectCommand(port int) string {
	return fmt.Sprintf("sudo ss -ltnp 'sport = :%d'", port)
}
