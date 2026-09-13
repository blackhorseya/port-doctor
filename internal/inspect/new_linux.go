//go:build linux

package inspect

import (
	"fmt"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// New returns the inspectors for Linux, backed by procfs.
func New() (doctor.PortInspector, doctor.ProcessInspector, error) {
	i := newProcfsInspector("/proc")
	return i, i, nil
}

// ElevatedInspectCommand returns a command that identifies the listener when
// it belongs to another user.
func ElevatedInspectCommand(port int) string {
	return fmt.Sprintf("sudo ss -ltnp 'sport = :%d'", port)
}
