//go:build !linux

package inspect

import (
	"fmt"
	"runtime"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// New reports that this operating system is not supported.
func New() (doctor.PortInspector, doctor.ProcessInspector, error) {
	return nil, nil, fmt.Errorf("%w: %s (port-doctor supports macOS and Linux)", ErrUnsupportedPlatform, runtime.GOOS)
}

// ElevatedInspectCommand has nothing to suggest on unsupported platforms.
func ElevatedInspectCommand(int) string { return "" }
