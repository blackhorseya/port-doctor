//go:build !linux && !darwin

package inspect

import (
	"fmt"
	"runtime"
)

// New reports that this operating system is not supported.
func New() (HostInspector, error) {
	return nil, fmt.Errorf("%w: %s (port-doctor supports macOS and Linux)", ErrUnsupportedPlatform, runtime.GOOS)
}

// ElevatedInspectCommand has nothing to suggest on unsupported platforms.
func ElevatedInspectCommand(int) string { return "" }
