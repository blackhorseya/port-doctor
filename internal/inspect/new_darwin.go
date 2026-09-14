//go:build darwin

package inspect

import (
	"context"
	"fmt"
	"os/exec"
)

// New returns the inspector for macOS, backed by netstat and ps.
func New() (HostInspector, error) {
	return newDarwinInspector(runCommand), nil
}

func runCommand(c context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(c, name, args...).Output()
}

// ElevatedInspectCommand returns a command that identifies the listener when
// netstat could not attribute it to a process.
func ElevatedInspectCommand(port int) string {
	return fmt.Sprintf("sudo lsof -nP -iTCP:%d -sTCP:LISTEN", port)
}
