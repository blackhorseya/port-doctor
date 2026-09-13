// Package cli implements the port-doctor command: argument handling,
// orchestration of the diagnosis, and exit codes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/blackhorseya/port-doctor/internal/doctor"
	"github.com/blackhorseya/port-doctor/internal/inspect"
	"github.com/blackhorseya/port-doctor/internal/presenter"
)

// Exit codes, as documented in the README.
const (
	exitAvailable = 0 // nothing is listening on the port
	exitInUse     = 1 // a process is listening on the port
	exitError     = 2 // the diagnosis could not be performed
)

// inspectTimeout bounds the system utilities and procfs walks so a wedged
// tool cannot hang port-doctor. A variable so tests can shrink it.
var inspectTimeout = 15 * time.Second

// Diagnoser is the one thing the command needs from the rest of the program.
type Diagnoser interface {
	Diagnose(c context.Context, port int) (doctor.Report, error)
}

// newDiagnoser builds the platform doctor. A variable so tests can swap in
// fakes for situations that are hard to stage for real, such as permission
// failures.
var newDiagnoser = func() (Diagnoser, error) {
	ports, procs, err := inspect.New()
	if err != nil {
		return nil, err
	}
	return &doctor.Doctor{
		Ports:                  ports,
		Processes:              procs,
		ElevatedInspectCommand: inspect.ElevatedInspectCommand,
	}, nil
}

// Run executes port-doctor with args (excluding the program name) and
// returns the process exit code.
func Run(c context.Context, version string, args []string, stdout, stderr io.Writer) int {
	var report doctor.Report
	cmd := newCommand(version, &report)
	cmd.SetArgs(allowNegativeNumbers(args))
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	err := cmd.ExecuteContext(c)
	if err == nil {
		if report.Status == doctor.StatusInUse {
			return exitInUse
		}
		return exitAvailable
	}

	// Nothing useful can be done if stderr itself is broken.
	_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
	if h := hint(err); h != "" {
		_, _ = fmt.Fprintf(stderr, "hint: %s\n", h)
	}
	return exitError
}

func newCommand(version string, report *doctor.Report) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port-doctor <port>",
		Short: "Find out what is using a local TCP port",
		Long: "port-doctor explains why a local TCP port is unavailable.\n\n" +
			"It finds the process listening on the port, shows its PID, name and\n" +
			"owner, the address it is bound to, and suggests what to do next.\n" +
			"It never stops or modifies anything itself.",
		Example: "  port-doctor 8080\n" +
			"  port-doctor 5432",
		Version:           resolveVersion(version),
		Args:              onePort,
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return diagnose(cmd.Context(), args[0], report, cmd.OutOrStdout())
		},
	}
	cmd.SetVersionTemplate("port-doctor {{.Version}}\n")
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &usageError{err: err}
	})
	return cmd
}

func onePort(_ *cobra.Command, args []string) error {
	switch len(args) {
	case 1:
		return nil
	case 0:
		return &usageError{err: errors.New("missing port argument")}
	default:
		return &usageError{err: fmt.Errorf("expected one port argument, got %d", len(args))}
	}
}

// diagnose validates arg, runs the platform doctor on it and renders the
// result to w, storing the report so Run can pick the exit code.
func diagnose(c context.Context, arg string, report *doctor.Report, w io.Writer) error {
	port, err := doctor.ParsePort(arg)
	if err != nil {
		return &usageError{err: err}
	}
	d, err := newDiagnoser()
	if err != nil {
		return err
	}

	c, cancel := context.WithTimeout(c, inspectTimeout)
	defer cancel()
	r, err := d.Diagnose(c, port)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("inspection timed out after %s", inspectTimeout)
		}
		return err
	}
	*report = r
	return presenter.Render(w, r)
}

// allowNegativeNumbers stops the flag parser from reading "-1" as the flag
// "-1": everything from the first negative number on is passed through as
// arguments so it reaches port validation and gets the range error instead.
func allowNegativeNumbers(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args
		}
		if n, err := strconv.ParseInt(a, 10, 64); err == nil && n < 0 {
			out := make([]string, 0, len(args)+1)
			out = append(out, args[:i]...)
			out = append(out, "--")
			return append(out, args[i:]...)
		}
	}
	return args
}

// hint suggests how to fix err, or returns "" when there is nothing useful
// to add beyond the error message itself.
func hint(err error) string {
	if _, ok := errors.AsType[*usageError](err); ok {
		return "usage: port-doctor <port>, for example: port-doctor 8080"
	}
	if errors.Is(err, inspect.ErrUnsupportedPlatform) {
		return "port-doctor diagnoses ports on macOS and Linux only"
	}
	return ""
}

// usageError marks errors caused by how the command was invoked.
type usageError struct {
	err error
}

func (x *usageError) Error() string {
	return x.err.Error()
}

func (x *usageError) Unwrap() error {
	return x.err
}

// resolveVersion prefers the version stamped at build time and falls back to
// the module version recorded by `go install module@version`.
func resolveVersion(stamped string) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
