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
	exitAvailable = 0 // nothing is listening on the port and no container publishes it; also a completed scan
	exitInUse     = 1 // a process is listening on the port or a container publishes it
	exitError     = 2 // the diagnosis or scan could not be performed
)

// inspectTimeout bounds the system utilities and procfs walks so a wedged
// tool cannot hang port-doctor. A variable so tests can shrink it.
var inspectTimeout = 15 * time.Second

// Diagnoser is the one thing the commands need from the rest of the program.
type Diagnoser interface {
	Diagnose(c context.Context, port int) (doctor.Report, error)
	Scan(c context.Context) (doctor.Overview, error)
}

// newDiagnoser builds the platform doctor. A variable so tests can swap in
// fakes for situations that are hard to stage for real, such as permission
// failures.
var newDiagnoser = func() (Diagnoser, error) {
	host, err := inspect.New()
	if err != nil {
		return nil, err
	}
	containers := inspect.NewContainerInspector()
	return &doctor.Doctor{
		Ports:                  host,
		Processes:              host,
		Listeners:              host,
		Containers:             containers,
		AllContainers:          containers,
		ElevatedInspectCommand: inspect.ElevatedInspectCommand,
	}, nil
}

// Run executes port-doctor with args (excluding the program name) and
// returns the process exit code.
func Run(c context.Context, version string, args []string, stdout, stderr io.Writer) int {
	code := exitAvailable
	cmd := newCommand(version, &code)
	cmd.SetArgs(allowNegativeNumbers(args))
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	err := cmd.ExecuteContext(c)
	if err == nil {
		return code
	}

	// Nothing useful can be done if stderr itself is broken.
	_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
	if h := hint(err); h != "" {
		_, _ = fmt.Fprintf(stderr, "hint: %s\n", h)
	}
	return exitError
}

// newCommand builds the root command and its scan subcommand. A command
// that completes writes its exit code to code; a failure is returned as an
// error and mapped to exitError by Run.
func newCommand(version string, code *int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port-doctor <port>",
		Short: "Find out what is using a local TCP port",
		Long: "port-doctor explains why a local TCP port is unavailable.\n\n" +
			"It finds the process listening on the port, shows its PID, name and\n" +
			"owner, the address it is bound to, and suggests what to do next.\n" +
			"When a Docker or Podman container publishes the port, it names the\n" +
			"container instead of the runtime's port forwarder.\n" +
			"\"port-doctor scan\" lists every listening port the same way.\n" +
			"It never stops or modifies anything itself.",
		Example: "  port-doctor 8080\n" +
			"  port-doctor 5432\n" +
			"  port-doctor scan",
		Version:           resolveVersion(version),
		Args:              onePort,
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return diagnose(cmd.Context(), args[0], code, cmd.OutOrStdout())
		},
	}
	cmd.SetVersionTemplate("port-doctor {{.Version}}\n")
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &usageError{err: err}
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "scan",
		Short: "List every listening TCP port",
		Long: "port-doctor scan lists every TCP port with a listening socket on this\n" +
			"machine, one line per port and process: the interfaces it is bound to,\n" +
			"the PID, name and owner of the process holding it, and the Docker or\n" +
			"Podman container publishing it. It reads the local socket table and\n" +
			"never connects to a port.",
		Example: "  port-doctor scan\n" +
			"  port-doctor scan | grep 8080",
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return scan(cmd.Context(), cmd.OutOrStdout())
		},
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

func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return &usageError{err: fmt.Errorf("scan takes no arguments, got %d", len(args))}
	}
	return nil
}

// diagnose validates arg, runs the platform doctor on it and renders the
// result to w, setting code to exitInUse when the port is taken.
func diagnose(c context.Context, arg string, code *int, w io.Writer) error {
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
		return describe(err)
	}
	if r.Status == doctor.StatusInUse {
		*code = exitInUse
	}
	return presenter.Render(w, r)
}

// scan lists every listening port and renders the overview to w. A
// completed scan always exits 0, even when nothing is listening.
func scan(c context.Context, w io.Writer) error {
	d, err := newDiagnoser()
	if err != nil {
		return err
	}

	c, cancel := context.WithTimeout(c, inspectTimeout)
	defer cancel()
	o, err := d.Scan(c)
	if err != nil {
		return describe(err)
	}
	return presenter.RenderOverview(w, o)
}

// describe replaces the bare deadline error with one that says how long
// port-doctor waited.
func describe(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("inspection timed out after %s", inspectTimeout)
	}
	return err
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
		return "usage: port-doctor <port> or port-doctor scan, for example: port-doctor 8080"
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
