package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blackhorseya/port-doctor/internal/doctor"
	"github.com/blackhorseya/port-doctor/internal/inspect"
)

type result struct {
	code   int
	stdout string
	stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), "v1.2.3", args, &stdout, &stderr)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// fakeDoctor stands in for the platform doctor so exit codes and messages
// can be pinned without staging real sockets.
type fakeDoctor struct {
	report doctor.Report
	err    error
	block  bool // wait for the context to expire, then return its error
}

func (f fakeDoctor) Diagnose(c context.Context, port int) (doctor.Report, error) {
	if f.block {
		<-c.Done()
		return doctor.Report{}, c.Err()
	}
	r := f.report
	r.Port = port
	return r, f.err
}

func useDoctor(t *testing.T, d Diagnoser, err error) {
	t.Helper()
	prev := newDiagnoser
	newDiagnoser = func() (Diagnoser, error) { return d, err }
	t.Cleanup(func() { newDiagnoser = prev })
}

func inUse(pid int) doctor.Report {
	return doctor.Report{
		Status: doctor.StatusInUse,
		Occupants: []doctor.Occupant{{
			Process:   doctor.Process{PID: pid, Name: "api-server", User: "sean"},
			Listeners: []doctor.Listener{{Protocol: doctor.ProtocolTCP, Addr: netip.MustParseAddrPort("0.0.0.0:8080"), PID: pid}},
		}},
		Diagnosis:   "Another process is listening on port 8080 (all interfaces).",
		Suggestions: []doctor.Suggestion{{Title: "Stop", Commands: []string{fmt.Sprintf("kill %d", pid)}}},
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		doctor Diagnoser
		err    error
		want   int
	}{
		{"no arguments", nil, fakeDoctor{}, nil, exitError},
		{"too many arguments", []string{"8080", "3000"}, fakeDoctor{}, nil, exitError},
		{"unknown flag", []string{"--bogus", "8080"}, fakeDoctor{}, nil, exitError},
		{"port not a number", []string{"abc"}, fakeDoctor{}, nil, exitError},
		{"port zero", []string{"0"}, fakeDoctor{}, nil, exitError},
		{"port negative", []string{"-1"}, fakeDoctor{}, nil, exitError},
		{"port too large", []string{"65536"}, fakeDoctor{}, nil, exitError},
		{"unsupported platform", []string{"8080"}, nil, inspect.ErrUnsupportedPlatform, exitError},
		{"inspection failed", []string{"8080"}, fakeDoctor{err: errors.New("netstat failed")}, nil, exitError},
		{"available", []string{"8080"}, fakeDoctor{}, nil, exitAvailable},
		{"in use", []string{"8080"}, fakeDoctor{report: inUse(42)}, nil, exitInUse},
		{"help", []string{"--help"}, fakeDoctor{}, nil, exitAvailable},
		{"version", []string{"--version"}, fakeDoctor{}, nil, exitAvailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useDoctor(t, tt.doctor, tt.err)
			if res := run(t, tt.args...); res.code != tt.want {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, tt.want, res.stdout, res.stderr)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"not a number", []string{"abc"}, `Error: invalid port "abc"` + "\n"},
		{"zero", []string{"0"}, "Error: port must be between 1 and 65535\n"},
		{"negative", []string{"-1"}, "Error: port must be between 1 and 65535\n"},
		{"too large", []string{"99999"}, "Error: port must be between 1 and 65535\n"},
		{"missing", nil, "Error: missing port argument\n"},
		{"too many", []string{"1", "2", "3"}, "Error: expected one port argument, got 3\n"},
		{"unknown flag", []string{"--bogus"}, "Error: unknown flag: --bogus\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useDoctor(t, fakeDoctor{}, nil)
			res := run(t, tt.args...)
			if !strings.HasPrefix(res.stderr, tt.want) {
				t.Errorf("stderr = %q, want prefix %q", res.stderr, tt.want)
			}
			if !strings.Contains(res.stderr, "hint: usage: port-doctor <port>") {
				t.Errorf("stderr = %q, want a usage hint", res.stderr)
			}
			if res.stdout != "" {
				t.Errorf("stdout = %q, want nothing", res.stdout)
			}
		})
	}
}

func TestUnsupportedPlatformMessage(t *testing.T) {
	useDoctor(t, nil, fmt.Errorf("%w: plan9", inspect.ErrUnsupportedPlatform))
	res := run(t, "8080")
	if res.code != exitError {
		t.Fatalf("exit code = %d", res.code)
	}
	if !strings.Contains(res.stderr, "Error: unsupported platform: plan9") || !strings.Contains(res.stderr, "hint: port-doctor diagnoses ports on macOS and Linux only") {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestVersion(t *testing.T) {
	useDoctor(t, fakeDoctor{}, nil)
	res := run(t, "--version")
	if res.stdout != "port-doctor v1.2.3\n" {
		t.Errorf("stdout = %q", res.stdout)
	}
}

func TestHelp(t *testing.T) {
	useDoctor(t, fakeDoctor{}, nil)
	res := run(t, "--help")
	for _, want := range []string{"Usage:\n  port-doctor <port>", "port-doctor 8080", "--version"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("help output lacks %q:\n%s", want, res.stdout)
		}
	}
	if strings.Contains(res.stdout, "completion") {
		t.Errorf("help output should not advertise the completion command:\n%s", res.stdout)
	}
}

func TestRendersReport(t *testing.T) {
	useDoctor(t, fakeDoctor{report: inUse(18432)}, nil)
	res := run(t, "8080")
	if res.code != exitInUse {
		t.Fatalf("exit code = %d, stderr:\n%s", res.code, res.stderr)
	}
	for _, want := range []string{"✗ Port 8080 is in use", "  PID       18432", "  Name      api-server", "  Address   0.0.0.0:8080", "    kill 18432"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, res.stdout)
		}
	}
	if res.stderr != "" {
		t.Errorf("stderr = %q, want nothing", res.stderr)
	}
}

func TestInspectionTimeout(t *testing.T) {
	prev := inspectTimeout
	inspectTimeout = 20 * time.Millisecond
	t.Cleanup(func() { inspectTimeout = prev })
	useDoctor(t, fakeDoctor{block: true}, nil)

	res := run(t, "8080")
	if res.code != exitError {
		t.Fatalf("exit code = %d", res.code)
	}
	if res.stderr != "Error: inspection timed out after 20ms\n" {
		t.Errorf("stderr = %q", res.stderr)
	}
}

func TestAllowNegativeNumbers(t *testing.T) {
	tests := []struct {
		in, want []string
	}{
		{[]string{"8080"}, []string{"8080"}},
		{[]string{"-1"}, []string{"--", "-1"}},
		{[]string{"--help", "-5"}, []string{"--help", "--", "-5"}},
		{[]string{"--", "-1"}, []string{"--", "-1"}},
		{[]string{"--bogus"}, []string{"--bogus"}},
	}
	for _, tt := range tests {
		got := allowNegativeNumbers(tt.in)
		if strings.Join(got, " ") != strings.Join(tt.want, " ") {
			t.Errorf("allowNegativeNumbers(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestEndToEnd runs the real platform inspectors against a listener owned
// by the test process itself.
func TestEndToEnd(t *testing.T) {
	if _, err := inspect.New(); err != nil {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	res := run(t, fmt.Sprint(port))
	if res.code != exitInUse {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, exitInUse, res.stdout, res.stderr)
	}
	for _, want := range []string{
		fmt.Sprintf("✗ Port %d is in use", port),
		fmt.Sprintf("  PID       %d", os.Getpid()),
		fmt.Sprintf("  Address   127.0.0.1:%d", port),
		fmt.Sprintf("Another process is listening on port %d (localhost only).", port),
		fmt.Sprintf("    kill %d", os.Getpid()),
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, res.stdout)
		}
	}

	// Close the listener: the port must read as available again. A listener
	// that never accepted a connection leaves no TIME_WAIT behind.
	_ = ln.Close()
	res = run(t, fmt.Sprint(port))
	if res.code != exitAvailable || !strings.HasPrefix(res.stdout, fmt.Sprintf("✓ Port %d is available\n", port)) {
		t.Errorf("after close: exit code = %d\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
}
