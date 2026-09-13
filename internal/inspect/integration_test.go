package inspect

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"testing"
	"time"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// These tests run the real platform inspectors against sockets owned by the
// test process. They are skipped on unsupported platforms.

func inspectors(t *testing.T) (doctor.PortInspector, doctor.ProcessInspector) {
	t.Helper()
	ports, procs, err := New()
	if err != nil {
		t.Skip(err)
	}
	return ports, procs
}

func mustAddrPort(s string) netip.AddrPort {
	return netip.MustParseAddrPort(s)
}

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

func TestRealListeners(t *testing.T) {
	ports, _ := inspectors(t)
	me := currentUser(t)

	// The network is pinned to tcp4/tcp6 because plain "tcp" with a wildcard
	// address makes Go open a dual-stack [::] socket even for "0.0.0.0".
	tests := []struct {
		name    string
		network string
		listen  string
		want    func(netip.Addr) bool
	}{
		{"loopback v4", "tcp4", "127.0.0.1:0", func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") }},
		{"all interfaces v4", "tcp4", "0.0.0.0:0", func(a netip.Addr) bool { return a.Is4() && a.IsUnspecified() }},
		{"loopback v6", "tcp6", "[::1]:0", func(a netip.Addr) bool { return a == netip.MustParseAddr("::1") }},
		{"all interfaces v6", "tcp6", "[::]:0", func(a netip.Addr) bool { return a.Is6() && a.IsUnspecified() }},
		{"dual stack", "tcp", ":0", func(a netip.Addr) bool { return a.Is6() && a.IsUnspecified() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen(tt.network, tt.listen)
			if err != nil {
				t.Skipf("cannot listen on %s: %v", tt.listen, err)
			}
			defer func() { _ = ln.Close() }()
			port := ln.Addr().(*net.TCPAddr).Port

			info, err := ports.InspectPort(t.Context(), port)
			if err != nil {
				t.Fatal(err)
			}
			if len(info.Listeners) != 1 {
				t.Fatalf("listeners = %+v, want exactly one", info.Listeners)
			}
			l := info.Listeners[0]
			if l.Protocol != doctor.ProtocolTCP || int(l.Addr.Port()) != port || !tt.want(l.Addr.Addr()) {
				t.Errorf("listener = %+v", l)
			}
			if l.PID != os.Getpid() {
				t.Errorf("PID = %d, want %d (this process)", l.PID, os.Getpid())
			}
			if l.User != "" && l.User != me {
				t.Errorf("User = %q, want %q or unknown", l.User, me)
			}
		})
	}
}

func TestRealProcess(t *testing.T) {
	_, procs := inspectors(t)

	p, err := procs.InspectProcess(t.Context(), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != os.Getpid() || p.Name == "" {
		t.Errorf("process = %+v", p)
	}
	if me := currentUser(t); p.User != me {
		t.Errorf("User = %q, want %q", p.User, me)
	}

	// A process that has just exited: the PID is gone, not an error.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if _, err := procs.InspectProcess(t.Context(), pid); !errors.Is(err, doctor.ErrProcessNotFound) {
		t.Errorf("exited process: error = %v, want ErrProcessNotFound", err)
	}

	// A PID above every platform's maximum must not crash either.
	if _, err := procs.InspectProcess(t.Context(), 4194304); !errors.Is(err, doctor.ErrProcessNotFound) {
		t.Errorf("absurd PID: error = %v, want ErrProcessNotFound", err)
	}
}

// TestRealLingeringSockets closes a connection from the server side so the
// server's socket sits in TIME_WAIT on the port after the listener is gone.
func TestRealLingeringSockets(t *testing.T) {
	ports, _ := inspectors(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close() // active close: this side enters TIME_WAIT
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(client) // wait for the server's FIN
	_ = client.Close()
	_ = ln.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		info, err := ports.InspectPort(t.Context(), port)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, n := range info.OtherSockets {
			total += n
		}
		if len(info.Listeners) == 0 && total > 0 {
			if info.OtherSockets["TIME_WAIT"] == 0 {
				t.Logf("no TIME_WAIT yet, states: %v", info.OtherSockets)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected lingering sockets on port %d, got %+v", port, info)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
