package inspect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// commandRunner runs an external command and returns its stdout. It exists so
// tests can feed canned output instead of executing anything.
type commandRunner func(c context.Context, name string, args ...string) ([]byte, error)

func runCommand(c context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(c, name, args...).Output()
}

// darwinInspector is the macOS implementation. It uses `netstat -anv`, which
// reads the socket table through sysctl and therefore sees every user's
// sockets and their PIDs without root, unlike lsof. Process metadata comes
// from `ps`, which is likewise visible for all users.
type darwinInspector struct {
	run commandRunner
}

func newDarwinInspector(run commandRunner) *darwinInspector {
	return &darwinInspector{run: run}
}

// InspectPort implements doctor.PortInspector.
func (i *darwinInspector) InspectPort(c context.Context, port int) (doctor.PortInfo, error) {
	out, err := i.run(c, "netstat", "-anv", "-p", "tcp")
	if err != nil {
		// A command killed by the deadline reports "signal: killed"; the
		// context error is the one worth showing.
		if cerr := c.Err(); cerr != nil {
			return doctor.PortInfo{}, cerr
		}
		return doctor.PortInfo{}, describeCommandError("netstat", err)
	}
	rows, err := parseNetstat(bytes.NewReader(out), port)
	if err != nil {
		return doctor.PortInfo{}, fmt.Errorf("parse netstat output: %w", err)
	}

	info := doctor.PortInfo{OtherSockets: map[string]int{}}
	for _, row := range rows {
		if row.state != "LISTEN" {
			info.OtherSockets[row.state]++
			continue
		}
		info.Listeners = append(info.Listeners, doctor.Listener{
			Protocol: doctor.ProtocolTCP,
			Addr:     row.addr,
			PID:      row.pid,
		})
	}
	return info, nil
}

// InspectProcess implements doctor.ProcessInspector.
func (i *darwinInspector) InspectProcess(c context.Context, pid int) (doctor.Process, error) {
	out, err := i.run(c, "ps", "-p", strconv.Itoa(pid), "-o", "uid=,comm=")
	line := strings.TrimSpace(string(out))
	if err != nil {
		if cerr := c.Err(); cerr != nil {
			return doctor.Process{}, cerr
		}
		// ps exits 1 with empty output when the PID does not exist.
		if _, ok := errors.AsType[*exec.ExitError](err); ok && line == "" {
			return doctor.Process{}, doctor.ErrProcessNotFound
		}
		return doctor.Process{}, describeCommandError("ps", err)
	}
	if line == "" {
		return doctor.Process{}, doctor.ErrProcessNotFound
	}

	p := doctor.Process{PID: pid}
	uidText, comm, _ := strings.Cut(line, " ")
	if uid, err := strconv.Atoi(uidText); err == nil {
		p.User = lookupUser(uid)
	}
	// comm is the executable path, which may contain spaces; its base name is
	// the untruncated process name.
	if base := filepath.Base(strings.TrimSpace(comm)); base != "." && base != "/" {
		p.Name = base
	}
	return p, nil
}

func describeCommandError(name string, err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%s is not installed, which port-doctor needs on macOS", name)
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
			return fmt.Errorf("%s failed: %s", name, msg)
		}
	}
	return fmt.Errorf("run %s: %w", name, err)
}

// netstatRow is one TCP socket from `netstat -anv`.
type netstatRow struct {
	addr  netip.AddrPort
	state string
	pid   int // 0 when the column is absent or unparsable
}

// parseNetstat returns the rows whose local port equals port.
//
// The column layout of `netstat -anv` changes between macOS releases. Older
// versions print a bare "pid" column; macOS 26 prints "process:pid", where the
// process name may contain spaces. Both are handled by locating the pid column
// in the header and counting the fixed columns that follow it, so rows are
// read from the end where the layout is stable.
func parseNetstat(r io.Reader, port int) ([]netstatRow, error) {
	var out []netstatRow
	trailing := -1 // columns after the pid column, or -1 when unknown
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Proto" {
			trailing = columnsAfterPID(fields)
			continue
		}
		if !strings.HasPrefix(fields[0], "tcp") || len(fields) < 6 {
			continue
		}
		addr, ok := parseNetstatAddr(fields[0], fields[3])
		if !ok || int(addr.Port()) != port {
			continue
		}
		row := netstatRow{addr: addr, state: fields[5]}
		if trailing >= 0 && len(fields) > 6+trailing {
			row.pid = parseNetstatPID(fields[len(fields)-1-trailing])
		}
		out = append(out, row)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func columnsAfterPID(header []string) int {
	for idx, col := range header {
		if col == "pid" || strings.HasSuffix(col, ":pid") {
			return len(header) - 1 - idx
		}
	}
	return -1
}

// parseNetstatPID reads "18432", "Python:18432" or "(Plu:18432".
func parseNetstatPID(token string) int {
	if idx := strings.LastIndex(token, ":"); idx >= 0 {
		token = token[idx+1:]
	}
	pid, err := strconv.Atoi(token)
	if err != nil || pid < 0 {
		return 0
	}
	return pid
}

// parseNetstatAddr reads BSD-style "host.port" where host may be "*",
// "127.0.0.1", "::1" or "fe80::1%lo0". A wildcard host means 0.0.0.0 for
// tcp4 and [::] for tcp6/tcp46 (a dual-stack socket).
func parseNetstatAddr(proto, local string) (netip.AddrPort, bool) {
	dot := strings.LastIndex(local, ".")
	if dot < 0 {
		return netip.AddrPort{}, false
	}
	host, portText := local[:dot], local[dot+1:]
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var ip netip.Addr
	switch {
	case host == "*" && proto == "tcp4":
		ip = netip.IPv4Unspecified()
	case host == "*":
		ip = netip.IPv6Unspecified()
	default:
		ip, err = netip.ParseAddr(host)
		if err != nil {
			return netip.AddrPort{}, false
		}
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}
