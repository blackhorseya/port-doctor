package inspect

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// procfsInspector is the Linux implementation. It reads /proc/net/tcp{,6} to
// find sockets and walks /proc/<pid>/fd to map socket inodes back to PIDs.
//
// /proc/net/tcp is readable by everyone and lists every socket on the host,
// so "in use" is always detected. Mapping an inode to a PID requires reading
// another process's fd table, which only works for your own processes unless
// you are root; in that case the PID stays 0 but the owning uid is still
// reported.
type procfsInspector struct {
	// root is "/proc" in production and a fixture tree in tests.
	root string
}

func newProcfsInspector(root string) *procfsInspector {
	return &procfsInspector{root: root}
}

// InspectPort implements doctor.PortInspector.
func (i *procfsInspector) InspectPort(_ context.Context, port int) (doctor.PortInfo, error) {
	socks, err := i.sockets()
	if err != nil {
		return doctor.PortInfo{}, err
	}
	info := doctor.PortInfo{OtherSockets: map[string]int{}}
	var listeners []procSocket
	for _, s := range socks {
		if int(s.addr.Port()) != port {
			continue
		}
		if s.state == "LISTEN" {
			listeners = append(listeners, s)
		} else {
			info.OtherSockets[s.state]++
		}
	}
	info.Listeners = i.attribute(listeners)
	return info, nil
}

// ListListeners implements doctor.ListenerInspector.
func (i *procfsInspector) ListListeners(_ context.Context) ([]doctor.Listener, error) {
	socks, err := i.sockets()
	if err != nil {
		return nil, err
	}
	var listeners []procSocket
	for _, s := range socks {
		if s.state == "LISTEN" {
			listeners = append(listeners, s)
		}
	}
	return i.attribute(listeners), nil
}

// sockets reads every TCP socket of both address families. A missing tcp6
// table means IPv6 is disabled and is not an error; both missing is.
func (i *procfsInspector) sockets() ([]procSocket, error) {
	var out []procSocket
	opened := 0
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		socks, err := i.readSockets(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		opened++
		out = append(out, socks...)
	}
	if opened == 0 {
		return nil, fmt.Errorf("read %s/net/tcp: %w", i.root, fs.ErrNotExist)
	}
	return out, nil
}

// attribute maps listening sockets to their owning PIDs with one walk of
// /proc and converts them for the doctor. Nil when there are none.
func (i *procfsInspector) attribute(listeners []procSocket) []doctor.Listener {
	if len(listeners) == 0 {
		return nil
	}
	wanted := map[uint64]bool{}
	for _, s := range listeners {
		wanted[s.inode] = true
	}
	owners := i.socketOwners(wanted)
	out := make([]doctor.Listener, 0, len(listeners))
	for _, s := range listeners {
		out = append(out, doctor.Listener{
			Protocol: doctor.ProtocolTCP,
			Addr:     s.addr,
			PID:      owners[s.inode],
			User:     lookupUser(s.uid),
		})
	}
	return out
}

func (i *procfsInspector) readSockets(name string) ([]procSocket, error) {
	f, err := os.Open(filepath.Join(i.root, name))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	socks, err := parseProcNetTCP(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	return socks, nil
}

// socketOwners returns, for each wanted socket inode, the PID that should be
// shown as its owner. A listening socket is often shared by a parent and its
// forked workers; the lowest PID is normally the process that created it,
// except PID 1 (systemd socket activation), which is skipped when any other
// owner exists.
func (i *procfsInspector) socketOwners(wanted map[uint64]bool) map[uint64]int {
	owners := map[uint64]int{}
	entries, err := os.ReadDir(i.root)
	if err != nil {
		return owners
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && e.IsDir() {
			pids = append(pids, pid)
		}
	}
	// Ascending PID order means the first owner found is the lowest one.
	slices.Sort(pids)
	for _, pid := range pids {
		if len(owners) == len(wanted) && !owners1Only(owners) {
			break
		}
		fdDir := filepath.Join(i.root, strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Not ours to read, or the process just exited.
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok || !wanted[inode] {
				continue
			}
			if cur, seen := owners[inode]; !seen || cur == 1 {
				owners[inode] = pid
			}
		}
	}
	return owners
}

func owners1Only(owners map[uint64]int) bool {
	for _, pid := range owners {
		if pid == 1 {
			return true
		}
	}
	return false
}

// socketInode extracts N from an fd link target of the form "socket:[N]".
func socketInode(target string) (uint64, bool) {
	rest, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	return n, err == nil
}

// InspectProcess implements doctor.ProcessInspector.
func (i *procfsInspector) InspectProcess(_ context.Context, pid int) (doctor.Process, error) {
	dir := filepath.Join(i.root, strconv.Itoa(pid))
	p := doctor.Process{PID: pid}

	comm, err := os.ReadFile(filepath.Join(dir, "comm"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return doctor.Process{}, doctor.ErrProcessNotFound
	case errors.Is(err, fs.ErrPermission):
		return doctor.Process{}, doctor.ErrPermission
	case err != nil:
		return doctor.Process{}, fmt.Errorf("read process %d: %w", pid, err)
	}
	p.Name = strings.TrimSpace(string(comm))

	// comm is truncated to 15 bytes by the kernel; the exe link carries the
	// full name but is only readable for your own processes.
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		exe = strings.TrimSuffix(exe, " (deleted)")
		if base := filepath.Base(exe); base != "" && base != "." && base != "/" {
			p.Name = base
		}
	}

	if status, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		if uid, ok := statusUID(string(status)); ok {
			p.User = lookupUser(uid)
		}
	}
	return p, nil
}

// statusUID returns the real uid from the "Uid:" line of /proc/<pid>/status.
func statusUID(status string) (int, bool) {
	for line := range strings.SplitSeq(status, "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.Atoi(fields[0])
		return uid, err == nil
	}
	return 0, false
}

// procSocket is one row of /proc/net/tcp or /proc/net/tcp6.
type procSocket struct {
	addr  netip.AddrPort
	state string
	uid   int
	inode uint64
}

// tcpStates maps the kernel's hex state codes (include/net/tcp_states.h).
var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
	"0C": "NEW_SYN_RECV",
}

// parseProcNetTCP returns every socket in the table.
//
// Row layout (header omitted):
//
//	sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
func parseProcNetTCP(r io.Reader) ([]procSocket, error) {
	var out []procSocket
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[0] == "sl" {
			continue
		}
		addr, err := decodeProcAddr(fields[1])
		if err != nil {
			return nil, fmt.Errorf("local address %q: %w", fields[1], err)
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil {
			return nil, fmt.Errorf("uid %q: %w", fields[7], err)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("inode %q: %w", fields[9], err)
		}
		state, ok := tcpStates[strings.ToUpper(fields[3])]
		if !ok {
			state = "UNKNOWN(" + fields[3] + ")"
		}
		out = append(out, procSocket{addr: addr, state: state, uid: uid, inode: inode})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeProcAddr parses the "HEXADDR:HEXPORT" form used by /proc/net/tcp.
//
// The kernel prints each 32-bit word of the address in host byte order, so on
// the little-endian targets port-doctor ships for, every 4-byte group must be
// reversed. The port is printed as a plain big-endian number.
func decodeProcAddr(s string) (netip.AddrPort, error) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("missing port")
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port: %w", err)
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address: %w", err)
	}
	if len(raw) != 4 && len(raw) != 16 {
		return netip.AddrPort{}, fmt.Errorf("address has %d bytes", len(raw))
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, errors.New("address is not an IP")
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
