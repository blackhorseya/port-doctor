package inspect

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F90 0100007F:C351 06 00000000:00000000 03:00001234 00000000     0        0 0 3 0000000000000000
   3: 0100007F:C352 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 4 30 10 -1
   4: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0
`

const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 778 1 0000000000000000 100 0 0 10 0
`

func TestDecodeProcAddr(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"0100007F:1F90", "127.0.0.1:8080"},
		{"00000000:0050", "0.0.0.0:80"},
		{"0501A8C0:1BB8", "192.168.1.5:7096"},
		{"00000000000000000000000000000000:1F90", "[::]:8080"},
		{"00000000000000000000000001000000:1F90", "[::1]:8080"},
		{"0000000000000000FFFF00000100007F:1F90", "[::ffff:127.0.0.1]:8080"},
	}
	for _, tt := range tests {
		got, err := decodeProcAddr(tt.in)
		if err != nil {
			t.Errorf("decodeProcAddr(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("decodeProcAddr(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}

	for _, bad := range []string{"0100007F", "0100007F:ZZZZ", "0100:1F90", "XY00007F:1F90"} {
		if _, err := decodeProcAddr(bad); err == nil {
			t.Errorf("decodeProcAddr(%q) succeeded, want error", bad)
		}
	}
}

// procSocketsOn parses table and keeps the sockets on port.
func procSocketsOn(t *testing.T, table string, port int) []procSocket {
	t.Helper()
	all, err := parseProcNetTCP(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	var out []procSocket
	for _, s := range all {
		if int(s.addr.Port()) == port {
			out = append(out, s)
		}
	}
	return out
}

func TestParseProcNetTCP(t *testing.T) {
	all, err := parseProcNetTCP(strings.NewReader(procNetTCP))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Errorf("rows = %d, want every socket in the fixture (5)", len(all))
	}

	socks := procSocketsOn(t, procNetTCP, 8080)
	want := []procSocket{
		{addr: mustAddrPort("127.0.0.1:8080"), state: "LISTEN", uid: 1000, inode: 12345},
		{addr: mustAddrPort("127.0.0.1:8080"), state: "ESTABLISHED", uid: 1000, inode: 12346},
		{addr: mustAddrPort("127.0.0.1:8080"), state: "TIME_WAIT", uid: 0, inode: 0},
	}
	if len(socks) != len(want) {
		t.Fatalf("got %d sockets %+v, want %d", len(socks), socks, len(want))
	}
	for i := range want {
		if socks[i] != want[i] {
			t.Errorf("socket %d = %+v, want %+v", i, socks[i], want[i])
		}
	}

	if socks = procSocketsOn(t, procNetTCP, 3000); len(socks) != 1 || socks[0].addr.String() != "0.0.0.0:3000" {
		t.Errorf("port 3000: %+v", socks)
	}
	if _, err := parseProcNetTCP(strings.NewReader("   0: BROKEN:1F90 x x 0A x x x 1000 0 1\n")); err == nil {
		t.Error("corrupt row should be an error")
	}
}

func TestProcfsListListeners(t *testing.T) {
	f := newFakeProc(t)
	f.process("100", "api-server", 1000, "/opt/app/bin/api-server-linux-amd64")
	f.link("100/fd/3", "socket:[12345]")
	f.link("1/fd/7", "socket:[777]") // socket activation: PID 1 also holds it
	f.link("900/fd/2", "socket:[777]")
	// inodes 12348 and 778 belong to nobody readable

	got, err := newProcfsInspector(f.root).ListListeners(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []doctor.Listener{
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("127.0.0.1:8080"), PID: 100, User: lookupUser(1000)},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("0.0.0.0:3000"), PID: 0, User: lookupUser(1000)},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[::]:8080"), PID: 900, User: lookupUser(0)},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[::1]:3000"), PID: 0, User: lookupUser(1000)},
	}
	if len(got) != len(want) {
		t.Fatalf("listeners = %+v, want %+v (LISTEN rows of both tables)", got, want)
	}
	for n := range want {
		if got[n] != want[n] {
			t.Errorf("listener %d = %+v, want %+v", n, got[n], want[n])
		}
	}

	if _, err := newProcfsInspector(t.TempDir()).ListListeners(t.Context()); err == nil {
		t.Error("no socket tables at all should be an error")
	}
}

// fakeProc builds a procfs look-alike under a temp dir.
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) fakeProc {
	t.Helper()
	root := t.TempDir()
	f := fakeProc{t: t, root: root}
	f.write("net/tcp", procNetTCP)
	f.write("net/tcp6", procNetTCP6)
	return f
}

func (f fakeProc) write(rel, content string) {
	f.t.Helper()
	path := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f fakeProc) link(rel, target string) {
	f.t.Helper()
	path := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		f.t.Fatal(err)
	}
}

func (f fakeProc) process(pid, comm string, uid int, exe string) {
	f.t.Helper()
	f.write(pid+"/comm", comm+"\n")
	f.write(pid+"/status", "Name:\t"+comm+"\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t"+pid+"\nUid:\t"+strings.Repeat(strconv.Itoa(uid)+"\t", 3)+strconv.Itoa(uid)+"\n")
	if exe != "" {
		f.link(pid+"/exe", exe)
	}
}

func TestProcfsInspectPort(t *testing.T) {
	f := newFakeProc(t)
	f.process("100", "api-server", 1000, "/opt/app/bin/api-server-linux-amd64")
	f.link("100/fd/3", "socket:[12345]")
	f.link("100/fd/0", "/dev/null")
	f.process("250", "api-server", 1000, "") // forked worker sharing the socket
	f.link("250/fd/4", "socket:[12345]")
	f.link("1/fd/7", "socket:[777]") // socket activation: PID 1 also holds it
	f.link("900/fd/2", "socket:[777]")
	f.link("300/fd/1", "pipe:[555]")
	f.write("self/comm", "port-doctor\n") // non-numeric entries are ignored
	f.write("abc/comm", "junk\n")

	i := newProcfsInspector(f.root)
	info, err := i.InspectPort(t.Context(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	want := []doctor.Listener{
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("127.0.0.1:8080"), PID: 100, User: lookupUser(1000)},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[::]:8080"), PID: 900, User: lookupUser(0)},
	}
	if len(info.Listeners) != len(want) {
		t.Fatalf("listeners = %+v, want %+v", info.Listeners, want)
	}
	for n := range want {
		if info.Listeners[n] != want[n] {
			t.Errorf("listener %d = %+v, want %+v", n, info.Listeners[n], want[n])
		}
	}
	if info.OtherSockets["ESTABLISHED"] != 1 || info.OtherSockets["TIME_WAIT"] != 1 || len(info.OtherSockets) != 2 {
		t.Errorf("other sockets = %v", info.OtherSockets)
	}
}

func TestProcfsInspectPortUnattributed(t *testing.T) {
	f := newFakeProc(t)
	f.link("1/fd/7", "socket:[777]") // only PID 1 holds it: report PID 1 rather than nothing
	// nobody readable holds inode 12345

	i := newProcfsInspector(f.root)
	info, err := i.InspectPort(t.Context(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	if info.Listeners[0].PID != 0 || info.Listeners[0].User != lookupUser(1000) {
		t.Errorf("unattributed listener = %+v, want PID 0 with owner kept", info.Listeners[0])
	}
	if info.Listeners[1].PID != 1 {
		t.Errorf("PID 1 as the only owner should still be reported, got %+v", info.Listeners[1])
	}
}

func TestProcfsInspectPortAvailable(t *testing.T) {
	f := newFakeProc(t)
	info, err := newProcfsInspector(f.root).InspectPort(t.Context(), 9999)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Listeners) != 0 || len(info.OtherSockets) != 0 {
		t.Errorf("info = %+v, want empty", info)
	}
}

func TestProcfsInspectPortWithoutIPv6(t *testing.T) {
	root := t.TempDir()
	f := fakeProc{t: t, root: root}
	f.write("net/tcp", procNetTCP)
	info, err := newProcfsInspector(root).InspectPort(t.Context(), 8080)
	if err != nil {
		t.Fatalf("a missing tcp6 table must not be an error: %v", err)
	}
	if len(info.Listeners) != 1 {
		t.Errorf("listeners = %+v", info.Listeners)
	}

	if _, err := newProcfsInspector(t.TempDir()).InspectPort(t.Context(), 8080); err == nil {
		t.Error("no socket tables at all should be an error")
	}
}

func TestProcfsInspectProcess(t *testing.T) {
	f := newFakeProc(t)
	f.process("100", "api-server", 1000, "/opt/app/bin/api-server-linux-amd64")
	f.process("250", "worker", 1000, "")
	f.process("600", "node", 1000, "/usr/bin/node (deleted)")
	i := newProcfsInspector(f.root)

	p, err := i.InspectProcess(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := (doctor.Process{PID: 100, Name: "api-server-linux-amd64", User: lookupUser(1000)}); p != want {
		t.Errorf("process = %+v, want %+v (exe wins over the truncated comm)", p, want)
	}

	p, err = i.InspectProcess(t.Context(), 250)
	if err != nil || p.Name != "worker" {
		t.Errorf("comm fallback: %+v, %v", p, err)
	}

	p, err = i.InspectProcess(t.Context(), 600)
	if err != nil || p.Name != "node" {
		t.Errorf("deleted exe: %+v, %v", p, err)
	}

	if _, err := i.InspectProcess(t.Context(), 404); !errors.Is(err, doctor.ErrProcessNotFound) {
		t.Errorf("missing process: %v, want ErrProcessNotFound", err)
	}
}

func TestProcfsInspectProcessPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	f := newFakeProc(t)
	f.write("500/comm", "secret\n")
	if err := os.Chmod(filepath.Join(f.root, "500/comm"), 0); err != nil {
		t.Fatal(err)
	}
	_, err := newProcfsInspector(f.root).InspectProcess(t.Context(), 500)
	if !errors.Is(err, doctor.ErrPermission) {
		t.Errorf("error = %v, want ErrPermission", err)
	}
}

func TestStatusUID(t *testing.T) {
	uid, ok := statusUID("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n")
	if !ok || uid != 1000 {
		t.Errorf("statusUID = %d, %v", uid, ok)
	}
	if _, ok := statusUID("Name:\tx\n"); ok {
		t.Error("missing Uid line should not be ok")
	}
}

func TestSocketInode(t *testing.T) {
	if n, ok := socketInode("socket:[12345]"); !ok || n != 12345 {
		t.Errorf("socketInode = %d, %v", n, ok)
	}
	for _, bad := range []string{"pipe:[1]", "socket:[x]", "socket:[1", "/dev/null"} {
		if _, ok := socketInode(bad); ok {
			t.Errorf("socketInode(%q) ok, want false", bad)
		}
	}
}

func TestLookupUserFallsBackToNumber(t *testing.T) {
	if got := lookupUser(4000000000); got != "4000000000" {
		t.Errorf("lookupUser = %q, want the number", got)
	}
}
