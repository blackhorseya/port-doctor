package inspect

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// netstatModern is `netstat -anv -p tcp` on macOS 26: the process name and
// pid share one column, and the name may contain spaces or be truncated.
const netstatModern = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp6       0      0  ::1.48125              *.*                    LISTEN                 0            0  131072  131072           Python:25873  00000 00000006 000000000900d388 00000000 00000800      1      0 000000
tcp4       0      0  127.0.0.1.48124        *.*                    LISTEN                 0            0  131072  131072           Python:25873  00000 00000006 000000000900d387 00000000 00000800      1      0 000000
tcp46      0      0  *.48123                *.*                    LISTEN                 0            0  131072  131072           Python:25873  00000 00000006 000000000900d386 00000000 00000800      1      0 000000
tcp4       0      0  127.0.0.1.62243        *.*                    LISTEN                 0            0  131072  131072 Code Helper (Plu:17120  00100 00000106 00000000090093f4 00000001 00000800      1      0 000000
tcp46      0      0  *.53137                *.*                    LISTEN                 0            0  131072  131072         rapportd:645    00100 00000006 0000000008fc9431 00000000 00080800      1      0 000000
tcp4       0      0  127.0.0.1.48124        127.0.0.1.64547        ESTABLISHED            0            0  408300  146988           Python:25873  00002 00000004 000000000902ae7c 00000080 01000800      2      0 000000
tcp4       0      0  127.0.0.1.64547        127.0.0.1.48124        ESTABLISHED            0            0  408300  146988           Python:25873  00002 00000000 000000000902ae7b 00000080 04000900      2      0 000000
tcp4       0      0  127.0.0.1.48124        127.0.0.1.64546        TIME_WAIT             52            0  408300  146988           Python:25873  02031 00000004 000000000902ae79 00000080 01000800      0      0 000000
tcp4       0      0  fe80::1%lo0.48126      *.*                    LISTEN                 0            0  131072  131072           Python:25873  00000 00000006 000000000900d389 00000000 00000800      1      0 000000
`

// netstatLegacy is the layout of macOS 12 to 15, with separate pid and
// epid columns.
const netstatLegacy = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat  shiwat    pid   epid  state    options           gencnt    flags   flags1 usscnt rtncnt fltrs
tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN      131072  131072  18432      0 0x0000 0x00000106 000000000000d6f3 00000000 00000800      1      0 000000
tcp6       0      0  *.8080                 *.*                    LISTEN      131072  131072  18432      0 0x0000 0x00000106 000000000000d6f4 00000000 00000800      1      0 000000
tcp4       0      0  127.0.0.1.8080         127.0.0.1.52344        TIME_WAIT   131072  131072      0      0 0x0000 0x00000000 000000000000d6f5 00000000 00000000      0      0 000000
tcp4       0      0  192.168.1.5.8080       *.*                    LISTEN      131072  131072  18500      0 0x0000 0x00000106 000000000000d6f6 00000000 00000800      1      0 000000
tcp4       0      0  127.0.0.1.3000         *.*                    LISTEN      131072  131072    999      0 0x0000 0x00000106 000000000000d6f7 00000000 00000800      1      0 000000
`

// rows parses output and keeps the sockets on port.
func rows(t *testing.T, output string, port int) []netstatRow {
	t.Helper()
	all, err := parseNetstat(strings.NewReader(output))
	if err != nil {
		t.Fatal(err)
	}
	var got []netstatRow
	for _, r := range all {
		if int(r.addr.Port()) == port {
			got = append(got, r)
		}
	}
	return got
}

func TestParseNetstatEveryRow(t *testing.T) {
	all, err := parseNetstat(strings.NewReader(netstatModern))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 9 {
		t.Errorf("rows = %d, want every socket in the fixture (9)", len(all))
	}
}

func TestParseNetstatModern(t *testing.T) {
	got := rows(t, netstatModern, 48124)
	want := []netstatRow{
		{addr: mustAddrPort("127.0.0.1:48124"), state: "LISTEN", pid: 25873},
		{addr: mustAddrPort("127.0.0.1:48124"), state: "ESTABLISHED", pid: 25873},
		{addr: mustAddrPort("127.0.0.1:48124"), state: "TIME_WAIT", pid: 25873},
	}
	assertRows(t, got, want)

	tests := []struct {
		port int
		want netstatRow
	}{
		{62243, netstatRow{addr: mustAddrPort("127.0.0.1:62243"), state: "LISTEN", pid: 17120}}, // name with spaces
		{48123, netstatRow{addr: mustAddrPort("[::]:48123"), state: "LISTEN", pid: 25873}},      // tcp46 wildcard
		{48125, netstatRow{addr: mustAddrPort("[::1]:48125"), state: "LISTEN", pid: 25873}},
		{53137, netstatRow{addr: mustAddrPort("[::]:53137"), state: "LISTEN", pid: 645}},
		{48126, netstatRow{addr: mustAddrPort("[fe80::1%lo0]:48126"), state: "LISTEN", pid: 25873}},
	}
	for _, tt := range tests {
		assertRows(t, rows(t, netstatModern, tt.port), []netstatRow{tt.want})
	}
	if got := rows(t, netstatModern, 64547); len(got) != 1 || got[0].state != "ESTABLISHED" {
		t.Errorf("client side of the connection = %+v", got)
	}
	if got := rows(t, netstatModern, 9999); len(got) != 0 {
		t.Errorf("unused port = %+v", got)
	}
}

func TestParseNetstatLegacy(t *testing.T) {
	got := rows(t, netstatLegacy, 8080)
	want := []netstatRow{
		{addr: mustAddrPort("127.0.0.1:8080"), state: "LISTEN", pid: 18432},
		{addr: mustAddrPort("[::]:8080"), state: "LISTEN", pid: 18432},
		{addr: mustAddrPort("127.0.0.1:8080"), state: "TIME_WAIT", pid: 0},
		{addr: mustAddrPort("192.168.1.5:8080"), state: "LISTEN", pid: 18500},
	}
	assertRows(t, got, want)
}

func TestParseNetstatWithoutPIDColumn(t *testing.T) {
	// An unknown layout still yields the listener, just without a PID.
	output := "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n" +
		"tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN\n"
	got := rows(t, output, 8080)
	assertRows(t, got, []netstatRow{{addr: mustAddrPort("127.0.0.1:8080"), state: "LISTEN"}})
}

func TestColumnsAfterPID(t *testing.T) {
	if got := columnsAfterPID(strings.Fields("Proto Recv-Q Send-Q Local Address Foreign Address (state) rhiwat shiwat pid epid state options gencnt flags flags1 usscnt rtncnt fltrs")); got != 9 {
		t.Errorf("legacy header: %d, want 9", got)
	}
	if got := columnsAfterPID(strings.Fields("Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes rhiwat shiwat process:pid state options gencnt flags flags1 usecnt rtncnt fltrs")); got != 8 {
		t.Errorf("modern header: %d, want 8", got)
	}
	if got := columnsAfterPID(strings.Fields("Proto Local Address")); got != -1 {
		t.Errorf("no pid column: %d, want -1", got)
	}
}

func TestParseNetstatPID(t *testing.T) {
	tests := map[string]int{"18432": 18432, "Python:25873": 25873, "(Plu:17120": 17120, "a:b:7": 7, ":0": 0, "junk": 0, "-5": 0}
	for in, want := range tests {
		if got := parseNetstatPID(in); got != want {
			t.Errorf("parseNetstatPID(%q) = %d, want %d", in, got, want)
		}
	}
}

func assertRows(t *testing.T, got, want []netstatRow) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// fakeRunner replays canned command output keyed by the command name.
type fakeRunner struct {
	outputs map[string][]byte
	errs    map[string]error
	calls   []string
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.outputs[name], f.errs[name]
}

func TestDarwinInspectPort(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"netstat": []byte(netstatModern)}}
	i := newDarwinInspector(r.run)

	info, err := i.InspectPort(t.Context(), 48124)
	if err != nil {
		t.Fatal(err)
	}
	want := []doctor.Listener{{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("127.0.0.1:48124"), PID: 25873}}
	if len(info.Listeners) != 1 || info.Listeners[0] != want[0] {
		t.Errorf("listeners = %+v, want %+v", info.Listeners, want)
	}
	if info.OtherSockets["ESTABLISHED"] != 1 || info.OtherSockets["TIME_WAIT"] != 1 {
		t.Errorf("other sockets = %v", info.OtherSockets)
	}
	if len(r.calls) != 1 || r.calls[0] != "netstat -anv -p tcp" {
		t.Errorf("calls = %q", r.calls)
	}
}

func TestDarwinListListeners(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{"netstat": []byte(netstatModern)}}
	got, err := newDarwinInspector(r.run).ListListeners(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []doctor.Listener{
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[::1]:48125"), PID: 25873},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("127.0.0.1:48124"), PID: 25873},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[::]:48123"), PID: 25873},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("127.0.0.1:62243"), PID: 17120},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[::]:53137"), PID: 645},
		{Protocol: doctor.ProtocolTCP, Addr: mustAddrPort("[fe80::1%lo0]:48126"), PID: 25873},
	}
	if len(got) != len(want) {
		t.Fatalf("listeners = %+v, want %+v (LISTEN rows only)", got, want)
	}
	for n := range want {
		if got[n] != want[n] {
			t.Errorf("listener %d = %+v, want %+v", n, got[n], want[n])
		}
	}
	if len(r.calls) != 1 || r.calls[0] != "netstat -anv -p tcp" {
		t.Errorf("calls = %q, want one netstat", r.calls)
	}

	r = &fakeRunner{outputs: map[string][]byte{"netstat": []byte(netstatLegacy)}}
	got, err = newDarwinInspector(r.run).ListListeners(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, l := range got {
		pids = append(pids, l.PID)
	}
	if want := []int{18432, 18432, 18500, 999}; !slices.Equal(pids, want) {
		t.Errorf("legacy layout PIDs = %v, want %v", pids, want)
	}

	r = &fakeRunner{errs: map[string]error{"netstat": exec.ErrNotFound}}
	if _, err := newDarwinInspector(r.run).ListListeners(t.Context()); err == nil || !strings.Contains(err.Error(), "netstat is not installed") {
		t.Errorf("missing netstat: %v", err)
	}
}

func TestDarwinInspectPortErrors(t *testing.T) {
	r := &fakeRunner{errs: map[string]error{"netstat": exec.ErrNotFound}}
	_, err := newDarwinInspector(r.run).InspectPort(t.Context(), 1)
	if err == nil || !strings.Contains(err.Error(), "netstat is not installed") {
		t.Errorf("missing netstat: %v", err)
	}

	r = &fakeRunner{errs: map[string]error{"netstat": &exec.ExitError{Stderr: []byte("netstat: kvm_open: permission denied\n")}}}
	_, err = newDarwinInspector(r.run).InspectPort(t.Context(), 1)
	if err == nil || err.Error() != "netstat failed: netstat: kvm_open: permission denied" {
		t.Errorf("failing netstat: %v", err)
	}
}

func TestDarwinContextErrorWins(t *testing.T) {
	// exec reports "signal: killed" for a command cut off by the deadline;
	// the context error must surface instead so the CLI can say "timed out".
	c, cancel := context.WithCancel(t.Context())
	cancel()
	killed := &exec.ExitError{}
	r := &fakeRunner{errs: map[string]error{"netstat": killed, "ps": killed}}
	i := newDarwinInspector(r.run)

	if _, err := i.InspectPort(c, 8080); !errors.Is(err, context.Canceled) {
		t.Errorf("InspectPort error = %v, want context.Canceled", err)
	}
	if _, err := i.InspectProcess(c, 1); !errors.Is(err, context.Canceled) {
		t.Errorf("InspectProcess error = %v, want context.Canceled", err)
	}
	if _, err := i.ListListeners(c); !errors.Is(err, context.Canceled) {
		t.Errorf("ListListeners error = %v, want context.Canceled", err)
	}
}

func TestDarwinInspectProcess(t *testing.T) {
	r := &fakeRunner{outputs: map[string][]byte{
		"ps": []byte("  501 /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)\n"),
	}}
	i := newDarwinInspector(r.run)

	p, err := i.InspectProcess(t.Context(), 17120)
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != 17120 || p.Name != "Code Helper (Plugin)" || p.User != lookupUser(501) {
		t.Errorf("process = %+v", p)
	}
	if r.calls[0] != "ps -p 17120 -o uid=,comm=" {
		t.Errorf("calls = %q", r.calls)
	}

	r = &fakeRunner{outputs: map[string][]byte{"ps": []byte("    0 /sbin/launchd\n")}}
	if p, err := newDarwinInspector(r.run).InspectProcess(t.Context(), 1); err != nil || p.Name != "launchd" || p.User != "root" {
		t.Errorf("launchd: %+v, %v", p, err)
	}
}

func TestDarwinInspectProcessGone(t *testing.T) {
	// ps exits 1 and prints nothing for a PID that does not exist.
	r := &fakeRunner{errs: map[string]error{"ps": &exec.ExitError{Stderr: []byte("ps: process id too large: 4194304")}}}
	_, err := newDarwinInspector(r.run).InspectProcess(t.Context(), 4194304)
	if !errors.Is(err, doctor.ErrProcessNotFound) {
		t.Errorf("error = %v, want ErrProcessNotFound", err)
	}

	r = &fakeRunner{outputs: map[string][]byte{"ps": []byte("\n")}}
	if _, err := newDarwinInspector(r.run).InspectProcess(t.Context(), 7); !errors.Is(err, doctor.ErrProcessNotFound) {
		t.Errorf("empty output: %v, want ErrProcessNotFound", err)
	}
}
