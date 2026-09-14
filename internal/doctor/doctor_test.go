package doctor

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type fakePorts struct {
	info PortInfo
	err  error
}

func (f fakePorts) InspectPort(context.Context, int) (PortInfo, error) {
	return f.info, f.err
}

type fakeProcs struct {
	procs map[int]Process
	errs  map[int]error
}

func (f fakeProcs) InspectProcess(_ context.Context, pid int) (Process, error) {
	if err, ok := f.errs[pid]; ok {
		return Process{}, err
	}
	if p, ok := f.procs[pid]; ok {
		return p, nil
	}
	return Process{}, ErrProcessNotFound
}

func listener(addr string, pid int) Listener {
	return Listener{Protocol: ProtocolTCP, Addr: netip.MustParseAddrPort(addr), PID: pid}
}

func elevated(port int) string {
	return "sudo inspect " + strconv.Itoa(port)
}

func diagnose(t *testing.T, info PortInfo, procs fakeProcs) Report {
	t.Helper()
	x := &Doctor{Ports: fakePorts{info: info}, Processes: procs, ElevatedInspectCommand: elevated}
	r, err := x.Diagnose(t.Context(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr error // sentinel to match, or nil
		invalid bool  // expect the "invalid port" error
	}{
		{in: "8080", want: 8080},
		{in: "1", want: 1},
		{in: "65535", want: 65535},
		{in: " 443 ", want: 443},
		{in: "0", wantErr: ErrPortRange},
		{in: "65536", wantErr: ErrPortRange},
		{in: "-1", wantErr: ErrPortRange},
		{in: "99999999999999999999", wantErr: ErrPortRange},
		{in: "abc", invalid: true},
		{in: "", invalid: true},
		{in: "8080abc", invalid: true},
		{in: "80.80", invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParsePort(tt.in)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParsePort(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
			case tt.invalid:
				if err == nil || !strings.Contains(err.Error(), "invalid port") {
					t.Fatalf("ParsePort(%q) error = %v, want invalid port", tt.in, err)
				}
			default:
				if err != nil || got != tt.want {
					t.Fatalf("ParsePort(%q) = %d, %v, want %d", tt.in, got, err, tt.want)
				}
			}
		})
	}
}

func TestDiagnoseAvailable(t *testing.T) {
	r := diagnose(t, PortInfo{}, fakeProcs{})
	if r.Status != StatusAvailable {
		t.Fatalf("status = %v, want available", r.Status)
	}
	if len(r.Occupants) != 0 || len(r.Suggestions) != 0 || len(r.Notes) != 0 || r.Diagnosis != "" {
		t.Fatalf("available report should be empty, got %+v", r)
	}
}

func TestDiagnoseAvailableWithLingeringSockets(t *testing.T) {
	r := diagnose(t, PortInfo{OtherSockets: map[string]int{"TIME_WAIT": 3, "CLOSE_WAIT": 1}}, fakeProcs{})
	if r.Status != StatusAvailable {
		t.Fatalf("status = %v, want available", r.Status)
	}
	want := []string{"No process is listening, but 4 sockets still use port 8080 (1 CLOSE_WAIT, 3 TIME_WAIT). A new listener may fail to bind until they close."}
	if !slices.Equal(r.Notes, want) {
		t.Fatalf("notes = %q, want %q", r.Notes, want)
	}

	r = diagnose(t, PortInfo{OtherSockets: map[string]int{"TIME_WAIT": 1}}, fakeProcs{})
	if !strings.HasPrefix(r.Notes[0], "No process is listening, but 1 socket still uses port 8080 (1 TIME_WAIT).") {
		t.Fatalf("singular note = %q", r.Notes[0])
	}
}

func TestDiagnoseInUse(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("0.0.0.0:8080", 18432)}}
	procs := fakeProcs{procs: map[int]Process{18432: {PID: 18432, Name: "api-server", User: "sean"}}}
	r := diagnose(t, info, procs)

	if r.Status != StatusInUse {
		t.Fatalf("status = %v, want in use", r.Status)
	}
	if len(r.Occupants) != 1 {
		t.Fatalf("occupants = %+v, want one", r.Occupants)
	}
	occ := r.Occupants[0]
	if occ.Process != (Process{PID: 18432, Name: "api-server", User: "sean"}) || occ.Exited {
		t.Errorf("process = %+v, exited = %v", occ.Process, occ.Exited)
	}
	if r.Diagnosis != "Another process is listening on port 8080 (all interfaces)." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	want := []Suggestion{
		{Title: "Inspect", Commands: []string{"ps -p 18432"}},
		{Title: "Stop", Commands: []string{"kill 18432"}},
	}
	assertSuggestions(t, r.Suggestions, want)
	if len(r.Notes) != 0 {
		t.Errorf("notes = %q, want none", r.Notes)
	}
}

func TestDiagnoseScope(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  string
	}{
		{"localhost v4", []string{"127.0.0.1:8080"}, "(localhost only)"},
		{"localhost v4 and v6", []string{"127.0.0.1:8080", "[::1]:8080"}, "(localhost only)"},
		{"wildcard v6", []string{"[::]:8080"}, "(all interfaces)"},
		{"wildcard among specific", []string{"127.0.0.1:8080", "0.0.0.0:8080"}, "(all interfaces)"},
		{"mapped wildcard", []string{"[::ffff:0.0.0.0]:8080"}, "(all interfaces)"},
		{"one specific interface", []string{"192.168.1.5:8080"}, "(192.168.1.5 only)"},
		{"several specific interfaces", []string{"192.168.1.5:8080", "10.0.0.2:8080"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ls []Listener
			for _, a := range tt.addrs {
				ls = append(ls, listener(a, 7))
			}
			r := diagnose(t, PortInfo{Listeners: ls}, fakeProcs{procs: map[int]Process{7: {PID: 7, Name: "x"}}})
			want := "Another process is listening on port 8080" + strings.TrimSuffix(" "+tt.want, " ") + "."
			if r.Diagnosis != want {
				t.Errorf("diagnosis = %q, want %q", r.Diagnosis, want)
			}
		})
	}
}

func TestDiagnoseSortsListenersAndOccupants(t *testing.T) {
	info := PortInfo{Listeners: []Listener{
		listener("[::1]:8080", 300),
		listener("10.0.0.2:8080", 100),
		listener("127.0.0.1:8080", 300),
	}}
	procs := fakeProcs{procs: map[int]Process{100: {Name: "a"}, 300: {Name: "b"}}}
	r := diagnose(t, info, procs)

	if len(r.Occupants) != 2 || r.Occupants[0].Process.PID != 100 || r.Occupants[1].Process.PID != 300 {
		t.Fatalf("occupants not ordered by PID: %+v", r.Occupants)
	}
	got := []string{r.Occupants[1].Listeners[0].Addr.String(), r.Occupants[1].Listeners[1].Addr.String()}
	if !slices.Equal(got, []string{"127.0.0.1:8080", "[::1]:8080"}) {
		t.Errorf("listeners not ordered IPv4 first: %v", got)
	}
	if r.Diagnosis != "2 processes are listening on port 8080." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"ps -p 100", "ps -p 300"}},
		{Title: "Stop", Commands: []string{"kill 100", "kill 300"}},
	})
}

func TestDiagnoseUnknownPID(t *testing.T) {
	info := PortInfo{Listeners: []Listener{{Protocol: ProtocolTCP, Addr: netip.MustParseAddrPort("0.0.0.0:8080"), User: "root"}}}
	r := diagnose(t, info, fakeProcs{})

	occ := r.Occupants[0]
	if occ.Process.PID != 0 || occ.Process.User != "root" || occ.Process.Name != "" {
		t.Errorf("process = %+v", occ.Process)
	}
	if r.Diagnosis != "A process is listening on port 8080 (all interfaces), but it could not be identified." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Identify (needs elevated privileges)", Commands: []string{"sudo inspect 8080"}},
	})
	want := []string{"The listening process could not be identified, usually because it belongs to another user."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q", r.Notes)
	}
}

func TestDiagnoseUnknownPIDWithoutElevatedCommand(t *testing.T) {
	x := &Doctor{Ports: fakePorts{info: PortInfo{Listeners: []Listener{listener("0.0.0.0:8080", 0)}}}, Processes: fakeProcs{}}
	r, err := x.Diagnose(t.Context(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Suggestions) != 0 {
		t.Errorf("suggestions = %+v, want none", r.Suggestions)
	}
}

func TestDiagnoseUnknownPIDListedLast(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("[::]:8080", 0), listener("127.0.0.1:8080", 42)}}
	r := diagnose(t, info, fakeProcs{procs: map[int]Process{42: {Name: "dev"}}})
	if r.Occupants[0].Process.PID != 42 || r.Occupants[1].Process.PID != 0 {
		t.Errorf("unknown occupant should come last: %+v", r.Occupants)
	}
}

func TestDiagnoseProcessExited(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("127.0.0.1:8080", 5)}}
	r := diagnose(t, info, fakeProcs{errs: map[int]error{5: ErrProcessNotFound}})

	if r.Status != StatusInUse {
		t.Fatalf("status = %v, want in use (the listing saw a listener)", r.Status)
	}
	if !r.Occupants[0].Exited {
		t.Error("occupant should be marked exited")
	}
	if len(r.Suggestions) != 0 {
		t.Errorf("suggestions = %+v, want none for a dead PID", r.Suggestions)
	}
	want := []string{"Process 5 exited during inspection, so the port may be free now. Run port-doctor again to confirm."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q", r.Notes)
	}
}

func TestDiagnoseProcessPermissionDenied(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("127.0.0.1:8080", 5), listener("[::1]:8080", 5)}}
	r := diagnose(t, info, fakeProcs{errs: map[int]error{5: ErrPermission}})

	if r.Occupants[0].Process != (Process{PID: 5}) {
		t.Errorf("process = %+v, want bare PID", r.Occupants[0].Process)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"ps -p 5"}},
		{Title: "Stop", Commands: []string{"kill 5"}},
	})
	want := []string{"Some process information could not be read due to permissions."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q (must not repeat per listener)", r.Notes)
	}
}

func TestDiagnoseProcessUnexpectedError(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("127.0.0.1:8080", 5)}}
	r := diagnose(t, info, fakeProcs{errs: map[int]error{5: errors.New("boom")}})
	want := []string{"Process information for PID 5 could not be read."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q", r.Notes)
	}
}

func TestDiagnoseUserFallsBackToListenerOwner(t *testing.T) {
	l := listener("127.0.0.1:8080", 5)
	l.User = "postgres"
	r := diagnose(t, PortInfo{Listeners: []Listener{l}}, fakeProcs{procs: map[int]Process{5: {Name: "postgres"}}})
	if r.Occupants[0].Process.User != "postgres" {
		t.Errorf("user = %q, want the socket owner", r.Occupants[0].Process.User)
	}
}

func TestDiagnosePortInspectorError(t *testing.T) {
	boom := errors.New("boom")
	x := &Doctor{Ports: fakePorts{err: boom}, Processes: fakeProcs{}}
	_, err := x.Diagnose(t.Context(), 8080)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want wrapped boom", err)
	}
	if !strings.Contains(err.Error(), "inspect port 8080") {
		t.Errorf("error = %q, want context", err)
	}
}

func assertSuggestions(t *testing.T, got, want []Suggestion) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("suggestions = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Title != want[i].Title || !slices.Equal(got[i].Commands, want[i].Commands) {
			t.Errorf("suggestion %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
