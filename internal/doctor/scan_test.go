package doctor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

type fakeListeners struct {
	ls  []Listener
	err error
}

func (f fakeListeners) ListListeners(context.Context) ([]Listener, error) {
	return f.ls, f.err
}

// countingProcs records how often each PID is looked up, so the
// once-per-PID rule can be pinned.
type countingProcs struct {
	fakeProcs
	calls map[int]int
}

func (f *countingProcs) InspectProcess(c context.Context, pid int) (Process, error) {
	f.calls[pid]++
	return f.fakeProcs.InspectProcess(c, pid)
}

func scan(t *testing.T, ls []Listener, procs ProcessInspector, containers ContainerLister) Overview {
	t.Helper()
	x := &Doctor{Ports: fakePorts{}, Processes: procs, Listeners: fakeListeners{ls: ls}, AllContainers: containers}
	o, err := x.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// rowLine flattens a row for comparison: port, bind, pid, name, user and
// the container names.
func rowLine(r Row) string {
	var cts []string
	for _, ct := range r.Containers {
		cts = append(cts, ct.Name)
	}
	name := r.Process.Name
	if r.Exited {
		name = "(exited)"
	}
	return strings.TrimRight(fmt.Sprintf("%d %s %d %s %s [%s]", r.Port, r.Bind, r.Process.PID, name, r.Process.User, strings.Join(cts, ",")), " ")
}

func assertRows(t *testing.T, rows []Row, want []string) {
	t.Helper()
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, rowLine(r))
	}
	if !slices.Equal(got, want) {
		t.Errorf("rows =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func assertNotes(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("notes = %q, want %q", got, want)
	}
}

func userListener(addr string, pid int, user string) Listener {
	l := listener(addr, pid)
	l.User = user
	return l
}

func TestScanEmpty(t *testing.T) {
	o := scan(t, nil, fakeProcs{}, nil)
	if len(o.Rows) != 0 || len(o.Notes) != 0 {
		t.Fatalf("overview = %+v, want empty", o)
	}
}

func TestScanOneRowPerPortAndProcess(t *testing.T) {
	ls := []Listener{
		listener("[::]:8080", 100),
		listener("0.0.0.0:8080", 100),
		listener("[::1]:3000", 200),
		listener("127.0.0.1:3000", 200),
		listener("192.168.1.5:443", 300),
		listener("192.168.1.5:9000", 300),
		listener("10.0.0.1:9000", 300),
	}
	procs := &countingProcs{
		fakeProcs: fakeProcs{procs: map[int]Process{
			100: {PID: 100, Name: "api-server", User: "sean"},
			200: {PID: 200, Name: "node", User: "sean"},
			300: {PID: 300, Name: "nginx", User: "root"},
		}},
		calls: map[int]int{},
	}
	o := scan(t, ls, procs, nil)

	assertRows(t, o.Rows, []string{
		"443 192.168.1.5 300 nginx root []",
		"3000 localhost 200 node sean []",
		"8080 all 100 api-server sean []",
		"9000 10.0.0.1,192.168.1.5 300 nginx root []",
	})
	assertNotes(t, o.Notes, nil)
	if got := o.Rows[2].Listeners; len(got) != 2 || got[0].Addr.String() != "0.0.0.0:8080" || got[1].Addr.String() != "[::]:8080" {
		t.Errorf("8080 listeners = %+v, want IPv4 first", got)
	}
	if procs.calls[300] != 1 {
		t.Errorf("PID 300 looked up %d times, want once for its two ports", procs.calls[300])
	}
}

func TestScanKeepsProcessesApart(t *testing.T) {
	ls := []Listener{
		listener("127.0.0.1:8080", 200),
		listener("[::1]:8080", 100),
	}
	procs := fakeProcs{procs: map[int]Process{
		100: {PID: 100, Name: "a", User: "sean"},
		200: {PID: 200, Name: "b", User: "sean"},
	}}
	o := scan(t, ls, procs, nil)
	assertRows(t, o.Rows, []string{
		"8080 localhost 100 a sean []",
		"8080 localhost 200 b sean []",
	})
}

func TestScanUnidentifiedShareOneRowPerPort(t *testing.T) {
	// Linux: two root-owned listeners procfs cannot attribute (docker-proxy
	// per address family, or any other user's server) plus one of our own.
	ls := []Listener{
		userListener("[::]:80", 0, "root"),
		userListener("0.0.0.0:80", 0, "root"),
		userListener("127.0.0.1:80", 100, "sean"),
		userListener("[::]:443", 0, "root"),
	}
	procs := fakeProcs{procs: map[int]Process{100: {PID: 100, Name: "dev-proxy", User: "sean"}}}
	o := scan(t, ls, procs, nil)

	assertRows(t, o.Rows, []string{
		"80 localhost 100 dev-proxy sean []",
		"80 all 0  root []",
		"443 all 0  root []",
	})
	assertNotes(t, o.Notes, []string{"2 ports are held by processes that could not be identified, usually because they belong to another user."})

	o = scan(t, ls[:2], procs, nil)
	assertNotes(t, o.Notes, []string{"1 port is held by a process that could not be identified, usually because it belongs to another user."})
}

func TestScanProcessNotes(t *testing.T) {
	ls := []Listener{
		listener("127.0.0.1:3000", 7),
		listener("127.0.0.1:3001", 7),
		listener("127.0.0.1:4000", 8),
		listener("127.0.0.1:5000", 9),
	}
	procs := &countingProcs{
		fakeProcs: fakeProcs{errs: map[int]error{8: ErrPermission, 9: errors.New("boom")}}, // 7 is gone
		calls:     map[int]int{},
	}
	o := scan(t, ls, procs, nil)

	assertRows(t, o.Rows, []string{
		"3000 localhost 7 (exited)  []",
		"3001 localhost 7 (exited)  []",
		"4000 localhost 8   []",
		"5000 localhost 9   []",
	})
	assertNotes(t, o.Notes, []string{
		"Process 7 exited during the scan, so its ports may be free now.",
		"Some process information could not be read due to permissions.",
		"Process information for PID 9 could not be read.",
	})
	if procs.calls[7] != 1 {
		t.Errorf("PID 7 looked up %d times, want once", procs.calls[7])
	}
}

func TestScanContainers(t *testing.T) {
	ls := []Listener{
		listener("[::]:5432", 3189),
		listener("[::]:6379", 3189),
		userListener("[::]:80", 0, "root"),
		userListener("0.0.0.0:80", 0, "root"),
		userListener("[::]:443", 0, "root"),
	}
	web := container("docker", "web", mapping("0.0.0.0:80", 80), mapping("[::]:80", 80), mapping("0.0.0.0:443", 443), mapping("[::]:443", 443))
	cs := []Container{
		container("podman", "redis-dev", mapping("0.0.0.0:6379", 6379)),
		container("podman", "postgres-dev", mapping("0.0.0.0:5432", 5432)),
		web,
		container("docker", "api-b", mapping("0.0.0.0:9000", 8080), mapping("[::]:9000", 8080)),
		container("docker", "api-a", mapping("127.0.0.1:9000", 8080)),
	}
	o := scan(t, ls, gvproxy, fakeContainers{cs: cs})

	assertRows(t, o.Rows, []string{
		"80 all 0  root [web]",
		"443 all 0  root [web]",
		"5432 all 3189 gvproxy sean [postgres-dev]",
		"6379 all 3189 gvproxy sean [redis-dev]",
		"9000 all 0   [api-a,api-b]",
	})
	assertNotes(t, o.Notes, nil) // the container explains the root-owned listeners

	for _, r := range o.Rows[:2] {
		for _, m := range r.Containers[0].Mappings {
			if int(m.Host.Port()) != r.Port {
				t.Errorf("row %d carries mapping %+v of another port", r.Port, m)
			}
		}
		if len(r.Containers[0].Mappings) != 2 {
			t.Errorf("row %d mappings = %+v, want both address families", r.Port, r.Containers[0].Mappings)
		}
	}
	if len(web.Mappings) != 4 {
		t.Errorf("the caller's container was modified: %+v", web.Mappings)
	}
	if r := o.Rows[4]; len(r.Listeners) != 0 || r.Process != (Process{}) || r.Exited {
		t.Errorf("container-only row = %+v, want no listeners and a zero process", r)
	}
}

func TestScanContainerNotes(t *testing.T) {
	tests := []struct {
		name string
		cs   []Container
		err  error
		want string
	}{
		{"failed", nil, errors.New("/var/run/docker.sock: boom"), "Containers were not checked: /var/run/docker.sock: boom."},
		{"partial", []Container{container("docker", "web", mapping("0.0.0.0:80", 80))}, errors.New("/run/podman/podman.sock: boom"), "Some containers may be missing: /run/podman/podman.sock: boom."},
		{"permission", nil, fmt.Errorf("/run/podman/podman.sock: %w", ErrPermission), "Containers were not checked: /run/podman/podman.sock: permission denied. Only a user with access to the runtime socket can see them."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := scan(t, nil, fakeProcs{}, fakeContainers{cs: tt.cs, err: tt.err})
			assertNotes(t, o.Notes, []string{tt.want})
			if len(o.Rows) != len(tt.cs) {
				t.Errorf("rows = %+v, want one per container", o.Rows)
			}
		})
	}
}

func TestScanListError(t *testing.T) {
	x := &Doctor{Ports: fakePorts{}, Processes: fakeProcs{}, Listeners: fakeListeners{err: errors.New("netstat failed")}}
	_, err := x.Scan(t.Context())
	if err == nil || err.Error() != "list listeners: netstat failed" {
		t.Errorf("error = %v", err)
	}

	x = &Doctor{Ports: fakePorts{}, Processes: fakeProcs{}}
	if _, err := x.Scan(t.Context()); err == nil {
		t.Error("a doctor without a listener inspector should refuse to scan")
	}
}

func TestScanStopsWhenContextEnds(t *testing.T) {
	c, cancel := context.WithCancel(t.Context())
	cancel()
	x := &Doctor{
		Ports:     fakePorts{},
		Processes: fakeProcs{procs: map[int]Process{100: {PID: 100, Name: "a"}}},
		Listeners: fakeListeners{ls: []Listener{listener("127.0.0.1:1", 100), listener("127.0.0.1:2", 200)}},
	}
	if _, err := x.Scan(c); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestBind(t *testing.T) {
	tests := []struct {
		addrs []string
		want  string
	}{
		{[]string{"0.0.0.0"}, "all"},
		{[]string{"::"}, "all"},
		{[]string{"::ffff:0.0.0.0"}, "all"},
		{[]string{"127.0.0.1", "::"}, "all"},
		{[]string{"127.0.0.1"}, "localhost"},
		{[]string{"127.0.0.1", "::1"}, "localhost"},
		{[]string{"192.168.1.5"}, "192.168.1.5"},
		{[]string{"192.168.1.5", "192.168.1.5"}, "192.168.1.5"},
		{[]string{"192.168.1.5", "10.0.0.1"}, "10.0.0.1,192.168.1.5"},
		{[]string{"127.0.0.1", "192.168.1.5"}, "127.0.0.1,192.168.1.5"},
		{[]string{"fe80::1%lo0"}, "fe80::1%lo0"},
	}
	for _, tt := range tests {
		addrs := make([]netip.Addr, 0, len(tt.addrs))
		for _, a := range tt.addrs {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		if got := bind(addrs); got != tt.want {
			t.Errorf("bind(%v) = %q, want %q", tt.addrs, got, tt.want)
		}
	}
}
