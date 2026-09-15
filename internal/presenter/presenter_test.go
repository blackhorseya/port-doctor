package presenter

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

func render(t *testing.T, r doctor.Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func listener(addr string, pid int) doctor.Listener {
	return doctor.Listener{Protocol: doctor.ProtocolTCP, Addr: netip.MustParseAddrPort(addr), PID: pid}
}

func mapping(host string, containerPort int) doctor.PortMapping {
	return doctor.PortMapping{Host: netip.MustParseAddrPort(host), ContainerPort: containerPort, Protocol: doctor.ProtocolTCP}
}

func TestRenderAvailable(t *testing.T) {
	got := render(t, doctor.Report{Port: 8080, Status: doctor.StatusAvailable})
	want := "✓ Port 8080 is available\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderAvailableWithNote(t *testing.T) {
	got := render(t, doctor.Report{
		Port:   8080,
		Status: doctor.StatusAvailable,
		Notes:  []string{"No process is listening, but 2 sockets still use port 8080 (2 TIME_WAIT). A new listener may fail to bind until they close."},
	})
	want := `✓ Port 8080 is available

No process is listening, but 2 sockets still use port 8080 (2 TIME_WAIT). A new listener may fail to bind until they close.
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderInUse(t *testing.T) {
	got := render(t, doctor.Report{
		Port:   8080,
		Status: doctor.StatusInUse,
		Occupants: []doctor.Occupant{{
			Process:   doctor.Process{PID: 18432, Name: "api-server", User: "sean"},
			Listeners: []doctor.Listener{listener("0.0.0.0:8080", 18432)},
		}},
		Diagnosis: "Another process is listening on port 8080 (all interfaces).",
		Suggestions: []doctor.Suggestion{
			{Title: "Inspect", Commands: []string{"ps -p 18432"}},
			{Title: "Stop", Commands: []string{"kill 18432"}},
		},
	})
	want := `✗ Port 8080 is in use

Process
  PID       18432
  Name      api-server
  User      sean

Network
  Protocol  TCP
  Address   0.0.0.0:8080

Diagnosis
  Another process is listening on port 8080 (all interfaces).

Suggestions
  Inspect:
    ps -p 18432

  Stop:
    kill 18432
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderDegraded(t *testing.T) {
	got := render(t, doctor.Report{
		Port:   80,
		Status: doctor.StatusInUse,
		Occupants: []doctor.Occupant{
			{
				Process:   doctor.Process{PID: 18432},
				Listeners: []doctor.Listener{listener("127.0.0.1:80", 18432), listener("[::1]:80", 18432)},
			},
			{
				Process:   doctor.Process{User: "root"},
				Listeners: []doctor.Listener{listener("[::]:80", 0)},
			},
		},
		Diagnosis: "2 processes are listening on port 80.",
		Suggestions: []doctor.Suggestion{
			{Title: "Inspect", Commands: []string{"ps -p 18432"}},
			{Title: "Stop", Commands: []string{"kill 18432"}},
			{Title: "Identify (needs elevated privileges)", Commands: []string{"sudo ss -ltnp 'sport = :80'"}},
		},
		Notes: []string{
			"Some process information could not be read due to permissions.",
			"The listening process could not be identified, usually because it belongs to another user.",
		},
	})
	want := `✗ Port 80 is in use

Process
  PID       18432
  Name      unavailable
  User      unavailable

Network
  Protocol  TCP
  Address   127.0.0.1:80
  Address   [::1]:80

Process
  PID       unknown
  Name      unavailable
  User      root

Network
  Protocol  TCP
  Address   [::]:80

Diagnosis
  2 processes are listening on port 80.

Suggestions
  Inspect:
    ps -p 18432

  Stop:
    kill 18432

  Identify (needs elevated privileges):
    sudo ss -ltnp 'sport = :80'

Some process information could not be read due to permissions.
The listening process could not be identified, usually because it belongs to another user.
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderExited(t *testing.T) {
	got := render(t, doctor.Report{
		Port:   3000,
		Status: doctor.StatusInUse,
		Occupants: []doctor.Occupant{{
			Process:   doctor.Process{PID: 7},
			Exited:    true,
			Listeners: []doctor.Listener{listener("127.0.0.1:3000", 7)},
		}},
		Diagnosis: "Another process is listening on port 3000 (localhost only).",
		Notes:     []string{"Process 7 exited during inspection, so the port may be free now. Run port-doctor again to confirm."},
	})
	want := `✗ Port 3000 is in use

Process
  PID       7
  Name      unavailable (process exited)
  User      unavailable

Network
  Protocol  TCP
  Address   127.0.0.1:3000

Diagnosis
  Another process is listening on port 3000 (localhost only).

Process 7 exited during inspection, so the port may be free now. Run port-doctor again to confirm.
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderContainer(t *testing.T) {
	got := render(t, doctor.Report{
		Port:   5432,
		Status: doctor.StatusInUse,
		Occupants: []doctor.Occupant{{
			Process:   doctor.Process{PID: 3189, Name: "gvproxy", User: "sean"},
			Listeners: []doctor.Listener{listener("[::]:5432", 3189)},
		}},
		Containers: []doctor.Container{{
			Runtime:  "podman",
			ID:       "5f9709733f64",
			Name:     "demo-db-1",
			Image:    "docker.io/library/postgres:17",
			Mappings: []doctor.PortMapping{mapping("0.0.0.0:5432", 5432)},
			Compose:  doctor.ComposeService{Project: "demo", Service: "db"},
		}},
		Diagnosis: "Container demo-db-1 (podman) publishes port 5432 (all interfaces).",
		Suggestions: []doctor.Suggestion{
			{Title: "Inspect", Commands: []string{"podman logs --tail 20 demo-db-1"}},
			{Title: "Stop", Commands: []string{"podman compose -p demo stop db"}},
		},
	})
	want := `✗ Port 5432 is in use

Process
  PID       3189
  Name      gvproxy
  User      sean

Network
  Protocol  TCP
  Address   [::]:5432

Container
  Runtime   podman
  Name      demo-db-1
  Image     docker.io/library/postgres:17
  Compose   demo / db
  Mapping   0.0.0.0:5432 → 5432/tcp

Diagnosis
  Container demo-db-1 (podman) publishes port 5432 (all interfaces).

Suggestions
  Inspect:
    podman logs --tail 20 demo-db-1

  Stop:
    podman compose -p demo stop db
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderContainerWithoutListener(t *testing.T) {
	got := render(t, doctor.Report{
		Port:   8080,
		Status: doctor.StatusInUse,
		Containers: []doctor.Container{{
			Runtime:  "docker",
			ID:       "1d0dc789506e",
			Name:     "web",
			Image:    "nginx:1.27",
			Mappings: []doctor.PortMapping{mapping("0.0.0.0:8080", 80), mapping("[::]:8080", 80)},
		}},
		Diagnosis: "Container web (docker) publishes port 8080 (all interfaces); no host process is listening, so the runtime forwards the traffic itself.",
		Suggestions: []doctor.Suggestion{
			{Title: "Inspect", Commands: []string{"docker logs --tail 20 web"}},
			{Title: "Stop", Commands: []string{"docker stop web"}},
		},
		Notes: []string{"Some containers may be missing: /run/podman/podman.sock: permission denied. Only a user with access to the runtime socket can see them."},
	})
	want := `✗ Port 8080 is in use

Container
  Runtime   docker
  Name      web
  Image     nginx:1.27
  Mapping   0.0.0.0:8080 → 80/tcp
  Mapping   [::]:8080 → 80/tcp

Diagnosis
  Container web (docker) publishes port 8080 (all interfaces); no host process is listening, so the runtime forwards the traffic itself.

Suggestions
  Inspect:
    docker logs --tail 20 web

  Stop:
    docker stop web

Some containers may be missing: /run/podman/podman.sock: permission denied. Only a user with access to the runtime socket can see them.
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func renderOverview(t *testing.T, o doctor.Overview) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderOverview(&buf, o); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func overviewRows() []doctor.Row {
	return []doctor.Row{
		{Port: 443, Bind: "all", Process: doctor.Process{PID: 23693, Name: "io.tailscale.ipn", User: "root"}, Listeners: []doctor.Listener{listener("[::]:443", 23693)}},
		{Port: 3000, Bind: "localhost", Process: doctor.Process{PID: 7}, Exited: true, Listeners: []doctor.Listener{listener("127.0.0.1:3000", 7)}},
		{Port: 5000, Bind: "all", Process: doctor.Process{PID: 1253, Name: "ControlCenter", User: "sean"}, Listeners: []doctor.Listener{listener("0.0.0.0:5000", 1253), listener("[::]:5000", 1253)}},
		{
			Port: 5432, Bind: "all", Process: doctor.Process{PID: 3189, Name: "gvproxy", User: "sean"},
			Listeners:  []doctor.Listener{listener("[::]:5432", 3189)},
			Containers: []doctor.Container{{Runtime: "podman", ID: "5f9709733f64", Name: "postgres-dev", Image: "postgres:17", Mappings: []doctor.PortMapping{mapping("0.0.0.0:5432", 5432)}}},
		},
		{
			Port: 6379, Bind: "all",
			Containers: []doctor.Container{{Runtime: "docker", ID: "1d0dc789506e", Name: "redis-dev", Image: "redis:7", Mappings: []doctor.PortMapping{mapping("0.0.0.0:6379", 6379), mapping("[::]:6379", 6379)}}},
		},
		{Port: 8080, Bind: "localhost", Process: doctor.Process{PID: 41022, Name: "node", User: "sean"}, Listeners: []doctor.Listener{listener("127.0.0.1:8080", 41022)}},
		{
			Port: 9000, Bind: "10.0.0.1,192.168.1.5", Process: doctor.Process{User: "root"},
			Listeners: []doctor.Listener{listener("10.0.0.1:9000", 0), listener("192.168.1.5:9000", 0)},
			Containers: []doctor.Container{
				{Runtime: "docker", ID: "aaaaaaaaaaaa", Name: "api-a", Mappings: []doctor.PortMapping{mapping("10.0.0.1:9000", 8080)}},
				{Runtime: "docker", ID: "bbbbbbbbbbbb", Name: "api-b", Mappings: []doctor.PortMapping{mapping("192.168.1.5:9000", 8080)}},
			},
		},
	}
}

const overviewGolden = `PORT  BIND                  PID    PROCESS           USER  CONTAINER
443   all                   23693  io.tailscale.ipn  root
3000  localhost             7      (exited)          -
5000  all                   1253   ControlCenter     sean
5432  all                   3189   gvproxy           sean  postgres-dev (podman)
6379  all                   -      -                 -     redis-dev (docker)
8080  localhost             41022  node              sean
9000  10.0.0.1,192.168.1.5  -      -                 root  api-a (docker), api-b (docker)
`

func TestRenderOverview(t *testing.T) {
	got := renderOverview(t, doctor.Overview{Rows: overviewRows()})
	if got != overviewGolden {
		t.Errorf("got:\n%s\nwant:\n%s", got, overviewGolden)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasSuffix(line, " ") {
			t.Errorf("trailing spaces in %q", line)
		}
	}
}

func TestRenderOverviewWithNotes(t *testing.T) {
	got := renderOverview(t, doctor.Overview{
		Rows: overviewRows()[:1],
		Notes: []string{
			"2 ports are held by processes that could not be identified, usually because they belong to another user.",
			"Containers were not checked: /var/run/docker.sock: permission denied. Only a user with access to the runtime socket can see them.",
		},
	})
	want := `PORT  BIND  PID    PROCESS           USER  CONTAINER
443   all   23693  io.tailscale.ipn  root

2 ports are held by processes that could not be identified, usually because they belong to another user.
Containers were not checked: /var/run/docker.sock: permission denied. Only a user with access to the runtime socket can see them.
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderOverviewEmpty(t *testing.T) {
	if got := renderOverview(t, doctor.Overview{}); got != "No TCP port is listening.\n" {
		t.Errorf("got %q", got)
	}
	got := renderOverview(t, doctor.Overview{Notes: []string{"Containers were not checked: boom."}})
	if got != "No TCP port is listening.\n\nContainers were not checked: boom.\n" {
		t.Errorf("got %q", got)
	}
}

func TestRenderOverviewWideCharacters(t *testing.T) {
	// Column widths are measured in terminal cells, not bytes or runes.
	got := renderOverview(t, doctor.Overview{Rows: []doctor.Row{
		{Port: 80, Bind: "all", Process: doctor.Process{PID: 1, Name: "資料庫", User: "root"}},
		{Port: 81, Bind: "all", Process: doctor.Process{PID: 2, Name: "api", User: "root"}},
	}})
	want := `PORT  BIND  PID  PROCESS  USER  CONTAINER
80    all   1    資料庫   root
81    all   2    api      root
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestRenderOverviewColorKeepsAlignment forces a color profile onto the
// buffer: with escape codes in the output, the visible layout must still be
// the plain golden, which the plain-text tests alone cannot prove.
func TestRenderOverviewColorKeepsAlignment(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	got := renderOverview(t, doctor.Overview{Rows: overviewRows()})
	if !strings.Contains(got, "\x1b[") {
		t.Fatal("expected escape codes with CLICOLOR_FORCE=1")
	}
	if stripped := ansi.Strip(got); stripped != overviewGolden {
		t.Errorf("visible layout with colors:\n%s\nwant:\n%s", stripped, overviewGolden)
	}
}
