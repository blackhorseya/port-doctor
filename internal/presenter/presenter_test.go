package presenter

import (
	"bytes"
	"net/netip"
	"testing"

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
