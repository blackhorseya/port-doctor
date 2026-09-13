// Package doctor defines the diagnosis model of port-doctor and the
// orchestration that turns raw socket and process facts into a Report.
//
// It knows nothing about operating systems: platform specifics live behind
// the PortInspector and ProcessInspector interfaces, implemented in package
// inspect.
package doctor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Protocol is the transport protocol of a socket.
type Protocol string

// ProtocolTCP is the only protocol diagnosed in v0.1.
const ProtocolTCP Protocol = "TCP"

// Listener is a socket in the LISTEN state bound to the diagnosed port.
type Listener struct {
	Protocol Protocol
	Addr     netip.AddrPort
	// PID is the process owning the socket, or 0 when it could not be
	// determined (typically because it belongs to another user).
	PID int
	// User owns the socket when the platform exposes that even without the
	// PID, as Linux procfs does. Empty when unknown.
	User string
}

// PortInfo is everything a platform can tell about one local port.
type PortInfo struct {
	Listeners []Listener
	// OtherSockets counts sockets bound to the port that are not listening,
	// keyed by state such as "TIME_WAIT". They can still make a bind fail.
	OtherSockets map[string]int
}

// Process is metadata about one process. Empty fields are unknown.
type Process struct {
	PID  int
	Name string
	User string
}

// PortInspector finds the sockets bound to a local port.
type PortInspector interface {
	InspectPort(c context.Context, port int) (PortInfo, error)
}

// ProcessInspector reads metadata about a running process.
type ProcessInspector interface {
	InspectProcess(c context.Context, pid int) (Process, error)
}

var (
	// ErrProcessNotFound reports that no process with the PID exists (any more).
	ErrProcessNotFound = errors.New("process not found")
	// ErrPermission reports that the operating system refused access.
	ErrPermission = errors.New("permission denied")
	// ErrPortRange reports a port outside the valid TCP range.
	ErrPortRange = errors.New("port must be between 1 and 65535")
)

// ParsePort validates a user-supplied port string.
func ParsePort(s string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, ErrPortRange
		}
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, ErrPortRange
	}
	return int(n), nil
}

// Status is the headline verdict for a port.
type Status int

const (
	// StatusAvailable means nothing is listening on the port.
	StatusAvailable Status = iota
	// StatusInUse means at least one socket is listening on the port.
	StatusInUse
)

// Occupant is one process, identified or not, with its listeners on the port.
type Occupant struct {
	// Process has PID 0 when the owner of the listeners could not be identified.
	Process Process
	// Exited is set when the process disappeared between finding the listener
	// and reading its metadata.
	Exited    bool
	Listeners []Listener
}

// Suggestion is a titled group of commands the user may run next.
type Suggestion struct {
	Title    string
	Commands []string
}

// Report is the complete diagnosis of one port.
type Report struct {
	Port         int
	Status       Status
	Occupants    []Occupant
	OtherSockets map[string]int
	// Diagnosis is a one-sentence explanation; empty when the port is available.
	Diagnosis   string
	Suggestions []Suggestion
	// Notes explain degraded or surprising results, one sentence each.
	Notes []string
}

// Doctor orchestrates the inspectors into a Report. It never modifies the
// system: every suggestion is text for the user to run.
type Doctor struct {
	Ports     PortInspector
	Processes ProcessInspector
	// ElevatedInspectCommand returns a platform command that can identify a
	// listener when normal privileges are not enough. Optional.
	ElevatedInspectCommand func(port int) string
}

// Diagnose explains the state of a local TCP port.
//
// Only a failure to list the port's sockets is an error. Missing process
// metadata degrades the report and is explained in Report.Notes.
func (x *Doctor) Diagnose(c context.Context, port int) (Report, error) {
	info, err := x.Ports.InspectPort(c, port)
	if err != nil {
		return Report{}, fmt.Errorf("inspect port %d: %w", port, err)
	}

	r := Report{Port: port, OtherSockets: info.OtherSockets}
	if len(info.Listeners) == 0 {
		r.Status = StatusAvailable
		if note := lingeringNote(port, info.OtherSockets); note != "" {
			r.Notes = append(r.Notes, note)
		}
		return r, nil
	}

	r.Status = StatusInUse
	r.Occupants, r.Notes = x.identify(c, info.Listeners)
	r.Diagnosis = diagnosis(port, r.Occupants)
	r.Suggestions = x.suggest(port, r.Occupants)
	return r, nil
}

// identify groups listeners by PID and enriches each group with process
// metadata, collecting a note for every way that enrichment can degrade.
func (x *Doctor) identify(c context.Context, listeners []Listener) ([]Occupant, []string) {
	byPID := map[int][]Listener{}
	for _, l := range listeners {
		byPID[l.PID] = append(byPID[l.PID], l)
	}
	pids := slices.Sorted(maps.Keys(byPID))
	if pids[0] == 0 {
		// Unidentified listeners read best after the identified ones.
		pids = append(pids[1:], 0)
	}

	var occupants []Occupant
	var notes []string
	for _, pid := range pids {
		ls := byPID[pid]
		slices.SortFunc(ls, func(a, b Listener) int { return a.Addr.Compare(b.Addr) })
		occ := Occupant{Process: Process{PID: pid, User: firstUser(ls)}, Listeners: ls}

		if pid == 0 {
			notes = append(notes, "The listening process could not be identified, usually because it belongs to another user.")
			occupants = append(occupants, occ)
			continue
		}

		p, err := x.Processes.InspectProcess(c, pid)
		switch {
		case err == nil:
			occ.Process.Name = p.Name
			occ.Process.User = cmp.Or(p.User, occ.Process.User)
		case errors.Is(err, ErrProcessNotFound):
			occ.Exited = true
			notes = append(notes, fmt.Sprintf("Process %d exited during inspection, so the port may be free now. Run port-doctor again to confirm.", pid))
		case errors.Is(err, ErrPermission):
			notes = append(notes, "Some process information could not be read due to permissions.")
		default:
			notes = append(notes, fmt.Sprintf("Process information for PID %d could not be read.", pid))
		}
		occupants = append(occupants, occ)
	}
	return occupants, dedupe(notes)
}

func firstUser(ls []Listener) string {
	for _, l := range ls {
		if l.User != "" {
			return l.User
		}
	}
	return ""
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func diagnosis(port int, occupants []Occupant) string {
	if len(occupants) > 1 {
		return fmt.Sprintf("%d processes are listening on port %d.", len(occupants), port)
	}
	occ := occupants[0]
	where := scope(occ.Listeners)
	if occ.Process.PID == 0 {
		return fmt.Sprintf("A process is listening on port %d%s, but it could not be identified.", port, where)
	}
	return fmt.Sprintf("Another process is listening on port %d%s.", port, where)
}

// scope summarises which interfaces the listeners cover, because
// 127.0.0.1:8080 and 0.0.0.0:8080 mean very different things to a developer.
func scope(ls []Listener) string {
	loopback := true
	ips := map[netip.Addr]bool{}
	for _, l := range ls {
		ip := l.Addr.Addr().Unmap()
		if ip.IsUnspecified() {
			return " (all interfaces)"
		}
		loopback = loopback && ip.IsLoopback()
		ips[ip] = true
	}
	if loopback {
		return " (localhost only)"
	}
	if len(ips) == 1 {
		for ip := range ips {
			return fmt.Sprintf(" (%s only)", ip)
		}
	}
	return ""
}

// suggest proposes conservative next steps. Nothing is executed.
func (x *Doctor) suggest(port int, occupants []Occupant) []Suggestion {
	var inspect, stop, identify []string
	for _, occ := range occupants {
		switch {
		case occ.Process.PID == 0:
			if x.ElevatedInspectCommand != nil {
				identify = append(identify, x.ElevatedInspectCommand(port))
			}
		case occ.Exited:
			// A dead PID may be reused; never suggest killing it.
		default:
			inspect = append(inspect, fmt.Sprintf("ps -p %d", occ.Process.PID))
			stop = append(stop, fmt.Sprintf("kill %d", occ.Process.PID))
		}
	}

	var s []Suggestion
	if len(inspect) > 0 {
		s = append(s, Suggestion{Title: "Inspect", Commands: inspect})
	}
	if len(stop) > 0 {
		s = append(s, Suggestion{Title: "Stop", Commands: stop})
	}
	if len(identify) > 0 {
		s = append(s, Suggestion{Title: "Identify (needs elevated privileges)", Commands: dedupe(identify)})
	}
	return s
}

// lingeringNote explains why a bind may still fail on a port with no listener.
func lingeringNote(port int, others map[string]int) string {
	total := 0
	for _, n := range others {
		total += n
	}
	if total == 0 {
		return ""
	}
	states := slices.Sorted(maps.Keys(others))
	parts := make([]string, 0, len(states))
	for _, st := range states {
		parts = append(parts, fmt.Sprintf("%d %s", others[st], st))
	}
	sockets := "sockets still use"
	if total == 1 {
		sockets = "socket still uses"
	}
	return fmt.Sprintf("No process is listening, but %d %s port %d (%s). A new listener may fail to bind until they close.",
		total, sockets, port, strings.Join(parts, ", "))
}
