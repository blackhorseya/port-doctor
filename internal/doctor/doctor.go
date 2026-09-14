// Package doctor defines the diagnosis model of port-doctor and the
// orchestration that turns raw socket and process facts into a Report.
//
// It knows nothing about operating systems or container runtimes: platform
// specifics live behind the PortInspector, ProcessInspector and
// ContainerInspector interfaces, implemented in package inspect.
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

// ProtocolTCP is the only protocol port-doctor diagnoses.
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

// Container is a running container that publishes the diagnosed port on
// the host.
type Container struct {
	// Runtime is the command line tool that manages the container,
	// "docker" or "podman"; suggestions are phrased with it.
	Runtime string
	// ID is the short container ID.
	ID    string
	Name  string
	Image string
	// Mappings are the container's published ports that match the
	// diagnosed port, IPv4 before IPv6.
	Mappings []PortMapping
	// Compose is set when the container is managed by Compose.
	Compose ComposeService
}

// PortMapping is one host address forwarded into a container.
type PortMapping struct {
	Host          netip.AddrPort
	ContainerPort int
	Protocol      Protocol
}

// ComposeService identifies the Compose project and service that own a
// container. Zero when the container was not started by Compose.
type ComposeService struct {
	Project string
	Service string
}

// ContainerInspector finds running containers that publish a host port.
type ContainerInspector interface {
	// PublishedContainers returns the running containers publishing port on
	// this host, with Mappings limited to that port. It returns nothing, and
	// no error, when no container runtime is available.
	PublishedContainers(c context.Context, port int) ([]Container, error)
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
	// StatusAvailable means nothing is listening on the port and no
	// container publishes it.
	StatusAvailable Status = iota
	// StatusInUse means at least one socket is listening on the port or a
	// container publishes it.
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
	// Containers publish the port on the host, whether or not a host
	// process was found listening for them.
	Containers []Container
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
	// Containers finds containers publishing the port. Optional: nil skips
	// container detection.
	Containers ContainerInspector
	// Listeners lists every listening socket for Scan. Diagnose does not
	// use it.
	Listeners ListenerInspector
	// AllContainers lists every container's published ports for Scan.
	// Optional: nil skips container detection.
	AllContainers ContainerLister
	// ElevatedInspectCommand returns a platform command that can identify a
	// listener when normal privileges are not enough. Optional.
	ElevatedInspectCommand func(port int) string
}

// Diagnose explains the state of a local TCP port.
//
// Only a failure to list the port's sockets is an error. Missing process
// metadata and an unreachable container runtime degrade the report and are
// explained in Report.Notes. A port published by a container counts as in
// use even when no host process is listening for it, because the runtime
// then forwards the traffic with packet rules and a new server would never
// see a connection.
func (x *Doctor) Diagnose(c context.Context, port int) (Report, error) {
	info, err := x.Ports.InspectPort(c, port)
	if err != nil {
		return Report{}, fmt.Errorf("inspect port %d: %w", port, err)
	}

	r := Report{Port: port, OtherSockets: info.OtherSockets}
	var containerNotes []string
	r.Containers, containerNotes = x.publishedContainers(c, port)

	if len(info.Listeners) == 0 && len(r.Containers) == 0 {
		r.Status = StatusAvailable
		if note := lingeringNote(port, info.OtherSockets); note != "" {
			r.Notes = append(r.Notes, note)
		}
		r.Notes = append(r.Notes, containerNotes...)
		return r, nil
	}

	r.Status = StatusInUse
	var notes []string
	if len(info.Listeners) > 0 {
		r.Occupants, notes = x.identify(c, info.Listeners)
	}
	if len(r.Containers) > 0 {
		// The container explains an unidentified listener: on Linux it is
		// docker-proxy running as root, which procfs cannot map to a PID.
		notes = slices.DeleteFunc(notes, func(n string) bool { return n == unidentifiedNote })
	}
	notes = append(notes, forwarderNotes(port, r.Occupants, r.Containers)...)
	r.Notes = dedupe(append(notes, containerNotes...))
	r.Diagnosis = diagnosis(port, r.Occupants, r.Containers)
	r.Suggestions = x.suggest(port, r.Occupants, r.Containers)
	return r, nil
}

// publishedContainers asks the container inspector, if any, which containers
// publish the port. Failures never abort the diagnosis: the listener facts
// stand on their own and the failure becomes a note.
func (x *Doctor) publishedContainers(c context.Context, port int) ([]Container, []string) {
	if x.Containers == nil {
		return nil, nil
	}
	cs, err := x.Containers.PublishedContainers(c, port)
	var notes []string
	if note := containerNote(len(cs) > 0, err); note != "" {
		notes = append(notes, note)
	}
	sortContainers(cs)
	return cs, notes
}

// containerNote explains a failed container check. When the inspector still
// returned some containers the failure means the list may be incomplete
// rather than absent.
func containerNote(some bool, err error) string {
	if err == nil {
		return ""
	}
	note := fmt.Sprintf("Containers were not checked: %v.", err)
	if some {
		note = fmt.Sprintf("Some containers may be missing: %v.", err)
	}
	if errors.Is(err, ErrPermission) {
		note += " Only a user with access to the runtime socket can see them."
	}
	return note
}

// sortContainers orders containers by name and their mappings IPv4 first.
func sortContainers(cs []Container) {
	slices.SortFunc(cs, func(a, b Container) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	for i := range cs {
		slices.SortFunc(cs[i].Mappings, func(a, b PortMapping) int { return a.Host.Compare(b.Host) })
	}
}

const unidentifiedNote = "The listening process could not be identified, usually because it belongs to another user."

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
			notes = append(notes, unidentifiedNote)
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

func diagnosis(port int, occupants []Occupant, containers []Container) string {
	switch {
	case len(containers) > 1:
		return fmt.Sprintf("%d containers publish port %d.", len(containers), port)
	case len(containers) == 1:
		ct := containers[0]
		where := scope(mappingAddrs(ct.Mappings))
		if len(occupants) == 0 {
			return fmt.Sprintf("Container %s (%s) publishes port %d%s; no host process is listening, so the runtime forwards the traffic itself.", ct.Name, ct.Runtime, port, where)
		}
		return fmt.Sprintf("Container %s (%s) publishes port %d%s.", ct.Name, ct.Runtime, port, where)
	case len(occupants) > 1:
		return fmt.Sprintf("%d processes are listening on port %d.", len(occupants), port)
	}
	occ := occupants[0]
	where := scope(listenerAddrs(occ.Listeners))
	if occ.Process.PID == 0 {
		return fmt.Sprintf("A process is listening on port %d%s, but it could not be identified.", port, where)
	}
	return fmt.Sprintf("Another process is listening on port %d%s.", port, where)
}

func listenerAddrs(ls []Listener) []netip.Addr {
	out := make([]netip.Addr, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Addr.Addr())
	}
	return out
}

func mappingAddrs(ms []PortMapping) []netip.Addr {
	out := make([]netip.Addr, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Host.Addr())
	}
	return out
}

// scope summarises which interfaces the addresses cover, because
// 127.0.0.1:8080 and 0.0.0.0:8080 mean very different things to a developer.
func scope(addrs []netip.Addr) string {
	all, loopback, ips := summariseBind(addrs)
	switch {
	case all:
		return " (all interfaces)"
	case loopback:
		return " (localhost only)"
	case len(ips) == 1:
		return fmt.Sprintf(" (%s only)", ips[0])
	}
	return ""
}

// summariseBind reduces bound addresses to what a summary needs: whether
// any of them is a wildcard (all interfaces), whether all of them are
// loopback, and otherwise the distinct addresses in order. IPv4-mapped IPv6
// addresses are unmapped first so ::ffff:0.0.0.0 counts as a wildcard.
func summariseBind(addrs []netip.Addr) (all, loopback bool, ips []netip.Addr) {
	loopback = true
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		ip := a.Unmap()
		if ip.IsUnspecified() {
			return true, false, nil
		}
		loopback = loopback && ip.IsLoopback()
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	return false, loopback, ips
}

// runtimeForwarders are host processes that hold published ports on behalf
// of a container runtime, keyed by process name. Killing one takes every
// container offline, so they never get a kill suggestion even when the
// container behind the port could not be found.
var runtimeForwarders = map[string]string{
	"docker-proxy":       "docker",
	"com.docker.backend": "docker",
	"vpnkit":             "docker",
	"rootlesskit":        "docker",
	"gvproxy":            "podman",
	"rootlessport":       "podman",
	"slirp4netns":        "podman",
}

// forwarderNotes explains listeners that are runtime port forwarders when no
// container was found to account for them, typically because the runtime's
// API socket is not enabled or not reachable.
func forwarderNotes(port int, occupants []Occupant, containers []Container) []string {
	if len(containers) > 0 {
		return nil
	}
	var notes []string
	for _, occ := range occupants {
		runtime, ok := runtimeForwarders[occ.Process.Name]
		if !ok {
			continue
		}
		notes = append(notes, fmt.Sprintf("%s (PID %d) forwards ports for %s containers, but no container publishing port %d was found, so the runtime's API socket may be unreachable. Killing it would disconnect every container.",
			occ.Process.Name, occ.Process.PID, runtime, port))
	}
	return notes
}

// suggest proposes conservative next steps. Nothing is executed.
//
// Once a container explains the port, the host listener is the runtime's
// forwarder and the only sensible action is to stop the container, so no
// process-level command is suggested at all.
func (x *Doctor) suggest(port int, occupants []Occupant, containers []Container) []Suggestion {
	if len(containers) > 0 {
		return containerSuggestions(containers)
	}
	var inspect, stop, identify []string
	for _, occ := range occupants {
		_, forwarder := runtimeForwarders[occ.Process.Name]
		switch {
		case occ.Process.PID == 0:
			if x.ElevatedInspectCommand != nil {
				identify = append(identify, x.ElevatedInspectCommand(port))
			}
		case occ.Exited:
			// A dead PID may be reused; never suggest killing it.
		case forwarder:
			inspect = append(inspect, fmt.Sprintf("%s ps", runtimeForwarders[occ.Process.Name]))
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

// containerSuggestions phrases the next steps with the runtime's own CLI.
// A Compose-managed container is stopped through Compose so that a later
// `compose up` does not silently bring it back.
func containerSuggestions(containers []Container) []Suggestion {
	var inspect, stop []string
	for _, ct := range containers {
		inspect = append(inspect, fmt.Sprintf("%s logs --tail 20 %s", ct.Runtime, ct.Name))
		if ct.Compose.Project != "" && ct.Compose.Service != "" {
			stop = append(stop, fmt.Sprintf("%s compose -p %s stop %s", ct.Runtime, ct.Compose.Project, ct.Compose.Service))
		} else {
			stop = append(stop, fmt.Sprintf("%s stop %s", ct.Runtime, ct.Name))
		}
	}
	return []Suggestion{
		{Title: "Inspect", Commands: dedupe(inspect)},
		{Title: "Stop", Commands: dedupe(stop)},
	}
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
