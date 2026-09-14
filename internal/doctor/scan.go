package doctor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strings"
)

// ListenerInspector lists every listening TCP socket on the host.
type ListenerInspector interface {
	ListListeners(c context.Context) ([]Listener, error)
}

// ContainerLister lists every running container with its published ports.
type ContainerLister interface {
	// ListContainers returns every running container with all of its
	// published TCP ports in Mappings; a container that publishes nothing
	// has none. It returns nothing, and no error, when no container runtime
	// is available.
	ListContainers(c context.Context) ([]Container, error)
}

// Overview is the result of Scan: every listening TCP port on the host.
type Overview struct {
	Rows []Row
	// Notes explain degraded results, one sentence each.
	Notes []string
}

// Row is one listening port as held by one process. Listeners that could
// not be attributed to a process share one row per port, just as they share
// one Occupant in a Report. A port published by a container with no host
// listener gets a row of its own, with no Listeners and a zero Process.
type Row struct {
	Port int
	// Bind summarises the bound addresses: "all" for a wildcard, "localhost"
	// when every address is loopback, otherwise the distinct addresses
	// separated by commas.
	Bind string
	// Listeners are the sockets merged into this row, IPv4 first.
	Listeners []Listener
	// Process has PID 0 when the listeners could not be attributed to a
	// process, and is the zero value when only a container publishes the port.
	Process Process
	// Exited is set when the process disappeared between listing the
	// sockets and reading its metadata.
	Exited bool
	// Containers publish this port, with Mappings limited to it.
	Containers []Container
}

// Scan lists every listening TCP port on the host.
//
// Only a failure to list the sockets is an error. Missing process metadata
// and an unreachable container runtime degrade the overview and are
// explained in Overview.Notes, as in Diagnose.
func (x *Doctor) Scan(c context.Context) (Overview, error) {
	if x.Listeners == nil {
		return Overview{}, errors.New("no listener inspector configured")
	}
	listeners, err := x.Listeners.ListListeners(c)
	if err != nil {
		return Overview{}, fmt.Errorf("list listeners: %w", err)
	}
	containers, containerNotes := x.listContainers(c)

	o := Overview{Rows: rows(listeners, containers)}
	notes, err := x.enrich(c, o.Rows)
	if err != nil {
		return Overview{}, err
	}
	o.Notes = dedupe(append(notes, containerNotes...))
	return o, nil
}

func (x *Doctor) listContainers(c context.Context) ([]Container, []string) {
	if x.AllContainers == nil {
		return nil, nil
	}
	cs, err := x.AllContainers.ListContainers(c)
	if note := containerNote(len(cs) > 0, err); note != "" {
		return cs, []string{note}
	}
	return cs, nil
}

// rows groups listeners into one row per port and process, then attaches
// the containers publishing each port. A container publishing several
// ports appears in each of their rows with only that port's mappings; a
// port nobody listens on but a container publishes gets a row of its own.
func rows(listeners []Listener, containers []Container) []Row {
	type key struct{ port, pid int }
	index := map[key]int{}
	var out []Row
	for _, l := range listeners {
		k := key{int(l.Addr.Port()), l.PID}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, Row{Port: k.port, Process: Process{PID: l.PID}})
		}
		out[i].Listeners = append(out[i].Listeners, l)
	}

	for _, ct := range containers {
		for _, port := range publishedPorts(ct) {
			attached := false
			for i := range out {
				if out[i].Port == port {
					out[i].Containers = append(out[i].Containers, onPort(ct, port))
					attached = true
				}
			}
			if !attached {
				out = append(out, Row{Port: port, Containers: []Container{onPort(ct, port)}})
			}
		}
	}

	for i := range out {
		r := &out[i]
		slices.SortFunc(r.Listeners, func(a, b Listener) int { return a.Addr.Compare(b.Addr) })
		sortContainers(r.Containers)
		r.Process.User = firstUser(r.Listeners)
		addrs := listenerAddrs(r.Listeners)
		if len(addrs) == 0 {
			for _, ct := range r.Containers {
				addrs = append(addrs, mappingAddrs(ct.Mappings)...)
			}
		}
		r.Bind = bind(addrs)
	}
	slices.SortFunc(out, func(a, b Row) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(pidRank(a), pidRank(b)))
	})
	return out
}

// pidRank orders identified processes by PID and unidentified ones last.
func pidRank(r Row) int {
	if r.Process.PID == 0 {
		return math.MaxInt
	}
	return r.Process.PID
}

// publishedPorts returns the distinct host ports a container publishes.
func publishedPorts(ct Container) []int {
	ports := map[int]bool{}
	for _, m := range ct.Mappings {
		ports[int(m.Host.Port())] = true
	}
	return slices.Sorted(maps.Keys(ports))
}

// onPort returns a copy of ct with only the mappings for port.
func onPort(ct Container, port int) Container {
	var ms []PortMapping
	for _, m := range ct.Mappings {
		if int(m.Host.Port()) == port {
			ms = append(ms, m)
		}
	}
	ct.Mappings = ms
	return ct
}

// bind is the BIND column of the overview: the same summary as the
// diagnosis scope, in one word where possible.
func bind(addrs []netip.Addr) string {
	all, loopback, ips := summariseBind(addrs)
	switch {
	case all:
		return "all"
	case loopback:
		return "localhost"
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

// enrich reads process metadata once per PID and reports the same
// degradations as Diagnose. It stops with the context's error once the
// caller's deadline passes, rather than adding a note for every remaining PID.
func (x *Doctor) enrich(c context.Context, rows []Row) ([]string, error) {
	type lookup struct {
		p   Process
		err error
	}
	cache := map[int]lookup{}
	var notes []string
	unidentified := 0
	for i := range rows {
		r := &rows[i]
		pid := r.Process.PID
		if pid == 0 {
			// A container explains an unidentified listener: on Linux it is
			// docker-proxy running as root, which procfs cannot map to a PID.
			if len(r.Listeners) > 0 && len(r.Containers) == 0 {
				unidentified++
			}
			continue
		}
		res, ok := cache[pid]
		if !ok {
			p, err := x.Processes.InspectProcess(c, pid)
			if cerr := c.Err(); cerr != nil {
				return nil, cerr
			}
			res = lookup{p: p, err: err}
			cache[pid] = res
			switch {
			case err == nil:
			case errors.Is(err, ErrProcessNotFound):
				notes = append(notes, fmt.Sprintf("Process %d exited during the scan, so its ports may be free now.", pid))
			case errors.Is(err, ErrPermission):
				notes = append(notes, "Some process information could not be read due to permissions.")
			default:
				notes = append(notes, fmt.Sprintf("Process information for PID %d could not be read.", pid))
			}
		}
		switch {
		case res.err == nil:
			r.Process.Name = res.p.Name
			r.Process.User = cmp.Or(res.p.User, r.Process.User)
		case errors.Is(res.err, ErrProcessNotFound):
			r.Exited = true
		}
	}
	if unidentified > 0 {
		notes = append(notes, unidentifiedRowsNote(unidentified))
	}
	return dedupe(notes), nil
}

func unidentifiedRowsNote(n int) string {
	if n == 1 {
		return "1 port is held by a process that could not be identified, usually because it belongs to another user."
	}
	return fmt.Sprintf("%d ports are held by processes that could not be identified, usually because they belong to another user.", n)
}
