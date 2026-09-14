package doctor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

type fakeContainers struct {
	cs  []Container
	err error
}

func (f fakeContainers) PublishedContainers(context.Context, int) ([]Container, error) {
	return f.cs, f.err
}

func mapping(host string, containerPort int) PortMapping {
	return PortMapping{Host: netip.MustParseAddrPort(host), ContainerPort: containerPort, Protocol: ProtocolTCP}
}

func container(runtime, name string, mappings ...PortMapping) Container {
	return Container{Runtime: runtime, ID: "0123456789ab", Name: name, Image: name + ":latest", Mappings: mappings}
}

func diagnoseWithContainers(t *testing.T, info PortInfo, procs fakeProcs, containers fakeContainers) Report {
	t.Helper()
	x := &Doctor{Ports: fakePorts{info: info}, Processes: procs, Containers: containers, ElevatedInspectCommand: elevated}
	r, err := x.Diagnose(t.Context(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The forwarder that holds a published port on macOS with Podman.
var gvproxy = fakeProcs{procs: map[int]Process{3189: {PID: 3189, Name: "gvproxy", User: "sean"}}}

func TestDiagnoseContainerWithListener(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("[::]:8080", 3189)}}
	ct := container("podman", "postgres-dev", mapping("0.0.0.0:8080", 5432))
	r := diagnoseWithContainers(t, info, gvproxy, fakeContainers{cs: []Container{ct}})

	if r.Status != StatusInUse {
		t.Fatalf("status = %v, want in use", r.Status)
	}
	if len(r.Occupants) != 1 || r.Occupants[0].Process.Name != "gvproxy" {
		t.Errorf("occupants = %+v, want the forwarder", r.Occupants)
	}
	if len(r.Containers) != 1 || r.Containers[0].Name != "postgres-dev" {
		t.Errorf("containers = %+v", r.Containers)
	}
	if r.Diagnosis != "Container postgres-dev (podman) publishes port 8080 (all interfaces)." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"podman logs --tail 20 postgres-dev"}},
		{Title: "Stop", Commands: []string{"podman stop postgres-dev"}},
	})
	if len(r.Notes) != 0 {
		t.Errorf("notes = %q, want none", r.Notes)
	}
}

func TestDiagnoseContainerNeverSuggestsKill(t *testing.T) {
	// Even an ordinary-looking process gets no kill once a container explains
	// the port: on Linux the listener is docker-proxy, on macOS the whole
	// Docker Desktop backend.
	info := PortInfo{Listeners: []Listener{listener("0.0.0.0:8080", 42)}}
	procs := fakeProcs{procs: map[int]Process{42: {PID: 42, Name: "com.docker.backend"}}}
	r := diagnoseWithContainers(t, info, procs, fakeContainers{cs: []Container{container("docker", "web", mapping("0.0.0.0:8080", 80))}})
	for _, s := range r.Suggestions {
		for _, cmd := range s.Commands {
			if cmd == "kill 42" || cmd == "ps -p 42" {
				t.Errorf("suggestions contain %q: %+v", cmd, r.Suggestions)
			}
		}
	}
}

func TestDiagnoseContainerExplainsUnidentifiedListener(t *testing.T) {
	// Linux with Docker Engine: docker-proxy runs as root, so procfs cannot
	// name the PID. The container is the explanation, so the usual "could
	// not be identified" note and the sudo hint would only contradict it.
	l := listener("0.0.0.0:8080", 0)
	l.User = "root"
	ct := container("docker", "web", mapping("0.0.0.0:8080", 80), mapping("[::]:8080", 80))
	r := diagnoseWithContainers(t, PortInfo{Listeners: []Listener{l}}, fakeProcs{}, fakeContainers{cs: []Container{ct}})

	if len(r.Occupants) != 1 || r.Occupants[0].Process.PID != 0 || r.Occupants[0].Process.User != "root" {
		t.Errorf("occupants = %+v, want the unidentified root listener kept", r.Occupants)
	}
	if r.Diagnosis != "Container web (docker) publishes port 8080 (all interfaces)." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"docker logs --tail 20 web"}},
		{Title: "Stop", Commands: []string{"docker stop web"}},
	})
	if len(r.Notes) != 0 {
		t.Errorf("notes = %q, want none", r.Notes)
	}
}

func TestDiagnoseContainerWithoutListener(t *testing.T) {
	ct := container("docker", "web", mapping("0.0.0.0:8080", 80))
	r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{cs: []Container{ct}})

	if r.Status != StatusInUse {
		t.Fatalf("status = %v, want in use: the runtime forwards the port without a listener", r.Status)
	}
	if len(r.Occupants) != 0 {
		t.Errorf("occupants = %+v, want none", r.Occupants)
	}
	want := "Container web (docker) publishes port 8080 (all interfaces); no host process is listening, so the runtime forwards the traffic itself."
	if r.Diagnosis != want {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"docker logs --tail 20 web"}},
		{Title: "Stop", Commands: []string{"docker stop web"}},
	})
}

func TestDiagnoseComposeContainer(t *testing.T) {
	ct := container("docker", "demo-cache-1", mapping("127.0.0.1:8080", 6379))
	ct.Compose = ComposeService{Project: "demo", Service: "cache"}
	r := diagnoseWithContainers(t, PortInfo{Listeners: []Listener{listener("127.0.0.1:8080", 42)}},
		fakeProcs{procs: map[int]Process{42: {Name: "docker-proxy"}}}, fakeContainers{cs: []Container{ct}})

	if r.Diagnosis != "Container demo-cache-1 (docker) publishes port 8080 (localhost only)." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"docker logs --tail 20 demo-cache-1"}},
		{Title: "Stop", Commands: []string{"docker compose -p demo stop cache"}},
	})
}

func TestDiagnoseComposeLabelsIncomplete(t *testing.T) {
	ct := container("docker", "half", mapping("0.0.0.0:8080", 80))
	ct.Compose = ComposeService{Project: "demo"} // no service: cannot address it through Compose
	r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{cs: []Container{ct}})
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"docker logs --tail 20 half"}},
		{Title: "Stop", Commands: []string{"docker stop half"}},
	})
}

func TestDiagnoseContainersSortedByName(t *testing.T) {
	cs := []Container{
		container("docker", "zeta", mapping("192.168.1.5:8080", 80)),
		container("docker", "alpha", mapping("127.0.0.1:8080", 80)),
	}
	r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{cs: cs})
	if r.Containers[0].Name != "alpha" || r.Containers[1].Name != "zeta" {
		t.Errorf("containers not sorted by name: %+v", r.Containers)
	}
	if r.Diagnosis != "2 containers publish port 8080." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"docker logs --tail 20 alpha", "docker logs --tail 20 zeta"}},
		{Title: "Stop", Commands: []string{"docker stop alpha", "docker stop zeta"}},
	})
}

func TestDiagnoseContainerMappingsSortedIPv4First(t *testing.T) {
	ct := container("docker", "web", mapping("[::]:8080", 80), mapping("0.0.0.0:8080", 80))
	r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{cs: []Container{ct}})
	got := []string{r.Containers[0].Mappings[0].Host.String(), r.Containers[0].Mappings[1].Host.String()}
	if !slices.Equal(got, []string{"0.0.0.0:8080", "[::]:8080"}) {
		t.Errorf("mappings = %v", got)
	}
}

func TestDiagnoseContainerScope(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		want  string
	}{
		{"localhost", []string{"127.0.0.1:8080"}, " (localhost only)"},
		{"wildcard v4 and v6", []string{"0.0.0.0:8080", "[::]:8080"}, " (all interfaces)"},
		{"one interface", []string{"192.168.1.5:8080"}, " (192.168.1.5 only)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ms []PortMapping
			for _, h := range tt.hosts {
				ms = append(ms, mapping(h, 80))
			}
			r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{cs: []Container{container("docker", "web", ms...)}})
			want := fmt.Sprintf("Container web (docker) publishes port 8080%s; no host process is listening, so the runtime forwards the traffic itself.", tt.want)
			if r.Diagnosis != want {
				t.Errorf("diagnosis = %q, want %q", r.Diagnosis, want)
			}
		})
	}
}

func TestDiagnoseContainerCheckFailed(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("0.0.0.0:8080", 18432)}}
	procs := fakeProcs{procs: map[int]Process{18432: {PID: 18432, Name: "api-server", User: "sean"}}}
	r := diagnoseWithContainers(t, info, procs, fakeContainers{err: errors.New("/var/run/docker.sock did not answer within 2s")})

	// The listener facts and the usual suggestions stand on their own.
	if r.Status != StatusInUse || r.Diagnosis != "Another process is listening on port 8080 (all interfaces)." {
		t.Errorf("status = %v, diagnosis = %q", r.Status, r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"ps -p 18432"}},
		{Title: "Stop", Commands: []string{"kill 18432"}},
	})
	want := []string{"Containers were not checked: /var/run/docker.sock did not answer within 2s."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q, want %q", r.Notes, want)
	}
}

func TestDiagnoseContainerCheckPermissionDenied(t *testing.T) {
	err := fmt.Errorf("/var/run/docker.sock: %w", ErrPermission)
	r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{err: err})

	if r.Status != StatusAvailable {
		t.Fatalf("status = %v, want available", r.Status)
	}
	want := []string{"Containers were not checked: /var/run/docker.sock: permission denied. Only a user with access to the runtime socket can see them."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q, want %q", r.Notes, want)
	}
}

func TestDiagnoseContainerCheckFailedAfterLingeringNote(t *testing.T) {
	info := PortInfo{OtherSockets: map[string]int{"TIME_WAIT": 1}}
	r := diagnoseWithContainers(t, info, fakeProcs{}, fakeContainers{err: errors.New("boom")})
	if len(r.Notes) != 2 || r.Notes[1] != "Containers were not checked: boom." {
		t.Errorf("notes = %q, want the lingering note followed by the container note", r.Notes)
	}
}

func TestDiagnosePartialContainerCheck(t *testing.T) {
	ct := container("docker", "web", mapping("0.0.0.0:8080", 80))
	r := diagnoseWithContainers(t, PortInfo{}, fakeProcs{}, fakeContainers{cs: []Container{ct}, err: errors.New("second socket failed")})
	if len(r.Containers) != 1 {
		t.Fatalf("containers = %+v, want the one that was found", r.Containers)
	}
	want := []string{"Some containers may be missing: second socket failed."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q, want %q", r.Notes, want)
	}
}

func TestDiagnoseForwarderWithoutContainer(t *testing.T) {
	// Podman on Linux without its API socket enabled: the listener is
	// rootlessport, nothing answers about containers, and killing the
	// forwarder would take every container offline.
	info := PortInfo{Listeners: []Listener{listener("0.0.0.0:8080", 900)}}
	procs := fakeProcs{procs: map[int]Process{900: {PID: 900, Name: "rootlessport", User: "sean"}}}
	r := diagnoseWithContainers(t, info, procs, fakeContainers{})

	if r.Diagnosis != "Another process is listening on port 8080 (all interfaces)." {
		t.Errorf("diagnosis = %q", r.Diagnosis)
	}
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"podman ps"}},
	})
	want := []string{"rootlessport (PID 900) forwards ports for podman containers, but no container publishing port 8080 was found, so the runtime's API socket may be unreachable. Killing it would disconnect every container."}
	if !slices.Equal(r.Notes, want) {
		t.Errorf("notes = %q", r.Notes)
	}
}

func TestDiagnoseForwarderWithoutContainerInspector(t *testing.T) {
	// The forwarder protection does not depend on container detection being
	// wired at all.
	info := PortInfo{Listeners: []Listener{listener("[::]:8080", 3189)}}
	r := diagnose(t, info, gvproxy)
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"podman ps"}},
	})
	if len(r.Notes) != 1 {
		t.Errorf("notes = %q, want the forwarder note", r.Notes)
	}
}

func TestDiagnoseForwarderNextToOrdinaryProcess(t *testing.T) {
	info := PortInfo{Listeners: []Listener{listener("127.0.0.1:8080", 42), listener("[::]:8080", 3189)}}
	procs := fakeProcs{procs: map[int]Process{42: {PID: 42, Name: "dev"}, 3189: {PID: 3189, Name: "gvproxy"}}}
	r := diagnoseWithContainers(t, info, procs, fakeContainers{})
	assertSuggestions(t, r.Suggestions, []Suggestion{
		{Title: "Inspect", Commands: []string{"ps -p 42", "podman ps"}},
		{Title: "Stop", Commands: []string{"kill 42"}},
	})
}
