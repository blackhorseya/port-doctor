package inspect

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// TestRealContainer starts a container with a published port through the
// docker or podman CLI and checks that the inspector, and the whole doctor,
// attribute the port to it. It needs a runtime and network access to pull
// alpine, so it runs only when PORT_DOCTOR_CONTAINER_TEST is set (see
// `task test-container` and the container job in CI).
func TestRealContainer(t *testing.T) {
	if os.Getenv("PORT_DOCTOR_CONTAINER_TEST") == "" {
		t.Skip("set PORT_DOCTOR_CONTAINER_TEST=1 to run against a real container runtime")
	}
	cli := runtimeCLI(t)
	name := fmt.Sprintf("port-doctor-test-%d", os.Getpid())
	runCLI(t, cli, "run", "-d", "--rm", "--name", name,
		"--label", "com.docker.compose.project=port-doctor-test",
		"--label", "com.docker.compose.service=web",
		"-p", "80", "docker.io/library/alpine:3", "sleep", "300")
	t.Cleanup(func() { _ = exec.Command(cli, "rm", "-f", name).Run() })

	// "docker port" prints one line per address family, e.g. "0.0.0.0:32768".
	first, _, _ := strings.Cut(strings.TrimSpace(runCLI(t, cli, "port", name, "80/tcp")), "\n")
	ap, err := netip.ParseAddrPort(strings.TrimSpace(first))
	if err != nil {
		t.Fatalf("cannot parse published address %q: %v", first, err)
	}
	port := int(ap.Port())

	cs, err := NewContainerInspector().PublishedContainers(t.Context(), port)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("containers on port %d = %+v, want exactly one", port, cs)
	}
	ct := cs[0]
	if ct.Name != name || (ct.Runtime != "docker" && ct.Runtime != "podman") || !strings.Contains(ct.Image, "alpine") {
		t.Errorf("container = %+v", ct)
	}
	if ct.Compose != (doctor.ComposeService{Project: "port-doctor-test", Service: "web"}) {
		t.Errorf("compose = %+v", ct.Compose)
	}
	if len(ct.Mappings) == 0 {
		t.Fatal("no mappings")
	}
	for _, m := range ct.Mappings {
		if int(m.Host.Port()) != port || m.ContainerPort != 80 {
			t.Errorf("mapping = %+v, want host port %d to container port 80", m, port)
		}
	}

	// The whole doctor: in use, attributed to the container, and never a
	// kill for the runtime's port forwarder (or for nothing, when the
	// runtime publishes with packet rules and no host listener exists).
	ports, procs, err := New()
	if err != nil {
		t.Skip(err)
	}
	x := &doctor.Doctor{Ports: ports, Processes: procs, Containers: NewContainerInspector(), ElevatedInspectCommand: ElevatedInspectCommand}
	r, err := x.Diagnose(t.Context(), port)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != doctor.StatusInUse || len(r.Containers) != 1 {
		t.Errorf("report = %+v", r)
	}
	for _, s := range r.Suggestions {
		for _, cmd := range s.Commands {
			if strings.HasPrefix(cmd, "kill ") {
				t.Errorf("suggested %q for a container-published port", cmd)
			}
		}
	}
	t.Logf("diagnosis: %s; notes: %q", r.Diagnosis, r.Notes)
}

func runtimeCLI(t *testing.T) string {
	t.Helper()
	for _, cli := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(cli); err == nil {
			return cli
		}
	}
	t.Fatal("PORT_DOCTOR_CONTAINER_TEST is set but neither docker nor podman is on PATH")
	return ""
}

func runCLI(t *testing.T, cli string, args ...string) string {
	t.Helper()
	out, err := exec.Command(cli, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", cli, strings.Join(args, " "), err, out)
	}
	return string(out)
}
