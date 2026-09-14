package inspect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// dockerList is what Docker Engine answers for a Compose-managed postgres
// published with a plain "-p 5432:5432" (one entry per address family), an
// nginx published on localhost only with a legacy link alias, an exposed but
// unpublished port and a UDP publication on the diagnosed port.
const dockerList = `[
 {"Id":"5f9709733f64f051adb48040712cc5ebcd027ecbbcbbbb91ea8b9819ab941642","Names":["/demo-db-1"],"Image":"postgres:17","Command":"docker-entrypoint.sh postgres","State":"running",
  "Ports":[{"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"},{"IP":"::","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"}],
  "Labels":{"com.docker.compose.project":"demo","com.docker.compose.service":"db"}},
 {"Id":"1d0dc789506e626d87d3862d1735c481819490dc86f90b733a3efd35a217e728","Names":["/proxy/backend","/web"],"Image":"nginx:1.27","State":"running",
  "Ports":[{"PrivatePort":443,"Type":"tcp"},{"IP":"127.0.0.1","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"IP":"0.0.0.0","PrivatePort":53,"PublicPort":5432,"Type":"udp"}],
  "Labels":{}}
]`

// podmanList is Podman's answer for "podman run -p 15379:6379 redis".
const podmanList = `[{"Id":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","Names":["/pd-probe-a"],"Image":"docker.io/library/redis:7-alpine","State":"running","Ports":[{"IP":"0.0.0.0","PrivatePort":6379,"PublicPort":15379,"Type":"tcp"}],"Labels":{}}]`

type fakeRuntime struct {
	path     string
	requests atomic.Int32
}

// socketPath returns a short path for a unix socket: macOS caps socket
// paths at 104 bytes and t.TempDir() is easily longer than that.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "api.sock")
}

func serveOn(t *testing.T, path string, handler http.Handler) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// serveRuntime answers /containers/json the way a container runtime does.
func serveRuntime(t *testing.T, server string, status int, body string) *fakeRuntime {
	t.Helper()
	rt := &fakeRuntime{path: socketPath(t)}
	serveOn(t, rt.path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.requests.Add(1)
		if r.URL.Path != "/containers/json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", server)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	return rt
}

// serveHanging accepts requests and never answers them.
func serveHanging(t *testing.T) string {
	t.Helper()
	path := socketPath(t)
	serveOn(t, path, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	return path
}

func newInspector(sockets ...string) *containerInspector {
	return &containerInspector{sockets: sockets, timeout: time.Second}
}

func hosts(ct doctor.Container) []string {
	var out []string
	for _, m := range ct.Mappings {
		out = append(out, m.Host.String())
	}
	slices.Sort(out)
	return out
}

func TestPublishedContainersDocker(t *testing.T) {
	rt := serveRuntime(t, "Docker/27.3.1 (linux)", http.StatusOK, dockerList)
	i := newInspector(rt.path)

	cs, err := i.PublishedContainers(t.Context(), 5432)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("containers = %+v, want the postgres only (the nginx entry on 5432 is UDP)", cs)
	}
	ct := cs[0]
	if ct.Runtime != "docker" || ct.ID != "5f9709733f64" || ct.Name != "demo-db-1" || ct.Image != "postgres:17" {
		t.Errorf("container = %+v", ct)
	}
	if ct.Compose != (doctor.ComposeService{Project: "demo", Service: "db"}) {
		t.Errorf("compose = %+v", ct.Compose)
	}
	if got := hosts(ct); !slices.Equal(got, []string{"0.0.0.0:5432", "[::]:5432"}) {
		t.Errorf("mapping hosts = %v, want both address families", got)
	}
	for _, m := range ct.Mappings {
		if m.ContainerPort != 5432 || m.Protocol != doctor.ProtocolTCP {
			t.Errorf("mapping = %+v", m)
		}
	}

	cs, err = i.PublishedContainers(t.Context(), 8080)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Name != "web" || cs[0].Compose != (doctor.ComposeService{}) {
		t.Fatalf("containers = %+v, want web with its own name, not the link alias", cs)
	}
	if got := hosts(cs[0]); !slices.Equal(got, []string{"127.0.0.1:8080"}) || cs[0].Mappings[0].ContainerPort != 80 {
		t.Errorf("mappings = %+v", cs[0].Mappings)
	}

	// Exposed but not published.
	if cs, err = i.PublishedContainers(t.Context(), 443); err != nil || len(cs) != 0 {
		t.Errorf("port 443: containers = %+v, err = %v; want none", cs, err)
	}
}

func TestPublishedContainersPodman(t *testing.T) {
	rt := serveRuntime(t, "Libpod/5.8.1 (linux)", http.StatusOK, podmanList)
	cs, err := newInspector(rt.path).PublishedContainers(t.Context(), 15379)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Runtime != "podman" || cs[0].Name != "pd-probe-a" || cs[0].Image != "docker.io/library/redis:7-alpine" {
		t.Fatalf("containers = %+v", cs)
	}
	if got := hosts(cs[0]); !slices.Equal(got, []string{"0.0.0.0:15379"}) || cs[0].Mappings[0].ContainerPort != 6379 {
		t.Errorf("mappings = %+v", cs[0].Mappings)
	}
}

func TestPublishedContainersNoRuntime(t *testing.T) {
	dir := filepath.Dir(socketPath(t))
	missing := filepath.Join(dir, "nope.sock")
	regular := filepath.Join(dir, "file")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := newInspector(missing, regular).PublishedContainers(t.Context(), 8080)
	if err != nil || cs != nil {
		t.Errorf("containers = %+v, err = %v; want nothing and no error", cs, err)
	}
}

func TestPublishedContainersDeadSocket(t *testing.T) {
	// A stopped Docker Desktop leaves its socket file behind.
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()

	cs, err := newInspector(path).PublishedContainers(t.Context(), 8080)
	if err != nil || cs != nil {
		t.Errorf("containers = %+v, err = %v; want the dead socket skipped silently", cs, err)
	}
}

func TestPublishedContainersPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can connect to any socket")
	}
	rt := serveRuntime(t, "Docker/27.3.1 (linux)", http.StatusOK, dockerList)
	if err := os.Chmod(rt.path, 0); err != nil {
		t.Fatal(err)
	}
	cs, err := newInspector(rt.path).PublishedContainers(t.Context(), 5432)
	if !errors.Is(err, doctor.ErrPermission) {
		t.Fatalf("error = %v, want ErrPermission", err)
	}
	if !strings.Contains(err.Error(), rt.path) || cs != nil {
		t.Errorf("error = %q, containers = %+v", err, cs)
	}
}

func TestPublishedContainersTimeout(t *testing.T) {
	path := serveHanging(t)
	i := &containerInspector{sockets: []string{path}, timeout: 50 * time.Millisecond}

	start := time.Now()
	cs, err := i.PublishedContainers(t.Context(), 8080)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %s, want the per-socket timeout to apply", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), path+" did not answer within 50ms") || cs != nil {
		t.Errorf("containers = %+v, err = %v", cs, err)
	}
}

func TestPublishedContainersCallerDeadlineWins(t *testing.T) {
	path := serveHanging(t)
	c, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err := newInspector(path).PublishedContainers(c, 8080)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the caller's deadline", err)
	}

	c, cancel = context.WithCancel(t.Context())
	cancel()
	rt := serveRuntime(t, "Docker/27.3.1 (linux)", http.StatusOK, dockerList)
	if _, err := newInspector(rt.path).PublishedContainers(c, 5432); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestPublishedContainersQueriesEachDaemonOnce(t *testing.T) {
	// /var/run/docker.sock is commonly a symlink to the real socket.
	rt := serveRuntime(t, "Libpod/5.8.1 (linux)", http.StatusOK, podmanList)
	link := filepath.Join(filepath.Dir(rt.path), "link.sock")
	if err := os.Symlink(rt.path, link); err != nil {
		t.Fatal(err)
	}
	cs, err := newInspector(link, rt.path).PublishedContainers(t.Context(), 15379)
	if err != nil || len(cs) != 1 {
		t.Fatalf("containers = %+v, err = %v", cs, err)
	}
	if n := rt.requests.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestPublishedContainersMergesRuntimes(t *testing.T) {
	d := serveRuntime(t, "Docker/27.3.1 (linux)", http.StatusOK, dockerList)
	p := serveRuntime(t, "Libpod/5.8.1 (linux)", http.StatusOK, podmanList)
	i := newInspector(d.path, p.path)

	cs, err := i.PublishedContainers(t.Context(), 8080)
	if err != nil || len(cs) != 1 || cs[0].Runtime != "docker" {
		t.Errorf("port 8080: containers = %+v, err = %v", cs, err)
	}
	cs, err = i.PublishedContainers(t.Context(), 15379)
	if err != nil || len(cs) != 1 || cs[0].Runtime != "podman" {
		t.Errorf("port 15379: containers = %+v, err = %v", cs, err)
	}

	// Two sockets to the same daemon that are not symlinks of each other.
	twin := serveRuntime(t, "Libpod/5.8.1 (linux)", http.StatusOK, podmanList)
	cs, err = newInspector(p.path, twin.path).PublishedContainers(t.Context(), 15379)
	if err != nil || len(cs) != 1 {
		t.Errorf("same container via two sockets: containers = %+v, err = %v", cs, err)
	}
}

func TestPublishedContainersBrokenRuntimeDoesNotHideWorkingOne(t *testing.T) {
	broken := serveRuntime(t, "Docker/27.3.1 (linux)", http.StatusInternalServerError, "")
	ok := serveRuntime(t, "Libpod/5.8.1 (linux)", http.StatusOK, podmanList)

	cs, err := newInspector(broken.path, ok.path).PublishedContainers(t.Context(), 15379)
	if err != nil || len(cs) != 1 {
		t.Errorf("containers = %+v, err = %v; want the working runtime's answer", cs, err)
	}

	cs, err = newInspector(broken.path, ok.path).PublishedContainers(t.Context(), 8080)
	if err == nil || !strings.Contains(err.Error(), broken.path+" answered HTTP 500") || cs != nil {
		t.Errorf("no match anywhere: containers = %+v, err = %v; want the failure reported", cs, err)
	}
}

func TestPublishedContainersMalformedAnswer(t *testing.T) {
	rt := serveRuntime(t, "Docker/27.3.1 (linux)", http.StatusOK, "<html>not a runtime</html>")
	_, err := newInspector(rt.path).PublishedContainers(t.Context(), 8080)
	if err == nil || !strings.Contains(err.Error(), "something other than a container list") {
		t.Errorf("error = %v", err)
	}
}

func TestPublishedOnUnparsableIP(t *testing.T) {
	list := []apiContainer{{ID: "abc", Names: []string{"/x"}, Ports: []apiPort{{IP: "", PublicPort: 80, PrivatePort: 80, Type: "tcp"}}}}
	cs := publishedOn(list, 80, "docker")
	if len(cs) != 1 || cs[0].Mappings[0].Host.String() != "0.0.0.0:80" {
		t.Errorf("containers = %+v, want the wildcard assumed", cs)
	}
}

func TestContainerSockets(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	got := containerSockets(env(map[string]string{"DOCKER_HOST": "unix:///tmp/custom.sock", "XDG_RUNTIME_DIR": "/run/user/1000"}), "/home/dev")
	want := []string{
		"/tmp/custom.sock",
		"/run/user/1000/docker.sock",
		"/run/user/1000/podman/podman.sock",
		"/var/run/docker.sock",
		"/run/podman/podman.sock",
		"/home/dev/.docker/run/docker.sock",
		"/home/dev/.docker/desktop/docker.sock",
		"/home/dev/.colima/default/docker.sock",
		"/home/dev/.orbstack/run/docker.sock",
		"/home/dev/.rd/docker.sock",
		"/home/dev/.local/share/containers/podman/machine/podman.sock",
	}
	if !slices.Equal(got, want) {
		t.Errorf("sockets = %q\nwant      %q", got, want)
	}

	// Remote hosts are ignored, and so is a missing home directory.
	got = containerSockets(env(map[string]string{"DOCKER_HOST": "ssh://core@127.0.0.1/run/podman/podman.sock"}), "")
	if !slices.Equal(got, []string{"/var/run/docker.sock", "/run/podman/podman.sock"}) {
		t.Errorf("sockets = %q", got)
	}
	got = containerSockets(env(map[string]string{"DOCKER_HOST": "tcp://127.0.0.1:2375"}), "")
	if got[0] != "/var/run/docker.sock" {
		t.Errorf("sockets = %q, want tcp host ignored", got)
	}
}

func TestRuntimeName(t *testing.T) {
	tests := map[string]string{
		"Docker/27.3.1 (linux)": "docker",
		"Libpod/5.8.1 (linux)":  "podman",
		"":                      "docker",
	}
	for server, want := range tests {
		if got := runtimeName(server); got != want {
			t.Errorf("runtimeName(%q) = %q, want %q", server, got, want)
		}
	}
}
