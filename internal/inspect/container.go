package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

// containerTimeout bounds each request to a container runtime so a wedged
// daemon delays the report by at most this much per socket.
const containerTimeout = 2 * time.Second

// maxContainerList caps the response body read from a runtime.
const maxContainerList = 16 << 20

// errDeadSocket marks a socket file nobody listens on, such as the one a
// stopped Docker Desktop leaves behind. It is skipped, not reported.
var errDeadSocket = errors.New("nothing is listening on the socket")

// containerInspector asks every reachable container runtime socket which
// running containers publish a port. Docker Engine and Podman answer the
// same request, GET /containers/json, over their unix sockets, so no
// runtime CLI is needed and none is run.
type containerInspector struct {
	// sockets are candidate unix socket paths in priority order. Missing and
	// dead ones are skipped; several paths to one daemon are queried once.
	sockets []string
	timeout time.Duration
}

// NewContainerInspector returns an inspector for the container runtime
// sockets that may exist on this machine. Nothing is contacted until
// PublishedContainers or ListContainers is called.
func NewContainerInspector() RuntimeInspector {
	home, _ := os.UserHomeDir()
	return &containerInspector{sockets: containerSockets(os.Getenv, home), timeout: containerTimeout}
}

// containerSockets lists where Docker Engine, Docker Desktop, Podman and the
// common Docker Desktop alternatives put their API sockets, rootless
// variants included. DOCKER_HOST
// comes first when it names a unix socket; tcp:// and ssh:// hosts are
// ignored because reaching them needs credentials port-doctor does not have.
func containerSockets(getenv func(string) string, home string) []string {
	var out []string
	if h := getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		if p := strings.TrimPrefix(h, "unix://"); p != "" {
			out = append(out, p)
		}
	}
	if dir := getenv("XDG_RUNTIME_DIR"); dir != "" {
		// Rootless Docker and the Podman user socket.
		out = append(out, filepath.Join(dir, "docker.sock"), filepath.Join(dir, "podman", "podman.sock"))
	}
	out = append(out, "/var/run/docker.sock", "/run/podman/podman.sock")
	if home != "" {
		for _, rel := range []string{
			".docker/run/docker.sock",                            // Docker Desktop
			".docker/desktop/docker.sock",                        // Docker Desktop, older releases and Linux
			".colima/default/docker.sock",                        // Colima
			".orbstack/run/docker.sock",                          // OrbStack
			".rd/docker.sock",                                    // Rancher Desktop
			".local/share/containers/podman/machine/podman.sock", // Podman machine
		} {
			out = append(out, filepath.Join(home, rel))
		}
	}
	return out
}

// PublishedContainers implements doctor.ContainerInspector.
func (i *containerInspector) PublishedContainers(c context.Context, port int) ([]doctor.Container, error) {
	all, err := i.collect(c)
	return settle(c, onPort(all, port), err)
}

// ListContainers implements doctor.ContainerLister.
func (i *containerInspector) ListContainers(c context.Context) ([]doctor.Container, error) {
	all, err := i.collect(c)
	return settle(c, all, err)
}

// collect queries each live socket and merges the answers, deduplicated by
// container ID because several paths often lead to the same daemon. It
// returns everything found together with the first socket failure, if any;
// settle decides whether that failure matters.
func (i *containerInspector) collect(c context.Context) ([]doctor.Container, error) {
	var found []doctor.Container
	seen := map[string]bool{}
	tried := map[string]bool{}
	var firstErr error
	for _, path := range i.sockets {
		if err := c.Err(); err != nil {
			return found, err
		}
		path, ok := liveSocket(path, tried)
		if !ok {
			continue
		}
		cs, err := i.query(c, path)
		switch {
		case errors.Is(err, errDeadSocket):
			continue
		case err != nil:
			if c.Err() != nil {
				return found, c.Err()
			}
			firstErr = cmpErr(firstErr, err)
			continue
		}
		for _, ct := range cs {
			if !seen[ct.ID] {
				seen[ct.ID] = true
				found = append(found, ct)
			}
		}
	}
	return found, firstErr
}

// settle applies the reporting rule shared by both methods: the caller's
// context error always surfaces, with whatever was found so far; a socket
// failure surfaces only when nothing was found, so a broken second runtime
// never hides the containers of a working one.
func settle(c context.Context, found []doctor.Container, err error) ([]doctor.Container, error) {
	if cerr := c.Err(); cerr != nil {
		return found, cerr
	}
	if len(found) == 0 {
		return nil, err
	}
	return found, nil
}

// onPort keeps the containers publishing port, with only that port's mappings.
func onPort(cs []doctor.Container, port int) []doctor.Container {
	var out []doctor.Container
	for _, ct := range cs {
		var ms []doctor.PortMapping
		for _, m := range ct.Mappings {
			if int(m.Host.Port()) == port {
				ms = append(ms, m)
			}
		}
		if len(ms) == 0 {
			continue
		}
		ct.Mappings = ms
		out = append(out, ct)
	}
	return out
}

func cmpErr(first, next error) error {
	if first != nil {
		return first
	}
	return next
}

// liveSocket resolves path to the socket file it names, so that symlinks to
// one daemon are recognised, and reports whether it is worth contacting.
func liveSocket(path string, tried map[string]bool) (string, bool) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false // does not exist
	}
	fi, err := os.Stat(resolved)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || tried[resolved] {
		return "", false
	}
	tried[resolved] = true
	return resolved, true
}

// query lists the running containers of one runtime and keeps those that
// publish a TCP port. The Server header tells Docker Engine and Podman apart.
func (i *containerInspector) query(parent context.Context, path string) ([]doctor.Container, error) {
	c, cancel := context.WithTimeout(parent, i.timeout)
	defer cancel()

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	// The host in the URL is irrelevant: the transport always dials path.
	req, err := http.NewRequestWithContext(c, http.MethodGet, "http://runtime/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, i.classify(parent, c, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxContainerList))
	if err != nil {
		return nil, i.classify(parent, c, path, err)
	}
	var list []apiContainer
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("%s answered with something other than a container list", path)
	}
	return toContainers(list, runtimeName(resp.Header.Get("Server"))), nil
}

// classify turns a transport failure into the error the doctor should see:
// the caller's own cancellation first, then this socket's timeout, then the
// failures that mean "skip" (nobody listening) or "note" (no permission).
func (i *containerInspector) classify(parent, c context.Context, path string, err error) error {
	if perr := parent.Err(); perr != nil {
		return perr
	}
	if c.Err() != nil {
		return fmt.Errorf("%s did not answer within %s", path, i.timeout)
	}
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ENOENT):
		return errDeadSocket
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%s: %w", path, doctor.ErrPermission)
	}
	return fmt.Errorf("%s: %w", path, err)
}

// apiContainer is the subset of a /containers/json entry port-doctor reads.
// Command, environment and mounts are deliberately not decoded.
type apiContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Ports  []apiPort         `json:"Ports"`
	Labels map[string]string `json:"Labels"`
}

// apiPort is one entry of a container's Ports. Entries without PublicPort
// are exposed but not published. Docker lists a plain "-p 8080:80" twice,
// once for 0.0.0.0 and once for ::; Podman lists it once.
type apiPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

func runtimeName(server string) string {
	if strings.HasPrefix(strings.ToLower(server), "libpod") {
		return "podman"
	}
	return "docker"
}

// toContainers converts the runtime's answer, keeping the containers that
// publish at least one TCP port together with all of their TCP mappings.
// Exposed-only ports (no PublicPort) and UDP publications are dropped.
func toContainers(list []apiContainer, runtime string) []doctor.Container {
	var out []doctor.Container
	for _, ac := range list {
		var mappings []doctor.PortMapping
		for _, p := range ac.Ports {
			if p.PublicPort < 1 || p.PublicPort > 65535 || !strings.EqualFold(p.Type, "tcp") {
				continue
			}
			ip, err := netip.ParseAddr(p.IP)
			if err != nil {
				ip = netip.IPv4Unspecified()
			}
			mappings = append(mappings, doctor.PortMapping{
				Host:          netip.AddrPortFrom(ip, uint16(p.PublicPort)),
				ContainerPort: p.PrivatePort,
				Protocol:      doctor.ProtocolTCP,
			})
		}
		if len(mappings) == 0 {
			continue
		}
		out = append(out, doctor.Container{
			Runtime:  runtime,
			ID:       shortID(ac.ID),
			Name:     containerName(ac.Names),
			Image:    ac.Image,
			Mappings: mappings,
			Compose: doctor.ComposeService{
				Project: ac.Labels["com.docker.compose.project"],
				Service: ac.Labels["com.docker.compose.service"],
			},
		})
	}
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// containerName picks the container's own name from Names, which Docker
// prefixes with "/" and pads with "/other/alias" entries for legacy links.
func containerName(names []string) string {
	for _, n := range names {
		n = strings.TrimPrefix(n, "/")
		if !strings.Contains(n, "/") {
			return n
		}
	}
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return ""
}
