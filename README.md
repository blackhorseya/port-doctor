# port-doctor

Find out what's using your port.

```
$ port-doctor 8080

✗ Port 8080 is in use

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
```

```
$ port-doctor 5432

✗ Port 5432 is in use

Process
  PID       3189
  Name      gvproxy
  User      sean

Network
  Protocol  TCP
  Address   [::]:5432

Container
  Runtime   podman
  Name      myapp-db-1
  Image     docker.io/library/postgres:17
  Compose   myapp / db
  Mapping   0.0.0.0:5432 → 5432/tcp

Diagnosis
  Container myapp-db-1 (podman) publishes port 5432 (all interfaces).

Suggestions
  Inspect:
    podman logs --tail 20 myapp-db-1

  Stop:
    podman compose -p myapp stop db
```

```
$ port-doctor 3000

✓ Port 3000 is available
```

`listen tcp :8080: bind: address already in use` usually means a detour
through `lsof`, `ps`, `ss` or `netstat`, with different flags on every
operating system. `port-doctor` answers the one question you actually have
— *what's using this port?* — in a single command, on macOS and Linux, with
the same output on both. When the port belongs to a Docker or Podman
container it names the container, not the runtime's port forwarder, and
suggests `docker stop` rather than a `kill` that would take every container
offline.

## Install

**Go**

```
go install github.com/blackhorseya/port-doctor/cmd/port-doctor@latest
```

**Prebuilt binaries** (macOS / Linux)

Download the archive for your platform from the
[releases page](https://github.com/blackhorseya/port-doctor/releases), then
put `port-doctor` somewhere on your `PATH`:

```
tar -xzf port-doctor_*_darwin_arm64.tar.gz
mv port-doctor /usr/local/bin/
```

No root, no daemon, no configuration files, no telemetry.

## Usage

```
port-doctor <port>
port-doctor --version
port-doctor --help
```

For an occupied port, `port-doctor` shows:

- **Process** — PID, name and owner of the listener.
- **Network** — protocol and the exact address it is bound to, because
  `127.0.0.1:8080` (localhost only), `0.0.0.0:8080` (every IPv4 interface)
  and `[::]:8080` (every interface, dual-stack) mean different things.
- **Container** — when a container publishes the port: the runtime
  (`docker` or `podman`), the container's name and image, its Compose
  project and service if it has them, and every host address mapped to it.
- **Diagnosis** — one sentence you can act on.
- **Suggestions** — commands to inspect or stop the process or container.
  `port-doctor` only prints them; it never terminates or modifies anything.

When several processes listen on the same port (for example one on
`127.0.0.1` and another on a LAN address), each gets its own block.

For a free port that still has sockets in `TIME_WAIT` or another closing
state, the port is reported as available with a note, because a new listener
can fail to bind until those sockets expire.

### Containers

The process holding a port published by a container is the runtime's port
forwarder — `docker-proxy` on Linux, `com.docker.backend` for Docker
Desktop, `gvproxy` for a Podman machine — and killing it would disconnect
every container at once. `port-doctor` therefore asks the runtime which
container is behind the port and suggests stopping that container instead.
A Compose-managed container is stopped through `compose`, so the next
`compose up` does not quietly bring it back.

The runtime is queried through its API socket; the `docker` and `podman`
commands are never run. The sockets tried are `$DOCKER_HOST` when it is a
`unix://` socket, the rootless Docker and Podman sockets under
`$XDG_RUNTIME_DIR`, `/var/run/docker.sock`, `/run/podman/podman.sock`, and
the Docker Desktop, Colima, OrbStack, Rancher Desktop and Podman machine
sockets under your home directory. Docker Engine and Podman both
answer, and both are reported with their own command name. Sockets that do
not exist or that nothing listens on are skipped; a socket you may not read
adds a note instead of failing the diagnosis; a runtime gets two seconds to
answer. Only the container's name, image, published ports and Compose labels
are read — never its command line, environment or mounts.

A port that a container publishes without any host listener (Docker with
`userland-proxy` disabled forwards with packet rules alone) is still reported
as in use, exit code `1`, because a server bound there would never receive a
connection. That configuration is covered by fixture tests only.

If the listener is a known port forwarder but no runtime socket answers —
Podman on Linux without `podman.socket` enabled, for example — the report
says so, suggests `podman ps`, and never suggests killing the forwarder.

### Permissions

Everything works as a normal user. Finding the listener never needs root on
either platform; only some process details can be out of reach:

- **macOS** reads the socket table through `netstat`, which reports every
  user's sockets and their PIDs, so even a root-owned listener is fully
  identified.
- **Linux** reads `/proc/net/tcp` and `/proc/net/tcp6`, which list every
  socket and its owning user, then maps the socket to a PID through
  `/proc/<pid>/fd`. That last step only works for your own processes unless
  you are root. When the PID cannot be determined, the owner is still shown
  and `port-doctor` suggests a privileged command to finish the job:

```
✗ Port 80 is in use

Process
  PID       unknown
  Name      unavailable
  User      root

Network
  Protocol  TCP
  Address   0.0.0.0:80

Diagnosis
  A process is listening on port 80 (all interfaces), but it could not be identified.

Suggestions
  Identify (needs elevated privileges):
    sudo ss -ltnp 'sport = :80'

The listening process could not be identified, usually because it belongs to another user.
```

Partial information is always preferred over a failure, and a listener that
exits while it is being inspected is reported as such rather than crashing
the tool.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | The port is available |
| `1`  | The port is in use — a process listens on it or a container publishes it |
| `2`  | The diagnosis could not be performed — invalid arguments, unsupported platform, or a system utility failed |

This makes `port-doctor` usable in scripts:

```sh
port-doctor 8080 >/dev/null || echo "8080 is taken"
```

### Invalid input

```
$ port-doctor abc
Error: invalid port "abc"
hint: usage: port-doctor <port>, for example: port-doctor 8080

$ port-doctor 99999
Error: port must be between 1 and 65535
hint: usage: port-doctor <port>, for example: port-doctor 8080
```

Missing arguments, extra arguments, port `0` and negative numbers are
rejected the same way, with exit code `2`.

## How it works

`port-doctor` inspects the actual listener rather than trying to connect to
the port, so it can tell you *who* holds it, not just that something answers.

| Platform | Sockets and PIDs | Process details |
|----------|------------------|-----------------|
| macOS | `netstat -anv -p tcp` | `ps -p <pid> -o uid=,comm=` |
| Linux | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/<pid>/fd` | `/proc/<pid>/comm`, `exe`, `status` |

`netstat` is used on macOS instead of `lsof` because `lsof` cannot see
other users' processes without root and would report a port held by a
system daemon as free.

Containers come from the runtime's own API — `GET /containers/json` on the
Docker Engine or Podman socket, which answer identically — so no container
CLI needs to be installed.

Only TCP is diagnosed. Process command lines and environment variables are
never shown, since they routinely contain secrets.

## Roadmap

- **v0.1 — Local TCP ports** ✓
- **v0.2 — Container awareness** ✓: ports published by Docker or Podman
  containers are attributed to the container, with `docker stop` /
  `podman stop` (or `compose stop`) in place of `kill`.
- **v0.3 — Port overview**: `port-doctor scan` listing every local listener.

`port-doctor` stays focused on one question — what's using this port? — and
will not grow into a general networking or security tool.

## Development

Developer commands use [Task](https://taskfile.dev) (`brew install go-task`):

```
task build       # → ./bin/port-doctor
task test           # unit + integration tests (opens real listeners on localhost)
task test-linux     # the same suite inside a golang container (Docker or Podman)
task test-container # attribute a port to a real container (starts and removes one alpine container)
task lint
```

Parsers for `/proc/net/tcp` and `netstat` output are pure functions with
fixture tests that run on every platform; the integration tests exercise the
real inspectors against sockets owned by the test process. The container
inspector is tested against fake Docker and Podman runtimes served on unix
sockets, and `task test-container` (also a CI job on Docker Engine) against
a real one.

## License

[Apache License 2.0](LICENSE)
