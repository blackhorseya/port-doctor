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
$ port-doctor 3000

✓ Port 3000 is available
```

`listen tcp :8080: bind: address already in use` usually means a detour
through `lsof`, `ps`, `ss` or `netstat`, with different flags on every
operating system. `port-doctor` answers the one question you actually have
— *what's using this port?* — in a single command, on macOS and Linux, with
the same output on both.

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
- **Diagnosis** — one sentence you can act on.
- **Suggestions** — commands to inspect or stop the process. `port-doctor`
  only prints them; it never terminates or modifies another process.

When several processes listen on the same port (for example one on
`127.0.0.1` and another on a LAN address), each gets its own block.

For a free port that still has sockets in `TIME_WAIT` or another closing
state, the port is reported as available with a note, because a new listener
can fail to bind until those sockets expire.

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
| `1`  | The port is in use |
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

Only TCP is diagnosed in v0.1. Process command lines and environment
variables are never shown, since they routinely contain secrets.

## Roadmap

- **v0.1 — Local TCP ports** ✓
- **v0.2 — Docker awareness**: recognise ports published by a container and
  suggest `docker stop <container>`.
- **v0.3 — Port overview**: `port-doctor scan` listing every local listener.

`port-doctor` stays focused on one question — what's using this port? — and
will not grow into a general networking or security tool.

## Development

Developer commands use [Task](https://taskfile.dev) (`brew install go-task`):

```
task build       # → ./bin/port-doctor
task test        # unit + integration tests (opens real listeners on localhost)
task test-linux  # the same suite inside a golang container (Docker or Podman)
task lint
```

Parsers for `/proc/net/tcp` and `netstat` output are pure functions with
fixture tests that run on every platform; the integration tests exercise the
real inspectors against sockets owned by the test process.

## License

[Apache License 2.0](LICENSE)
