# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`port-doctor <port>` — a small Go CLI that answers "what's using this port?" for a local TCP port on macOS and Linux: the listening process (PID, name, owner), the exact bound address, a one-line diagnosis and conservative next-step commands. v0.1 is deliberately narrow: no killing, no `--free`, no Docker/Kubernetes, no UDP, no scanning, no config files, no daemon, no telemetry. It must never terminate or modify another process. When scope is unclear, pick the smaller implementation.

## Commands

Dev commands use [Task](https://taskfile.dev) (`Taskfile.yml`); binaries go to `./bin/`.

```
task build        # ./bin/port-doctor, version stamped from git describe
task test         # go test -race ./...  (integration tests open real listeners on localhost)
task test-linux   # same suite inside a golang:1.27 container (Docker or Podman)
task lint         # go vet + golangci-lint under GOOS=darwin and GOOS=linux (v2 config in .golangci.yml)
task fmt          # gofmt + goimports via golangci-lint fmt
task snapshot     # goreleaser release --snapshot --clean → ./dist
```

Single test: `go test ./internal/inspect -run TestParseNetstatModern -v`
Validate release config: `goreleaser check`. Releases are cut by pushing a `v*` tag (`.github/workflows/release.yml`).

## Architecture

Four packages under `internal/`, wired by `cli.diagnose` in `internal/cli/cli.go`:

```
doctor.ParsePort                      validate the argument (1–65535)
inspect.New                           platform PortInspector + ProcessInspector (build-tagged constructors)
doctor.Doctor.Diagnose                orchestration: list sockets → group by PID → enrich → diagnosis + suggestions
presenter.Render                      terminal output (lipgloss v2, plain text when not a TTY)
```

`cmd/port-doctor/main.go` only wires signals and calls `cli.Run`, which returns an exit code instead of calling `os.Exit` — tests call `Run` in-process. `cli.newDiagnoser` is a package variable so tests can swap in a fake doctor.

### Domain (`internal/doctor`)

- The interfaces `PortInspector` and `ProcessInspector` are defined here, on the consumer side; `inspect` only returns concrete types. Doctor tests use fakes and never touch the OS.
- `Diagnose` returns an error only when the socket listing itself fails (exit 2). Everything about process metadata degrades into `Report.Notes`: `ErrProcessNotFound` marks the occupant `Exited` (and suppresses `kill` suggestions because the PID may be reused), `ErrPermission` adds the permissions note, any other error adds a generic note. `Listener.PID == 0` means "could not be identified"; `Listener.User` may still be known (Linux) and is used as a fallback for `Process.User`.
- Occupants are grouped by PID, ordered by PID with the unidentified group last; listeners within a group are sorted IPv4 before IPv6. The diagnosis scope hint (`localhost only` / `all interfaces` / `<ip> only`) comes from `scope`; `Unmap()` is applied so `::ffff:0.0.0.0` counts as wildcard.
- A port with no listener but sockets in other states (`TIME_WAIT`, `CLOSE_WAIT`, …) is still `StatusAvailable` (exit 0) with a note from `lingeringNote`.

### Inspectors (`internal/inspect`)

- Parsers (`procfs.go`, `netstat.go`) carry no build tags so their fixture tests run on every platform; only `new_linux.go` / `new_darwin.go` / `new_other.go` are gated. `procfsInspector.root` and `darwinInspector.run` are injection points for tests (a fake `/proc` tree, a canned command runner).
- **macOS uses `netstat -anv -p tcp`, not `lsof`.** `lsof` cannot see other users' sockets without root and would report a root-owned port as free; `netstat` reads the table via sysctl and shows every socket with its PID. The column layout differs across macOS releases (macOS 26 merges name and pid into `process:pid`, and names may contain spaces; older releases have separate `pid`/`epid` columns). `parseNetstat` locates the pid column in the header and counts the columns after it, then reads each row from the end — never index rows from the left past the first six fields. Keep fixtures for both layouts. `*.port` means `0.0.0.0` for `tcp4` and `[::]` for `tcp6`/`tcp46`.
- macOS process metadata is `ps -p <pid> -o uid=,comm=`: the first token is the uid, the rest is the executable path (may contain spaces); its base name is the untruncated process name. `ps` exiting 1 with empty output means the PID is gone → `ErrProcessNotFound`.
- **Linux reads `/proc/net/tcp{,6}` directly** (no `ss` dependency). Addresses are hex with each 4-byte word in host (little-endian) order; the port is big-endian. A missing `tcp6` table (IPv6 disabled) is not an error; both tables missing is. `socketOwners` walks `/proc/<pid>/fd` in ascending PID order and reports the lowest PID holding the socket (parent before forked workers), except PID 1 when any other owner exists (systemd socket activation). Unreadable fd tables (other users' processes) are skipped silently; the listener keeps its uid from `/proc/net/tcp`.
- Linux process name prefers the `exe` link's base name (strip ` (deleted)`) over `comm`, which the kernel truncates to 15 bytes; `exe` is only readable for your own processes, so `comm` is the fallback.
- `ElevatedInspectCommand` supplies the per-platform `sudo …` hint used when a PID is unknown.

### Errors and exit codes

Exit codes (0 available, 1 in use, 2 cannot diagnose) are documented in README.md and pinned by `TestExitCodes` in `internal/cli/cli_test.go` — change both together. Cobra argument/flag errors and `doctor.ParsePort` errors are wrapped in `*usageError`; `cli.hint` maps errors to a `hint:` line. Error output format is `Error: <message>`. `allowNegativeNumbers` inserts `--` before a negative argument so `port-doctor -1` reaches port validation instead of being rejected as an unknown flag.

### Output

`presenter.Render` builds sections joined by blank lines and writes through `lipgloss.Fprint`, which strips ANSI when the writer is not a color terminal, so tests see plain text. Sections: headline, then per occupant Process + Network, Diagnosis, Suggestions, then Notes as bare dimmed lines. Labels are padded to 10 columns (`  %-10s%s`). If you change the format, update the golden strings in `presenter_test.go`, the assertions in `cli_test.go`, and the examples in README.md (its first screen is the product demo).

## Testing notes

- Integration tests (`internal/inspect/integration_test.go`, `cli.TestEndToEnd`) listen on ephemeral ports owned by the test process and assert the reported PID is `os.Getpid()`. They pin the network to `tcp4`/`tcp6`: plain `"tcp"` with a wildcard address makes Go open a dual-stack `[::]` socket even for `0.0.0.0`.
- `TestRealLingeringSockets` closes a connection from the server side so the server socket sits in `TIME_WAIT` on the port; it polls briefly because the state transition is asynchronous.
- `TestProcfsInspectProcessPermission` is skipped as root (root can read a mode-000 file), so it is skipped in the Docker run.

- Lint runs for both GOOS values (Taskfile and a CI matrix) because build-tagged files hide symbols from the other platform: a helper referenced only from `new_darwin.go` is "unused" on Linux.

## Code conventions

- Go 1.26: prefer `errors.AsType[T]`, `strings.SplitSeq`, `slices.Sorted(maps.Keys(m))` (gopls flags the older forms).
- Receivers: `i` for the infrastructure types (`*procfsInspector`, `*darwinInspector`), `x` for domain and error types (`*doctor.Doctor`, `*usageError`); context parameters are named `c`.
- Version is injected with `-X main.version=...` (Taskfile, GoReleaser uses `v{{ .Version }}`); `cli.resolveVersion` falls back to `debug.ReadBuildInfo` for `go install ...@vX`.
