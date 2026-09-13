// Command port-doctor explains why a local TCP port is unavailable.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/blackhorseya/port-doctor/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	c, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(c, version, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
