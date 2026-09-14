// Package inspect implements the platform-specific inspectors used by
// package doctor.
//
// Linux reads procfs directly; macOS shells out to netstat and ps. Both
// parsers are free of build tags so their unit tests run on every platform;
// only the constructors in new_*.go are platform-gated.
package inspect

import (
	"errors"
	"os/user"
	"strconv"
)

// ErrUnsupportedPlatform is returned by New on operating systems port-doctor
// does not know how to inspect.
var ErrUnsupportedPlatform = errors.New("unsupported platform")

// lookupUser resolves a uid to a username, falling back to the number so the
// report still says who owns the socket on systems with unusual user stores.
func lookupUser(uid int) string {
	id := strconv.Itoa(uid)
	u, err := user.LookupId(id)
	if err != nil {
		return id
	}
	return u.Username
}
