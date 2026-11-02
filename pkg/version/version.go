package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current semantic version of RedirX.
	Version = "1.0.0"
	// Commit is the git commit SHA at build time.
	Commit = "dev"
	// BuildDate is the timestamp at build time.
	BuildDate = "unknown"
)

// Info returns formatted version information.
func Info() string {
	return fmt.Sprintf("RedirX v%s (commit: %s, built: %s, runtime: %s/%s)",
		Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

