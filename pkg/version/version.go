package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current semantic version of RedirX.
	Version = "3.1.2"
	// Author is the developer and maintainer.
	Author = "Md. Khaledul Islam (@khaleddevsec)"
	// Commit is the git commit SHA at build time.
	Commit = "dev"
	// BuildDate is the timestamp at build time.
	BuildDate = "unknown"
)

// Info returns formatted version and author information.
func Info() string {
	return fmt.Sprintf("RedirX v%s by %s (commit: %s, built: %s, runtime: %s/%s)",
		Version, Author, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}
