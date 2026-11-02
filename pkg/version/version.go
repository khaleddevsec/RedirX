package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current semantic version of RedirX.
	Version = "3.1.2"
	// Author is the developer's GitHub username.
	Author = "khaleddevsec"
	// Commit is the git commit SHA at build time.
	Commit = "dev"
	// BuildDate is the timestamp at build time.
	BuildDate = "unknown"
)

// Info returns formatted version information.
func Info() string {
	return fmt.Sprintf("RedirX v%s by %s (commit: %s, built: %s, runtime: %s/%s)",
		Version, Author, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

// Banner returns the ASCII art banner with exact DorkX-style formatting.
func Banner() string {
	return `
 ____           _ _       __  __
|  _ \ ___   __| (_)_ __  \ \/ /
| |_) / _ \ / _` + "`" + ` | | '__|  \  / 
|  _ <  __/| (_| | | |     /  \ 
|_| \_\___| \__,_|_|_|    /_/\_\

              Open Redirect CLI Tool
    by ` + "\033[33m" + Author + "\033[0m" + ` | ` + "\033[36mv" + Version + "\033[0m" + ` ` + "\033[32m(latest)\033[0m" + ` | https://github.com/khaleddevsec/RedirX
`
}
