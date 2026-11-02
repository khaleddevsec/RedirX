package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

var (
	globalLogger *slog.Logger
	logOnce      sync.Once
	logFile      *os.File
)

// ANSI color codes for terminal formatting
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorGray    = "\033[90m"
	ColorBold    = "\033[1m"
)

// InitLogger configures global structured logging.
func InitLogger(logDir string, verbose bool, silent bool) (*slog.Logger, error) {
	var err error
	logOnce.Do(func() {
		var writers []io.Writer

		if !silent {
			writers = append(writers, os.Stderr)
		}

		if logDir != "" {
			if mkErr := os.MkdirAll(logDir, 0755); mkErr == nil {
				filePath := filepath.Join(logDir, "redirx.log")
				f, fErr := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
				if fErr == nil {
					logFile = f
					writers = append(writers, f)
				}
			}
		}

		var multiWriter io.Writer
		if len(writers) == 0 {
			multiWriter = io.Discard
		} else if len(writers) == 1 {
			multiWriter = writers[0]
		} else {
			multiWriter = io.MultiWriter(writers...)
		}

		level := slog.LevelInfo
		if verbose {
			level = slog.LevelDebug
		} else if silent {
			level = slog.LevelError
		}

		handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{
			Level: level,
		})

		globalLogger = slog.New(handler)
		slog.SetDefault(globalLogger)
	})

	return globalLogger, err
}

// CloseLogger flushes and closes open log file descriptors.
func CloseLogger() {
	if logFile != nil {
		_ = logFile.Sync()
		_ = logFile.Close()
	}
}

// Console helpers for interactive output

func PrintSuccess(format string, a ...interface{}) {
	fmt.Printf(ColorGreen+"[+] "+ColorReset+format+"\n", a...)
}

func PrintInfo(format string, a ...interface{}) {
	fmt.Printf(ColorCyan+"[*] "+ColorReset+format+"\n", a...)
}

func PrintWarn(format string, a ...interface{}) {
	fmt.Printf(ColorYellow+"[!] "+ColorReset+format+"\n", a...)
}

func PrintError(format string, a ...interface{}) {
	fmt.Printf(ColorRed+"[-] "+ColorReset+format+"\n", a...)
}

func PrintVuln(format string, a ...interface{}) {
	fmt.Printf(ColorMagenta+ColorBold+"[redirx] "+ColorRed+ColorBold+"[!] VULNERABLE: "+ColorReset+format+"\n", a...)
}

func PrintPotential(format string, a ...interface{}) {
	fmt.Printf(ColorMagenta+ColorBold+"[redirx] "+ColorYellow+ColorBold+"[?] POTENTIAL: "+ColorReset+format+"\n", a...)
}

