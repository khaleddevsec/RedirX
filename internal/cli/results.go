package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"redirx/internal/config"
	"redirx/internal/logger"
)

func newResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "results",
		Short: "List previous scan results and generated reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs, err := config.InitAppDirs(flagDataDir)
			if err != nil {
				return err
			}

			fmt.Println(logger.ColorBold + "[*] Stored Scan Results (" + dirs.Results + "):" + logger.ColorReset)

			entries, err := os.ReadDir(dirs.Results)
			if err != nil {
				return fmt.Errorf("failed reading results directory: %w", err)
			}

			count := 0
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					continue
				}

				count++
				sizeKB := float64(info.Size()) / 1024.0
				modTime := info.ModTime().Format("2006-01-02 15:04:05")

				ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(entry.Name()), "."))
				color := logger.ColorReset
				switch ext {
				case "HTML":
					color = logger.ColorCyan
				case "JSON":
					color = logger.ColorYellow
				case "TXT":
					color = logger.ColorGreen
				}

				fmt.Printf("  [%s%4s%s] %-35s %8.2f KB  (%s)\n",
					color, ext, logger.ColorReset, entry.Name(), sizeKB, modTime)
			}

			if count == 0 {
				fmt.Println("  (No scan results found)")
			}

			return nil
		},
	}
}

