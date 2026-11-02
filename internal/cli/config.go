package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"redirx/internal/config"
	"redirx/internal/logger"
)

func newConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Display RedirX data directories and active configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs, err := config.InitAppDirs(flagDataDir)
			if err != nil {
				return err
			}

			fmt.Println(logger.ColorBold + "[*] RedirX Directory Configuration:" + logger.ColorReset)
			fmt.Printf("  Root Directory:       %s\n", dirs.Root)
			fmt.Printf("  Results Directory:    %s\n", dirs.Results)
			fmt.Printf("  Reports Directory:    %s\n", dirs.Reports)
			fmt.Printf("  Logs Directory:       %s\n", dirs.Logs)
			fmt.Printf("  Config Directory:     %s\n", dirs.Config)
			fmt.Printf("  Wordlists Directory:  %s\n", dirs.Wordlists)
			fmt.Printf("  Backups Directory:    %s\n", dirs.Backups)

			envDir := os.Getenv("REDIRX_DATA_DIR")
			if envDir != "" {
				fmt.Printf("\n  [i] REDIRX_DATA_DIR Environment: %s\n", envDir)
			}
			return nil
		},
	}
}

