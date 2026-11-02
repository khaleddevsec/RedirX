package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"redirx/internal/config"
	"redirx/internal/logger"
	"redirx/internal/updater"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Check and install the latest RedirX release from GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs, err := config.InitAppDirs(flagDataDir)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			if err := updater.CheckAndApplyUpdate(ctx, dirs.Backups); err != nil {
				logger.PrintError("Update check failed: %v", err)
				return err
			}
			return nil
		},
	}
}

