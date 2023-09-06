package cmd

import (
	"fmt"
	"github.com/GhostManager/cobalt_sync/cmd/config"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Displays Cobalt Parser's version information",
	Long:  "Displays Cobalt Parser's version information.",
	Run:   displayVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func displayVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("Cobalt Parser ( %s, %s )\n", config.Version, config.BuildDate)
}
