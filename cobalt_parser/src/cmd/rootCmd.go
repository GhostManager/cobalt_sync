package cmd

// @its_a_feature_ 8/30/2023
import (
	"fmt"
	"github.com/GhostManager/cobalt_sync/cmd/config"
	"github.com/GhostManager/cobalt_sync/cmd/internal"
	"os"
)

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cobalt-parser",
	Short: fmt.Sprintf("A command line interface for parsing Cobalt Strike logs. Version: %s", config.Version),
	Long: fmt.Sprintf(`cobalt-parser (%s) is a command line interface for parsing and watching Cobalt Strike log files.
Commands are grouped by their use and all support '-h' for help.`, config.Version),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	internal.Initialize()
}
