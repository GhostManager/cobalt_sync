package cmd

// @its_a_feature_ 8/30/2023
import (
	"github.com/GhostManager/cobalt_sync/cmd/internal"
	"github.com/spf13/cobra"
	"log"
)

var printCmd = &cobra.Command{
	Use:   "print [logs path]",
	Short: "Parse Cobalt Strike logs folder and print output",
	Long:  `Run this command to parse a Cobalt Strike log folder and print the output in sorted JSON.`,
	Run:   printLogs,
	Args:  cobra.ExactArgs(1),
}

func init() {
	rootCmd.AddCommand(printCmd)
	printCmd.Flags().StringVarP(
		&server,
		"server",
		"s",
		"",
		`Send new Beacon, task, and input events to remote server`,
	)
	printCmd.Flags().BoolVarP(
		&printNewToStdout,
		"displayNew",
		"d",
		false,
		"New events should print as they're parsed")
	printCmd.Flags().BoolVarP(
		&verbose,
		"verbose",
		"v",
		false,
		"Print verbose debugging")
	printCmd.Flags().StringVarP(
		&output,
		"output",
		"o",
		"",
		"Processed events go to a file")
}

func printLogs(cmd *cobra.Command, args []string) {
	internal.SetURL(server)
	go internal.ListenForLogData(false, printNewToStdout, output)
	err := internal.WalkFiles(verbose, args[0], false)
	if err != nil {
		log.Fatal(err)
	}
	internal.SortEvents()
	internal.PrintEvents()
}
