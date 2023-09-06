package cmd

// @its_a_feature_ 8/30/2023
import (
	"github.com/GhostManager/cobalt_sync/cmd/internal"
	"github.com/spf13/cobra"
	"log"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor [logs path]",
	Short: "monitor logs directory for changes",
	Long:  `Run this command to monitor a Cobalt Strike logs directory for changes.`,
	Run:   monitor,
	Args:  cobra.ExactArgs(1),
}

var server string
var reprocess bool
var printNewToStdout bool
var output string
var onlyHashes bool
var verbose bool

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().StringVarP(
		&server,
		"server",
		"s",
		"",
		`Send new beacon, task, and input events to remote server`,
	)
	monitorCmd.Flags().BoolVarP(
		&reprocess,
		"reprocess",
		"i",
		true,
		`Reprocess all log files at midnight each day`)
	monitorCmd.Flags().BoolVarP(
		&printNewToStdout,
		"displayNew",
		"d",
		false,
		"New events should print as they're parsed")
	monitorCmd.Flags().StringVarP(
		&output,
		"output",
		"o",
		"",
		"Processed events go to a file")
	monitorCmd.Flags().BoolVarP(
		&onlyHashes,
		"onlyHashes",
		"",
		false,
		"To minimize memory, only save hashed information about events instead of full tasking (can't be used with printSorted)")
	monitorCmd.Flags().BoolVarP(
		&verbose,
		"verbose",
		"v",
		false,
		"Print verbose debugging")

}

func monitor(cmd *cobra.Command, args []string) {
	internal.SetURL(server)
	go internal.ListenForLogData(onlyHashes, printNewToStdout, output)
	go internal.ListenForWatcherEvents(verbose)
	err := internal.WalkFiles(verbose, args[0], true)
	if err != nil {
		log.Fatal(err)
	}
	if reprocess {
		go internal.PeriodicallyReProcess(verbose, args[0], onlyHashes)
	}
	if !onlyHashes {
		internal.SortEvents()
		internal.PrintEvents()
	}
	forever := make(chan bool)
	<-forever
}
