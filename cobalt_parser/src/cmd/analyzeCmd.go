package cmd

// @its_a_feature_ 8/30/2023
import (
	"encoding/json"
	"fmt"
	"github.com/GhostManager/cobalt_sync/cmd/internal"
	"github.com/spf13/cobra"
	"log"
	"strings"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [logs path]",
	Short: "Parse Cobalt Strike logs folder and analyze",
	Long:  `Run this command to parse a Cobalt Strike log folder and print analysis of data.`,
	Run:   analyze,
	Args:  cobra.ExactArgs(1),
}
var inputCommandsOfInterest []string
var showErrors bool

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().BoolVarP(
		&verbose,
		"verbose",
		"v",
		false,
		"Print verbose debugging")
	analyzeCmd.Flags().BoolVarP(
		&showErrors,
		"errors",
		"e",
		false,
		"Show stats about errors")
	analyzeCmd.Flags().StringVarP(
		&output,
		"output",
		"o",
		"",
		"Processed events go to a file")
	analyzeCmd.Flags().StringArrayVarP(
		&inputCommandsOfInterest,
		"commands",
		"c",
		[]string{},
		"Input command names to find unique instances")
}

func analyze(cmd *cobra.Command, args []string) {
	go internal.ListenForLogData(false, false, output)
	err := internal.WalkFiles(verbose, args[0], false)
	if err != nil {
		log.Fatal(err)
	}
	allEvents := internal.GetEvents(verbose)
	beaconCount := len(allEvents)
	fmt.Println("Total Beacons:", beaconCount)
	inputCount := 0
	taskCount := 0
	errorCount := 0
	userStats := make(map[string]int)
	beaconHosts := []string{}
	userAccounts := []string{}
	errorEvents := []string{}
	uniqueInputCommands := make(map[string][]string, len(inputCommandsOfInterest))
	for beaconID, _ := range allEvents {
		if !internal.StringInSlice(allEvents[beaconID].Computer, beaconHosts) {
			beaconHosts = append(beaconHosts, allEvents[beaconID].Computer)
		}
		if !internal.StringInSlice(allEvents[beaconID].User, userAccounts) {
			userAccounts = append(userAccounts, allEvents[beaconID].User)
		}
		for eventIndex, _ := range allEvents[beaconID].Events {
			switch allEvents[beaconID].Events[eventIndex].Event {
			case "input":
				inputCount += 1
				if _, ok := userStats[allEvents[beaconID].Events[eventIndex].Operator]; !ok {
					userStats[allEvents[beaconID].Events[eventIndex].Operator] = 1
				} else {
					userStats[allEvents[beaconID].Events[eventIndex].Operator] += 1
				}
				if len(inputCommandsOfInterest) > 0 {
					inputCmdPieces := strings.Split(allEvents[beaconID].Events[eventIndex].Message, " ")
					if len(inputCmdPieces) > 0 {
						if internal.StringInSlice(inputCmdPieces[0], inputCommandsOfInterest) {
							if _, ok := uniqueInputCommands[inputCmdPieces[0]]; !ok {
								uniqueInputCommands[inputCmdPieces[0]] = []string{}
							}
							if !internal.StringInSlice(allEvents[beaconID].Events[eventIndex].Message, uniqueInputCommands[inputCmdPieces[0]]) {
								uniqueInputCommands[inputCmdPieces[0]] = append(uniqueInputCommands[inputCmdPieces[0]],
									allEvents[beaconID].Events[eventIndex].Message)
							}
						}
					}
				}
			case "task":
				taskCount += 1
			case "error":
				errorCount += 1
				if showErrors {
					if !internal.StringInSlice(allEvents[beaconID].Events[eventIndex].Message, errorEvents) {
						errorEvents = append(errorEvents, allEvents[beaconID].Events[eventIndex].Message)
					}
				}
			}
		}
	}
	fmt.Println("Total Input events:", inputCount)
	fmt.Println("Total Task events:", taskCount)
	fmt.Println("Total Error events:", errorCount)
	fmt.Println("Hosts with Beacons:", beaconHosts)
	fmt.Println("Accounts with Beacons:", userAccounts)
	printMap("Total User stats:", userStats)
	if len(inputCommandsOfInterest) > 0 {
		printMap("Commands of Interest:", uniqueInputCommands)
	}
	if showErrors {
		printMap("Errors:", errorEvents)
	}
}

func printMap(message string, thing interface{}) {
	jsonBytes, err := json.MarshalIndent(thing, "", "  ")
	if err != nil {
		log.Println("[-] Failed to marshal Beacon data into JSON: ", err)
		return
	}
	fmt.Println(message, string(jsonBytes))
}
