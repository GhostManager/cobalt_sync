package internal

// @its_a_feature_ 8/30/2023
import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func listenForNewLogData(onlyHashes bool, printNewToStdout bool, output string) {
	eventsWaitingForBeaconData := make(map[string][]*event)
	var appendFile *os.File
	var err error
	if onlyHashes && printNewToStdout && output != "" {
		// This means that we don't want to save everything in memory, but do want to save it all to disk
		appendFile, err = os.OpenFile(output,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer appendFile.Close()
	}
	for {
		select {
		case h := <-hashChannel:
			// Only record that we've seen something once we get confirmation that it was processed externally
			hashEvents[h] = 1
		case b := <-beaconChannel:
			//fmt.Printf("Got new beacon data: %v\n", b)
			eventString := fmt.Sprintf("%s-%s", b.ID, b.StringTime)
			sha256Sum := sha256.Sum256([]byte(eventString))
			sha256SumString := fmt.Sprintf("%x", sha256Sum)
			b.Hash = sha256SumString
			if _, ok := hashEvents[sha256SumString]; ok {
				b.Wg.Done()
				continue
			}
			if _, ok := events[b.ID]; !ok {
				// We don't know about this Beacon, so add it
				events[b.ID] = b
				// Now that we know about the Beacon, check if there's events waiting to be associated
				go emitNewData(b, targetURL, b.Hash)
				if printNewToStdout {
					printEvent(b, appendFile)
				}
				if _, ok = eventsWaitingForBeaconData[b.ID]; ok {
					// There are some, so add those to the beacon now
					for _, e := range eventsWaitingForBeaconData[b.ID] {
						e.SourceIP = b.Internal
						e.DestIP = b.Internal
						e.UserContext = b.User
						if !onlyHashes {
							events[b.ID].Events = append(events[b.ID].Events, e)
						}
						go emitNewData(&eventWithContext{
							event:  e,
							Beacon: b,
						}, targetURL, b.Hash)
					}
					delete(eventsWaitingForBeaconData, b.ID)
				}
				b.Wg.Done()
				continue
			}
			// We've seen this Beacon before, so update the data
			if b.ParsedTime.After(events[b.ID].ParsedTime) {
				// Only update if this new beacon timestamp is after the one we currently know about
				events[b.ID].OS = b.OS
				events[b.ID].ParsedTime = b.ParsedTime
				events[b.ID].StringTime = b.StringTime
				events[b.ID].User = b.User
				events[b.ID].Process = b.Process
				events[b.ID].PID = b.PID
				events[b.ID].Version = b.Version
				events[b.ID].Arch = b.Arch
				events[b.ID].Build = b.Build
				events[b.ID].Computer = b.Computer
				events[b.ID].External = b.External
				events[b.ID].Internal = b.Internal
			}
			b.Wg.Done()
		case e := <-eventChannel:
			//fmt.Printf("Got new event data: %v\n", e)
			eventString := fmt.Sprintf("%s-%s-%s-%s-%s",
				e.BeaconID, e.StringTime, e.Event, e.Operator, e.Message)
			sha256Sum := sha256.Sum256([]byte(eventString))
			sha256SumString := fmt.Sprintf("%x", sha256Sum)
			e.Hash = sha256SumString
			if _, ok := hashEvents[sha256SumString]; !ok {
				// This is a new event
				if _, ok = events[e.BeaconID]; !ok {
					e.Wg.Done()
					// We got event information before Beacon information, so save it for later
					if _, ok = eventsWaitingForBeaconData[e.BeaconID]; !ok {
						// This is the first even we've seen for this `beaconID` that doesn't exist yet
						eventsWaitingForBeaconData[e.BeaconID] = []*event{e}
						continue
					}
					// We have seen that `beaconId` before with other events and still don't have Beacon data
					eventsWaitingForBeaconData[e.BeaconID] = append(eventsWaitingForBeaconData[e.BeaconID], e)
					continue
				}
				e.SourceIP = events[e.BeaconID].Internal
				e.DestIP = events[e.BeaconID].Internal
				e.UserContext = events[e.BeaconID].User
				go emitNewData(&eventWithContext{
					event:  e,
					Beacon: events[e.BeaconID],
				}, targetURL, e.Hash)
				if printNewToStdout {
					printEvent(e, appendFile)
				}
				if !onlyHashes {
					events[e.BeaconID].Events = append(events[e.BeaconID].Events, e)
				}

			}
			e.Wg.Done()
		case <-sortEventsChannel:
			for beaconID, _ := range events {
				sort.Slice(events[beaconID].Events[:], func(i, j int) bool {
					if events[beaconID].Events[i].ParsedTime == events[beaconID].Events[j].ParsedTime {
						if events[beaconID].Events[i].Event == "input" {
							return true
						}
					}
					return events[beaconID].Events[i].ParsedTime.Before(events[beaconID].Events[j].ParsedTime)
				})
			}
			doneSortingEventsChannel <- true
		case <-printEventsChannel:
			jsonEvents, err := json.MarshalIndent(events, "", "  ")
			if err != nil {
				log.Println("[-] Failed to marshal events map:", err)
				return
			}
			if output != "" {
				err = os.WriteFile(output, jsonEvents, 0644)
				if err != nil {
					log.Println("[-] Failed to write to file:", err)
				}
			} else {
				fmt.Println(string(jsonEvents))
			}
			donePrintingEventsChannel <- true
		case <-getEventsChannel:
			newEvents := make(map[string]beacon, len(events))
			for beaconID, _ := range events {
				newEvents[beaconID] = *events[beaconID]
			}
			doneGetEventsChannel <- newEvents
		}
	}
}
func WalkFiles(verbose bool, filePath string, useWatcher bool) error {
	if verbose {
		log.Println("[*] Processing logs from:", filePath)
	}

	wg := sync.WaitGroup{}
	err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Don't parse directories
		if info.IsDir() {
			if useWatcher && !StringInSlice(info.Name(), ignoredFileNames) {
				err = watcher.Add(path)
				if err != nil {
					log.Println("[-] Failed to add path to watcher list:", path, err)
				}
			}
			return nil
		}
		// Don't parse events, weblog, or downloads
		if StringInSlice(info.Name(), ignoredFileNames) {
			return nil
		}
		// Only parse the remaining .log files
		if strings.HasSuffix(info.Name(), ".log") {
			wg.Add(1)
			if verbose {
				log.Println("[*] processing file: ", path)
			}
			go processLogFile(&wg, path, info)
		}
		return nil
	})
	wg.Wait()
	if verbose {
		log.Println("[+] Finished processing all files")
	}
	return err
}
func processLogFile(parentWg *sync.WaitGroup, path string, info os.FileInfo) {
	defer parentWg.Done()
	filenamePieces1 := strings.Split(info.Name(), "_")
	if len(filenamePieces1) != 2 {
		log.Println("[-] Bad filename", info.Name())
		return
	}
	beaconIDPieces := strings.Split(filenamePieces1[1], ".")
	if len(beaconIDPieces) != 2 {
		log.Println("[-] Bad filename", info.Name())
		return
	}
	beaconID := beaconIDPieces[0]
	readFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer readFile.Close()
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	logFileYear := getYearFromPath(path)
	wg := sync.WaitGroup{}
	for fileScanner.Scan() {
		line := fileScanner.Text()
		wg.Add(1)
		processLogFileEntry(path, logFileYear, &wg, beaconID, line)
	}
	wg.Wait()
}
func processLogFileEntry(path string, logFileYear string, wg *sync.WaitGroup, beaconID string, content string) {
	/*
		metadata: 08/28 16:39:45 UTC [metadata] 208.71.164.195 <- 192.168.53.133; computer: DESKTOP-F6NR9SF; user: itsafeature; process: beacon_x64_nacph.net.exe; pid: 10120; os: Windows; version: 6.2; build: 9200; beacon arch: x64 (x64)
		note: 08/28 16:39:39 UTC [note] context:itsafeature
		task: 08/28 16:39:39 UTC [task] <T1012> Tasked beacon to query HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5 /v Version (x64)
		task: 08/28 17:55:54 UTC [task] <> Tasked beacon to print working directory
		input: 08/28 16:39:58 UTC [input] <itsafeature3.10> shell whoami
		indicator: 08/22 15:53:26 UTC [indicator] service: \\. 592f09b
		indicator: 08/22 17:05:30 UTC [indicator] service: \\ACHILLES b4aa5f8
		indicator: 08/22 15:53:26 UTC [indicator] file: b5245ab5f5d527dd28a6582cf26ad821 316416 bytes \\127.0.0.1\ADMIN$\592f09b.exe
		error: 08/23 03:25:54 UTC [error] could not open C\*: 3 - ERROR_PATH_NOT_FOUND

		don't care about: note, output, checkin, indicator

		timeAndTypeRegex: [0] is raw string, [1] is timestamp, [2] is method
		taskRegEx: [0] is raw string, [1] is timestamp, [2] is method, [3] is mitre, [4] is tasking
		inputRegEx: [0] is raw string, [1] is timestamp, [2] is method, [3] is user, [4] is input
	*/
	timeAndTypeRegexMatches := timeAndTypeRegex.FindStringSubmatch(content)
	if len(timeAndTypeRegexMatches) > 0 {
		//fmt.Printf("%s: timeAndTypeRegex: %v\n", path, timeAndTypeRegexMatches)
		if timeAndTypeRegexMatches[2] == "input" {
			//log.Println(content)
			findInputSubmatches := inputRegEx.FindStringSubmatch(content)
			if len(findInputSubmatches) != 5 {
				log.Println("[-] Failed to process input with regex:", content)
				wg.Done()
				return
			}
			parsedTime, err := time.Parse("2006/01/02 15:04:05 UTC", logFileYear+"/"+findInputSubmatches[1])
			if err != nil {
				wg.Done()
				log.Println("[-] Failed to parse time:", err)
				return
			}
			e := &event{
				BeaconID:   beaconID,
				FilePath:   path,
				StringTime: findInputSubmatches[1],
				ParsedTime: parsedTime,
				Event:      timeAndTypeRegexMatches[2],
				Operator:   findInputSubmatches[3],
				Message:    findInputSubmatches[4],
				MITRE:      []string{},
				Wg:         wg,
			}
			eventChannel <- e
			return
			//fmt.Printf("%s: input: %v\n", path, findInputSubmatches[4])
		} else if timeAndTypeRegexMatches[2] == "task" {
			//log.Println(content)
			findTaskSubmatches := taskRegEx.FindStringSubmatch(content)
			if len(findTaskSubmatches) != 5 {
				log.Println("[-] Failed to process task with regex:", content)
				wg.Done()
				return
			}
			parsedTime, err := time.Parse("2006/01/02 15:04:05 UTC", logFileYear+"/"+findTaskSubmatches[1])
			if err != nil {
				log.Println("[-] Failed to parse time:", err)
				wg.Done()
				return
			}
			mitrePieces := strings.Split(findTaskSubmatches[3], ", ")
			mitreWithoutEmpty := []string{}
			for _, mitre := range mitrePieces {
				if mitre != "" {
					mitreWithoutEmpty = append(mitreWithoutEmpty, mitre)
				}
			}
			e := &event{
				BeaconID:   beaconID,
				FilePath:   path,
				StringTime: findTaskSubmatches[1],
				ParsedTime: parsedTime,
				Event:      timeAndTypeRegexMatches[2],
				Operator:   "",
				MITRE:      mitreWithoutEmpty,
				Message:    findTaskSubmatches[4],
				Wg:         wg,
			}
			eventChannel <- e
			return
			//fmt.Printf("%s: task: %v\n", path, findTaskSubmatches[4])
		} else if timeAndTypeRegexMatches[2] == "metadata" {
			//log.Println(content)
			findMetadataMatches := metadataRegEx.FindStringSubmatch(content)
			if len(findMetadataMatches) != 4 {
				log.Println("[-] Failed to process task with regex:", content)
				wg.Done()
				return
			}
			parsedTime, err := time.Parse("2006/01/02 15:04:05 UTC", logFileYear+"/"+findMetadataMatches[1])
			if err != nil {
				log.Println("[-] Failed to parse time:", err)
				wg.Done()
				return
			}
			metadataRaw := findMetadataMatches[3]
			metadataPieces := strings.Split(metadataRaw, ";")
			newBeacon := &beacon{
				Event:      "metadata",
				ID:         beaconID,
				ParsedTime: parsedTime,
				FilePath:   path,
				StringTime: findMetadataMatches[1],
				Wg:         wg,
			}
			for _, entry := range metadataPieces {
				if strings.Contains(entry, " <- ") {
					ips := strings.Split(entry, " <- ")
					newBeacon.Internal = ips[1]
					newBeacon.External = ips[0]
				} else if strings.Contains(entry, " -> ") {
					ips := strings.Split(entry, " -> ")
					newBeacon.Internal = ips[1]
					newBeacon.External = ips[0]
				} else {
					entryPieces := strings.Split(entry, ":")
					switch strings.TrimSpace(entryPieces[0]) {
					case "computer":
						newBeacon.Computer = strings.TrimSpace(entryPieces[1])
					case "user":
						newBeacon.User = strings.TrimSpace(entryPieces[1])
					case "process":
						newBeacon.Process = strings.TrimSpace(entryPieces[1])
					case "pid":
						pid, err := strconv.Atoi(strings.TrimSpace(entryPieces[1]))
						if err != nil {
							fmt.Printf("Failed to process pid: %s\n", strings.TrimSpace(entryPieces[1]))
							pid = 0
						}
						newBeacon.PID = pid
					case "os":
						newBeacon.OS = strings.TrimSpace(entryPieces[1])
					case "version":
						newBeacon.Version = strings.TrimSpace(entryPieces[1])
					case "build":
						newBeacon.Build = strings.TrimSpace(entryPieces[1])
					case "beacon arch":
						newBeacon.Arch = strings.TrimSpace(entryPieces[1])
					}
				}

			}
			// It's possible we detect file modifications before they're done and don't get all the data
			if newBeacon.PID != 0 {
				beaconChannel <- newBeacon
				return
			}
		} else if timeAndTypeRegexMatches[2] == "error" {
			findErrorMatches := errorRegEx.FindStringSubmatch(content)
			if len(findErrorMatches) != 4 {
				log.Println("[-] Failed to process error with regex:", content)
				wg.Done()
				return
			}
			parsedTime, err := time.Parse("2006/01/02 15:04:05 UTC", logFileYear+"/"+findErrorMatches[1])
			if err != nil {
				log.Println("[-] Failed to parse time:", err)
				wg.Done()
				return
			}
			e := &event{
				BeaconID:   beaconID,
				FilePath:   path,
				StringTime: findErrorMatches[1],
				ParsedTime: parsedTime,
				Event:      timeAndTypeRegexMatches[2],
				Operator:   "",
				MITRE:      []string{},
				Message:    findErrorMatches[3],
				Wg:         wg,
			}
			eventChannel <- e
			return
		}
	}
	wg.Done()
}
func SortEvents() {
	sortEventsChannel <- true
	<-doneSortingEventsChannel
}
func GetEvents(verbose bool) map[string]beacon {
	if verbose {
		log.Println("[*] Sorting events")
	}
	sortEventsChannel <- true
	<-doneSortingEventsChannel
	if verbose {
		log.Println("[*] getting events")
	}
	getEventsChannel <- true
	eventsCopy := <-doneGetEventsChannel
	return eventsCopy
}
func PrintEvents() {
	printEventsChannel <- true
	<-donePrintingEventsChannel
}
func printEvent[V *beacon | *event](p V, appendFile *os.File) {
	jsonBytes, err := json.Marshal(p)
	if err != nil {
		log.Println("[-] Failed to marshal Beacon data into JSON: ", err)
		return
	}
	if appendFile != nil {
		if _, err = appendFile.WriteString(string(jsonBytes) + "\n"); err != nil {
			log.Println(err)
		}
	} else {
		fmt.Println(string(jsonBytes))
	}
}
