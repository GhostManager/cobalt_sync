package internal

// @its_a_feature_ 8/30/2023
import (
	"github.com/fsnotify/fsnotify"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func ListenForWatcherEvents(verbose bool) {
	defer func() {
		log.Println("[-] No longer listeningForWatcherEvents")
	}()
	for {
		select {
		case watcherEvent, ok := <-watcher.Events:
			if !ok {
				return
			}
			if verbose {
				log.Println("[*] Watcher Event:", watcherEvent)
			}
			if watcherEvent.Has(fsnotify.Write) || watcherEvent.Has(fsnotify.Create) {
				// get information about the file/folder
				createInfo, err := os.Stat(watcherEvent.Name)
				if err != nil {
					log.Println("[-] Failed to get information about modified file/folder")
					continue
				}
				// if it's a folder, watch it
				if createInfo.IsDir() {
					if verbose {
						log.Println("[*] added new path to watch", watcherEvent.Name)
					}
					watcher.Add(watcherEvent.Name)
					continue
				}
				// if it's a file, make sure it's a good filename and process it
				filename := filepath.Base(watcherEvent.Name)
				if len(filename) == 0 {
					if verbose {
						log.Println("[*] Watcher Event Ignored")
					}
					continue
				} else if strings.HasPrefix(filename, ".") {
					if verbose {
						log.Println("[*] Watcher Event Ignored")
					}
					continue
				} else if StringInSlice(filename, ignoredFileNames) {
					if verbose {
						log.Println("[*] Watcher Event Ignored")
					}
					continue
				} else if strings.HasSuffix(filename, "~") {
					if verbose {
						log.Println("[*] Watcher Event Ignored")
					}
					continue
				}
				wg := sync.WaitGroup{}
				wg.Add(1)
				if verbose {
					log.Println("[*] About to process modified file")
				}
				processLogFile(&wg, watcherEvent.Name, createInfo)
				wg.Wait()
				if verbose {
					log.Println("[+] Finished processing modified file")
				}
			} else if verbose {
				log.Println("[*] Watcher Event Ignored")
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("[-] Watcher Error:", err)
		}
	}
}
func PeriodicallyReProcess(verbose bool, logsPath string, onlyHashes bool) {
	for {
		if time.Now().Hour() == 0 {
			err := WalkFiles(verbose, logsPath, false)
			if err != nil {
				log.Println(err)
			}
			if !onlyHashes {
				SortEvents()
				PrintEvents()
			}
		}
		time.Sleep(1 * time.Hour)
	}

}
