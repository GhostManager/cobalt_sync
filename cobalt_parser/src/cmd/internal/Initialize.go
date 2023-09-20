package internal

// @its_a_feature_ 8/30/2023
import (
	"crypto/tls"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"time"
)

var events map[string]*beacon
var hashEvents map[string]int
var beaconChannel chan *beacon
var eventChannel chan *event
var hashChannel chan string
var sortEventsChannel chan bool
var doneSortingEventsChannel chan bool
var printEventsChannel chan bool
var donePrintingEventsChannel chan bool
var getEventsChannel chan bool
var doneGetEventsChannel chan map[string]beacon
var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	MaxIdleConns:    10,
	MaxConnsPerHost: 10,
	//IdleConnTimeout: 1 * time.Nanosecond,
}
var client = &http.Client{
	Timeout:   5 * time.Second,
	Transport: tr,
}
var limitingHTTPClient *RLHTTPClient
var ignoredFileNames = []string{
	"weblog.log", "events.log", "downloads.log", "screenshots.log", "keylogs.log", "screenshots", "keystrokes",
}
var targetURL = ""
var watcher *fsnotify.Watcher

func Initialize() {
	var err error
	rl := rate.NewLimiter(20, 100) // 100 events per second with a max burst of 500
	limitingHTTPClient = NewClient(rl)
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	events = make(map[string]*beacon)
	hashEvents = make(map[string]int)
	beaconChannel = make(chan *beacon, 20)
	eventChannel = make(chan *event, 20)
	hashChannel = make(chan string, 20)
	sortEventsChannel = make(chan bool, 1)
	doneSortingEventsChannel = make(chan bool, 1)
	printEventsChannel = make(chan bool, 1)
	donePrintingEventsChannel = make(chan bool, 1)
	getEventsChannel = make(chan bool, 1)
	doneGetEventsChannel = make(chan map[string]beacon, 1)
}

func ListenForLogData(onlyHashes bool, printNewToStdout bool, output string) {
	go listenForNewLogData(onlyHashes, printNewToStdout, output)
}
