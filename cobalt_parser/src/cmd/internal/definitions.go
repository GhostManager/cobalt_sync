package internal

// @its_a_feature_ 8/30/2023
import (
	"context"
	"net/http"
	"regexp"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var timeAndTypeRegex = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\]`)

// 11/26 21:19:49 UTC [input] <its_a_feature_> <task 2b587bb952a76505> upload
var inputRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] [<,\x{003C}](?P<user>.*?)[>,\x{003E}] [<,\x{003C}]task (?P<taskID>.*?)[>,\x{003E}] (?P<input>.*)`)

// 11/26 21:19:52 UTC [task] <its_a_feature_> <task 2b587bb952a76505> Tasked beacon to upload /home/user/Desktop/beacon_smb_x64.exe as beacon_smb_x64.exe
// 11/26 21:58:33 UTC [task] <its_a_feature_> <T1018, T1093> <task 18f219cfc9e4bdc> Tasked beacon to run net view
var taskRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] [<,\x{003C}](?P<user>.*?)[>,\x{003E}] ?[<,\x{003C}]?(?P<mitre>[T*\d*\.*\d*,* *]*?)?[>,\x{003E}]? [<,\x{003C}]task (?P<taskID>.*?)[>,\x{003E}] (?P<task>.*)`)

// 11/26 21:04:56 UTC [metadata] ExternalIP <- InternalIP; computer: ComputerA; user: Administrator *; process: beacon.exe; pid: 7116; os: Windows; version: 6.2; build:
// 9200; beacon arch: x64 (x64)
// 11/26 21:20:26 UTC [metadata] beacon_663277710 -> InternalIP; computer: ComputerA; user: Administrator *; process: beacon_smb_x64.exe; pid: 4848; os: Windows; version: 6
// .2; build: 9200; beacon arch: x64 (x64)
// 11/26 21:57:26 UTC [metadata] beacon_1221499242 -> InternalIP; computer: ComputerA; user: SYSTEM *; process: rundll32.exe; pid: 5652; os: Windows; version: 10.0; build:
// 20348; beacon arch: x64 (x64)
var metadataRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] (?P<metadata>.*)`)

// 11/26 21:59:17 UTC [error] <task 182dca1f117ef4aa> Could not connect to pipe: 2 - ERROR_FILE_NOT_FOUND
var errorRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] [<,\x{003C}]task (?P<taskID>.*?)[>,\x{003E}] (?P<error>.*)`)

type beacon struct {
	Event      string          `json:"event"`
	FilePath   string          `json:"filepath"`
	ID         string          `json:"bid"`
	StringTime string          `json:"time"`
	ParsedTime time.Time       `json:"parsed_time"`
	Internal   string          `json:"internal"`
	External   string          `json:"external"`
	Computer   string          `json:"computer"`
	User       string          `json:"user"`
	Process    string          `json:"process"`
	PID        int             `json:"pid"`
	OS         string          `json:"os"`
	Version    string          `json:"version"`
	Build      string          `json:"build"`
	Arch       string          `json:"arch"`
	Hash       string          `json:"-"`
	Events     []*event        `json:"events"`
	Wg         *sync.WaitGroup `json:"-"`
}

type event struct {
	BeaconID    string          `json:"bid"`
	FilePath    string          `json:"filepath"`
	StringTime  string          `json:"time"`
	ParsedTime  time.Time       `json:"parsed_time"`
	Event       string          `json:"event"`
	Operator    string          `json:"operator"`
	MITRE       []string        `json:"mitre"`
	Message     string          `json:"message"`
	Hash        string          `json:"-"`
	SourceIP    string          `json:"source_ip"`
	DestIP      string          `json:"dest_ip"`
	UserContext string          `json:"user_context"`
	TaskID      string          `json:"task_id"`
	Wg          *sync.WaitGroup `json:"-"`
}

type eventWithContext struct {
	*event
	Beacon *beacon `json:"beacon"`
}

// RLHTTPClient Rate Limited HTTP Client
type RLHTTPClient struct {
	client      *http.Client
	Ratelimiter *rate.Limiter
}

// Do dispatches the HTTP request to the network
func (c *RLHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Comment out the below 5 lines to turn off ratelimiting
	ctx := context.Background()
	err := c.Ratelimiter.Wait(ctx) // This is a blocking call that honors the rate limit
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// NewClient return http client with a ratelimiter
func NewClient(rl *rate.Limiter) *RLHTTPClient {
	c := &RLHTTPClient{
		client:      http.DefaultClient,
		Ratelimiter: rl,
	}
	return c
}
