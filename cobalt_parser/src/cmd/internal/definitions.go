package internal

// @its_a_feature_ 8/30/2023
import (
	"context"
	"golang.org/x/time/rate"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var timeAndTypeRegex = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\]`)
var inputRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] [<,\x{003C}](?P<user>.*?)[>,\x{003E}] (?P<input>.*)`)
var taskRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] [<,\x{003C}](?P<mitre>[T*\d*\.*\d*,* *]*?)[>,\x{003E}] (?P<task>.*)`)
var metadataRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] (?P<metadata>.*)`)
var errorRegEx = regexp.MustCompile(`^(?P<timestamp>\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC) \[(?P<method>.*?)\] (?P<error>.*)`)

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
