package config

// @its_a_feature_ 8/30/2023
var (
	// Cobalt Parser version
	// This gets populated at build time with the following flags:
	//   go build -ldflags="-s -w \
	//   -X 'github.com/GhostManager/cobalt_sync/cmd/config.Version=`git describe --tags --abbrev=0`' \
	//   -X 'github.com/GhostManager/cobalt_sync/cmd/config.BuildDate=`date -u '+%d %b %Y'`'" \
	//   -o ghostwriter-cli main.go
	Version     string = "v2.0.3"
	BuildDate   string
	Name        string = "Cobalt Parser"
	DisplayName string = "Cobalt Parser"
	Description string = "A command line interface for parsing Cobalt Strike Beacon logs"
)
