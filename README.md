# cobalt_sync

[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat)](https://github.com/specterops#ghostwriter)

[![Python Version](https://img.shields.io/badge/Python-3.10-brightgreen.svg)](.) [![License](https://img.shields.io/badge/License-BSD3-darkred.svg)](.) ![GitHub Release (Latest by Date)](https://img.shields.io/github/v/release/GhostManager/cobalt_sync?label=Latest%20Release) ![GitHub Release Date](https://img.shields.io/github/release-date/GhostManager/cobalt_sync?label=Release%20Date&color=blue)

The `cobalt_sync` utility is a standalone Cobalt Strike Aggressor script that connects to an instance of [Ghostwriter](https://github.com/GhostManager/Ghostwriter) (>=v3.0.1) for automated activity logging. 

The current version of `cobalt_sync` requires Ghostwriter >=v3.0.1.

**Authors**: Daniel Heinsen and Andrew Chiles of SpecterOps

## Usage

### Getting Started

To authenticate to your instances of Ghostwriter, you will need this information handy:

* Ghostwriter URL
* Ghostwriter GraphQL API token
* Ghostwriter log ID

#### Ghostwriter API Token & Activity Log

You can get your log's ID by opening the log's webpage and looking at the top of the page. You'll see "Oplog ID #" followed by a number. That's the ID number you need.

To generate an API token for your Ghostwriter instance, visit your user profile and click on the "Create" button in the "API Tokens" section.

The token must be attached to an account that has access to the project containing your target oplog. You can read more about the [authorization controls on the Ghostwriter wiki](https://www.ghostwriter.wiki/features/graphql-api/authorization).

### Loading & Configuring via agscript

1. Modify variables in _oplog.cna_ with the appropriate values for your environment.

   ```bash
    ###########################################
    $oplog::GhostwriterOplogURL = "<https://ghostwriter.local/v1/graphql>"; # No trailing /, include the /v1/graphql
    $oplog::GhostwriterOplogID = "<ID>";
    $oplog::GhostwriterOplogAPIKey = "<API KEY>";
    ###########################################
    ```
2. Execute _oplog.cna_ via `agscript` on your team server to report activity from all operators on the team server.
3. Verify a new entry was created in your Ghostwriter activity log. If not, check your Event Log and script console for connection or authentication errors.

## Troubleshooting

- Ensure the team server where `cobalt_sync` (_oplog.cna_) is running has network access to Ghostwriter.
- Ensure the OplogID and OplogAPI key are correct for the provided Ghostwriter URL.

## References

- [Ghostwriter](https://github.com/GhostManager/Ghostwriter) - Engagement Management and Reporting Platform
- [Ghostwriter's Official Documentation - Operation Logging w/ Ghostwriter](https://ghostwriter.wiki/features/operation-logs) - Guidance on operation logging setup and usage with Ghostwriter
- [Blog - Updates to Ghostwriter: UI and Operation Logs](https://posts.specterops.io/updates-to-ghostwriter-ui-and-operation-logs-d6b3bc3d3fbd_) - Initial announcement of the operation logging features in Ghostwriter
