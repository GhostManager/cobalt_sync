# cobalt_sync

Standalone Cobalt Strike Operation Logging Aggressor script for Ghostwriter 2.0+

**Authors**: Daniel Heinsen and Andrew Chiles of SpecterOps

## Usage

0. Modify variables in `oplog.cna` with the appropriate values for your environment.

   ```
    ###########################################
    $oplog::GhostwriterOplogURL = "<https://ghostwriter.local>"; # No trailing /
    $oplog::GhostwriterOplogID = "<ID>";
    $oplog::GhostwriterOplogAPIKey = "<API KEY>";
    ###########################################
    ```
1. Execute `oplog.cna` via agscript on your teamserver to report activity from all operators on the teamserver.
2. Verify a new entry was created in your Ghostwriter oplog. If not, check your Event Log and script console for connection or authentication errors.

## Troubleshooting

- Ensure the teamserver where cobalt_sync (oplog.cna) is running has network access to Ghostwriter.
- Ensure the OplogID and OplogAPI key are correct for the provided Ghostwriter URL

## References

- [Ghostwriter](https://github.com/GhostManager/Ghostwriter) - Engagement Management and Reporting Platform
- [Ghostwriter's Official Documentation - Operation Logging w/ Ghostwriter](https://ghostwriter.wiki/features/operation-logs) - Guidance on operation logging setup and usage with Ghostwriter
- [Blog - Updates to Ghostwriter: UI and Operation Logs](https://posts.specterops.io/updates-to-ghostwriter-ui-and-operation-logs-d6b3bc3d3fbd_) - Initial announcement of the operation logging features in Ghostwriter
