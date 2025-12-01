# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.5] - 01 December 2025

### Changed

* Updated the cobalt_parser to handle new <task val> fields in Cobalt Strike 4.12 logs
* Updated the cobalt_web to create tags in Ghostwriter based on the MITRE fields from Cobalt Strike logs
* Updated the cobalt_web to set the new task identifiers from CS4.12 in the output field in Ghostwriter logs

## [2.0.4] - 08 April 2024

### Changed

* Updated entry_identifier to entryIdentifier
* Added extraFields for oplog creation

## [2.0.3] - 05 January 2024

### Changed

* Updated the logic for hash checking within cobalt_parser to track seen hashes first and optionally remove them if they fail to send
  * this prevents an issue where repeated writes to a file within a short timeframe (1s) caused duplicate entries sent
* Updated cobalt_web's hash creator to sort dictionary keys for a more consistent check

## [2.0.2] - 08 December 2023

### Changed

* Added in a webhook notification for when everything is successfully connected and when there are errors
  * error messages are limited to 1 per 30 min to help prevent spam
  * These use the WEBHOOK_DEFAULT_URL and WEBHOOK_DEFAULT_ALERT_CHANNEL environment variables
    * Note: No `#` needed for the channel, that's automatically applied
* Updated the messages that go to Ghostwriter:
  * Destination IP is now left blank
  * Source is now of the format: HOSTNAME (Internal IP)
  * New callbacks have more information in their Description field and other fields left blank
  * Task events now also have the PID and Callback BeaconID listed

## [2.0.1] - 15 November 2023

### Changed

* Added a limit to the log size to prevent the log file from growing too large

## [2.0.0] - 18 September 2023

### Added

* Added `cobalt_parser`, a golang program to parse and monitor Cobalt Strike logs and ship parsed events to a web server
* Added `cobalt_web`, a Python web server that accepts cobalt events and posts them to Ghostwriter's v4 GraphQL endpoint
* Added a Redis service container that functions a database to store hashes of Cobalt Strike messages to prevent duplicates

### Changed

* `cobalt_sync` now syncs activities via Ghostwriter's GraphQL API 

### Removed

* Removed use of the legacy Ghostwriter REST API (removed in Ghostwriter v4)

## [1.0.0] - 29 October 2021

### Added

* Initial commit of `cobalt_sync` for Ghostwriter v2
