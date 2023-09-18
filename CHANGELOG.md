# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
