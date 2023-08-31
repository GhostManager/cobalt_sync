# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 30 August 2023

### Added

* cobalt_parser is a golang program to parse and monitor Cobalt Strike logs and ship parsed events to a web server
* cobalt_web is a python web server that accepts cobalt events and posts them to Ghostwriter's v4 GraphQL endpoint
* redis is a database to store hashes of cobalt messages to prevent duplicates

## [2.0.0] - 11 May 2023

### Changed

* Updated to use Ghostwriter 3's GraphQL API
  * Logs are now collected via Cobalt Strike's _Sleep Python Bridge_

## [2.0.0] - 29 October 2021

### Added

* Initial commit of `cobalt_sync` for Ghostwriter v2
