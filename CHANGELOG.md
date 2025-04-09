# Changelog

## [Unreleased]

### Added
- New `-debug-stream` command to receive real-time debug logs from the server
- Added User-Agent information to block list log messages
- Added domain name to challenge server log messages
- Configuration file support with `-config` flag
- Socket path can now be configured via command line or config file
- Enhanced IP check to show containing subnet when an IP is blocked by a subnet rule
- Socket permissions changed to 0666 to allow non-root clients to connect
- Improved client-server communication with better error handling

### Changed
- Updated PHP web interface to use the new socket path configuration
- Improved command line flag handling to properly override config file settings
- Enhanced debug logging for configuration settings

### Fixed
- Fixed isIPBlocked function to return subnet information when an IP is blocked by a subnet