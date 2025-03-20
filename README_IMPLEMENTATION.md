# Apache Block Implementation Guide

This guide explains how to implement the fixes to prevent re-processing log entries and re-blocking already blocked IPs.

## Files Modified

1. **types.go**
   - Added `LastTimestamp` and `LastProcessedIP` fields to the `FileState` struct

2. **firewall.go**
   - Improved `addBlockRule` function to check if rules already exist
   - Improved `blockIP` function to skip already blocked IPs
   - Improved `blockSubnet` function to skip already blocked subnets

3. **logmonitor.go**
   - Updated `processLogEntry` function to track timestamps and skip already blocked IPs

## New Files Created

1. **timestamp.go**
   - Added functions to extract timestamps from log entries
   - Added functions to compare timestamps

2. **logmonitor_updated_functions.go**
   - Updated `readNewContent` and `processLogFile` functions to pass state to `processLogEntry`

## Implementation Steps

1. **Update the `FileState` struct in types.go**
   - This has already been applied

2. **Add the timestamp.go file**
   - This has already been created

3. **Update the firewall.go functions**
   - These have already been applied

4. **Update the logmonitor.go functions**
   - The `processLogEntry` function has been updated
   - You need to update the `readNewContent` and `processLogFile` functions

### To update the remaining functions:

1. Open logmonitor.go in your editor
2. Find the `readNewContent` function and update line 259:
   ```go
   processLogEntry(trimmedLine, filePath)
   ```
   to:
   ```go
   processLogEntry(trimmedLine, filePath, state)
   ```

3. Find the `processLogFile` function and update line 259:
   ```go
   processLogEntry(trimmedLine, filePath)
   ```
   to:
   ```go
   processLogEntry(trimmedLine, filePath, state)
   ```

4. Alternatively, you can replace these functions with the versions in `logmonitor_updated_functions.go`

## Testing

After implementing these changes:

1. Run the program with the `-debug` flag
2. Check the logs for:
   - Messages about skipping already blocked IPs
   - Messages about skipping older log entries
   - No iptables errors about duplicate rules

## Expected Behavior

- Log entries with timestamps older than the last processed timestamp will be skipped
- Already blocked IPs will not be re-blocked
- No iptables errors will occur when processing the same log file multiple times
- The blocklist file will be created and updated correctly