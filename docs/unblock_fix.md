# Unblock Fix Documentation

## Problem

When a client was unblocked using any of the unblock methods (`-unblock`, socket command, or challenge server), the system would only remove the IP from the `blockedIPs` map and firewall rules, but would leave the entry in the `ipAccessLog` map intact.

The `ipAccessLog` map tracks suspicious activity for each IP address, including:
- Count of suspicious requests
- Expiration time
- Last updated time
- The rule that triggered the record

## Impact

This caused a serious issue where:
1. An IP gets blocked after reaching the threshold (e.g., 3 detections)
2. Admin unblocks the IP
3. The IP's access record remains with count=3
4. The IP makes one more suspicious request
5. The IP gets immediately blocked again (count goes from 3 to 4)

Instead of requiring the full threshold of detections to block again, the IP would be blocked after just one more detection.

## Solution

The fix ensures that when an IP is unblocked, we also remove its entry from the `ipAccessLog` map so it starts fresh.

### Changes Made

1. **Updated `clientUnblockIP()` function in `client.go`**:
   - For individual IPs: Remove the IP's entry from `ipAccessLog`
   - For subnets: Remove all IPs within that subnet from `ipAccessLog`
   - Added debug logging to show when access log entries are removed

2. **All unblock paths now use this fix**:
   - Command line `-unblock` flag
   - Socket-based unblock commands
   - Challenge server successful verification
   - Main.go direct unblock handling

### Code Example

```go
// Before (problematic)
mu.Lock()
delete(blockedIPs, target)
mu.Unlock()

// After (fixed)
mu.Lock()
delete(blockedIPs, target)
// Remove the IP's access log entry so it starts fresh
if _, exists := ipAccessLog[target]; exists {
    delete(ipAccessLog, target)
    if debug {
        log.Printf("Removed access log entry for unblocked IP %s", target)
    }
}
mu.Unlock()
```

## Testing

The fix can be verified by:
1. Blocking an IP through normal detection
2. Unblocking it manually
3. Triggering one suspicious request from that IP
4. Confirming the IP is not immediately blocked again

## Benefits

- IPs that are unblocked now truly start fresh
- Reduces false positives from IPs that were legitimately unblocked
- Provides consistent behavior across all unblock methods
- Maintains the intended security threshold for all IPs
