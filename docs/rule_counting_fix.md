# Rule Counting Fix Documentation

## Problem

The system was not properly blocking IPs that triggered multiple different rules. This was a critical security issue where malicious IPs could avoid being blocked by triggering different types of suspicious activity.

### Example of the Problem

An IP `139.59.96.190` was making multiple suspicious requests:
1. 2 matches for "PHP File Redirects" (count = 2)
2. 1 match for "Apache PHP 403/404 404" (count reset to 1, but kept 2)
3. 1 match for "PHP File Redirects" (count reset to 1 again, but kept 2)
4. This continued indefinitely, never reaching the threshold of 3

## Root Cause

In `process_log_entry.go`, when an IP triggered a different rule than the previous one, the logic was:

```go
// BROKEN LOGIC
if record.Reason == reason {
    record.Count++  // Same rule - increment
} else {
    // Different rule - reset to 1 and keep higher count
    oldCount := record.Count
    record.Count = 1
    record.Reason = reason
    
    if oldCount > record.Count {
        record.Count = oldCount  // This kept it stuck at the same count
    }
}
```

This meant that switching between different rules would never allow the count to increase beyond the highest single-rule count.

## Solution

Changed the logic to increment the count for **any** suspicious activity, regardless of rule type:

```go
// FIXED LOGIC
if record.Reason == reason {
    record.Count++  // Same rule - increment
} else {
    // Different rule - still increment (all suspicious activity counts)
    record.Count++
    record.Reason = reason  // Update to latest rule
    record.LastUpdated = now
    record.ExpiresAt = now.Add(ruleDuration)
}
```

## Impact

### Before Fix
- IPs could avoid blocking by triggering different types of suspicious activity
- Security was compromised as malicious actors weren't being stopped
- Logs showed many rule matches but no blocking action

### After Fix
- All suspicious activity counts toward the blocking threshold
- IPs are properly blocked when they reach the threshold regardless of rule variety
- Improved security posture

## Testing

To verify the fix works:

1. Monitor logs for IPs with multiple rule matches
2. Confirm that IPs are blocked when they reach the threshold
3. Check that the count increases with each match, regardless of rule type

Example expected behavior:
```
Rule match: IP=139.59.96.190, Reason=PHP File Redirects (count: 1/3)
Rule match: IP=139.59.96.190, Reason=Apache PHP 403/404 404 (count: 2/3)  
Rule match: IP=139.59.96.190, Reason=PHP File Redirects (count: 3/3)
Blocked IP 139.59.96.190 for Apache PHP 403/404 404
```

## Files Modified

- `process_log_entry.go` - Fixed the rule counting logic
- `CHANGELOG.md` - Documented the critical fix
