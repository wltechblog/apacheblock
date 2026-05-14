# Code Review Issues

## Critical

### 1. Race condition on `AccessRecord` after lock release
**File:** `process_log_entry.go:109-141`
**Severity:** Critical

The `record` pointer is obtained under `mu.Lock()` but `record.Count` is read on line 141 *after* the lock has been released on line 138. Another goroutine could modify the record between the unlock and the read, leading to a data race.

```go
mu.Unlock()
// record.Count is read here without holding the lock
if record.Count >= ruleThreshold {
```

**Fix:** Read `record.Count` before releasing the lock, or restructure to hold the lock through the threshold check.

---

### 2. Dead code: expiration extension is unreachable
**File:** `process_log_entry.go:125-128`
**Severity:** Bug

`record.LastUpdated` is set to `now` on line 125, then `now.Sub(record.LastUpdated)` on line 126 is always `0`, so the condition `> time.Minute` is always false. The expiration extension logic never executes.

```go
record.LastUpdated = now
if now.Sub(record.LastUpdated) > time.Minute { // always false
    record.ExpiresAt = now.Add(ruleDuration)
}
```

**Fix:** Compare against the *previous* `LastUpdated` value before overwriting it.

---

### 3. NFTables implementation is incomplete / non-functional
**File:** `firewall.go:470-473, 494-498, 542-545`
**Severity:** Critical

Three NFTables methods return "not implemented" errors:
- `IsRulePresent` (line 470)
- `RemoveBlockRule` (line 494)
- `RemoveRedirectRule` (line 542)

This means nftables users **cannot unblock IPs or subnets**, and rule existence checks fail. The nftables backend is effectively broken.

**Fix:** Implement these methods using `nft list ruleset` parsing and `nft delete rule` with handle-based deletion.

---

### 4. X-Forwarded-For / X-Real-IP header spoofing enables bypass
**File:** `challenge_server.go:328-334, 384-390`
**Severity:** Security

The challenge server trusts `X-Forwarded-For` and `X-Real-IP` headers without validation. An attacker can spoof these headers to:
- Pretend to be a different IP during the reCAPTCHA challenge, unblocking an arbitrary IP
- Bypass the challenge entirely by spoofing a whitelisted IP

**Fix:** Only trust these headers if the request comes from a known, trusted proxy. Add a `trustedProxies` configuration option. Strip these headers from untrusted sources.

---

## High

### 5. Socket permissions are world-writable
**File:** `socket.go:51`
**Severity:** Security

The Unix domain socket is created with `0666` permissions, allowing any local user to send block/unblock commands. If no API key is set (the default), any local user can manipulate the firewall.

```go
os.Chmod(SocketPath, 0666)
```

**Fix:** Restrict socket permissions to `0600` or `0660` with appropriate group ownership. Consider making permissions configurable.

---

### 6. API key visible in process listing and debug logs
**File:** `main.go:40`, `socket.go:94`, `config.go:113`
**Severity:** Security

- The API key is passed as a CLI flag (`-apiKey`), making it visible to all users via `ps aux`.
- Debug log in `socket.go:94` logs the received API key: `log.Printf("Invalid API key received: %s", msg.APIKey)`.
- The API key is stored in plaintext in the config file.

**Fix:** Read the API key from an environment variable or a file with restricted permissions. Never log API keys. Redact the key in debug output.

---

### 7. Fragile subnet matching via string prefix
**File:** `firewall.go:668-669`
**Severity:** Bug

`blockSubnet` uses string prefix matching to find IPs in a subnet:

```go
if strings.HasPrefix(ip, strings.TrimSuffix(subnet, ".0/24")) {
```

This only works for `/24` subnets and can produce false positives. For example, subnet `10.0.1.0/24` would match IP `10.0.10.1` because `"10.0.1"` is a prefix of `"10.0.10.1"`.

**Fix:** Use proper CIDR containment checks with `net.ParseCIDR` and `ipNet.Contains()`.

---

### 8. Flag default-value detection breaks config file overrides
**File:** `main.go:71-85`
**Severity:** Bug

CLI flags are detected as "user-specified" by comparing against hardcoded defaults:

```go
if *thresholdFlag != 3 {
    threshold = *thresholdFlag
}
```

If the user explicitly passes `-threshold 3` on the CLI, it's treated as the default and won't override a config file value. More importantly, if the config file set `threshold = 5` but the user doesn't pass `-threshold`, the config file value is kept. But if the user passes `-threshold 3`, the config file value is still kept (since `*thresholdFlag != 3` is false). This is confusing and inconsistent behavior.

**Fix:** Use `flag.Visit()` to detect which flags were actually set by the user, rather than comparing against defaults.

---

### 9. Server log format overwritten after CLI/config parsing
**File:** `main.go:302-306`
**Severity:** Bug

After the config file and CLI flags have already set `logFormat`, lines 302-306 unconditionally set it again from the `-server` flag:

```go
if *server == "apache" || *server == "caddy" {
    logFormat = *server
}
```

This overwrites any value that was set by the config file. The earlier logic on lines 147-152 tried to preserve the config file value, but this later block always overwrites it.

**Fix:** Only apply the `-server` flag if it was explicitly set by the user (using `flag.Visit()`).

---

### 10. `debug_stream.go:60` - Unsafe type assertion can panic
**File:** `debug_stream.go:60`
**Severity:** Bug

```go
originalLogWriter = log.Writer().(*os.File)
```

If the log writer is not an `*os.File` (e.g., if another package has already wrapped it), this type assertion will panic at runtime.

**Fix:** Use a safe type assertion with comma-ok pattern: `if f, ok := log.Writer().(*os.File); ok { ... }`.

---

### 11. No graceful shutdown
**File:** `main.go:418`
**Severity:** Reliability

The server blocks on `select {}` with no signal handling. On termination:
- The socket listener is never closed
- The `fsnotify` watcher's `Close()` is deferred but `select {}` never returns
- HTTP servers for the challenge feature are never shut down
- Log file handles are not flushed/closed
- The blocklist may not be saved

**Fix:** Listen for `SIGTERM`/`SIGINT` signals, save the blocklist, close listeners, and exit cleanly.

---

### 12. `firewall.go:209` - Double execution of iptables command
**File:** `firewall.go:199-211`
**Severity:** Bug

In `IsRulePresent`, `cmd.Run()` is called on line 202, which consumes the process output. Then on line 209, `cmd.CombinedOutput()` is called on the same `cmd`, which would fail because the command has already been executed. Additionally, `output` from line 209 is assigned but was already set from an earlier call.

```go
cmd := exec.Command("iptables", fullArgs...)
err := cmd.Run()              // first execution
// ...
output, _ := cmd.CombinedOutput() // second execution on same cmd - fails
```

**Fix:** Use only `cmd.CombinedOutput()` and check both the output and error from that single call.

---

## Medium

### 13. IPv6 not supported
**File:** `utils.go:11-17`, `firewall.go:668-669`
**Severity:** Feature gap

`getSubnet` hardcodes a `/24` mask with 32 bits (IPv4 only). `blockSubnet`'s string prefix matching also doesn't work for IPv6 addresses. The entire blocking system silently drops or mishandles IPv6 traffic.

**Fix:** Detect IPv4 vs IPv6 and use appropriate masks (e.g., `/64` for IPv6). Use `net.ParseCIDR`/`Contains` for all subnet operations.

---

### 14. Excessive global mutable state
**Files:** `types.go`, many others
**Severity:** Maintainability

Nearly all configuration and state is stored in package-level global variables (`blockedIPs`, `blockedIPs`, `debug`, `verbose`, `whitelist`, etc.). This makes the code difficult to test, prevents multiple instances, and creates implicit coupling between all functions.

**Fix:** Encapsulate state in a `Server` struct and pass it through method receivers or dependency injection.

---

### 15. `RunClientMode` is dead code
**File:** `client.go:22`
**Severity:** Code quality

`RunClientMode()` is defined but never called anywhere in the codebase. `main.go` handles client mode directly in its own inline logic (lines 162-283). This creates two separate client-mode code paths that can diverge.

**Fix:** Remove `RunClientMode` or refactor `main.go` to use it, eliminating the duplicated logic.

---

### 16. `test_unblock_fix.go` is not a proper Go test
**File:** `test_unblock_fix.go`
**Severity:** Code quality

This file contains test-like code in the `main` package but uses `_test.go` naming convention improperly (it's named `test_unblock_fix.go`, not `*_test.go`). It doesn't use the `testing` package and would be compiled into the production binary.

**Fix:** Rename to `*_test.go`, use the `testing` package, and move to a proper test file. Or remove it if it was only for development.

---

### 17. DNS lookups block log processing
**File:** `domainwhitelist.go:113`, `process_log_entry.go:44`
**Severity:** Performance

`isDomainWhitelisted()` performs synchronous DNS reverse and forward lookups for every matched log entry. This can be slow (seconds per lookup) and blocks the log processing goroutine. Under high traffic, this creates a significant bottleneck.

**Fix:** Cache DNS lookup results with a TTL. Consider async lookups with a cached result.

---

### 18. `subnetBlockedIPs` map grows without bound
**File:** `types.go:31`, `process_log_entry.go:151-156`
**Severity:** Memory leak

IPs are added to `subnetBlockedIPs` when blocked, but once a subnet is blocked (and its individual IPs are removed from `blockedIPs`), the `subnetBlockedIPs` entries for that subnet are never cleaned up. Over time, this map grows indefinitely.

**Fix:** Clean up `subnetBlockedIPs[subnet]` entries when a subnet is blocked, or when the individual IPs are removed during subnet blocking.

---

### 19. `saveBlockList` TOCTOU race
**File:** `blocklist.go:22-35`
**Severity:** Correctness

The lock is released before writing to disk (line 35 unlocks, line 44 writes). Between unlock and write, the blocklist could change, resulting in the file not matching the current state. More critically, multiple concurrent `saveBlockList` calls could interleave file writes.

**Fix:** Serialize the data while holding the lock, then write outside the lock. Or hold the lock through the entire save operation.

---

### 20. Challenge server logged twice at startup
**File:** `logmonitor.go:548`, `challenge_log_cooldown.go:77-93`
**Severity:** Minor

`startChallengeLoggedIPsCleanupTask()` is called twice: once from `startChallengeServer()` (line 210) and once from `startPeriodicTasks()` (line 548). This results in two cleanup goroutines and duplicate cleanup runs.

**Fix:** Remove one of the calls.

---

### 21. `rules.json` in repository root conflicts with `rules.json` in config path
**File:** `rules.json`
**Severity:** Confusion

A `rules.json` exists in the repository root alongside `rules.go`. This could be confused with the runtime rules file at `/etc/apacheblock/rules.json`. It's unclear if this is a sample/default or accidentally committed runtime data.

**Fix:** Clarify the purpose (e.g., rename to `rules.example.json` or move to an `examples/` directory).

---

### 22. `example.com` in default domain whitelist
**File:** `domainwhitelist.go:89`
**Severity:** Logic error

The default domain whitelist file includes `example.com`, `google.com`, and `cloudflare.com`. If a user doesn't customize the domain whitelist file, these domains will be whitelisted, potentially allowing traffic from Google/Cloudflare IPs to bypass blocking.

**Fix:** Comment out all example entries in the generated file, or only include `127.0.0.1`/`localhost`.

---

### 23. `handleDebugStream` calls `os.Exit(0)` in signal handler
**File:** `socket.go:360`
**Severity:** Correctness

```go
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
go func() {
    <-sigChan
    fmt.Println("\nStopping debug stream...")
    conn.Close()
    os.Exit(0)
}()
```

This kills the entire client process on SIGINT/SIGTERM without cleanup. It also doesn't restore the default signal handlers after the debug stream ends, leaving the process in a broken signal state.

**Fix:** Use `context.Context` for cancellation instead of `os.Exit`. Restore signal handlers after the stream ends.

---

### 24. `getRuleThreshold` uses prefix matching on rule names
**File:** `rules.go:281`
**Severity:** Bug

```go
if rule.Name == ruleName || strings.HasPrefix(ruleName, rule.Name) {
```

The `reason` passed in includes extra data (e.g., `"Apache PHP 403/404 404"`), and `strings.HasPrefix` is used to match against rule names. This could match the wrong rule if one rule name is a prefix of another (e.g., `"Caddy PHP"` would match both `"Caddy PHP 403/404"` and `"Caddy PHP Redirects"`).

**Fix:** Use exact rule name matching by separating the rule name from the extra reason data.

---

### 25. `challengeCertPath` validation is too lax
**File:** `config.go:209`
**Severity:** Robustness

```go
if strings.Contains(value, "/") {
    challengeCertPath = value
}
```

Any string containing a `/` is accepted as a valid certificate path. This could accept malformed paths.

**Fix:** Validate that the path exists and is a directory, or at least use `filepath.IsAbs()` or `filepath.Clean()`.
