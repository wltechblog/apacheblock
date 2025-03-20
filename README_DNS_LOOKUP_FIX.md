# Apache Block DNS Lookup Fix

## Problem

Apache Block takes a very long time to start up, especially when there are many blocked IP addresses. This is because the application is performing DNS lookups when listing and checking firewall rules.

When running iptables commands like:
```bash
iptables -t filter -L apacheblock
```

By default, iptables tries to resolve IP addresses to hostnames, which causes DNS lookups for every IP address in the rules. This can take a very long time, especially if:
1. There are many blocked IPs
2. DNS resolution is slow or unavailable
3. The DNS server has rate limiting

## Solution

The fix is simple: add the `-n` flag to all iptables commands that list or check rules. This flag tells iptables to display numeric IP addresses without attempting DNS resolution.

The following iptables commands have been updated in `firewall.go`:

1. In `setupFirewallTable()` when checking if the chain exists:
   ```go
   cmd := exec.Command("iptables", "-t", "filter", "-L", firewallTable, "-n")
   ```

2. In `addBlockRule()` when checking if rules already exist:
   ```go
   cmd := exec.Command("iptables", "-t", "filter", "-C", firewallTable, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP", "-n")
   ```

3. In `removePortBlockingRules()` when checking if the chain exists:
   ```go
   cmd := exec.Command("iptables", "-t", "filter", "-L", firewallTable, "-n")
   ```

## How to Apply the Fix

1. Run the provided script:
   ```bash
   chmod +x fix_dns_lookups.sh
   ./fix_dns_lookups.sh
   ```

2. Compile the application:
   ```bash
   go build
   ```

## Expected Results

After applying this fix, you should see:
- Significantly faster startup time
- Reduced CPU usage during startup
- No change in functionality

## Technical Details

The `-n` flag in iptables commands prevents DNS resolution, which can be a significant performance bottleneck. This is especially important in security applications like Apache Block that may be dealing with many IP addresses.

From the iptables man page:
```
-n, --numeric
    Numeric output. IP addresses and port numbers will be printed in numeric format. By default, the program will try to display them as host names, network names, or services (whenever applicable).
```

This fix is minimal and targeted, focusing only on the specific issue without adding unnecessary files or making extensive changes to the codebase.