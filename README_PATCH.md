# Apache Block DNS Lookup Fix

This patch fixes the slow startup time in Apache Block by adding the `-n` flag to iptables commands to disable DNS lookups.

## Option 1: Apply the patch

```bash
# Apply the patch
patch -p0 < dns_lookup_fix.patch

# Compile the application
go build
```

## Option 2: Run the fix script

```bash
# Make the script executable
chmod +x fix_dns_lookups_clean.sh

# Run the script
./fix_dns_lookups_clean.sh

# Compile the application
go build
```

## Option 3: Manual fix

If the patch or script doesn't work, you can manually add the `-n` flag to these lines in `firewall.go`:

1. Line 16: `cmd := exec.Command("iptables", "-t", "filter", "-L", firewallTable, "-n")`
2. Line 96: `cmd := exec.Command("iptables", "-t", "filter", "-C", firewallTable, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP", "-n")`
3. Line 100: `cmd = exec.Command("iptables", "-t", "filter", "-C", firewallTable, "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP", "-n")`
4. Line 156: `cmd := exec.Command("iptables", "-t", "filter", "-L", firewallTable, "-n")`

Then compile the application:
```bash
go build
```