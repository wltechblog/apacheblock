# Apache Block

Apache Block is a security tool for web servers that monitors log files for suspicious activity and automatically blocks malicious IP addresses using iptables or nftables.

## Features

- Monitors Apache and Caddy log files for suspicious activity
- Automatically blocks IP addresses that exceed a threshold of suspicious requests
- Blocks entire subnets when multiple IPs from the same subnet are detected
- Maintains a whitelist of IP addresses, subnets, and domains that should never be blocked
- Persists blocklist between restarts
- Provides client mode for manual management of blocked IPs and subnets
- Uses a dedicated iptables/nftables chain for better organization of firewall rules
- Supports both iptables and nftables firewall backends
- Optional reCAPTCHA challenge for blocked IPs instead of immediate drop
- Syslog integration for centralized logging
- Ignored log files list to exclude specific files from monitoring
- Graceful shutdown on SIGTERM/SIGINT
- IPv4 and IPv6 support
- API key authentication via environment variable

## Requirements

- Linux system with iptables or nftables
- Go 1.16 or higher (for building from source)
- Root privileges (for firewall operations)

## Installation

You can install Apache Block directly using Go:

```bash
# Install the latest version
go install github.com/wltechblog/apacheblock@latest

# Create the configuration directory
sudo mkdir -p /etc/apacheblock

# Copy the binary to a system location (if not already in your PATH)
sudo cp $(go env GOPATH)/bin/apacheblock /usr/local/bin/
```

## Building from Source

Alternatively, you can build from source:

```bash
git clone https://github.com/wltechblog/apacheblock.git
cd apacheblock
go build -o apacheblock
sudo cp apacheblock /usr/local/bin/
```

## Usage

### Basic Usage

```bash
# Basic usage with default settings
sudo apacheblock

# Specify log format (apache or caddy)
sudo apacheblock -server apache

# Specify custom log directory
sudo apacheblock -logPath /var/log/apache2

# Specify custom whitelist file
sudo apacheblock -whitelist /path/to/whitelist.txt

# Specify custom domain whitelist file
sudo apacheblock -domainWhitelist /path/to/domainwhitelist.txt

# Enable debug mode for verbose logging
sudo apacheblock -debug

# Log to syslog instead of stdout
sudo apacheblock -logOutput syslog

# Remove all existing port blocking rules
sudo apacheblock -clean
```

### Advanced Usage with Configuration Options

```bash
# Set a custom threshold for IP blocking (5 suspicious requests)
sudo apacheblock -threshold 5

# Set a custom expiration period (10 minutes)
sudo apacheblock -expirationPeriod 10m

# Set a custom subnet threshold (5 IPs from the same subnet)
sudo apacheblock -subnetThreshold 5

# Disable automatic subnet blocking
sudo apacheblock -disableSubnetBlocking

# Process more log lines at startup (10000 lines)
sudo apacheblock -startupLines 10000

# Use nftables instead of iptables
sudo apacheblock -firewallType nftables

# Combine multiple options
sudo apacheblock -server apache -logPath /var/log/apache2 -threshold 5 -expirationPeriod 10m -logOutput syslog
```

### Client Mode

Apache Block includes a client mode that allows you to manually manage blocked IPs and subnets. Client mode commands communicate with a running server instance through a Unix domain socket, allowing you to modify the blocklist without restarting the server:

```bash
# Block an IP address
sudo apacheblock -block 1.2.3.4

# Block a subnet
sudo apacheblock -block 1.2.3.0/24

# Unblock an IP address
sudo apacheblock -unblock 1.2.3.4

# Unblock a subnet
sudo apacheblock -unblock 1.2.3.0/24

# Check if an IP address is blocked
# (Will also show if the IP is blocked because it's contained in a blocked subnet)
sudo apacheblock -check 1.2.3.4

# Check if a subnet is blocked
sudo apacheblock -check 1.2.3.0/24

# List all blocked IPs and subnets
sudo apacheblock -list

# Stream debug logs from the server in real-time
# Shows all matches, firewall actions, and challenge server requests
# Press Ctrl+C to stop
sudo apacheblock -debug-stream

# Use with API key authentication
sudo apacheblock -block 1.2.3.4 -apiKey "your-secret-key"

# Use with custom socket path
sudo apacheblock -block 1.2.3.4 -socketPath "/tmp/apacheblock.sock"

# Combine options
sudo apacheblock -block 1.2.3.4 -apiKey "your-secret-key" -socketPath "/tmp/apacheblock.sock"
```

#### Client-Server Communication

When you run a client mode command:

1. The client first attempts to communicate with a running server instance through a Unix domain socket (`/var/run/apacheblock.sock`).
2. If the server is running, the command is processed by the server, and changes take effect immediately.
3. If the server is not running, the client falls back to direct execution, modifying the blocklist file directly. In this case, you'll need to restart the server for changes to take effect.

This approach ensures that:
- You can manage blocks without restarting the server
- Changes are synchronized between client and server

#### API Key Authentication

You can secure the socket interface with an API key to prevent unauthorized access. When an API key is set, all client commands must include the same key to be processed.

To set an API key when starting the server:

```bash
# Via command-line flag
sudo apacheblock -apiKey "your-secret-key"

# Or via environment variable (avoids exposing the key in process listings)
sudo APACHEBLOCK_API_KEY="your-secret-key" apacheblock
```

Then, when using client commands, you must include the same API key:

```bash
sudo apacheblock -block 1.2.3.4 -apiKey "your-secret-key"
```

This feature is particularly useful when creating web interfaces or other tools that interact with the Apache Block service.

### PHP Web Interface

Apache Block includes a modern web interface built with PHP and Tailwind CSS that provides a user-friendly way to manage blocked IPs and subnets.

#### Features

- Material Design-inspired interface with Tailwind CSS
- Separate configuration file for security
- Responsive layout that works on mobile and desktop
- Quick actions to block, unblock, and check IP addresses
- Visual display of currently blocked IPs and subnets
- One-click unblocking directly from the list

#### Installation

1. Copy the example files to your web server directory:

```bash
# Create directory if it doesn't exist
sudo mkdir -p /var/www/html/apacheblock

# Copy the PHP files
sudo cp /path/to/apacheblock/examples/apacheblock.php /var/www/html/apacheblock/
sudo cp /path/to/apacheblock/examples/config.php /var/www/html/apacheblock/
```

2. Edit the configuration file to set your API key:

```bash
sudo nano /var/www/html/apacheblock/config.php
```

Update the configuration:

```php
<?php
$config = [
    'apiKey' => 'your-secret-key',  // Must match the key used when starting apacheblock
    'executablePath' => '/usr/local/bin/apacheblock',
    'debug' => false
];
```

3. Configure sudo to allow the web server user to run apacheblock without a password:

```bash
# Edit sudoers file
sudo visudo -f /etc/sudoers.d/apacheblock
```

Add the following line (replace `www-data` with your web server user):

```
www-data ALL=(ALL) NOPASSWD: /usr/local/bin/apacheblock
```

4. Set proper permissions:

```bash
sudo chown -R www-data:www-data /var/www/html/apacheblock
sudo chmod 640 /var/www/html/apacheblock/config.php
```

5. Access the web interface through your browser (e.g., `http://your-server/apacheblock/`).

#### Security Recommendations

- Place the web interface behind a secure HTTPS connection
- Implement web server authentication (e.g., HTTP Basic Auth)
- Consider using a more robust authentication system for production environments
- Regularly update your API key
- Limit access to the web interface using IP-based restrictions

#### Screenshots

The web interface provides a clean, modern design:

- Header with application title and description
- IP management card with input field and action buttons
- Results display for command output
- Separate lists for blocked IPs and subnets with one-click unblocking
- Responsive design that works on all device sizes

**Note**: This is a basic example. In a production environment, you should implement proper authentication for the web interface itself to prevent unauthorized access.

#### Troubleshooting the Web Interface

If the web interface shows "Service Not Running" even though the service is running:

1. Enable debug mode in `config.php`:
   ```php
   $config = [
       // ... other settings ...
       'debug' => true,
       // ... other settings ...
   ];
   ```

2. Check your web server's error log for detailed messages

3. Common issues:
   - Socket path mismatch: Make sure the `socketPath` in config.php matches the path used by the service
   - Permissions: The socket file has restricted permissions (0600); the web server user may need to be in the same group or run as root
   - API key mismatch: The API key in config.php must match the one used by the service
   - SELinux: On systems with SELinux, you may need to set appropriate contexts for the socket file

## Configuration

Apache Block can be configured in two ways:

1. Using command-line options
2. Using a configuration file

The configuration file provides a convenient way to set all options in one place, while command-line options allow for quick changes and overrides. Command-line options always take precedence over settings in the configuration file.

### Configuration File

By default, Apache Block looks for a configuration file at `/etc/apacheblock/apacheblock.conf`. You can specify a different location using the `-config` command-line option.

If the configuration file doesn't exist when the program starts, an example configuration file will be created automatically.

Example configuration file:

```
# Apache Block Configuration File
# This file contains configuration settings for the Apache Block service.
# Lines starting with # are comments and will be ignored.

# Log format: apache or caddy
server = apache

# Path to log files
logPath = /var/customers/logs

# Path to whitelist file
whitelist = /etc/apacheblock/whitelist.txt

# Path to domain whitelist file
domainWhitelist = /etc/apacheblock/domainwhitelist.txt

# Path to file listing log files to ignore (one basename or full path per line)
ignoreFiles = /etc/apacheblock/ignorefiles.txt

# Path to blocklist file
blocklist = /etc/apacheblock/blocklist.json

# Path to rules file
rules = /etc/apacheblock/rules.json

# Firewall type: iptables or nftables
firewallType = iptables

# Name of the firewall chain to use for blocking rules
firewallChain = apacheblock

# API key for socket authentication (leave empty for no authentication)
# Alternatively, use the APACHEBLOCK_API_KEY environment variable
apiKey =

# Path to the Unix domain socket for client-server communication
socketPath = /var/run/apacheblock.sock

# Enable debug mode (true/false)
debug = false

# Logging output: stdout or syslog
logOutput = stdout

# Enable verbose debug mode (true/false)
verbose = false

# Time period to monitor for malicious activity (e.g., 5m, 10m, 1h)
expirationPeriod = 5m

# Number of suspicious requests to trigger IP blocking
threshold = 3

# Number of IPs from a subnet to trigger subnet blocking
subnetThreshold = 3

# Disable automatic subnet blocking (true/false)
disableSubnetBlocking = false

# Number of log lines to process at startup
startupLines = 5000

# --- Challenge Feature Configuration ---

# Enable the reCAPTCHA challenge feature (true/false)
# If true, instead of dropping traffic, IPs will be redirected to the challengePort.
challengeEnable = false

# Port for the internal HTTPS challenge server to listen on
challengePort = 4443

# Port for the internal HTTP redirect server (redirects to HTTPS challenge)
challengeHTTPPort = 8088

# Path to the directory containing SSL certificates ([domain].key, [domain].crt)
# ApacheBlock will load certificates dynamically based on the requested domain (SNI).
# It will strip 'www.' prefix, so 'example.com.crt' works for both domains.
# If a specific cert isn't found, it falls back to an in-memory self-signed cert.
challengeCertPath = /etc/apacheblock/certs

# Google reCAPTCHA v2 Site Key (visible in HTML)
recaptchaSiteKey = YOUR_RECAPTCHA_SITE_KEY

# Google reCAPTCHA v2 Secret Key (keep private)
recaptchaSecretKey = YOUR_RECAPTCHA_SECRET_KEY

# Duration for which an IP remains whitelisted after solving a challenge (e.g., 5m, 1h)
challengeTempWhitelistDuration = 5m

# Comma-separated list of trusted reverse proxy IPs
# Only trust X-Forwarded-For/X-Real-IP headers from these addresses
trustedProxies =
```

## reCAPTCHA Challenge Feature (Optional)

Instead of immediately blocking traffic from a suspicious IP using `DROP`, Apache Block can be configured to redirect the user to an internal HTTPS server that presents a Google reCAPTCHA v2 challenge. This works with both iptables and nftables.

**How it works:**

1.  **Enable:** Set `challengeEnable = true` in the configuration file.
2.  **Configure:** Provide your Google reCAPTCHA v2 Site Key (`recaptchaSiteKey`) and Secret Key (`recaptchaSecretKey`), the port for the internal server (`challengePort`), and the path to your SSL certificates (`challengeCertPath`).
3.  **Redirection:** When an IP is flagged, Apache Block adds firewall rules to redirect HTTP and HTTPS traffic from that IP to the `challengePort`.
4.  **Challenge Server:** Apache Block runs an internal HTTPS server on `challengePort`.
    *   It uses SNI to identify the requested domain.
    *   It attempts to load the corresponding certificate (`domain_fullchain.pem`, `domain.key`) from `challengeCertPath`. It automatically handles `www.` prefixes (e.g., `example.com_fullchain.pem` works for `www.example.com`).
    *   If a specific certificate isn't found, it falls back to a self-signed certificate generated in memory at startup (this will cause browser warnings but allows the challenge to be presented).
    *   It serves an HTML page containing the reCAPTCHA widget.
5.  **Verification:** When the user submits the reCAPTCHA, the server verifies the response with Google using your secret key.
6.  **Unblocking:** Upon successful verification:
    *   If the IP was blocked individually, the redirect rules for that IP are removed.
    *   If the IP was blocked as part of a subnet, the subnet rule is removed and replaced with individual rules for all other IPs in that subnet (the verified IP is freed).
    *   The user's IP is added to a temporary whitelist for the duration specified by `challengeTempWhitelistDuration` (default 5 minutes) to prevent immediate re-blocking.
    *   A success page is displayed.

**Trusted Proxies:**

By default, the challenge server does not trust `X-Forwarded-For` or `X-Real-IP` headers, preventing header spoofing attacks. If your server is behind a reverse proxy (e.g., Cloudflare, nginx), configure `trustedProxies` with the proxy's IP address(es) so that client IPs are correctly identified:

```
trustedProxies = 10.0.0.1,10.0.0.2
```

**Requirements for Challenge Feature:**

*   `challengeEnable = true` in configuration.
*   Valid Google reCAPTCHA v2 Site and Secret keys.
*   A directory (`challengeCertPath`) containing valid SSL certificates named after the domains being protected.
*   The `challengePort` must be accessible to the users being redirected.

## Command-line Options

### Basic Options

| Option | Default | Description |
|--------|---------|-------------|
| `-config` | `/etc/apacheblock/apacheblock.conf` | Path to configuration file |
| `-server` | `apache` | Log format: `apache` or `caddy` |
| `-logPath` | `/var/customers/logs` | Directory containing log files |
| `-whitelist` | `/etc/apacheblock/whitelist.txt` | Path to whitelist file |
| `-domainWhitelist` | `/etc/apacheblock/domainwhitelist.txt` | Path to domain whitelist file |
| `-blocklist` | `/etc/apacheblock/blocklist.json` | Path to blocklist file |
| `-ignoreFiles` | `/etc/apacheblock/ignorefiles.txt` | Path to ignored log files list |
| `-rules` | `/etc/apacheblock/rules.json` | Path to rules file |
| `-table` | `apacheblock` | Name of the firewall chain to use (iptables/nftables) |
| `-firewallType` | `iptables` | Firewall type to use (`iptables` or `nftables`) |
| `-apiKey` | `""` | API key for socket authentication (or use `APACHEBLOCK_API_KEY` env var) |
| `-socketPath` | `/var/run/apacheblock.sock` | Path to the Unix domain socket for client-server communication |
| `-logOutput` | `stdout` | Logging output: `stdout` or `syslog` |
| `-debug` | `false` | Enable debug mode for basic logging |
| `-verbose` | `false` | Enable verbose debug mode (logs all processed lines and rule matching) |
| `-clean` | `false` | Remove all existing port blocking rules |
| `-disableSubnetBlocking` | `false` | Disable automatic subnet blocking |

### Client Mode Options

| Option | Default | Description |
|--------|---------|-------------|
| `-block` | | Block an IP address or CIDR range |
| `-unblock` | | Unblock an IP address or CIDR range |
| `-check` | | Check if an IP address or CIDR range is blocked |
| `-list` | `false` | List all blocked IPs and subnets |

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `-expirationPeriod` | `5m` | Time period to monitor for malicious activity |
| `-threshold` | `3` | Number of suspicious requests to trigger IP blocking |
| `-subnetThreshold` | `3` | Number of IPs from a subnet to trigger subnet blocking |
| `-startupLines` | `5000` | Number of log lines to process at startup |

## Ignored Log Files

Apache Block can skip specific log files that you don't want monitored. The ignored files list supports both basenames and full paths.

Example `/etc/apacheblock/ignorefiles.txt`:
```
# Ignore by basename (matches any file with this name in any subdirectory)
error.log

# Ignore by full path
/var/customers/logs/example.com/access.log
```

Entries without a leading `/` are matched by basename against any log file discovered in the log directory or its subdirectories. Full paths must match exactly.

If the file doesn't exist, an example file is created automatically at startup.

## Rules Configuration

Apache Block uses a rules-based system to detect suspicious activity. Rules are defined in a JSON file and can be customized to match different patterns in log files.

Each rule includes:
- **Name**: A unique name for the rule
- **Description**: A description of what the rule detects
- **LogFormat**: The log format this rule applies to (`apache`, `caddy`, or `all`)
- **Regex**: A regular expression to match in log lines
- **Threshold**: Number of matches to trigger blocking
- **Duration**: Time window for threshold (e.g., "5m")
- **Enabled**: Whether the rule is enabled

Example rules file:
```json
{
  "rules": [
    {
      "name": "Apache PHP 403/404",
      "description": "Detects requests to PHP files resulting in 403 or 404 status codes in Apache logs",
      "logFormat": "apache",
      "regex": "^([\\d\\.]+) .* \"GET .*\\.php(?:\\..*)?(\\?.*)? (403|404) .*",
      "threshold": 3,
      "duration": "5m",
      "enabled": true
    },
    {
      "name": "WordPress Login Attempts",
      "description": "Detects repeated failed login attempts to WordPress admin",
      "logFormat": "apache",
      "regex": "^([\\d\\.]+) .* \"POST .*wp-login\\.php.*\" (200|403) .*",
      "threshold": 5,
      "duration": "10m",
      "enabled": true
    }
  ]
}
```

If the rules file doesn't exist, the program will create a default rules file with example rules.

## Whitelist Configuration

### IP Whitelist

The IP whitelist file contains IP addresses and CIDR ranges that should never be blocked. Each entry should be on a separate line. Comments are supported using the `#` character.

Example whitelist file:
```
# Individual IP addresses
127.0.0.1
192.168.1.10

# CIDR notation for subnets
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

If the whitelist file doesn't exist, the program will create an example file at the specified location.

### Domain Whitelist

The domain whitelist file contains domain names that should never be blocked. When an IP address is matched in a log file, the program performs a reverse DNS lookup on the IP, verifies it with a forward lookup, and checks if the hostname matches any domain in the whitelist.

Example domain whitelist file:
```
# Individual domain names
# example.com
# google.com

# Subdomains
# api.example.com
# cdn.example.com
```

The domain whitelist feature works as follows:
1. When an IP address is detected in a log file, a reverse DNS lookup is performed to get the hostname
2. The hostname is verified with a forward DNS lookup to ensure it resolves back to the original IP
3. If the hostname matches a domain in the whitelist (either exact match or as a subdomain), the IP is not blocked

This feature is useful for ensuring that legitimate services from known domains are never blocked, even if their IP addresses change.

If the domain whitelist file doesn't exist, the program will create an example file at the specified location.

## Blocklist Persistence

The blocklist is stored in a JSON file to persist blocked IPs and subnets between program restarts. The file is automatically created and updated as IPs and subnets are blocked.

Example blocklist file:
```json
{
  "ips": [
    "1.2.3.4",
    "5.6.7.8"
  ],
  "subnets": [
    "9.10.11.0/24",
    "12.13.14.0/24"
  ]
}
```

When the program starts, it loads the blocklist from this file and applies the rules to the firewall. When new IPs or subnets are blocked, the file is updated automatically.

## How It Works

1. **Initialization**:
   - Creates a custom iptables or nftables chain for managing blocks
   - Loads IP whitelist entries from the specified file
   - Loads domain whitelist entries from the specified file
   - Loads the ignored log files list
   - Automatically adds local IP addresses to the whitelist
   - Loads the blocklist from a JSON file and applies it to the firewall
   - Starts a socket server for client communication

2. **Log Monitoring**:
   - Monitors log files in the specified directory and its subdirectories
   - Skips files listed in the ignored files list
   - Detects new log files and log rotation events
   - Processes log entries to identify suspicious activity

3. **Detection Logic**:
   - Uses a rules-based system with customizable regular expressions
   - Each rule has its own threshold and time window
   - Rules can be specific to Apache or Caddy logs, or apply to both
   - Default rules detect PHP file access attempts, WordPress login attempts, and SQL injection attempts

4. **Blocking Mechanism**:
   - When an IP exceeds the threshold of suspicious requests, it's blocked using iptables or nftables
   - When multiple IPs from the same subnet are blocked, the entire subnet is blocked
   - Blocks apply to both HTTP (port 80) and HTTPS (port 443) traffic
   - All blocks are saved to a JSON file for persistence between restarts
   - When an IP within a blocked subnet passes the reCAPTCHA challenge, the subnet rule is split back into individual IP rules (minus the verified IP)

5. **Graceful Shutdown**:
   - On SIGTERM or SIGINT, the blocklist is saved to disk before exiting

## Logging

Apache Block supports two logging outputs:

- **stdout** (default): Logs to standard error, suitable for systemd journal capture or pipe redirection.
- **syslog**: Logs to the system syslog daemon as facility `DAEMON` with priority `NOTICE`, using the tag `apacheblock`.

Set via configuration file:
```
logOutput = syslog
```

Or via command line:
```bash
sudo apacheblock -logOutput syslog
```

Block events include the triggering log line for audit purposes:
```
BLOCKED IP 1.2.3.4 from /var/log/access.log for Apache PHP 403/404 404 (User-Agent: curl/7.88) Request: 1.2.3.4 - - [13/May/2026:10:00:01 +0000] "GET /wp-login.php HTTP/1.1" 404 453
```

## Running as a Service

To run Apache Block as a systemd service:

1. Copy the service file from the repository:

```bash
sudo cp apacheblock.service /etc/systemd/system/
```

2. Edit the service file to customize the command-line options if needed:

```bash
sudo nano /etc/systemd/system/apacheblock.service
```

3. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable apacheblock
sudo systemctl start apacheblock
```

4. Check the service status:

```bash
sudo systemctl status apacheblock
```

5. Example of a customized service file with additional options:

```
[Unit]
Description=Apache Block - Web Server Security Tool
After=network.target

[Service]
Environment=APACHEBLOCK_API_KEY=your-secret-key
ExecStart=/usr/local/bin/apacheblock -logOutput syslog
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

## License

This project is licensed under the GNU Public License 2.0 - see the LICENSE file for details.
