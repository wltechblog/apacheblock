# Apache Block

Apache Block is a security tool for web servers that monitors log files for suspicious activity and automatically blocks malicious IP addresses using iptables.

## Features

- Monitors Apache and Caddy log files for suspicious activity
- Automatically blocks IP addresses that exceed a threshold of suspicious requests
- Blocks entire subnets when multiple IPs from the same subnet are detected
- Maintains a whitelist of IP addresses, subnets, and domains that should never be blocked
- Persists blocklist between restarts
- Provides client mode for manual management of blocked IPs and subnets
- Uses a dedicated iptables chain for better organization of firewall rules

## Requirements

- Linux system with iptables
- Go 1.16 or higher (for building from source)
- Root privileges (for iptables operations)

## Installation

You can install Apache Block directly using Go:

```bash
# Install the latest version
go install github.com/wltechblog/apacheblock@latest

# Create the whitelist directory
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

# Process more log lines at startup (10000 lines)
sudo apacheblock -startupLines 10000

# Combine multiple options
sudo apacheblock -server apache -logPath /var/log/apache2 -threshold 5 -expirationPeriod 10m -debug
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
sudo apacheblock -apiKey "your-secret-key"
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

# Path to blocklist file
blocklist = /etc/apacheblock/blocklist.json

# Path to rules file
rules = /etc/apacheblock/rules.json

# Name of the iptables chain to use
table = apacheblock

# API key for socket authentication (leave empty for no authentication)
apiKey =

# Path to the Unix domain socket for client-server communication
socketPath = /var/run/apacheblock.sock

# Enable debug mode (true/false)
debug = false

# Enable verbose debug mode (true/false)
verbose = false

# Time period to monitor for malicious activity (e.g., 5m, 10m, 1h)
expirationPeriod = 5m

# Number of suspicious requests to trigger IP blocking
threshold = 3

# Number of IPs from a subnet to trigger subnet blocking
subnetThreshold = 3

# Number of log lines to process at startup
startupLines = 5000
```

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
| `-rules` | `/etc/apacheblock/rules.json` | Path to rules file |
| `-table` | `apacheblock` | Name of the iptables chain to use |
| `-apiKey` | `""` | API key for socket authentication |
| `-socketPath` | `/var/run/apacheblock.sock` | Path to the Unix domain socket for client-server communication |
| `-debug` | `false` | Enable debug mode for basic logging |
| `-verbose` | `false` | Enable verbose debug mode (logs all processed lines and rule matching) |
| `-clean` | `false` | Remove all existing port blocking rules |

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
example.com
google.com
cloudflare.com

# Subdomains
api.example.com
cdn.example.com
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
   - Creates a custom iptables chain for managing blocks
   - Loads IP whitelist entries from the specified file
   - Loads domain whitelist entries from the specified file
   - Automatically adds local IP addresses to the whitelist
   - Loads the blocklist from a JSON file and applies it to the firewall
   - Starts a socket server for client communication

2. **Log Monitoring**:
   - Monitors log files in the specified directory and its subdirectories
   - Detects new log files and log rotation events
   - Processes log entries to identify suspicious activity

3. **Detection Logic**:
   - Uses a rules-based system with customizable regular expressions
   - Each rule has its own threshold and time window
   - Rules can be specific to Apache or Caddy logs, or apply to both
   - Default rules detect PHP file access attempts, WordPress login attempts, and SQL injection attempts

4. **Blocking Mechanism**:
   - When an IP exceeds the threshold of suspicious requests, it's blocked using iptables
   - When multiple IPs from the same subnet are blocked, the entire subnet is blocked
   - Blocks apply to both HTTP (port 80) and HTTPS (port 443) traffic
   - All blocks are saved to a JSON file for persistence between restarts

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
ExecStart=/usr/local/bin/apacheblock -server apache -logPath /var/log/apache2 -whitelist /etc/apacheblock/whitelist.txt -domainWhitelist /etc/apacheblock/domainwhitelist.txt -blocklist /etc/apacheblock/blocklist.json -table apacheblock -threshold 5 -expirationPeriod 10m
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

## Logging

Apache Block logs its activity to the standard output, which can be redirected to a file or captured by systemd when running as a service.

## License

This project is licensed under the GNU Public License 2.0 - see the LICENSE file for details.