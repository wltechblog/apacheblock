# Apache Block

Apache Block is a security tool for web servers that monitors log files for suspicious activity and automatically blocks malicious IP addresses using iptables.

## Features

- Monitors Apache and Caddy log files for suspicious activity
- Automatically blocks IP addresses that exceed a threshold of suspicious requests
- Blocks entire subnets when multiple IPs from the same subnet are detected
- Maintains a whitelist of IP addresses and subnets that should never be blocked
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
sudo apacheblock -check 1.2.3.4

# Check if a subnet is blocked
sudo apacheblock -check 1.2.3.0/24

# List all blocked IPs and subnets
sudo apacheblock -list
```

#### Client-Server Communication

When you run a client mode command:

1. The client first attempts to communicate with a running server instance through a Unix domain socket (`/var/run/apacheblock.sock`).
2. If the server is running, the command is processed by the server, and changes take effect immediately.
3. If the server is not running, the client falls back to direct execution, modifying the blocklist file directly. In this case, you'll need to restart the server for changes to take effect.

This approach ensures that:
- You can manage blocks without restarting the server
- Changes are synchronized between client and server
- The blocklist file remains consistent

## Command-line Options

### Basic Options

| Option | Default | Description |
|--------|---------|-------------|
| `-server` | `apache` | Log format: `apache` or `caddy` |
| `-logPath` | `/var/customers/logs` | Directory containing log files |
| `-whitelist` | `/etc/apacheblock/whitelist.txt` | Path to whitelist file |
| `-blocklist` | `/etc/apacheblock/blocklist.json` | Path to blocklist file |
| `-rules` | `/etc/apacheblock/rules.json` | Path to rules file |
| `-table` | `apacheblock` | Name of the iptables chain to use |
| `-debug` | `false` | Enable debug mode for verbose logging |
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

The whitelist file contains IP addresses and CIDR ranges that should never be blocked. Each entry should be on a separate line. Comments are supported using the `#` character.

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
   - Loads whitelist entries from the specified file
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
ExecStart=/usr/local/bin/apacheblock -server apache -logPath /var/log/apache2 -whitelist /etc/apacheblock/whitelist.txt -blocklist /etc/apacheblock/blocklist.json -table apacheblock -threshold 5 -expirationPeriod 10m
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

This project is licensed under the MIT License - see the LICENSE file for details.