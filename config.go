package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultConfigPath is the default path for the configuration file
	DefaultConfigPath = "/etc/apacheblock/apacheblock.conf"
)

// readConfigFile reads configuration settings from a file
func readConfigFile(configPath string) error {
	// Check if the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if debug {
			log.Printf("Configuration file %s does not exist, using command line arguments", configPath)
		}
		return nil
	}

	if debug {
		log.Printf("Reading configuration from %s", configPath)
	}

	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open configuration file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: Invalid configuration line %d: %s", lineNum, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Apply the configuration
		switch key {
		case "server":
			if value == "apache" || value == "caddy" {
				logFormat = value
				if debug {
					log.Printf("Config: Set server to %s", value)
				}
			} else {
				log.Printf("Warning: Invalid server value: %s", value)
			}
		case "logPath":
			if _, err := os.Stat(value); err == nil {
				logpath = value
				if debug {
					log.Printf("Config: Set logPath to %s", value)
				}
			} else {
				log.Printf("Warning: Invalid logPath value: %s", value)
			}
		case "whitelist":
			whitelistFilePath = value
			if debug {
				log.Printf("Config: Set whitelist to %s", value)
			}
		case "domainWhitelist":
			domainWhitelistPath = value
			if debug {
				log.Printf("Config: Set domainWhitelist to %s", value)
			}
		case "blocklist":
			blocklistFilePath = value
			if debug {
				log.Printf("Config: Set blocklist to %s", value)
			}
		case "rules":
			rulesFilePath = value
			if debug {
				log.Printf("Config: Set rules to %s", value)
			}
		case "firewallChain": // Renamed from table
			firewallChain = value
			if debug {
				log.Printf("Config: Set firewallChain to %s", value)
			}
		case "firewallType": // New
			if value == "iptables" || value == "nftables" {
				firewallType = value
				if debug {
					log.Printf("Config: Set firewallType to %s", value)
				}
			} else {
				log.Printf("Warning: Invalid firewallType value: %s (must be 'iptables' or 'nftables')", value)
			}
		case "apiKey":
			apiKey = value
			if debug {
				log.Printf("Config: Set apiKey")
			}
		case "socketPath":
			SocketPath = value
			if debug {
				log.Printf("Config: Set socketPath to %s", value)
			}
		case "debug":
			if value == "true" || value == "1" || value == "yes" {
				debug = true
				log.Printf("Config: Enabled debug mode")
			}
		case "verbose":
			if value == "true" || value == "1" || value == "yes" {
				verbose = true
				debug = true // Verbose implies debug
				log.Printf("Config: Enabled verbose debug mode")
			}
		case "expirationPeriod":
			if duration, err := time.ParseDuration(value); err == nil {
				expirationPeriod = duration
				if debug {
					log.Printf("Config: Set expirationPeriod to %v", duration)
				}
			} else {
				log.Printf("Warning: Invalid expirationPeriod value: %s", value)
			}
		case "threshold":
			var val int
			if _, err := fmt.Sscanf(value, "%d", &val); err == nil {
				threshold = val
				if debug {
					log.Printf("Config: Set threshold to %d", val)
				}
			} else {
				log.Printf("Warning: Invalid threshold value: %s", value)
			}
		case "subnetThreshold":
			var val int
			if _, err := fmt.Sscanf(value, "%d", &val); err == nil {
				subnetThreshold = val
				if debug {
					log.Printf("Config: Set subnetThreshold to %d", val)
				}
			} else {
				log.Printf("Warning: Invalid subnetThreshold value: %s", value)
			}
		case "disableSubnetBlocking":
			if value == "true" || value == "1" || value == "yes" {
				disableSubnetBlocking = true
				if debug {
					log.Printf("Config: Disabled subnet blocking")
				}
			}
		case "startupLines":
			var val int
			if _, err := fmt.Sscanf(value, "%d", &val); err == nil {
				startupLines = val
				if debug {
					log.Printf("Config: Set startupLines to %d", val)
				}
			} else {
				log.Printf("Warning: Invalid startupLines value: %s", value)
			}
			// Challenge Feature Configuration Parsing
		case "challengeEnable":
			if bVal, err := strconv.ParseBool(value); err == nil {
				challengeEnable = bVal
				if debug {
					log.Printf("Config: Set challengeEnable to %t", bVal)
				}
			} else {
				log.Printf("Warning: Invalid challengeEnable value: %s (must be true or false)", value)
			}
		case "challengePort":
			if iVal, err := strconv.Atoi(value); err == nil && iVal > 0 && iVal < 65536 {
				challengePort = iVal
				if debug {
					log.Printf("Config: Set challengePort to %d", iVal)
				}
			} else {
				log.Printf("Warning: Invalid challengePort value: %s (must be between 1 and 65535)", value)
			}
		case "challengeCertPath":
			// Basic check if it looks like a path, more robust check might be needed
			if strings.Contains(value, "/") {
				challengeCertPath = value
				if debug {
					log.Printf("Config: Set challengeCertPath to %s", value)
				}
			} else {
				log.Printf("Warning: Invalid challengeCertPath value: %s", value)
			}
		case "recaptchaSiteKey":
			recaptchaSiteKey = value
			if debug {
				log.Printf("Config: Set recaptchaSiteKey") // Don't log the key itself
			}
		case "recaptchaSecretKey":
			recaptchaSecretKey = value
			if debug {
				log.Printf("Config: Set recaptchaSecretKey") // Don't log the key itself
			}
		case "challengeTempWhitelistDuration":
			if duration, err := time.ParseDuration(value); err == nil {
				challengeTempWhitelistDuration = duration
				if debug {
					log.Printf("Config: Set challengeTempWhitelistDuration to %v", duration)
				}
			} else {
				log.Printf("Warning: Invalid challengeTempWhitelistDuration value: %s", value)
			}
		default:
			log.Printf("Warning: Unknown configuration key: %s", key)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading configuration file: %v", err)
	}

	log.Printf("Successfully loaded configuration from %s", configPath)
	return nil
}

// createExampleConfigFile creates an example configuration file with comments and default values
func createExampleConfigFile(configPath string) error {
	// Ensure the directory exists
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	content := `# Apache Block Configuration File
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

# Firewall type: iptables or nftables
firewallType = iptables

# Name of the firewall chain to use for blocking rules (e.g., iptables chain)
firewallChain = apacheblock

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

# Path to the directory containing SSL certificates ([domain].key, [domain].crt)
# ApacheBlock will load certificates dynamically based on the requested domain (SNI).
challengeCertPath = /etc/apacheblock/certs

# Google reCAPTCHA v2 Site Key (visible in HTML)
recaptchaSiteKey = YOUR_RECAPTCHA_SITE_KEY

# Google reCAPTCHA v2 Secret Key (keep private)
recaptchaSecretKey = YOUR_RECAPTCHA_SECRET_KEY

# Duration for which an IP remains whitelisted after solving a challenge (e.g., 5m, 1h)
challengeTempWhitelistDuration = 5m
`

	return os.WriteFile(configPath, []byte(content), 0644)
}
