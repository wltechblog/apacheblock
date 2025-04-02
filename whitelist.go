package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// readWhitelistFile reads IP addresses from the whitelist file and adds them to the whitelist map
func readWhitelistFile(filePath string) error {
	// Ensure the directory exists
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
		log.Printf("Created directory %s for whitelist file", dir)
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("Whitelist file %s does not exist, creating example file", filePath)
		if err := createExampleWhitelistFile(filePath); err != nil {
			log.Printf("Failed to create example whitelist file: %v", err)
		}
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open whitelist file: %v", err)
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

		// Validate IP address
		ip := net.ParseIP(line)
		if ip == nil {
			// Check if it's a CIDR notation
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				log.Printf("Invalid IP address or CIDR at line %d: %s", lineNum, line)
				continue
			}
			// For CIDR notation, we store the network address
			whitelist[ipNet.String()] = true
			// Log add only in debug
			if debug {
				log.Printf("Added subnet %s to whitelist", ipNet.String())
			}
		} else {
			whitelist[ip.String()] = true
			// Log add only in debug
			if debug {
				log.Printf("Added IP %s to whitelist", ip.String())
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading whitelist file: %v", err)
	}

	return nil
}

// createExampleWhitelistFile creates an example whitelist file with comments and sample entries
func createExampleWhitelistFile(filePath string) error {
	content := `# Apache Block Whitelist
# Add one IP address or CIDR range per line
# Lines starting with # are comments and will be ignored
# Examples:

# Individual IP addresses
127.0.0.1
192.168.1.10

# CIDR notation for subnets
# 10.0.0.0/8
# 172.16.0.0/12
# 192.168.0.0/16
`
	return os.WriteFile(filePath, []byte(content), 0644)
}

// isWhitelisted checks if an IP is in the whitelist
func isWhitelisted(ip string) bool {
	// Check if IP is directly whitelisted
	if _, whitelisted := whitelist[ip]; whitelisted {
		// Log skip only in debug
		if debug {
			log.Printf("IP %s is whitelisted, skipping", ip)
		}
		return true
	}

	// Check if IP is in a whitelisted CIDR range
	ipAddr := net.ParseIP(ip)
	if ipAddr != nil {
		for cidr := range whitelist {
			// Check if this is a CIDR notation
			if strings.Contains(cidr, "/") {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil && ipNet.Contains(ipAddr) {
					// Log skip only in debug
					if debug {
						log.Printf("IP %s is in whitelisted CIDR %s, skipping", ip, cidr)
					}
					return true
				}
			}
		}
	}

	return false
}
