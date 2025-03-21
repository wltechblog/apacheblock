package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Global variables for domain whitelist
var (
	domainWhitelist   = make(map[string]bool)
	domainWhitelistMu sync.RWMutex
)

// readDomainWhitelistFile reads domain names from the whitelist file and adds them to the domain whitelist map
func readDomainWhitelistFile(filePath string) error {
	// Ensure the directory exists
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
		log.Printf("Created directory %s for domain whitelist file", dir)
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("Domain whitelist file %s does not exist, creating example file", filePath)
		if err := createExampleDomainWhitelistFile(filePath); err != nil {
			log.Printf("Failed to create example domain whitelist file: %v", err)
		}
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open domain whitelist file: %v", err)
	}
	defer file.Close()

	// Clear existing domain whitelist
	domainWhitelistMu.Lock()
	domainWhitelist = make(map[string]bool)
	domainWhitelistMu.Unlock()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Add domain to whitelist
		domainWhitelistMu.Lock()
		domainWhitelist[line] = true
		domainWhitelistMu.Unlock()

		if debug {
			log.Printf("Added domain %s to domain whitelist", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading domain whitelist file: %v", err)
	}

	return nil
}

// createExampleDomainWhitelistFile creates an example domain whitelist file with comments and sample entries
func createExampleDomainWhitelistFile(filePath string) error {
	content := `# Apache Block Domain Whitelist
# Add one domain name per line
# Lines starting with # are comments and will be ignored
# Examples:

# Individual domain names
example.com
google.com
cloudflare.com

# Subdomains
api.example.com
cdn.example.com
`
	return os.WriteFile(filePath, []byte(content), 0644)
}

// isDomainWhitelisted checks if an IP address belongs to a whitelisted domain
// It performs reverse DNS lookup on the IP, verifies with forward lookup,
// and checks if the hostname matches any domain in the whitelist
func isDomainWhitelisted(ip string) bool {
	// Skip if domain whitelist is empty
	domainWhitelistMu.RLock()
	isEmpty := len(domainWhitelist) == 0
	domainWhitelistMu.RUnlock()

	if isEmpty {
		return false
	}

	// Perform reverse DNS lookup
	hostnames, err := net.LookupAddr(ip)
	if err != nil || len(hostnames) == 0 {
		if debug {
			log.Printf("No reverse DNS records found for IP %s or lookup error: %v", ip, err)
		}
		return false
	}

	// For each hostname returned by reverse lookup
	for _, hostname := range hostnames {
		// Remove trailing dot if present
		hostname = strings.TrimSuffix(hostname, ".")

		if debug {
			log.Printf("Reverse DNS lookup for IP %s returned hostname: %s", ip, hostname)
		}

		// Verify with forward lookup
		ips, err := net.LookupHost(hostname)
		if err != nil {
			if debug {
				log.Printf("Forward DNS lookup failed for hostname %s: %v", hostname, err)
			}
			continue
		}

		// Check if the original IP is in the forward lookup results
		ipFound := false
		for _, resolvedIP := range ips {
			if resolvedIP == ip {
				ipFound = true
				break
			}
		}

		if !ipFound {
			if debug {
				log.Printf("Forward DNS verification failed: IP %s not found in results for %s", ip, hostname)
			}
			continue
		}

		// Check if the hostname matches any domain in the whitelist
		domainWhitelistMu.RLock()
		for domain := range domainWhitelist {
			// Check for exact match or if hostname ends with .domain
			if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
				if debug {
					log.Printf("IP %s belongs to whitelisted domain %s (hostname: %s)", ip, domain, hostname)
				}
				domainWhitelistMu.RUnlock()
				return true
			}
		}
		domainWhitelistMu.RUnlock()
	}

	return false
}