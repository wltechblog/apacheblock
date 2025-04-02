package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// saveBlockList saves the current list of blocked IPs and subnets to a file
func saveBlockList() error {
	// Ensure the directory exists
	dir := filepath.Dir(blocklistFilePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Create the blocklist
	mu.Lock()
	blocklist := BlockList{
		IPs:     make([]string, 0, len(blockedIPs)),
		Subnets: make([]string, 0, len(blockedSubnets)),
	}

	for ip := range blockedIPs {
		blocklist.IPs = append(blocklist.IPs, ip)
	}

	for subnet := range blockedSubnets {
		blocklist.Subnets = append(blocklist.Subnets, subnet)
	}
	mu.Unlock()

	// Marshal to JSON
	data, err := json.MarshalIndent(blocklist, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blocklist: %v", err)
	}

	// Write to file
	if err := os.WriteFile(blocklistFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write blocklist file: %v", err)
	}

	// Log save success only in debug
	if debug {
		log.Printf("Saved blocklist to %s: %d IPs, %d subnets",
			blocklistFilePath, len(blocklist.IPs), len(blocklist.Subnets))
	}

	return nil
}

// loadBlockList loads the list of blocked IPs and subnets from a file
func loadBlockList() error {
	// Check if the file exists
	if _, err := os.Stat(blocklistFilePath); os.IsNotExist(err) {
		log.Printf("Blocklist file does not exist: %s", blocklistFilePath)
		return nil
	}

	// Read the file
	data, err := os.ReadFile(blocklistFilePath)
	if err != nil {
		return fmt.Errorf("failed to read blocklist file: %v", err)
	}

	// Unmarshal JSON
	var blocklist BlockList
	if err := json.Unmarshal(data, &blocklist); err != nil {
		return fmt.Errorf("failed to unmarshal blocklist: %v", err)
	}

	// Apply the blocklist
	mu.Lock()
	defer mu.Unlock()

	// Clear existing maps
	blockedIPs = make(map[string]struct{})
	blockedSubnets = make(map[string]struct{})

	// Add IPs and subnets to maps
	for _, ip := range blocklist.IPs {
		blockedIPs[ip] = struct{}{}
	}

	for _, subnet := range blocklist.Subnets {
		blockedSubnets[subnet] = struct{}{}
	}

	// Log load success only in debug
	if debug {
		log.Printf("Loaded blocklist from %s: %d IPs, %d subnets",
			blocklistFilePath, len(blocklist.IPs), len(blocklist.Subnets))
	}

	return nil
}
