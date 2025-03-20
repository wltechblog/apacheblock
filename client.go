package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// ClientCommand represents a command that can be executed in client mode
type ClientCommand string

const (
	BlockCommand   ClientCommand = "block"
	UnblockCommand ClientCommand = "unblock"
	CheckCommand   ClientCommand = "check"
	ListCommand    ClientCommand = "list"
)

// RunClientMode executes the client mode operation
func RunClientMode(command ClientCommand, target string) error {
	// Validate the command
	switch command {
	case BlockCommand, UnblockCommand, CheckCommand:
		// These commands require a target
		if target == "" {
			return fmt.Errorf("target IP or subnet is required for %s command", command)
		}
		
		// Validate the target as an IP or CIDR
		if !isValidIPOrCIDR(target) {
			return fmt.Errorf("invalid IP address or CIDR range: %s", target)
		}
	case ListCommand:
		// List command doesn't require a target
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	
	// Try to send the command to a running server first
	err := sendCommand(command, target)
	if err == nil {
		// Command was successfully sent to the server
		return nil
	}
	
	// If we couldn't connect to the server, fall back to direct execution
	log.Printf("Could not connect to server: %v", err)
	log.Printf("Executing command directly (changes will not affect a running server)")
	
	// Load the blocklist for all commands
	if err := loadBlockList(); err != nil {
		log.Printf("Warning: Failed to load blocklist: %v", err)
	}
	
	// Execute the command directly
	switch command {
	case BlockCommand:
		// Check if already blocked before setting up firewall
		isBlocked, err := isIPBlocked(target)
		if err != nil {
			return err
		}
		if isBlocked {
			fmt.Printf("%s is already blocked\n", target)
			return nil
		}
		
		// Now set up firewall and block
		if err := setupFirewallTable(); err != nil {
			return fmt.Errorf("failed to set up firewall table: %v", err)
		}
		return clientBlockIP(target)
		
	case UnblockCommand:
		// Check if already unblocked before setting up firewall
		isBlocked, err := isIPBlocked(target)
		if err != nil {
			return err
		}
		if !isBlocked {
			fmt.Printf("%s is not blocked\n", target)
			return nil
		}
		
		// Now set up firewall and unblock
		if err := setupFirewallTable(); err != nil {
			return fmt.Errorf("failed to set up firewall table: %v", err)
		}
		return clientUnblockIP(target)
		
	case CheckCommand:
		// No need to set up firewall for check
		return clientCheckIP(target)
		
	case ListCommand:
		// No need to set up firewall for list
		return clientListBlocked()
	}
	
	return nil
}

// clientBlockIP manually blocks an IP or subnet
func clientBlockIP(target string) error {
	// Check if it's already blocked
	isBlocked, err := isIPBlocked(target)
	if err != nil {
		return err
	}
	
	if isBlocked {
		fmt.Printf("%s is already blocked\n", target)
		return nil
	}
	
	// Determine if it's an IP or subnet
	if strings.Contains(target, "/") {
		// It's a subnet
		mu.Lock()
		blockedSubnets[target] = struct{}{}
		mu.Unlock()
		
		if err := addBlockRule(target); err != nil {
			return fmt.Errorf("failed to block subnet %s: %v", target, err)
		}
		
		fmt.Printf("Blocked subnet: %s\n", target)
	} else {
		// It's an IP
		mu.Lock()
		blockedIPs[target] = struct{}{}
		mu.Unlock()
		
		if err := addBlockRule(target); err != nil {
			return fmt.Errorf("failed to block IP %s: %v", target, err)
		}
		
		fmt.Printf("Blocked IP: %s\n", target)
	}
	
	// Save the blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking %s: %v", target, err)
	}
	
	return nil
}

// clientUnblockIP manually unblocks an IP or subnet
func clientUnblockIP(target string) error {
	// Check if it's blocked
	isBlocked, err := isIPBlocked(target)
	if err != nil {
		return err
	}
	
	if !isBlocked {
		fmt.Printf("%s is not blocked\n", target)
		return nil
	}
	
	// Remove from blocklist
	mu.Lock()
	if strings.Contains(target, "/") {
		delete(blockedSubnets, target)
	} else {
		delete(blockedIPs, target)
	}
	mu.Unlock()
	
	// Remove from firewall
	if err := removeBlockRule(target); err != nil {
		return fmt.Errorf("failed to unblock %s: %v", target, err)
	}
	
	fmt.Printf("Unblocked: %s\n", target)
	
	// Save the blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after unblocking %s: %v", target, err)
	}
	
	return nil
}

// clientCheckIP checks if an IP or subnet is blocked
func clientCheckIP(target string) error {
	isBlocked, err := isIPBlocked(target)
	if err != nil {
		return err
	}
	
	if isBlocked {
		fmt.Printf("%s is blocked\n", target)
	} else {
		fmt.Printf("%s is not blocked\n", target)
	}
	
	return nil
}

// clientListBlocked lists all blocked IPs and subnets
func clientListBlocked() error {
	mu.Lock()
	defer mu.Unlock()
	
	if len(blockedIPs) == 0 && len(blockedSubnets) == 0 {
		fmt.Println("No IPs or subnets are currently blocked")
		return nil
	}
	
	fmt.Println("Blocked IPs and subnets:")
	
	// Print blocked IPs
	for ip := range blockedIPs {
		fmt.Printf("IP: %s\n", ip)
	}
	
	// Print blocked subnets
	for subnet := range blockedSubnets {
		fmt.Printf("Subnet: %s\n", subnet)
	}
	
	return nil
}

// isIPBlocked checks if an IP or subnet is blocked
func isIPBlocked(target string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()
	
	// Check if it's a subnet
	if strings.Contains(target, "/") {
		_, exists := blockedSubnets[target]
		return exists, nil
	}
	
	// Check if it's an IP
	if _, exists := blockedIPs[target]; exists {
		return true, nil
	}
	
	// Check if the IP is in a blocked subnet
	ip := net.ParseIP(target)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", target)
	}
	
	for subnet := range blockedSubnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			continue
		}
		
		if ipNet.Contains(ip) {
			return true, nil
		}
	}
	
	return false, nil
}

// isValidIPOrCIDR validates an IP address or CIDR range
func isValidIPOrCIDR(target string) bool {
	// Check if it's a CIDR range
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		return err == nil
	}
	
	// Check if it's an IP address
	ip := net.ParseIP(target)
	return ip != nil
}