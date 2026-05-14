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
	DebugCommand   ClientCommand = "debug"
)

// clientBlockIP manually blocks an IP or subnet
func clientBlockIP(target string) error {
	// Check if it's already blocked
	isBlocked, subnet, err := isIPBlocked(target)
	if err != nil {
		return err
	}

	if isBlocked {
		if subnet != "" {
			fmt.Printf("%s is already blocked (contained in subnet %s)\n", target, subnet)
		} else {
			fmt.Printf("%s is already blocked\n", target)
		}
		return nil
	}

	// Determine if it's an IP or subnet
	if strings.Contains(target, "/") {
		// It's a subnet
		mu.Lock()
		blockedSubnets[target] = struct{}{}
		mu.Unlock()

		// Use fwManager method
		var addErr error
		if challengeEnable {
			addErr = fwManager.AddRedirectRule(target)
		} else {
			addErr = fwManager.AddBlockRule(target)
		}
		if addErr != nil {
			return fmt.Errorf("failed to add firewall rule for subnet %s: %v", target, addErr)
		}

		fmt.Printf("Blocked subnet: %s\n", target)
	} else {
		// It's an IP
		mu.Lock()
		blockedIPs[target] = struct{}{}
		mu.Unlock()

		// Use fwManager method
		var addErr error
		if challengeEnable {
			addErr = fwManager.AddRedirectRule(target)
		} else {
			addErr = fwManager.AddBlockRule(target)
		}
		if addErr != nil {
			return fmt.Errorf("failed to add firewall rule for IP %s: %v", target, addErr)
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
	isBlocked, _, err := isIPBlocked(target)
	if err != nil {
		return err
	}

	if !isBlocked {
		fmt.Printf("%s is not blocked\n", target)
		return nil
	}

	// Remove from blocklist and access log
	mu.Lock()
	if strings.Contains(target, "/") {
		delete(blockedSubnets, target)
		delete(subnetBlockedIPs, target)
		_, subnet, err := net.ParseCIDR(target)
		if err == nil {
			for ip := range ipAccessLog {
				if parsedIP := net.ParseIP(ip); parsedIP != nil && subnet.Contains(parsedIP) {
					delete(ipAccessLog, ip)
					if debug {
						log.Printf("Removed access log entry for IP %s (in unblocked subnet %s)", ip, target)
					}
				}
			}
		}
	} else {
		delete(blockedIPs, target)
		// Remove the IP's access log entry so it starts fresh
		if _, exists := ipAccessLog[target]; exists {
			delete(ipAccessLog, target)
			if debug {
				log.Printf("Removed access log entry for unblocked IP %s", target)
			}
		}
	}
	mu.Unlock()

	// Remove from firewall using the manager
	var removeErr error
	if fwManager == nil {
		// Should have been initialized by RunClientMode
		removeErr = fmt.Errorf("firewall manager not initialized in clientUnblockIP")
	} else {
		if challengeEnable {
			removeErr = fwManager.RemoveRedirectRule(target)
		} else {
			removeErr = fwManager.RemoveBlockRule(target)
		}
	}
	if removeErr != nil {
		// Log the error but continue to save the blocklist change
		log.Printf("Warning: Failed to remove firewall rule for %s: %v", target, removeErr)
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
	isBlocked, subnet, err := isIPBlocked(target)
	if err != nil {
		return err
	}

	if isBlocked {
		if subnet != "" {
			fmt.Printf("%s is blocked (contained in subnet %s)\n", target, subnet)
		} else {
			fmt.Printf("%s is blocked\n", target)
		}
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
// Returns: isBlocked, containingSubnet, error
// If the IP is directly blocked, containingSubnet will be empty
// If the IP is blocked because it's in a subnet, containingSubnet will contain that subnet
func isIPBlocked(target string) (bool, string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Check if it's a subnet
	if strings.Contains(target, "/") {
		_, exists := blockedSubnets[target]
		return exists, "", nil
	}

	// Check if it's an IP
	if _, exists := blockedIPs[target]; exists {
		return true, "", nil
	}

	// Check if the IP is in a blocked subnet
	ip := net.ParseIP(target)
	if ip == nil {
		return false, "", fmt.Errorf("invalid IP address: %s", target)
	}

	for subnet := range blockedSubnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			continue
		}

		if ipNet.Contains(ip) {
			return true, subnet, nil
		}
	}

	return false, "", nil
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
