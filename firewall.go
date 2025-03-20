package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// setupFirewallTable creates our custom iptables table and chain if they don't exist
// and sets up the necessary rules to use it for incoming connections
func setupFirewallTable() error {
	// Check if our chain exists
	cmd := exec.Command("iptables", "-t", "filter", "-L", firewallTable)
	if err := cmd.Run(); err != nil {
		// Chain doesn't exist, create it
		log.Printf("Creating custom iptables chain: %s", firewallTable)
		
		// Create the chain and set up rules
		cmds := [][]string{
			// Create the chain
			{"iptables", "-t", "filter", "-N", firewallTable},
			// Set default policy to RETURN (continue processing)
			{"iptables", "-t", "filter", "-A", firewallTable, "-j", "RETURN"},
			// Insert our chain at the beginning of the INPUT chain
			{"iptables", "-t", "filter", "-I", "INPUT", "1", "-j", firewallTable},
		}
		
		for _, cmdArgs := range cmds {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to run %v: %v", cmdArgs, err)
			}
		}
		
		log.Printf("Successfully created and configured iptables chain: %s", firewallTable)
	} else {
		// Chain exists, check if it's in the INPUT chain
		cmd = exec.Command("iptables", "-t", "filter", "-C", "INPUT", "-j", firewallTable)
		if err := cmd.Run(); err != nil {
			// Chain exists but not in INPUT chain, add it
			log.Printf("Adding existing chain %s to INPUT chain", firewallTable)
			cmd = exec.Command("iptables", "-t", "filter", "-I", "INPUT", "1", "-j", firewallTable)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add chain to INPUT: %v", err)
			}
		} else {
			log.Printf("Chain %s is already connected to INPUT chain", firewallTable)
		}
		
		// Flush the chain to start fresh
		if err := flushFirewallTable(); err != nil {
			return fmt.Errorf("failed to flush existing chain: %v", err)
		}
		
		log.Printf("Using existing iptables chain: %s (flushed)", firewallTable)
	}
	
	// Double-check that our chain is properly connected to the INPUT chain
	cmd = exec.Command("iptables", "-t", "filter", "-C", "INPUT", "-j", firewallTable)
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: Chain %s is not properly connected to INPUT chain, attempting to connect", firewallTable)
		cmd = exec.Command("iptables", "-t", "filter", "-I", "INPUT", "1", "-j", firewallTable)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to connect chain to INPUT: %v", err)
		}
		log.Printf("Successfully connected chain %s to INPUT chain", firewallTable)
	}
	
	return nil
}

// flushFirewallTable removes all rules from our custom iptables chain
func flushFirewallTable() error {
	cmd := exec.Command("iptables", "-t", "filter", "-F", firewallTable)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush iptables chain %s: %v", firewallTable, err)
	}
	
	// Re-add the default RETURN rule at the end
	cmd = exec.Command("iptables", "-t", "filter", "-A", firewallTable, "-j", "RETURN")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add default RETURN rule: %v", err)
	}
	
	log.Printf("Flushed iptables chain: %s", firewallTable)
	return nil
}

// addBlockRule adds a block rule for an IP or subnet to our custom chain
func addBlockRule(target string) error {
	cmd := exec.Command("iptables", "-t", "filter", "-I", firewallTable, "1", "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block %s on port 80: %v", target, err)
	}
	
	cmd = exec.Command("iptables", "-t", "filter", "-I", firewallTable, "1", "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block %s on port 443: %v", target, err)
	}
	
	return nil
}

// removeBlockRule removes a block rule for an IP or subnet from our custom chain
func removeBlockRule(target string) error {
	// Remove the rule for port 80
	cmd := exec.Command("iptables", "-t", "filter", "-D", firewallTable, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unblock %s on port 80: %v", target, err)
	}
	
	// Remove the rule for port 443
	cmd = exec.Command("iptables", "-t", "filter", "-D", firewallTable, "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unblock %s on port 443: %v", target, err)
	}
	
	return nil
}

// removePortBlockingRules removes all rules in our custom chain
func removePortBlockingRules() error {
	// Check if our chain exists
	cmd := exec.Command("iptables", "-t", "filter", "-L", firewallTable)
	if err := cmd.Run(); err != nil {
		// Chain doesn't exist, nothing to do
		log.Printf("Chain %s doesn't exist, nothing to remove", firewallTable)
	} else {
		// Chain exists, flush it
		if err := flushFirewallTable(); err != nil {
			log.Printf("Warning: Failed to flush iptables chain: %v", err)
			// Continue anyway
		}
	}
	
	// Clear the blocklist
	mu.Lock()
	blockedIPs = make(map[string]struct{})
	blockedSubnets = make(map[string]struct{})
	mu.Unlock()
	
	// Save the empty blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save empty blocklist: %v", err)
	}
	
	log.Println("Successfully removed all port blocking rules.")
	return nil
}

// blockIP adds an IP to the blocklist and blocks it in the firewall
func blockIP(ip, filePath string, rule string) {
	mu.Lock()
	defer mu.Unlock()
	
	// Check if the IP is already in the blocklist
	if _, exists := blockedIPs[ip]; exists {
		if debug {
			log.Printf("IP %s is already in the blocklist, ensuring firewall rule exists", ip)
		}
		
		// Even if it's already in the blocklist, try to add the rule to ensure it's in the firewall
		if err := addBlockRule(ip); err != nil {
			log.Printf("Failed to ensure block rule for IP %s: %v", ip, err)
		} else if debug {
			log.Printf("Ensured firewall rule exists for IP %s", ip)
		}
		return
	}

	// Add to our blocklist
	blockedIPs[ip] = struct{}{}
	
	// Add the block rule to our custom chain
	if err := addBlockRule(ip); err != nil {
		log.Printf("Failed to block IP %s: %v", ip, err)
		delete(blockedIPs, ip) // Remove from blocklist if we couldn't block it
		return
	}

	// Save the updated blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking IP %s: %v", ip, err)
	}

	log.Printf("Blocked IP %s from file %s for %s", ip, filePath, rule)
}

// blockSubnet adds a subnet to the blocklist and blocks it in the firewall
func blockSubnet(subnet string) {
	mu.Lock()
	defer mu.Unlock()
	
	if _, exists := blockedSubnets[subnet]; exists {
		if debug {
			log.Printf("Subnet %s is already in the blocklist, ensuring firewall rule exists", subnet)
		}
		
		// Even if it's already in the blocklist, try to add the rule to ensure it's in the firewall
		if err := addBlockRule(subnet); err != nil {
			log.Printf("Failed to ensure block rule for subnet %s: %v", subnet, err)
		} else if debug {
			log.Printf("Ensured firewall rule exists for subnet %s", subnet)
		}
		return
	}

	// Add to our blocklist
	blockedSubnets[subnet] = struct{}{}
	
	// Add the block rule to our custom chain
	if err := addBlockRule(subnet); err != nil {
		log.Printf("Failed to block subnet %s: %v", subnet, err)
		delete(blockedSubnets, subnet) // Remove from blocklist if we couldn't block it
		return
	}

	// Remove individual IP rules for this subnet from our custom chain
	for ip := range blockedIPs {
		if strings.HasPrefix(ip, strings.TrimSuffix(subnet, ".0/24")) {
			// Remove from our blocklist
			delete(blockedIPs, ip)
			
			// Remove from the firewall (ignore errors since we're replacing with subnet rule)
			cmd := exec.Command("iptables", "-t", "filter", "-D", firewallTable, "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP")
			cmd.Run()
			cmd = exec.Command("iptables", "-t", "filter", "-D", firewallTable, "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
			cmd.Run()
		}
	}

	// Save the updated blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking subnet %s: %v", subnet, err)
	}

	log.Printf("Blocked subnet %s and removed individual IPs", subnet)
}

// applyBlockList applies the current blocklist to the firewall
func applyBlockList() error {
	mu.Lock()
	defer mu.Unlock()
	
	// Apply IP blocks
	for ip := range blockedIPs {
		if err := addBlockRule(ip); err != nil {
			log.Printf("Failed to block IP %s: %v", ip, err)
		}
	}
	
	// Apply subnet blocks
	for subnet := range blockedSubnets {
		if err := addBlockRule(subnet); err != nil {
			log.Printf("Failed to block subnet %s: %v", subnet, err)
		}
	}
	
	log.Printf("Applied blocklist to firewall: %d IPs, %d subnets", 
		len(blockedIPs), len(blockedSubnets))
	
	return nil
}