package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// setupFirewallTable creates our custom iptables table and chain if they don't exist
// and sets up the necessary rules to use it for incoming connections
func setupFirewallTable() error {
	// First, check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}

	// Check if we have permission to run iptables
	versionCmd := exec.Command("iptables", "-V")
	output, err := versionCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot run iptables (permission issue?): %v, output: %s", err, string(output))
	}

	if debug {
		log.Printf("Using iptables version: %s", strings.TrimSpace(string(output)))
	}

	// Check if our chain exists (use -n to disable DNS lookups)
	cmd := exec.Command("iptables", "-w", "-t", "filter", "-L", firewallChain, "-n") // Renamed variable
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Chain doesn't exist, create it
		log.Printf("Creating custom iptables chain: %s", firewallChain) // Renamed variable

		// Create the chain and set up rules
		cmds := [][]string{
			// Create the chain
			{"iptables", "-w", "-t", "filter", "-N", firewallChain}, // Renamed variable
			// Set default policy to RETURN (continue processing)
			{"iptables", "-w", "-t", "filter", "-A", firewallChain, "-j", "RETURN"}, // Renamed variable
			// Insert our chain at the beginning of the INPUT chain
			{"iptables", "-w", "-t", "filter", "-I", "INPUT", "1", "-j", firewallChain}, // Renamed variable
		}

		for _, cmdArgs := range cmds {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to run %v: %v, output: %s", cmdArgs, err, string(output))
			}
			if debug {
				log.Printf("Successfully ran command: %v", cmdArgs)
			}
		}

		log.Printf("Successfully created and configured iptables chain: %s", firewallChain) // Renamed variable
	} else {
		// Chain exists, check if it's in the INPUT chain
		cmd = exec.Command("iptables", "-w", "-t", "filter", "-C", "INPUT", "-j", firewallChain) // Renamed variable
		output, err = cmd.CombinedOutput()
		if err != nil {
			// Chain exists but not in INPUT chain, add it
			log.Printf("Adding existing chain %s to INPUT chain", firewallChain)                          // Renamed variable
			cmd = exec.Command("iptables", "-w", "-t", "filter", "-I", "INPUT", "1", "-j", firewallChain) // Renamed variable
			output, err = cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to add chain to INPUT: %v, output: %s", err, string(output))
			}
		} else {
			log.Printf("Chain %s is already connected to INPUT chain", firewallChain) // Renamed variable
		}

		// Flush the chain to start fresh
		if err := flushFirewallTable(); err != nil {
			return fmt.Errorf("failed to flush existing chain: %v", err)
		}

		log.Printf("Using existing iptables chain: %s (flushed)", firewallChain) // Renamed variable
	}

	// Double-check that our chain is properly connected to the INPUT chain
	cmd = exec.Command("iptables", "-w", "-t", "filter", "-C", "INPUT", "-j", firewallChain) // Renamed variable
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Warning: Chain %s is not properly connected to INPUT chain, attempting to connect", firewallChain) // Renamed variable
		cmd = exec.Command("iptables", "-w", "-t", "filter", "-I", "INPUT", "1", "-j", firewallChain)                  // Renamed variable
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to connect chain to INPUT: %v, output: %s", err, string(output))
		}
		log.Printf("Successfully connected chain %s to INPUT chain", firewallChain) // Renamed variable
	}

	return nil
}

// flushFirewallTable removes all rules from our custom iptables chain
func flushFirewallTable() error {
	// First, check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}

	// Check if our chain exists before trying to flush it
	chainCheckCmd := exec.Command("iptables", "-w", "-t", "filter", "-L", firewallChain, "-n") // Renamed variable
	if err := chainCheckCmd.Run(); err != nil {
		// Chain doesn't exist, nothing to flush
		log.Printf("Chain %s doesn't exist, nothing to flush", firewallChain) // Renamed variable
		return nil
	}

	// Flush the chain
	cmd := exec.Command("iptables", "-w", "-t", "filter", "-F", firewallChain) // Renamed variable
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to flush iptables chain %s: %v, output: %s", firewallChain, err, string(output)) // Renamed variable
	}

	// Re-add the default RETURN rule at the end
	cmd = exec.Command("iptables", "-w", "-t", "filter", "-A", firewallChain, "-j", "RETURN") // Renamed variable
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Warning: Failed to add default RETURN rule: %v, output: %s", err, string(output))
		// Try an alternative approach
		cmd = exec.Command("iptables", "-w", "-t", "filter", "-I", firewallChain, "-j", "RETURN") // Renamed variable
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to add default RETURN rule (alternative method): %v, output: %s", err, string(output))
		}
	}

	log.Printf("Flushed iptables chain: %s", firewallChain) // Renamed variable
	return nil
}

// addBlockRule adds a block rule for an IP or subnet to our custom chain
// This improved version checks if the rule already exists before adding it
// and includes fallback mechanisms for different iptables versions
func addBlockRule(target string) error {
	// NOTE: Redundant internal blocklist check removed here to prevent deadlock
	// when called from applyBlockList, which already holds the mutex.
	// The primary check should happen in the calling function (e.g., blockIP).

	// First, check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}

	// Check if our chain exists before trying to add rules
	chainCheckCmd := exec.Command("iptables", "-w", "-t", "filter", "-L", firewallChain, "-n") // Renamed variable
	if err := chainCheckCmd.Run(); err != nil {
		// Try to create the chain if it doesn't exist
		if err := setupFirewallTable(); err != nil { // This function internally uses firewallChain now
			return fmt.Errorf("failed to set up firewall table: %v", err)
		}
	}

	// --- Delete-then-Insert approach for Port 80 ---
	// 1. Delete the rule (ignore error if it doesn't exist)
	deleteArgs80 := []string{"-w", "-t", "filter", "-D", firewallChain, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP"}
	cmd := exec.Command("iptables", deleteArgs80...)
	if debug {
		log.Printf("Attempting delete before insert: iptables %v", deleteArgs80)
	}
	cmd.Run() // Ignore error, rule might not exist

	// 2. Insert the rule at the top
	insertArgs80 := []string{"-w", "-t", "filter", "-I", firewallChain, "1", "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP"}
	cmd = exec.Command("iptables", insertArgs80...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If insert fails after delete attempt, it's a real error
		log.Printf("Failed to insert block rule for %s port 80: %v, output: %s", target, err, string(output))
		// Continue to try port 443, but report error later
	} else if debug {
		log.Printf("Ensured block rule exists for %s on port 80", target)
	}
	err80 := err // Store potential error

	// --- Delete-then-Insert approach for Port 443 ---
	// 1. Delete the rule (ignore error if it doesn't exist)
	deleteArgs443 := []string{"-w", "-t", "filter", "-D", firewallChain, "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP"}
	cmd = exec.Command("iptables", deleteArgs443...)
	if debug {
		log.Printf("Attempting delete before insert: iptables %v", deleteArgs443)
	}
	cmd.Run() // Ignore error

	// 2. Insert the rule at the top
	insertArgs443 := []string{"-w", "-t", "filter", "-I", firewallChain, "1", "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP"}
	cmd = exec.Command("iptables", insertArgs443...)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// If insert fails after delete attempt, it's a real error
		log.Printf("Failed to insert block rule for %s port 443: %v, output: %s", target, err, string(output))
	} else if debug {
		log.Printf("Ensured block rule exists for %s on port 443", target)
	}
	err443 := err // Store potential error

	// Return first error encountered, if any
	if err80 != nil {
		return fmt.Errorf("failed to ensure block rule for port 80: %w", err80)
	}
	if err443 != nil {
		return fmt.Errorf("failed to ensure block rule for port 443: %w", err443)
	}

	return nil
}

// addRedirectRule adds an iptables rule to redirect traffic from the target IP to the challenge port
func addRedirectRule(target string) error {
	// NOTE: Redundant internal blocklist check removed here to prevent deadlock
	// when called from applyBlockList, which already holds the mutex.
	// The primary check should happen in the calling function (e.g., blockIP).

	if firewallType != "iptables" {
		return fmt.Errorf("redirect rules currently only supported for iptables firewallType")
	}
	// First, check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}

	challengeHTTPSPortStr := fmt.Sprintf("%d", challengePort)    // Port for HTTPS challenge server
	challengeHTTPPortStr := fmt.Sprintf("%d", challengeHTTPPort) // Port for HTTP redirector

	// Define the rule specifications for adding (using -I for insert at top)
	// Port 80 traffic redirects to the HTTP redirector port
	// Port 443 traffic redirects to the HTTPS challenge port
	addRuleSpecs := [][]string{ // Use distinct name for add specs
		// Port 80 rule spec for adding -> Redirect to HTTP Port
		{"-w", "-t", "nat", "-I", "PREROUTING", "1", "-s", target, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", challengeHTTPPortStr},
		// Port 443 rule spec for adding -> Redirect to HTTPS Port
		{"-w", "-t", "nat", "-I", "PREROUTING", "1", "-s", target, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", challengeHTTPSPortStr},
	}

	var firstErr error
	rulesAdded := 0

	// Iterate over the specs for adding rules
	for _, addArgs := range addRuleSpecs {
		// Define the core rule spec (used for delete/check) by removing action/position/wait flags
		spec := make([]string, 0, len(addArgs)-3) // Estimate capacity
		for i, arg := range addArgs {
			if i > 0 && addArgs[i-1] == "-I" { // Skip position '1' after '-I'
				continue
			}
			if arg != "-w" && arg != "-I" && arg != "-D" && arg != "-C" { // Exclude action/wait flags
				spec = append(spec, arg)
			}
		}

		// --- Delete-then-Insert approach ---
		// 1. Delete the rule (ignore error if it doesn't exist)
		// Construct delete arguments: -w -D PREROUTING + spec
		deleteArgs := append([]string{"-w", "-D", "PREROUTING"}, spec...)
		cmd := exec.Command("iptables", deleteArgs...)
		if debug {
			log.Printf("Attempting delete before insert: iptables %v", strings.Join(deleteArgs, " "))
		}
		cmd.Run() // Ignore error

		// 2. Insert the rule at the top using the original addArgs (which include -I 1)
		cmd = exec.Command("iptables", addArgs...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Log failure but continue to try adding the other rule
			log.Printf("Failed to insert redirect rule (iptables %v): %v, output: %s", strings.Join(addArgs, " "), err, string(output))
			if firstErr == nil {
				firstErr = err // Store the first error encountered
			}
		} else {
			if debug {
				log.Printf("Ensured redirect rule exists: iptables %v", strings.Join(addArgs, " "))
			}
			rulesAdded++
		}
	}

	if rulesAdded > 0 {
		log.Printf("Ensured redirect rules are present for %s (Port 80 -> %s, Port 443 -> %s)", target, challengeHTTPPortStr, challengeHTTPSPortStr)
	}

	// Return the first error encountered, if any
	if firstErr != nil {
		return fmt.Errorf("failed to ensure redirect rule(s): %w", firstErr)
	}

	return nil
}

// removeRedirectRule removes iptables rules that redirect traffic from the target IP
func removeRedirectRule(target string) error {
	if firewallType != "iptables" {
		return fmt.Errorf("redirect rules currently only supported for iptables firewallType")
	}
	// First, check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}

	challengeHTTPSPortStr := fmt.Sprintf("%d", challengePort)    // Port for HTTPS challenge server
	challengeHTTPPortStr := fmt.Sprintf("%d", challengeHTTPPort) // Port for HTTP redirector

	// Define the rule specifications (without -C or -D)
	// Port 80 traffic redirects to the HTTP redirector port
	// Port 443 traffic redirects to the HTTPS challenge port
	ruleSpecs := [][]string{
		// Port 80 rule spec -> Redirect to HTTP Port
		{"-t", "nat", "-s", target, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", challengeHTTPPortStr},
		// Port 443 rule spec -> Redirect to HTTPS Port
		{"-t", "nat", "-s", target, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", challengeHTTPSPortStr},
	}

	var errors []string
	rulesRemoved := 0

	for _, spec := range ruleSpecs {
		// Check if the rule exists using the exact specification
		// We loop checking and deleting because there might be duplicate rules if something went wrong before.
		for {
			checkArgs := append([]string{"-w", "-C", "PREROUTING"}, spec...)
			checkCmd := exec.Command("iptables", checkArgs...)
			err := checkCmd.Run()

			if err != nil {
				// Rule doesn't exist (or another check error occurred)
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
					// Exit code 1 from -C means rule not found, which is expected after successful deletion or if it never existed.
					if debug && rulesRemoved == 0 { // Only log "not found" if we haven't removed any rule with this spec yet
						log.Printf("Redirect rule spec not found, skipping removal: iptables %v", checkArgs)
					}
				} else {
					// Different error during check
					errMsg := fmt.Sprintf("error checking redirect rule %v: %v", checkArgs, err)
					log.Println(errMsg)
					// errors = append(errors, errMsg) // Optionally report check errors
				}
				break // Stop trying to delete this specific rule spec
			}

			// Rule exists, attempt to delete it
			deleteArgs := append([]string{"-w", "-D", "PREROUTING"}, spec...)
			deleteCmd := exec.Command("iptables", deleteArgs...)
			output, deleteErr := deleteCmd.CombinedOutput()

			if deleteErr != nil {
				errMsg := fmt.Sprintf("failed to remove redirect rule %v: %v, output: %s", deleteArgs, deleteErr, string(output))
				log.Println(errMsg)
				errors = append(errors, errMsg)
				break // Stop trying to delete this spec if an error occurs
			} else {
				if debug {
					log.Printf("Successfully removed redirect rule instance: %v", deleteArgs)
				}
				rulesRemoved++
				// Loop again to check if there are more duplicate rules with the same spec
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered errors removing redirect rules for %s: %s", target, strings.Join(errors, "; "))
	}

	if rulesRemoved > 0 {
		log.Printf("Successfully removed %d redirect rule instance(s) for %s", rulesRemoved, target)
	} else {
		if debug {
			log.Printf("No redirect rules found or removed for %s", target)
		}
	}

	return nil // Success if no errors occurred during deletion attempts
}

// removeBlockRule removes a block rule for an IP or subnet from our custom chain
func removeBlockRule(target string) error {
	// First, check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}

	// Check if our chain exists before trying to remove rules
	chainCheckCmd := exec.Command("iptables", "-w", "-t", "filter", "-L", firewallChain, "-n") // Renamed variable
	if err := chainCheckCmd.Run(); err != nil {
		// Chain doesn't exist, nothing to remove
		if debug {
			log.Printf("Chain %s doesn't exist, no rules to remove for %s", firewallChain, target) // Renamed variable
		}
		return nil
	}

	// Check if the rule for port 80 exists before trying to remove it
	checkCmd := exec.Command("iptables", "-w", "-t", "filter", "-C", firewallChain, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP") // Renamed variable
	port80Exists := checkCmd.Run() == nil

	// Remove the rule for port 80 if it exists
	if port80Exists {
		cmd := exec.Command("iptables", "-w", "-t", "filter", "-D", firewallChain, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP") // Renamed variable
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Failed to unblock %s on port 80: %v, output: %s", target, err, string(output))
			// Continue anyway to try to remove the port 443 rule
		} else if debug {
			log.Printf("Removed block rule for %s on port 80", target)
		}
	} else if debug {
		log.Printf("No rule found for %s on port 80", target)
	}

	// Check if the rule for port 443 exists before trying to remove it
	checkCmd = exec.Command("iptables", "-w", "-t", "filter", "-C", firewallChain, "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP") // Renamed variable
	port443Exists := checkCmd.Run() == nil

	// Remove the rule for port 443 if it exists
	if port443Exists {
		cmd := exec.Command("iptables", "-w", "-t", "filter", "-D", firewallChain, "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP") // Renamed variable
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Failed to unblock %s on port 443: %v, output: %s", target, err, string(output))
			// Continue anyway
		} else if debug {
			log.Printf("Removed block rule for %s on port 443", target)
		}
	} else if debug {
		log.Printf("No rule found for %s on port 443", target)
	}

	return nil
}

// removePortBlockingRules removes all rules in our custom chain
func removePortBlockingRules() error {
	// Check if our chain exists (use -n to disable DNS lookups)
	cmd := exec.Command("iptables", "-w", "-t", "filter", "-L", firewallChain, "-n") // Renamed variable
	if err := cmd.Run(); err != nil {
		// Chain doesn't exist, nothing to do
		log.Printf("Chain %s doesn't exist, nothing to remove", firewallChain) // Renamed variable
	} else {
		// Chain exists, flush it
		if err := flushFirewallTable(); err != nil { // This function internally uses firewallChain now
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
	// Check if the IP is already in the blocklist
	alreadyBlocked := false

	mu.Lock()
	if _, exists := blockedIPs[ip]; exists {
		alreadyBlocked = true
	} else {
		// Add to our blocklist
		blockedIPs[ip] = struct{}{}
	}
	mu.Unlock()

	// If the IP is already blocked, we don't need to do anything else
	if alreadyBlocked {
		if debug {
			log.Printf("IP %s is already in the blocklist, skipping", ip)
		}
		return
	}

	// Add the appropriate firewall rule (Block or Redirect)
	var err error
	if challengeEnable {
		err = addRedirectRule(ip)
		if err != nil {
			log.Printf("Failed to add redirect rule for IP %s: %v", ip, err)
		}
	} else {
		err = addBlockRule(ip)
		if err != nil {
			log.Printf("Failed to add block rule for IP %s: %v", ip, err)
		}
	}

	// If adding the rule failed, remove from blocklist and return
	if err != nil {
		mu.Lock()
		delete(blockedIPs, ip)
		mu.Unlock()
		return
	}

	// Save the updated blocklist - don't hold the mutex while doing this
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking IP %s: %v", ip, err)
		// Log more details about the error in debug mode
		if debug {
			log.Printf("Error details: %v", err)
			// Try to check if the directory exists and is writable
			dir := filepath.Dir(blocklistFilePath)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				log.Printf("Directory %s does not exist", dir)
			} else {
				// Try to create a test file to check permissions
				testFile := filepath.Join(dir, "test.txt")
				if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
					log.Printf("Cannot write to directory %s: %v", dir, err)
				} else {
					os.Remove(testFile) // Clean up
					log.Printf("Directory %s is writable", dir)
				}
			}
		}
	} else if debug {
		log.Printf("Successfully saved blocklist to %s", blocklistFilePath)
	}

	// Log the blocking action
	log.Printf("Blocked IP %s from file %s for %s", ip, filePath, rule)
}

// blockSubnet adds a subnet to the blocklist and blocks it in the firewall
func blockSubnet(subnet string) {
	// Check if the subnet is already in the blocklist
	alreadyBlocked := false

	mu.Lock()
	if _, exists := blockedSubnets[subnet]; exists {
		alreadyBlocked = true
	} else {
		// Add to our blocklist
		blockedSubnets[subnet] = struct{}{}
	}

	// If this is a new subnet block, identify IPs to remove
	ipsToRemove := make([]string, 0)
	if !alreadyBlocked {
		for ip := range blockedIPs {
			if strings.HasPrefix(ip, strings.TrimSuffix(subnet, ".0/24")) {
				ipsToRemove = append(ipsToRemove, ip)
			}
		}
	}
	mu.Unlock()

	// If the subnet is already blocked, we don't need to do anything else
	if alreadyBlocked {
		if debug {
			log.Printf("Subnet %s is already in the blocklist, skipping", subnet)
		}
		return
	}

	// Add the appropriate firewall rule (Block or Redirect)
	var err error
	if challengeEnable {
		err = addRedirectRule(subnet)
		if err != nil {
			log.Printf("Failed to add redirect rule for subnet %s: %v", subnet, err)
		}
	} else {
		err = addBlockRule(subnet)
		if err != nil {
			log.Printf("Failed to add block rule for subnet %s: %v", subnet, err)
		}
	}

	// If adding the rule failed, remove from blocklist and return
	if err != nil {
		mu.Lock()
		delete(blockedSubnets, subnet)
		mu.Unlock()
		return
	}

	// If this is a new subnet block, remove individual IP rules for this subnet
	if len(ipsToRemove) > 0 {
		mu.Lock()
		// Remove IPs from our blocklist
		for _, ip := range ipsToRemove {
			delete(blockedIPs, ip)
		}
		mu.Unlock()

		// Remove from the firewall (ignore errors since we're replacing with subnet rule)
		for _, ip := range ipsToRemove {
			removeBlockRule(ip)
		}
	}

	// Save the updated blocklist - don't hold the mutex while doing this
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking subnet %s: %v", subnet, err)
		// Log more details about the error in debug mode
		if debug {
			log.Printf("Error details: %v", err)
			// Try to check if the directory exists and is writable
			dir := filepath.Dir(blocklistFilePath)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				log.Printf("Directory %s does not exist", dir)
			} else {
				// Try to create a test file to check permissions
				testFile := filepath.Join(dir, "test.txt")
				if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
					log.Printf("Cannot write to directory %s: %v", dir, err)
				} else {
					os.Remove(testFile) // Clean up
					log.Printf("Directory %s is writable", dir)
				}
			}
		}
	} else if debug {
		log.Printf("Successfully saved blocklist to %s", blocklistFilePath)
	}

	// Log the blocking action
	log.Printf("Blocked subnet %s and removed %d individual IPs", subnet, len(ipsToRemove))
}

// applyBlockList applies the current blocklist to the firewall
func applyBlockList() error {
	mu.Lock()
	defer mu.Unlock()

	// Apply IP blocks/redirects
	for ip := range blockedIPs {
		var err error
		if challengeEnable {
			err = addRedirectRule(ip)
			if err != nil {
				log.Printf("Failed to apply redirect rule for IP %s: %v", ip, err)
			}
		} else {
			err = addBlockRule(ip)
			if err != nil {
				log.Printf("Failed to apply block rule for IP %s: %v", ip, err)
			}
		}
	}

	// Apply subnet blocks/redirects
	for subnet := range blockedSubnets {
		var err error
		if challengeEnable {
			err = addRedirectRule(subnet)
			if err != nil {
				log.Printf("Failed to apply redirect rule for subnet %s: %v", subnet, err)
			}
		} else {
			err = addBlockRule(subnet)
			if err != nil {
				log.Printf("Failed to apply block rule for subnet %s: %v", subnet, err)
			}
		}
	}

	action := "block rules"
	if challengeEnable {
		action = "redirect rules"
	}
	log.Printf("Applied %s to firewall: %d IPs, %d subnets",
		action, len(blockedIPs), len(blockedSubnets))

	return nil
}
