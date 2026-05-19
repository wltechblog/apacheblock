package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// --- Firewall Manager Interface ---

// FirewallManager defines the interface for interacting with different firewall backends.
type FirewallManager interface {
	Setup() error                                   // Ensure necessary chains/tables exist.
	AddBlockRule(target string) error               // Add a rule to block traffic (DROP).
	RemoveBlockRule(target string) error            // Remove a blocking rule.
	AddRedirectRule(target string) error            // Add a rule to redirect traffic (for challenge).
	RemoveRedirectRule(target string) error         // Remove a redirect rule.
	Flush() error                                   // Flush all rules added by this tool.
	IsRulePresent(checkArgs []string) (bool, error) // Check if a specific rule exists.
}

// Global instance of the firewall manager
var (
	fwManager FirewallManager
	fwOnce    sync.Once // To initialize the manager only once
)

// InitFirewallManager selects and initializes the appropriate firewall manager based on config.
func InitFirewallManager() error {
	var initErr error
	fwOnce.Do(func() {
		log.Printf("Initializing Firewall Manager (Type: %s)...", firewallType)
		switch firewallType {
		case "iptables":
			fwManager = &IPTablesManager{chainName: firewallChain}
			initErr = fwManager.Setup()
		case "nftables":
			// Define table name (e.g., "inet apacheblock") and chain names
			tableName := "inet apacheblock" // Includes family
			filterChainName := firewallChain
			natChainName := firewallChain + "_nat"
			fwManager = &NFTablesManager{tableName: tableName, filterChain: filterChainName, natChain: natChainName}
			initErr = fwManager.Setup()
		default:
			initErr = fmt.Errorf("unsupported firewallType: %s", firewallType)
		}
		if initErr != nil {
			log.Printf("Firewall Manager initialization failed: %v", initErr)
		} else {
			log.Printf("Firewall Manager initialized successfully.")
		}
	})
	return initErr
}

// --- IPTables Implementation ---

// IPTablesManager implements FirewallManager using iptables commands.
type IPTablesManager struct {
	chainName string
}

// Setup ensures the iptables chain exists and is linked.
func (m *IPTablesManager) Setup() error {
	log.Println("Setting up iptables...")
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables command not found: %v", err)
	}
	versionCmd := exec.Command("iptables", "-V")
	output, err := versionCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot run iptables (permission issue?): %v, output: %s", err, string(output))
	}
	if debug {
		log.Printf("Using iptables version: %s", strings.TrimSpace(string(output)))
	}

	cmd := exec.Command("iptables", "-w", "-t", "filter", "-L", m.chainName, "-n")
	output, err = cmd.CombinedOutput()
	chainExists := err == nil

	if !chainExists {
		log.Printf("Creating custom iptables chain: %s", m.chainName)
		cmd = exec.Command("iptables", "-w", "-t", "filter", "-N", m.chainName)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to create chain %s: %v, output: %s", m.chainName, err, string(output))
		}
	}

	checkLinkCmd := exec.Command("iptables", "-w", "-t", "filter", "-C", "INPUT", "-j", m.chainName)
	if err := checkLinkCmd.Run(); err != nil {
		log.Printf("Linking chain %s to INPUT chain", m.chainName)
		insertLinkCmd := exec.Command("iptables", "-w", "-t", "filter", "-I", "INPUT", "1", "-j", m.chainName)
		output, err = insertLinkCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to link chain %s to INPUT: %v, output: %s", m.chainName, err, string(output))
		}
	} else {
		log.Printf("Chain %s is already linked to INPUT chain", m.chainName)
	}

	if chainExists {
		if err := m.Flush(); err != nil {
			if !strings.Contains(err.Error(), "doesn't exist") {
				return fmt.Errorf("failed to flush existing chain %s: %v", m.chainName, err)
			}
		} else {
			log.Printf("Using existing iptables chain: %s (flushed)", m.chainName)
		}
	} else {
		log.Printf("Successfully created and configured iptables chain: %s", m.chainName)
	}
	return nil
}

// Flush removes all rules added by this tool from the filter chain and NAT table.
func (m *IPTablesManager) Flush() error {
	// Flush the filter chain
	log.Printf("Flushing iptables filter chain: %s", m.chainName)
	cmd := exec.Command("iptables", "-w", "-t", "filter", "-F", m.chainName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No chain/target/match by that name") {
			log.Printf("Chain %s doesn't exist, nothing to flush.", m.chainName)
		} else {
			log.Printf("Warning: Failed to flush iptables filter chain %s: %v, output: %s", m.chainName, err, string(output))
			// Continue to try NAT cleanup
		}
	} else {
		log.Printf("Flushed filter chain: %s", m.chainName)
	}

	// Clean up NAT table redirect rules in PREROUTING chain
	log.Printf("Cleaning up NAT redirect rules in PREROUTING chain")

	// Clean up port 80 redirects
	cleanedCount80 := 0
	for {
		// Find and remove any redirects to our HTTP challenge port
		checkArgs := []string{"-w", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", challengeHTTPPort)}
		cmd := exec.Command("iptables", checkArgs...)
		checkErr := cmd.Run()

		if checkErr != nil {
			// No more matching rules
			break
		}

		// Rule exists, delete it
		deleteArgs := []string{"-w", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", challengeHTTPPort)}
		deleteCmd := exec.Command("iptables", deleteArgs...)
		deleteErr := deleteCmd.Run()

		if deleteErr != nil {
			log.Printf("Warning: Failed to delete NAT redirect rule for port 80: %v", deleteErr)
			break
		}

		cleanedCount80++
	}

	// Clean up port 443 redirects
	cleanedCount443 := 0
	for {
		// Find and remove any redirects to our HTTPS challenge port
		checkArgs := []string{"-w", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", challengePort)}
		cmd := exec.Command("iptables", checkArgs...)
		checkErr := cmd.Run()

		if checkErr != nil {
			// No more matching rules
			break
		}

		// Rule exists, delete it
		deleteArgs := []string{"-w", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", challengePort)}
		deleteCmd := exec.Command("iptables", deleteArgs...)
		deleteErr := deleteCmd.Run()

		if deleteErr != nil {
			log.Printf("Warning: Failed to delete NAT redirect rule for port 443: %v", deleteErr)
			break
		}

		cleanedCount443++
	}

	if cleanedCount80 > 0 || cleanedCount443 > 0 {
		log.Printf("Cleaned up NAT redirect rules: %d for port 80, %d for port 443", cleanedCount80, cleanedCount443)
	}

	return nil
}

// IsRulePresent checks if a specific iptables rule exists.
func (m *IPTablesManager) IsRulePresent(checkArgs []string) (bool, error) {
	fullArgs := append([]string{"-w"}, checkArgs...)
	cmd := exec.Command("iptables", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("error checking iptables rule %v: %v, output: %s", checkArgs, err, string(output))
}

// AddBlockRule adds a standard DROP rule using delete-then-insert.
func (m *IPTablesManager) AddBlockRule(target string) error {
	deleteArgs80 := []string{"-w", "-t", "filter", "-D", m.chainName, "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP"}
	exec.Command("iptables", deleteArgs80...).Run() // Ignore error
	insertArgs80 := []string{"-w", "-t", "filter", "-I", m.chainName, "1", "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP"}
	_, err80 := exec.Command("iptables", insertArgs80...).CombinedOutput()
	// Log errors unconditionally
	if err80 != nil {
		log.Printf("Failed to insert block rule for %s port 80: %v", target, err80)
	} else if debug { // Log success only in debug
		log.Printf("Ensured block rule exists for %s on port 80", target)
	}

	deleteArgs443 := []string{"-w", "-t", "filter", "-D", m.chainName, "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP"}
	exec.Command("iptables", deleteArgs443...).Run() // Ignore error
	insertArgs443 := []string{"-w", "-t", "filter", "-I", m.chainName, "1", "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP"}
	_, err443 := exec.Command("iptables", insertArgs443...).CombinedOutput()
	// Log errors unconditionally
	if err443 != nil {
		log.Printf("Failed to insert block rule for %s port 443: %v", target, err443)
	} else if debug { // Log success only in debug
		log.Printf("Ensured block rule exists for %s on port 443", target)
	}

	if err80 != nil {
		return fmt.Errorf("port 80 block failed: %w", err80)
	}
	if err443 != nil {
		return fmt.Errorf("port 443 block failed: %w", err443)
	}
	return nil
}

// RemoveBlockRule removes a standard DROP rule.
func (m *IPTablesManager) RemoveBlockRule(target string) error {
	var errors []string
	ruleSpecs := [][]string{
		{"-t", "filter", "-s", target, "-p", "tcp", "--dport", "80", "-j", "DROP"},
		{"-t", "filter", "-s", target, "-p", "tcp", "--dport", "443", "-j", "DROP"},
	}
	rulesRemoved := 0
	for _, spec := range ruleSpecs {
		for {
			deleteArgs := append([]string{"-w", "-D", m.chainName}, spec...)
			cmd := exec.Command("iptables", deleteArgs...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
					break
				}
				errMsg := fmt.Sprintf("failed to remove block rule %v: %v", deleteArgs, err)
				log.Println(errMsg)
				errors = append(errors, errMsg)
				break
			}
			if debug { // Log success only in debug
				log.Printf("Successfully removed block rule instance: %v", deleteArgs)
			}
			rulesRemoved++
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("errors removing block rules for %s: %s", target, strings.Join(errors, "; "))
	}
	if rulesRemoved > 0 {
		log.Printf("Successfully removed %d block rule instance(s) for %s", rulesRemoved, target)
	}
	return nil
}

// AddRedirectRule adds NAT redirect rules using delete-then-insert.
func (m *IPTablesManager) AddRedirectRule(target string) error {
	challengeHTTPSPortStr := fmt.Sprintf("%d", challengePort)
	challengeHTTPPortStr := fmt.Sprintf("%d", challengeHTTPPort)
	addRuleSpecs := [][]string{
		{"-w", "-t", "nat", "-I", "PREROUTING", "1", "-s", target, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", challengeHTTPPortStr},
		{"-w", "-t", "nat", "-I", "PREROUTING", "1", "-s", target, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", challengeHTTPSPortStr},
	}
	var firstErr error
	rulesAdded := 0
	for _, addArgs := range addRuleSpecs {
		spec := make([]string, 0, len(addArgs)-3)
		for i, arg := range addArgs {
			if i > 0 && addArgs[i-1] == "-I" {
				continue
			}
			if arg != "-w" && arg != "-I" {
				spec = append(spec, arg)
			}
		}
		deleteArgs := append([]string{"-w", "-D", "PREROUTING"}, spec...)
		exec.Command("iptables", deleteArgs...).Run() // Ignore error
		cmdIns := exec.Command("iptables", addArgs...)
		_, err := cmdIns.CombinedOutput()
		if err != nil {
			log.Printf("Failed to insert redirect rule (iptables %v): %v", strings.Join(addArgs, " "), err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			if debug { // Log success only in debug
				log.Printf("Ensured redirect rule exists: iptables %v", strings.Join(addArgs, " "))
			}
			rulesAdded++
		}
	}
	if rulesAdded > 0 {
		log.Printf("Ensured redirect rules are present for %s (Port 80 -> %s, Port 443 -> %s)", target, challengeHTTPPortStr, challengeHTTPSPortStr)
	}
	if firstErr != nil {
		return fmt.Errorf("failed to ensure redirect rule(s): %w", firstErr)
	}
	return nil
}

// RemoveRedirectRule removes NAT redirect rules.
func (m *IPTablesManager) RemoveRedirectRule(target string) error {
	challengeHTTPSPortStr := fmt.Sprintf("%d", challengePort)
	challengeHTTPPortStr := fmt.Sprintf("%d", challengeHTTPPort)
	ruleSpecs := [][]string{
		{"-t", "nat", "-s", target, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", challengeHTTPPortStr},
		{"-t", "nat", "-s", target, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", challengeHTTPSPortStr},
	}
	var errors []string
	rulesRemoved := 0
	for _, spec := range ruleSpecs {
		for {
			deleteArgs := append([]string{"-w", "-D", "PREROUTING"}, spec...)
			cmd := exec.Command("iptables", deleteArgs...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
					if debug && rulesRemoved == 0 {
						log.Printf("Redirect rule spec not found: iptables %v", deleteArgs)
					}
					break
				}
				errMsg := fmt.Sprintf("failed to remove redirect rule %v: %v", deleteArgs, err)
				log.Println(errMsg)
				errors = append(errors, errMsg)
				break
			}
			if debug { // Log success only in debug
				log.Printf("Successfully removed redirect rule instance: %v", deleteArgs)
			}
			rulesRemoved++
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("errors removing redirect rules for %s: %s", target, strings.Join(errors, "; "))
	}
	if rulesRemoved > 0 {
		log.Printf("Successfully removed %d redirect rule instance(s) for %s", rulesRemoved, target)
	}
	return nil
}

// --- NFTables Implementation ---

// NFTablesManager implements FirewallManager using nft commands.
type NFTablesManager struct {
	tableName   string // e.g., "inet apacheblock"
	filterChain string // e.g., "apacheblock_filter"
	natChain    string // e.g., "apacheblock_nat" (nft uses prerouting hook in nat table)
}

// runNFTCommand executes an nft command and returns its output.
func (m *NFTablesManager) runNFTCommand(args ...string) ([]byte, error) {
	cmd := exec.Command("nft", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Include output in error message for better debugging
		return output, fmt.Errorf("nft command failed (%v): %v, output: %s", args, err, string(output))
	}
	// Only log success in debug mode
	if debug {
		log.Printf("Successfully ran nft command: %v", args)
	}
	return output, nil
}

// Setup creates the necessary nftables table and chains.
func (m *NFTablesManager) Setup() error {
	log.Println("Setting up nftables...")
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft command not found: %v", err)
	}

	// Check permissions
	permCheckCmd := exec.Command("nft", "list", "tables")
	_, err := permCheckCmd.CombinedOutput()
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "Operation not permitted") {
			return fmt.Errorf("cannot run nft (permission issue?): %v", err)
		}
		log.Printf("Warning: nft permission check failed, proceeding cautiously: %v", err)
	}

	// Use a single transaction for setup
	// Assumes tableName is like "inet familyname"
	_, tableNameOnly := m.parseTableName() // Use blank identifier for unused family
	if tableNameOnly == "" {
		return fmt.Errorf("invalid nftables table name format: %s", m.tableName)
	}
	natTableName := "ip " + tableNameOnly // NAT table is typically ip family

	nftCommands := fmt.Sprintf(`
        add table %s;
        add chain %s %s { type filter hook input priority filter; policy accept; };
        add table %s;
        add chain %s %s { type nat hook prerouting priority dstnat; policy accept; };
    `, m.tableName, m.tableName, m.filterChain, natTableName, natTableName, m.natChain)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftCommands)
	output, err := cmd.CombinedOutput()

	// Ignore errors indicating components already exist
	if err != nil && !strings.Contains(string(output), "File exists") && !strings.Contains(string(output), "Object exists") {
		return fmt.Errorf("nftables setup transaction failed: %v, output: %s", err, string(output))
	}

	log.Println("NFTables setup complete (errors ignored if components already exist).")
	return nil
}

// Flush removes rules from our specific chains.
func (m *NFTablesManager) Flush() error {
	_, tableNameOnly := m.parseTableName() // Use blank identifier for unused family
	if tableNameOnly == "" {
		return fmt.Errorf("invalid nftables table name format: %s", m.tableName)
	}
	natTableName := "ip " + tableNameOnly

	log.Printf("Flushing nftables chains: %s/%s and %s/%s", m.tableName, m.filterChain, natTableName, m.natChain)
	// Flush filter chain
	_, errFilter := m.runNFTCommand("flush", "chain", m.tableName, m.filterChain)
	if errFilter != nil && !strings.Contains(errFilter.Error(), "No such file or directory") {
		log.Printf("Warning: Failed to flush nft filter chain: %v", errFilter)
	}
	// Flush nat chain
	_, errNat := m.runNFTCommand("flush", "chain", natTableName, m.natChain)
	if errNat != nil && !strings.Contains(errNat.Error(), "No such file or directory") {
		log.Printf("Warning: Failed to flush nft nat chain: %v", errNat)
	}

	if errFilter != nil && !strings.Contains(errFilter.Error(), "No such file or directory") {
		return errFilter
	}
	if errNat != nil && !strings.Contains(errNat.Error(), "No such file or directory") {
		return errNat
	}
	return nil
}

// IsRulePresent is complex in nftables as it requires listing and parsing. Placeholder.
func (m *NFTablesManager) IsRulePresent(checkArgs []string) (bool, error) {
	// checkArgs are iptables-style args; for nftables we do a best-effort check
	// by listing rules in our chains and searching for the target IP/subnet
	var target string
	for i, arg := range checkArgs {
		if arg == "-s" && i+1 < len(checkArgs) {
			target = checkArgs[i+1]
			break
		}
	}
	if target == "" {
		return false, nil
	}

	output, err := m.runNFTCommand("list", "ruleset")
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(output), target), nil
}

// AddBlockRule adds a drop rule to the filter chain.
func (m *NFTablesManager) AddBlockRule(target string) error {
	rule := fmt.Sprintf("add rule %s %s ip saddr %s tcp dport {80, 443} drop", m.tableName, m.filterChain, target)
	_, err := m.runNFTCommand(strings.Split(rule, " ")...)
	if err != nil {
		// Log existence check only in debug
		if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "Object exists") {
			if debug {
				log.Printf("NFTables block rule for %s likely already exists.", target)
			}
			return nil // Treat as success if rule exists
		}
		return fmt.Errorf("failed to add nft block rule for %s: %w", target, err)
	}
	log.Printf("Added nftables block rule for %s", target)
	return nil
}

// RemoveBlockRule removes a drop rule. Requires knowing the rule handle or exact spec. Placeholder.
func (m *NFTablesManager) RemoveBlockRule(target string) error {
	return m.deleteRulesByTarget(m.tableName, m.filterChain, target)
}

// AddRedirectRule adds redirect rules to the nat chain.
func (m *NFTablesManager) AddRedirectRule(target string) error {
	challengeHTTPSPortStr := fmt.Sprintf("%d", challengePort)
	challengeHTTPPortStr := fmt.Sprintf("%d", challengeHTTPPort)
	_, tableNameOnly := m.parseTableName()
	if tableNameOnly == "" {
		return fmt.Errorf("invalid nftables table name format: %s", m.tableName)
	}
	natTableName := "ip " + tableNameOnly

	rules := []string{
		fmt.Sprintf("add rule %s %s ip saddr %s tcp dport 80 redirect to :%s", natTableName, m.natChain, target, challengeHTTPPortStr),
		fmt.Sprintf("add rule %s %s ip saddr %s tcp dport 443 redirect to :%s", natTableName, m.natChain, target, challengeHTTPSPortStr),
	}

	var firstErr error
	for _, rule := range rules {
		_, err := m.runNFTCommand(strings.Split(rule, " ")...)
		if err != nil {
			if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "Object exists") {
				if debug {
					log.Printf("NFTables redirect rule likely already exists: %s", rule)
				}
				continue // Treat as success if rule exists
			}
			log.Printf("Failed to add nft redirect rule (%s): %v", rule, err)
			if firstErr == nil {
				firstErr = err
			}
		} else if debug { // Log success only in debug
			log.Printf("Added nftables redirect rule: %s", rule)
		}
	}
	if firstErr != nil {
		return fmt.Errorf("failed to add nft redirect rule(s) for %s: %w", target, firstErr)
	}
	log.Printf("Ensured nftables redirect rules are present for %s (Port 80 -> %s, Port 443 -> %s)", target, challengeHTTPPortStr, challengeHTTPSPortStr)
	return nil
}

// RemoveRedirectRule removes redirect rules. Requires knowing the rule handle or exact spec. Placeholder.
func (m *NFTablesManager) RemoveRedirectRule(target string) error {
	_, tableNameOnly := m.parseTableName()
	if tableNameOnly == "" {
		return fmt.Errorf("invalid nftables table name format: %s", m.tableName)
	}
	natTableName := "ip " + tableNameOnly
	return m.deleteRulesByTarget(natTableName, m.natChain, target)
}

// parseTableName splits "family name" into parts.
func (m *NFTablesManager) parseTableName() (string, string) {
	parts := strings.Fields(m.tableName)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", "" // Invalid format
}

var nftHandleRe = regexp.MustCompile(`# handle (\d+)`)

func (m *NFTablesManager) deleteRulesByTarget(tableName, chainName, target string) error {
	output, err := m.runNFTCommand("-a", "list", "chain", tableName, chainName)
	if err != nil {
		return fmt.Errorf("failed to list chain %s %s: %w", tableName, chainName, err)
	}

	var handles []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, target) {
			matches := nftHandleRe.FindStringSubmatch(line)
			if len(matches) == 2 {
				handles = append(handles, matches[1])
			}
		}
	}

	if len(handles) == 0 {
		if debug {
			log.Printf("No nft rules found for target %s in %s %s", target, tableName, chainName)
		}
		return nil
	}

	for _, handle := range handles {
		_, err := m.runNFTCommand("delete", "rule", tableName, chainName, "handle", handle)
		if err != nil {
			log.Printf("Warning: failed to delete nft rule handle %s: %v", handle, err)
		} else if debug {
			log.Printf("Deleted nft rule handle %s for target %s", handle, target)
		}
	}

	log.Printf("Removed %d nft rule(s) for %s in %s %s", len(handles), target, tableName, chainName)
	return nil
}

// --- Helper functions previously global, now potentially methods or standalone ---

// removePortBlockingRules uses fwManager.Flush() to clean up all firewall rules and clears internal state
func removePortBlockingRules() error {
	if fwManager == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	// List current rules before cleanup if in debug mode
	if debug {
		log.Println("Firewall rules before cleanup:")
		listFirewallRules()
	}

	// Flush firewall rules using the manager
	if err := fwManager.Flush(); err != nil {
		log.Printf("Warning: Failed to flush firewall rules via manager: %v", err)
		// Continue to clear internal state anyway
	}

	// Clear the internal blocklist state
	mu.Lock()
	blockedIPs = make(map[string]struct{})
	blockedSubnets = make(map[string]struct{})
	mu.Unlock()

	// Save the empty blocklist file
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save empty blocklist: %v", err)
	}

	// List current rules after cleanup if in debug mode
	if debug {
		log.Println("Firewall rules after cleanup:")
		listFirewallRules()
	}

	log.Println("Successfully removed all port blocking rules and cleared internal state.")
	return nil
}

// blockIP adds an IP to the blocklist and blocks it in the firewall
func getBlockInfo(ip string) *BlockInfo {
	blockedIPInfoMu.RLock()
	defer blockedIPInfoMu.RUnlock()
	return blockedIPInfo[ip]
}

func removeBlockInfo(ip string) {
	blockedIPInfoMu.Lock()
	delete(blockedIPInfo, ip)
	blockedIPInfoMu.Unlock()
}

func blockIP(ip, filePath string, rule string, triggeringRequest string, userAgent ...string) {
	if fwManager == nil {
		log.Println("Error: Firewall manager not initialized in blockIP")
		return
	}
	// Check if the IP is already in the blocklist
	alreadyBlocked := false
	mu.Lock()
	if _, exists := blockedIPs[ip]; exists {
		alreadyBlocked = true
	} else {
		blockedIPs[ip] = struct{}{} // Add to internal list first
	}
	mu.Unlock()

	if alreadyBlocked {
		if debug {
			log.Printf("IP %s is already in the blocklist, skipping firewall add", ip)
		}
		return
	}

	// Add the appropriate firewall rule
	var err error
	if challengeEnable {
		err = fwManager.AddRedirectRule(ip)
	} else {
		err = fwManager.AddBlockRule(ip)
	}

	if err != nil {
		log.Printf("Failed to add firewall rule for IP %s: %v", ip, err)
		mu.Lock()
		delete(blockedIPs, ip) // Rollback internal state if firewall add failed
		mu.Unlock()
		return
	}

	// Save the updated blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking IP %s: %v", ip, err)
	} else if debug { // Log success only in debug
		log.Printf("Successfully saved blocklist to %s", blocklistFilePath)
	}

	// Log with User-Agent if provided
	if len(userAgent) > 0 && userAgent[0] != "" {
		log.Printf("BLOCKED IP %s from %s for %s (User-Agent: %s) Request: %s", ip, filePath, rule, userAgent[0], triggeringRequest)
	} else {
		log.Printf("BLOCKED IP %s from %s for %s Request: %s", ip, filePath, rule, triggeringRequest)
	}

	ua := ""
	if len(userAgent) > 0 {
		ua = userAgent[0]
	}
	blockedIPInfoMu.Lock()
	blockedIPInfo[ip] = &BlockInfo{
		IP:                ip,
		TriggeringRequest: triggeringRequest,
		Rule:              rule,
		UserAgent:         ua,
		FilePath:          filePath,
		BlockedAt:         time.Now(),
	}
	blockedIPInfoMu.Unlock()
}

// blockSubnet adds a subnet to the blocklist and blocks it in the firewall
func blockSubnet(subnet string) {
	if fwManager == nil {
		log.Println("Error: Firewall manager not initialized in blockSubnet")
		return
	}
	alreadyBlocked := false
	mu.Lock()
	if _, exists := blockedSubnets[subnet]; exists {
		alreadyBlocked = true
	} else {
		blockedSubnets[subnet] = struct{}{} // Add to internal list first
	}

	ipsToRemove := make([]string, 0)
	if !alreadyBlocked {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err == nil {
			for ip := range blockedIPs {
				if parsedIP := net.ParseIP(ip); parsedIP != nil && ipNet.Contains(parsedIP) {
					ipsToRemove = append(ipsToRemove, ip)
				}
			}
		}
	}
	mu.Unlock()

	if alreadyBlocked {
		if debug {
			log.Printf("Subnet %s is already in the blocklist, skipping firewall add", subnet)
		}
		return
	}

	// Add the appropriate firewall rule
	var err error
	if challengeEnable {
		err = fwManager.AddRedirectRule(subnet)
	} else {
		err = fwManager.AddBlockRule(subnet)
	}

	if err != nil {
		log.Printf("Failed to add firewall rule for subnet %s: %v", subnet, err)
		mu.Lock()
		delete(blockedSubnets, subnet) // Rollback internal state
		mu.Unlock()
		return
	}

	// If this is a new subnet block, remove individual IP rules for this subnet
	if len(ipsToRemove) > 0 {
		mu.Lock()
		for _, ip := range ipsToRemove {
			delete(blockedIPs, ip)
		}
		mu.Unlock()

		for _, ip := range ipsToRemove {
			var removeErr error
			if challengeEnable {
				removeErr = fwManager.RemoveRedirectRule(ip)
			} else {
				removeErr = fwManager.RemoveBlockRule(ip)
			}
			if removeErr != nil {
				log.Printf("Warning: Failed to remove rule for individual IP %s during subnet block %s: %v", ip, subnet, removeErr)
			}
		}
	}

	// Save the updated blocklist
	if err := saveBlockList(); err != nil {
		log.Printf("Warning: Failed to save blocklist after blocking subnet %s: %v", subnet, err)
	} else if debug { // Log success only in debug
		log.Printf("Successfully saved blocklist to %s", blocklistFilePath)
	}
	log.Printf("Blocked subnet %s and removed %d individual IPs", subnet, len(ipsToRemove))
}

// applyBlockList applies the current blocklist to the firewall
func applyBlockList() error {
	if fwManager == nil {
		return fmt.Errorf("firewall manager not initialized")
	}
	mu.Lock()
	// Create copies of the lists to iterate over without holding the lock for too long
	ipsToApply := make([]string, 0, len(blockedIPs))
	for ip := range blockedIPs {
		ipsToApply = append(ipsToApply, ip)
	}
	subnetsToApply := make([]string, 0, len(blockedSubnets))
	for subnet := range blockedSubnets {
		subnetsToApply = append(subnetsToApply, subnet)
	}
	mu.Unlock()

	// Apply IP blocks/redirects
	for _, ip := range ipsToApply {
		var err error
		if challengeEnable {
			err = fwManager.AddRedirectRule(ip)
		} else {
			err = fwManager.AddBlockRule(ip)
		}
		if err != nil {
			log.Printf("Failed to apply firewall rule for IP %s: %v", ip, err)
		}
	}

	// Apply subnet blocks/redirects
	for _, subnet := range subnetsToApply {
		var err error
		if challengeEnable {
			err = fwManager.AddRedirectRule(subnet)
		} else {
			err = fwManager.AddBlockRule(subnet)
		}
		if err != nil {
			log.Printf("Failed to apply firewall rule for subnet %s: %v", subnet, err)
		}
	}

	action := "block rules"
	if challengeEnable {
		action = "redirect rules"
	}
	log.Printf("Applied %s to firewall: %d IPs, %d subnets",
		action, len(ipsToApply), len(subnetsToApply))

	return nil
}

// findContainingSubnet returns the blocked subnet that contains the given IP, or "" if none.
func findContainingSubnet(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	for subnet := range blockedSubnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return subnet
		}
	}
	return ""
}

// unblockIPFromSubnet removes the subnet-level firewall rule, re-adds individual
// rules for all OTHER IPs that were tracked in that subnet, and removes the subnet
// from the blocklist. The verified IP itself is NOT re-added.
func unblockIPFromSubnet(ip, subnet string) error {
	// Collect the other IPs in this subnet while holding the lock
	mu.Lock()
	otherIPs := make([]string, 0)
	if ips, ok := subnetBlockedIPs[subnet]; ok {
		for otherIP := range ips {
			if otherIP != ip {
				otherIPs = append(otherIPs, otherIP)
			}
		}
	}
	delete(subnetBlockedIPs, subnet)
	delete(blockedSubnets, subnet)
	mu.Unlock()

	// Remove the subnet-level firewall rule
	var removeErr error
	if challengeEnable {
		removeErr = fwManager.RemoveRedirectRule(subnet)
	} else {
		removeErr = fwManager.RemoveBlockRule(subnet)
	}
	if removeErr != nil {
		log.Printf("Warning: failed to remove subnet firewall rule for %s: %v", subnet, removeErr)
	}

	// Re-add individual rules for the remaining IPs in the subnet
	for _, otherIP := range otherIPs {
		mu.Lock()
		blockedIPs[otherIP] = struct{}{}
		mu.Unlock()

		var addErr error
		if challengeEnable {
			addErr = fwManager.AddRedirectRule(otherIP)
		} else {
			addErr = fwManager.AddBlockRule(otherIP)
		}
		if addErr != nil {
			log.Printf("Warning: failed to re-add individual rule for IP %s after splitting subnet %s: %v", otherIP, subnet, addErr)
		}
	}

	log.Printf("Split subnet %s: unblocked IP %s, re-added %d individual IP rules", subnet, ip, len(otherIPs))

	if err := saveBlockList(); err != nil {
		log.Printf("Warning: failed to save blocklist after splitting subnet %s: %v", subnet, err)
	}
	return nil
}
