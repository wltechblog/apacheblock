package main

import (
	"log"
	"os/exec"
)

// listIPTablesRules lists all iptables rules for debugging purposes
func listIPTablesRules() {
	if debug {
		log.Println("Listing current iptables rules for debugging:")

		// List filter table rules
		log.Println("Filter table rules:")
		cmd := exec.Command("iptables", "-t", "filter", "-L", "-v", "-n")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error listing filter table rules: %v", err)
		} else {
			log.Printf("\n%s", string(output))
		}

		// List NAT table rules
		log.Println("NAT table rules:")
		cmd = exec.Command("iptables", "-t", "nat", "-L", "-v", "-n")
		output, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error listing NAT table rules: %v", err)
		} else {
			log.Printf("\n%s", string(output))
		}
	}
}

// listNFTablesRules lists all nftables rules for debugging purposes
func listNFTablesRules() {
	if debug {
		log.Println("Listing current nftables rules for debugging:")

		cmd := exec.Command("nft", "list", "ruleset")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error listing nftables rules: %v", err)
		} else {
			log.Printf("\n%s", string(output))
		}
	}
}

// listFirewallRules lists all firewall rules based on the current firewall type
func listFirewallRules() {
	if !debug {
		return
	}

	log.Printf("Listing current firewall rules (type: %s)", firewallType)

	switch firewallType {
	case "iptables":
		listIPTablesRules()
	case "nftables":
		listNFTablesRules()
	default:
		log.Printf("Unknown firewall type: %s", firewallType)
	}
}
