package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	// Basic options
	clean := flag.Bool("clean", false, "Remove existing port blocking rules")
	server := flag.String("server", "apache", "Log format: apache or caddy")
	logPath := flag.String("logPath", "/var/customers/logs", "Log path")
	Debug := flag.Bool("debug", false, "Debug mode")
	Verbose := flag.Bool("verbose", false, "Verbose debug mode (logs all processed lines)")
	whitelistPath := flag.String("whitelist", whitelistFilePath, "Path to whitelist file")
	blocklistPath := flag.String("blocklist", blocklistFilePath, "Path to blocklist file")
	rulesPath := flag.String("rules", rulesFilePath, "Path to rules file")
	tableName := flag.String("table", firewallTable, "Name of the iptables chain to use")
	
	// Configuration options
	expPeriod := flag.Duration("expirationPeriod", 5*time.Minute, "Time period to monitor for malicious activity")
	thresholdFlag := flag.Int("threshold", 3, "Number of suspicious requests to trigger IP blocking")
	subnetThresholdFlag := flag.Int("subnetThreshold", 3, "Number of IPs from a subnet to trigger subnet blocking")
	startupLinesFlag := flag.Int("startupLines", 5000, "Number of log lines to process at startup")
	
	// Client mode options
	block := flag.String("block", "", "Block an IP address or CIDR range")
	unblock := flag.String("unblock", "", "Unblock an IP address or CIDR range")
	check := flag.String("check", "", "Check if an IP address or CIDR range is blocked")
	list := flag.Bool("list", false, "List all blocked IPs and subnets")
	
	flag.Parse()

	// Set configuration variables from flags
	expirationPeriod = *expPeriod
	threshold = *thresholdFlag
	subnetThreshold = *subnetThresholdFlag
	startupLines = *startupLinesFlag

	if *Debug {
		debug = true
		log.Println("Enabling debug mode")
	}
	
	if *Verbose {
		verbose = true
		debug = true // Verbose implies debug
		log.Println("Enabling verbose debug mode")
	}
	
	// Set the file paths and table name
	whitelistFilePath = *whitelistPath
	blocklistFilePath = *blocklistPath
	rulesFilePath = *rulesPath
	firewallTable = *tableName
	
	// Setup our custom firewall table
	if err := setupFirewallTable(); err != nil {
		log.Fatalf("Error setting up firewall table: %v", err)
	}
	
	// Load the blocklist from file
	if err := loadBlockList(); err != nil {
		log.Printf("Warning: Failed to load blocklist: %v", err)
	}
	
	// Load the rules from file
	if err := loadRules(); err != nil {
		log.Printf("Warning: Failed to load rules: %v", err)
	}
	
	// Check if we're in client mode
	clientMode := *block != "" || *unblock != "" || *check != "" || *list
	
	if clientMode {
		// Client mode - perform the requested operation and exit
		var err error
		
		if *block != "" {
			err = RunClientMode(BlockCommand, *block)
		} else if *unblock != "" {
			err = RunClientMode(UnblockCommand, *unblock)
		} else if *check != "" {
			err = RunClientMode(CheckCommand, *check)
		} else if *list {
			err = RunClientMode(ListCommand, "")
		}
		
		if err != nil {
			log.Fatalf("Error in client mode: %v", err)
		}
		
		os.Exit(0)
	}
	
	// Server mode - continue with normal operation
	
	if *server == "apache" || *server == "caddy" {
		logFormat = *server
	} else {
		log.Fatal("Invalid server")
	}
	_, err := os.Stat(*logPath)
	if err != nil {
		log.Fatal("logpath invalid")
	}
	logpath = *logPath

	if logFormat == "caddy" {
		fileSuffix = ".log"
	}
	
	// Log configuration settings
	log.Printf("Configuration: expirationPeriod=%v, threshold=%d, subnetThreshold=%d, startupLines=%d",
		expirationPeriod, threshold, subnetThreshold, startupLines)
	log.Printf("Files: whitelist=%s, blocklist=%s, iptables chain=%s",
		whitelistFilePath, blocklistFilePath, firewallTable)
	
	// Determine whitelisted addresses from local interfaces
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
			whitelist[ip.String()] = true
			if debug {
				log.Printf("Added local IP %s to whitelist", ip.String())
			}
		}
	}
	
	// Read whitelist from file
	if err := readWhitelistFile(whitelistFilePath); err != nil {
		log.Printf("Warning: Failed to read whitelist file: %v", err)
	} else {
		log.Printf("Successfully loaded whitelist from %s", whitelistFilePath)
	}

	if *clean {
		// Clean mode: remove all rules and reset blocklist
		if err := removePortBlockingRules(); err != nil {
			log.Fatalf("Error removing port blocking rules: %v", err)
		}
		os.Exit(0)
	}
	
	// Apply the blocklist to the firewall
	if err := applyBlockList(); err != nil {
		log.Printf("Warning: Failed to apply blocklist: %v", err)
	}

	// Start the socket server for client communication
	if err := startSocketServer(); err != nil {
		log.Printf("Warning: Failed to start socket server: %v", err)
		log.Printf("Client mode commands will not affect this running instance")
	} else {
		log.Printf("Socket server started, client mode commands will be processed by this instance")
	}

	// Set up the log file watcher
	watcher, err := setupLogWatcher()
	if err != nil {
		log.Fatalf("Failed to set up log watcher: %v", err)
	}
	defer watcher.Close()

	// Start periodic tasks
	startPeriodicTasks(watcher)

	// Process existing logs
	processExistingLogs()
	
	// Wait forever
	select {}
}