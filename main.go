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
	domainWhitelistPathFlag := flag.String("domainWhitelist", domainWhitelistPath, "Path to domain whitelist file")
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
	
	// API key for socket authentication
	apiKeyFlag := flag.String("apiKey", "", "API key for socket authentication")
	
	// Socket path for client-server communication
	socketPathFlag := flag.String("socketPath", SocketPath, "Path to the Unix domain socket for client-server communication")
	
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
	domainWhitelistPath = *domainWhitelistPathFlag
	blocklistFilePath = *blocklistPath
	rulesFilePath = *rulesPath
	firewallTable = *tableName
	
	// Set the API key if provided
	if *apiKeyFlag != "" {
		apiKey = *apiKeyFlag
		if debug {
			log.Println("API key set for socket authentication")
		}
	}
	
	// Set the socket path if provided
	if *socketPathFlag != "" {
		SocketPath = *socketPathFlag
		if debug {
			log.Println("Socket path set to:", SocketPath)
		}
	}
	
	// Check if we're in client mode
	clientMode := *block != "" || *unblock != "" || *check != "" || *list
	
	if clientMode {
		// For all client mode commands, try socket first
		var command ClientCommand
		var target string
		
		if *block != "" {
			command = BlockCommand
			target = *block
		} else if *unblock != "" {
			command = UnblockCommand
			target = *unblock
		} else if *check != "" {
			command = CheckCommand
			target = *check
		} else if *list {
			command = ListCommand
			target = ""
		}
		
		// Try to send the command to a running server first
		err := sendCommand(command, target)
		if err == nil {
			// Command was successfully sent to the server
			os.Exit(0)
		}
		
		// If socket failed, handle each command appropriately
		log.Printf("Could not connect to server: %v", err)
		log.Printf("Executing command directly")
		
		// Just load the blocklist for all commands
		if err := loadBlockList(); err != nil {
			log.Printf("Warning: Failed to load blocklist: %v", err)
		}
		
		// Handle each command differently
		switch command {
		case CheckCommand:
			// For check, we don't need to set up the firewall
			if err := clientCheckIP(target); err != nil {
				log.Fatalf("Error checking IP: %v", err)
			}
		case ListCommand:
			// For list, we don't need to set up the firewall
			if err := clientListBlocked(); err != nil {
				log.Fatalf("Error listing blocked IPs: %v", err)
			}
		case BlockCommand, UnblockCommand:
			// For block/unblock, we need to set up the firewall
			// But only do it once we've confirmed we need to make changes
			
			// For block, check if already blocked
			if command == BlockCommand {
				isBlocked, subnet, err := isIPBlocked(target)
				if err != nil {
					log.Fatalf("Error checking if IP is blocked: %v", err)
				}
				if isBlocked {
					if subnet != "" {
						log.Printf("%s is already blocked (contained in subnet %s)", target, subnet)
					} else {
						log.Printf("%s is already blocked", target)
					}
					os.Exit(0)
				}
				
				// Now we need to set up the firewall
				if err := setupFirewallTable(); err != nil {
					log.Fatalf("Error setting up firewall table: %v", err)
				}
				
				// Block the IP
				if err := clientBlockIP(target); err != nil {
					log.Fatalf("Error blocking IP: %v", err)
				}
			}
			
			// For unblock, check if already unblocked
			if command == UnblockCommand {
				isBlocked, _, err := isIPBlocked(target)
				if err != nil {
					log.Fatalf("Error checking if IP is blocked: %v", err)
				}
				if !isBlocked {
					log.Printf("%s is not blocked", target)
					os.Exit(0)
				}
				
				// Now we need to set up the firewall
				if err := setupFirewallTable(); err != nil {
					log.Fatalf("Error setting up firewall table: %v", err)
				}
				
				// Unblock the IP
				if err := clientUnblockIP(target); err != nil {
					log.Fatalf("Error unblocking IP: %v", err)
				}
			}
		}
		
		os.Exit(0)
	}
	
	// Server mode - continue with normal operation
	
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
	log.Printf("Files: whitelist=%s, domain whitelist=%s, blocklist=%s, iptables chain=%s",
		whitelistFilePath, domainWhitelistPath, blocklistFilePath, firewallTable)
	
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
	
	// Read domain whitelist from file
	if err := readDomainWhitelistFile(domainWhitelistPath); err != nil {
		log.Printf("Warning: Failed to read domain whitelist file: %v", err)
	} else {
		log.Printf("Successfully loaded domain whitelist from %s", domainWhitelistPath)
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