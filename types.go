package main

import (
	"os"
	"sync"
	"time"
)

// FileState tracks the state of a file being monitored
type FileState struct {
	File            *os.File
	Position        int64
	Size            int64
	LastMod         time.Time
	LastTimestamp   time.Time // Timestamp of the last processed log entry
	LastProcessedIP string    // Last IP that was processed
}

// Global variables
var (
	mu                  sync.Mutex
	stateMutex          sync.Mutex
	whitelist                  = map[string]bool{}
	fileSuffix                 = "access.log" // Log file suffix
	debug                      = false
	verbose                    = false // Verbose debug mode
	ipAccessLog                = make(map[string]*AccessRecord)
	blockedIPs                 = make(map[string]struct{})
	blockedSubnets             = make(map[string]struct{})
	subnetBlockedIPs           = make(map[string]map[string]struct{}) // maps subnet to set of blocked IPs
	fileStates                 = make(map[string]*FileState)
	logFormat           string = "apache"
	logpath             string = "/var/customers/logs" // Example default, might be overridden
	whitelistFilePath   string = "/etc/apacheblock/whitelist.txt"
	domainWhitelistPath string = "/etc/apacheblock/domainwhitelist.txt"
	blocklistFilePath   string = "/etc/apacheblock/blocklist.json"
	// rulesFilePath is declared locally in rules.go
	firewallChain string = "apacheblock" // Renamed from firewallTable
	firewallType  string = "iptables"    // New: "iptables" or "nftables"
	apiKey        string = ""
	// SocketPath is declared locally in socket.go

	// Core Configuration variables
	expirationPeriod      time.Duration = 5 * time.Minute
	threshold             int           = 3
	subnetThreshold       int           = 3
	disableSubnetBlocking bool          = false
	startupLines          int           = 5000

	// Challenge Feature Configuration
	challengeEnable                bool          = false
	challengePort                  int           = 4443 // Default challenge port
	challengeCertPath              string        = "/etc/apacheblock/certs"
	recaptchaSiteKey               string        = ""
	recaptchaSecretKey             string        = ""
	challengeTempWhitelistDuration time.Duration = 5 * time.Minute // New: Duration for temp whitelist

	// Internal State (Temporary Whitelist)
	tempWhitelist      map[string]time.Time // Map IP to expiry time
	tempWhitelistMutex sync.Mutex           // Mutex for temporary whitelist map
)

func init() {
	// Initialize maps
	tempWhitelist = make(map[string]time.Time)
}

// AccessRecord tracks suspicious activity for an IP address
type AccessRecord struct {
	Count       int
	ExpiresAt   time.Time
	LastUpdated time.Time
	Reason      string // The rule that triggered this record
}

// BlockList represents the list of blocked IPs and subnets for persistence
type BlockList struct {
	IPs     []string `json:"ips"`
	Subnets []string `json:"subnets"`
}

// CaddyLogEntry represents a log entry from Caddy server
type CaddyLogEntry struct {
	Request struct {
		ClientIP string `json:"client_ip"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
	} `json:"request"`
	Status int64 `json:"status"`
}
