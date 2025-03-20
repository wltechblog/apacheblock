package main

import (
	"os"
	"sync"
	"time"
)

// FileState tracks the state of a file being monitored
type FileState struct {
	File     *os.File
	Position int64
	Size     int64
	LastMod  time.Time
}

// Global variables
var (
	mu                sync.Mutex
	stateMutex        sync.Mutex
	whitelist         = map[string]bool{}
	fileSuffix        = "access.log" // Log file suffix
	debug             = false
	verbose           = false        // Verbose debug mode
	ipAccessLog       = make(map[string]*AccessRecord)
	blockedIPs        = make(map[string]struct{})
	blockedSubnets    = make(map[string]struct{})
	subnetAccessCount = make(map[string]int)
	fileStates        = make(map[string]*FileState)
	logFormat         string
	logpath           string
	whitelistFilePath = "/etc/apacheblock/whitelist.txt" // Default path for whitelist file
	blocklistFilePath = "/etc/apacheblock/blocklist.json" // Default path for blocklist file
	firewallTable     = "apacheblock" // Name of our custom iptables table
	
	// Configuration variables
	expirationPeriod time.Duration // Time period to monitor for malicious activity
	threshold        int           // Number of attempts to trigger blocking
	subnetThreshold  int           // Number of IPs from a subnet to trigger blocking
	startupLines     int           // Number of lines to process at startup
)

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