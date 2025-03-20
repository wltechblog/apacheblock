package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	logDir           = "/var/customers/logs" // Directory to monitor
	expirationPeriod = 5 * time.Minute       // Time period to monitor for malicious activity
	threshold        = 3                     // Number of attempts to trigger blocking
	subnetThreshold  = 3                     // Number of IPs from a subnet to trigger blocking
	startupLines     = 5000                  // Number of lines to process at startup
)

var (
	mu                sync.Mutex
	whitelist         = map[string]bool{}
	fileSuffix        = "access.log" // Log file suffix
	debug             = false
	ipAccessLog       = make(map[string]*AccessRecord)
	blockedIPs        = make(map[string]struct{})
	blockedSubnets    = make(map[string]struct{})
	subnetAccessCount = make(map[string]int)
	activeFiles       = make(map[string]*os.File)
	//	php404Regex       = regexp.MustCompile(`^([\d\.]+) .* "GET .*\.php .*" 404`)
	//	wpLoginRegex      = regexp.MustCompile(`^([\d\.]+) .* "POST /wp-login\.php(?:\?.*)?" .* "-" .*`) // New regex for wp-login.php
	phpUrlRegex       = regexp.MustCompile(`^([\d\.]+) .* "GET .*\.php(?:\..*)?(?:\?.*)?" (403|404) .*`)
	logFormat         string
	logpath           string
	whitelistFilePath = "/etc/apacheblock/whitelist.txt" // Default path for whitelist file
)

type AccessRecord struct {
	Count       int
	ExpiresAt   time.Time
	LastUpdated time.Time
}

// removePortBlockingRules removes all rules in the INPUT chain of iptables
// that block traffic to ports 80 or 443.
func removePortBlockingRules() error {
	// Get the current iptables rules
	cmd := exec.Command("iptables", "-L", "INPUT", "-n", "--line-numbers")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return err
	}

	rules := out.String()
	lines := strings.Split(rules, "\n")
	portBlockRegex := regexp.MustCompile(`^\s*(\d+)\s.*--.*tcp.*dpt:(80|443)`)

	// Iterate through the rules in reverse order to avoid invalid line numbers after deletions
	for i := len(lines) - 1; i >= 0; i-- {
		match := portBlockRegex.FindStringSubmatch(lines[i])
		if match != nil {
			lineNumber := match[1] // Line number of the rule
			log.Printf("Removing rule: %s", lines[i])
			// Remove the rule by its line number
			removeCmd := exec.Command("iptables", "-D", "INPUT", lineNumber)
			if err := removeCmd.Run(); err != nil {
				log.Printf("Failed to remove rule on line %s: %v", lineNumber, err)
			}
		}
	}
	return nil
}

// parseExistingRules parses the current iptables rules and populates the blockedIPs and blockedSubnets maps.
func parseExistingRules() error {
	cmd := exec.Command("iptables", "-L", "INPUT", "-n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return err
	}

	rules := out.String()
	lines := strings.Split(rules, "\n")
	ipBlockRegex := regexp.MustCompile(`^\s*DROP\s+all\s+--\s+(\S+)\s+0\.0\.0\.0/0\s+tcp\s+dpt:(80|443)`)
	subnetBlockRegex := regexp.MustCompile(`^\s*DROP\s+all\s+--\s+(\S+/\d+)\s+0\.0\.0\.0/0\s+tcp\s+dpt:(80|443)`)

	for _, line := range lines {
		if match := ipBlockRegex.FindStringSubmatch(line); match != nil {
			ip := match[1]
			blockedIPs[ip] = struct{}{}
		} else if match := subnetBlockRegex.FindStringSubmatch(line); match != nil {
			subnet := match[1]
			blockedSubnets[subnet] = struct{}{}
		}
	}

	return nil
}

func main() {
	clean := flag.Bool("clean", false, "Remove existing port blocking rules")
	server := flag.String("server", "apache", "Log format: apache or caddy")
	logPath := flag.String("logPath", "/var/customers/logs", "Log path")
	Debug := flag.Bool("debug", false, "Debug mode")
	whitelistPath := flag.String("whitelist", whitelistFilePath, "Path to whitelist file")
	flag.Parse()

	if *Debug {
		debug = true
		log.Println("Enabling debug mode")
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
	
	// Set the whitelist file path
	whitelistFilePath = *whitelistPath
	
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
		err := removePortBlockingRules()
		if err != nil {
			log.Fatalf("Error removing port blocking rules: %v", err)
		} else {
			log.Println("Successfully removed all port 80/443 blocking rules.")
		}
	} else {
		err := parseExistingRules()
		if err != nil {
			log.Fatalf("Error parsing existing rules: %v", err)
		}
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
					go handleNewOrModifiedLog(event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v\n", err)
			}
		}
	}()

	if err := watcher.Add(logDir); err != nil {
		log.Fatalf("Failed to add directory to watcher: %v", err)
	}

	processExistingLogs()
	select {}
}

func processExistingLogs() {
	files, err := filepath.Glob(filepath.Join(logDir, "*"+fileSuffix))
	if err != nil {
		log.Printf("Failed to list log files: %v", err)
		return
	}

	for _, file := range files {
		if debug {
			log.Printf("Found lof %s", file)
		}
		go handleNewOrModifiedLog(file)
	}
}

func handleNewOrModifiedLog(filePath string) {
	if !strings.HasSuffix(filePath, fileSuffix) {
		return
	}
	if debug {
		log.Printf("Starting log %s", filePath)
	}
	mu.Lock()
	defer mu.Unlock()

	if _, exists := activeFiles[filePath]; exists {
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", filePath, err)
		return
	}
	activeFiles[filePath] = file

	go followLogFile(filePath, file)
}

func followLogFile(filePath string, file *os.File) {
	defer func() {
		file.Close()
		mu.Lock()
		delete(activeFiles, filePath)
		mu.Unlock()
	}()

	if err := skipToLastLines(file, startupLines); err != nil {
		log.Printf("Error skipping lines for file %s: %v", filePath, err)
	}

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		processLogEntry(strings.TrimSpace(line), filePath)
	}
}

func skipToLastLines(file *os.File, lines int) error {
	bufferSize := int64(4096)
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	position := fileInfo.Size()
	var lineCount int

	for position > 0 {
		if position < bufferSize {
			bufferSize = position
		}

		position -= bufferSize
		file.Seek(position, io.SeekStart)

		buf := make([]byte, bufferSize)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		lineCount += bytes.Count(buf[:n], []byte{'\n'})
		if lineCount >= lines {
			break
		}
	}

	scanner := bufio.NewScanner(file)
	for lineCount > lines && scanner.Scan() {
		lineCount--
	}
	return scanner.Err()
}

func processLogEntry(line, filePath string) {
	var ip, reason string
	var flag bool

	if logFormat == "apache" {
		ip, reason, flag = processLogEntryApache(line)
	} else if logFormat == "caddy" {
		ip, reason, flag = processLogEntryCaddy(line)
	}
	if !flag {
		return
	}
	if debug {
		log.Printf("hit on ip %s for %s in %s", ip, reason, filePath)
	}
	mu.Lock()
	defer mu.Unlock()
	
	// Check if IP is directly whitelisted
	if _, whitelisted := whitelist[ip]; whitelisted {
		if debug {
			log.Printf("IP %s is whitelisted, skipping", ip)
		}
		return
	}
	
	// Check if IP is in a whitelisted CIDR range
	ipAddr := net.ParseIP(ip)
	if ipAddr != nil {
		for cidr := range whitelist {
			// Check if this is a CIDR notation
			if strings.Contains(cidr, "/") {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil && ipNet.Contains(ipAddr) {
					if debug {
						log.Printf("IP %s is in whitelisted CIDR %s, skipping", ip, cidr)
					}
					return
				}
			}
		}
	}
	if _, blocked := blockedIPs[ip]; blocked {
		return
	}
	if _, blocked := blockedSubnets[getSubnet(ip)]; blocked {
		return
	}

	record, exists := ipAccessLog[ip]
	now := time.Now()
	if exists {
		record.Count++
		record.LastUpdated = now
	} else {
		ipAccessLog[ip] = &AccessRecord{
			Count:       1,
			ExpiresAt:   now.Add(expirationPeriod),
			LastUpdated: now,
		}
	}

	if record := ipAccessLog[ip]; record.Count >= threshold {
		blockIP(ip, filePath, reason)
		delete(ipAccessLog, ip)
		checkSubnet(ip)
	}

}

func processLogEntryCaddy(line string) (ip, reason string, flag bool) {
	var logEntry CaddyLogEntry
	err := json.Unmarshal([]byte(line), &logEntry)
	if err != nil {
		return "", "", false
	}
	flag = false
	// logic
	// if uri is a php file and status is 404
	if (logEntry.Status == 404 || logEntry.Status == 403) && strings.Contains(logEntry.Request.URI, "php") {
		reason = "php with 404 or 403"
		flag = true
	}
	return logEntry.Request.ClientIP, reason, flag
}

func processLogEntryApache(line string) (ip, reason string, flag bool) {
	match := phpUrlRegex.FindStringSubmatch(line)
	reason = "PHP URL with 4xx error"

	if match == nil {
		return "", "", false
	}

	ip = match[1]
	if ip == "" {
		return "", "", false
	}
	return ip, reason, true
}

func isSubnetBlocked(ip string) bool {
	subnet := getSubnet(ip)
	_, ok := blockedSubnets[subnet]
	return ok
}

func checkSubnet(ip string) {
	subnet := getSubnet(ip)
	subnetAccessCount[subnet]++
	if subnetAccessCount[subnet] >= subnetThreshold {
		blockSubnet(subnet)
	}
}

func blockIP(ip, filePath string, rule string) {
	if _, exists := blockedIPs[ip]; exists {
		return
	}

	blockedIPs[ip] = struct{}{}
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to block IP %s: %v", ip, err)
		return
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to block IP %s: %v", ip, err)
		return
	}

	log.Printf("Blocked IP %s from file %s for %s", ip, filePath, rule)
}

func blockSubnet(subnet string) {
	if _, exists := blockedSubnets[subnet]; exists {
		return
	}

	blockedSubnets[subnet] = struct{}{}
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", subnet, "-p", "tcp", "--dport", "80", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to block subnet %s: %v", subnet, err)
		return
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-s", subnet, "-p", "tcp", "--dport", "443", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to block subnet %s: %v", subnet, err)
		return
	}

	// Remove individual IP rules for this subnet
	for ip := range blockedIPs {
		if strings.HasPrefix(ip, strings.TrimSuffix(subnet, ".0/24")) {
			delete(blockedIPs, ip)
			cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP")
			cmd.Run()
			cmd = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
			cmd.Run()
		}
	}

	log.Printf("Blocked subnet %s and removed individual IPs", subnet)
}

func getSubnet(ip string) string {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return ""
	}
	mask := net.CIDRMask(24, 32)
	return ipAddr.Mask(mask).String() + "/24"
}

// createExampleWhitelistFile creates an example whitelist file with comments and sample entries
func createExampleWhitelistFile(filePath string) error {
	content := `# Apache Block Whitelist
# Add one IP address or CIDR range per line
# Lines starting with # are comments and will be ignored
# Examples:

# Individual IP addresses
127.0.0.1
192.168.1.10

# CIDR notation for subnets
# 10.0.0.0/8
# 172.16.0.0/12
# 192.168.0.0/16
`
	return os.WriteFile(filePath, []byte(content), 0644)
}

// readWhitelistFile reads IP addresses from the whitelist file and adds them to the whitelist map
func readWhitelistFile(filePath string) error {
	// Ensure the directory exists
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
		log.Printf("Created directory %s for whitelist file", dir)
	}
	
	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("Whitelist file %s does not exist, creating example file", filePath)
		if err := createExampleWhitelistFile(filePath); err != nil {
			log.Printf("Failed to create example whitelist file: %v", err)
		}
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open whitelist file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Validate IP address
		ip := net.ParseIP(line)
		if ip == nil {
			// Check if it's a CIDR notation
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				log.Printf("Invalid IP address or CIDR at line %d: %s", lineNum, line)
				continue
			}
			// For CIDR notation, we store the network address
			whitelist[ipNet.String()] = true
			if debug {
				log.Printf("Added subnet %s to whitelist", ipNet.String())
			}
		} else {
			whitelist[ip.String()] = true
			if debug {
				log.Printf("Added IP %s to whitelist", ip.String())
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading whitelist file: %v", err)
	}
	
	return nil
}
