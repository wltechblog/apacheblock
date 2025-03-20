package main

import (
	"bufio"
	"bytes"
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
	fileSuffix       = "-access.log"         // Log file suffix
	expirationPeriod = 5 * time.Minute       // Time period to monitor for malicious activity
	threshold        = 3                     // Number of attempts to trigger blocking
	subnetThreshold  = 3                     // Number of IPs from a subnet to trigger blocking
	startupLines     = 5000                  // Number of lines to process at startup
)

var (
	mu        sync.Mutex
	whitelist = map[string]bool{}

	ipAccessLog       = make(map[string]*AccessRecord)
	blockedIPs        = make(map[string]struct{})
	blockedSubnets    = make(map[string]struct{})
	subnetAccessCount = make(map[string]int)
	activeFiles       = make(map[string]*os.File)
	php404Regex       = regexp.MustCompile(`^([\d\.]+) .* "GET .*\.php .*" 404`)
	//	phpPostWithBlankRefererRegex = regexp.MustCompile(`^([\d\.]+) .* "POST .*\.php(?:\?.*)?" .* "-" .*`)
	wpLoginRegex = regexp.MustCompile(`^([\d\.]+) .* "POST /wp-login\.php(?:\?.*)?" .* "-" .*`) // New regex for wp-login.php

	phpUrlRegex = regexp.MustCompile(`^([\d\.]+) .* "GET .*\.php(?:\..*)?(?:\?.*)?" (403|404) .*`)
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

func main() {

	// Determine whitelisted addresses
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
			whitelist[ip.String()] = true
		}
	}

	err := removePortBlockingRules()
	if err != nil {
		log.Fatalf("Error removing port blocking rules: %v", err)
	} else {
		log.Println("Successfully removed all port 80/443 blocking rules.")
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
		go handleNewOrModifiedLog(file)
	}
}

func handleNewOrModifiedLog(filePath string) {
	if !strings.HasSuffix(filePath, fileSuffix) {
		return
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
	reason := "PHP 404 error"
	match := php404Regex.FindStringSubmatch(line)
	if match == nil {
		match = wpLoginRegex.FindStringSubmatch(line)
		reason = "POST with black referer"
	}

	if match == nil {
		match = phpUrlRegex.FindStringSubmatch(line)
		reason = "PHP URL with 4xx error"
	}

	if match == nil {
		return
	}

	ip := match[1]
	if ip == "" {
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, whitelisted := whitelist[ip]; whitelisted {
		return
	}
	if _, blocked := blockedIPs[ip]; blocked {
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
