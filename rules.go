package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Rule defines a detection rule for suspicious activity
type Rule struct {
	Name        string        `json:"name"`        // Name of the rule
	Description string        `json:"description"` // Description of what the rule detects
	LogFormat   string        `json:"logFormat"`   // Log format this rule applies to (apache, caddy, or all)
	Regex       string        `json:"regex"`       // Regular expression to match in log lines
	Threshold   int           `json:"threshold"`   // Number of matches to trigger blocking
	Duration    time.Duration `json:"duration"`    // Time window for threshold (e.g., "5m")
	Enabled     bool          `json:"enabled"`     // Whether the rule is enabled
	
	// Compiled regex (not stored in JSON)
	compiledRegex *regexp.Regexp
}

// RuleSet contains all the rules
type RuleSet struct {
	Rules []Rule `json:"rules"`
}

// DefaultRulesPath is the default path for the rules file
const DefaultRulesPath = "/etc/apacheblock/rules.json"

// Global variables
var (
	rulesFilePath = DefaultRulesPath
	rules         []Rule
)

// loadRules loads the rules from the rules file
func loadRules() error {
	// Ensure the directory exists
	dir := filepath.Dir(rulesFilePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	
	// Check if the file exists
	if _, err := os.Stat(rulesFilePath); os.IsNotExist(err) {
		log.Printf("Rules file %s does not exist, creating default rules", rulesFilePath)
		if err := createDefaultRulesFile(); err != nil {
			return fmt.Errorf("failed to create default rules file: %v", err)
		}
	}
	
	// Read the file
	data, err := os.ReadFile(rulesFilePath)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %v", err)
	}
	
	// Unmarshal JSON
	var ruleSet RuleSet
	if err := json.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to unmarshal rules: %v", err)
	}
	
	// Compile regexes
	for i := range ruleSet.Rules {
		if !ruleSet.Rules[i].Enabled {
			continue
		}
		
		regex, err := regexp.Compile(ruleSet.Rules[i].Regex)
		if err != nil {
			log.Printf("Warning: Invalid regex in rule %s: %v", ruleSet.Rules[i].Name, err)
			continue
		}
		
		ruleSet.Rules[i].compiledRegex = regex
	}
	
	// Set the global rules
	rules = ruleSet.Rules
	
	log.Printf("Loaded %d rules from %s", len(rules), rulesFilePath)
	return nil
}

// createDefaultRulesFile creates a default rules file with example rules
func createDefaultRulesFile() error {
	// Create default rules
	defaultRules := RuleSet{
		Rules: []Rule{
			{
				Name:        "Apache PHP 403/404",
				Description: "Detects requests to PHP files resulting in 403 or 404 status codes in Apache logs",
				LogFormat:   "apache",
				Regex:       `^([\d\.]+) .* "GET .*\.php(?:\s+HTTP/[\d\.]+)?" (403|404) .*`,
				Threshold:   3,
				Duration:    5 * time.Minute,
				Enabled:     true,
			},
			{
				Name:        "WordPress PHP Redirects",
				Description: "Detects requests to PHP files resulting in 301 redirects (common in WordPress)",
				LogFormat:   "apache",
				Regex:       `^([\d\.]+) .* "GET .*\.php(?:\s+HTTP/[\d\.]+)?" 301 .*`,
				Threshold:   3,
				Duration:    5 * time.Minute,
				Enabled:     true,
			},
			{
				Name:        "Caddy PHP 403/404",
				Description: "Detects requests to PHP files resulting in 403 or 404 status codes in Caddy logs",
				LogFormat:   "caddy",
				Regex:       `.*\.php.*`,
				Threshold:   3,
				Duration:    5 * time.Minute,
				Enabled:     true,
			},
			{
				Name:        "Caddy PHP Redirects",
				Description: "Detects requests to PHP files resulting in 301 redirects in Caddy logs",
				LogFormat:   "caddy",
				Regex:       `.*\.php.*`,
				Threshold:   3,
				Duration:    5 * time.Minute,
				Enabled:     true,
			},
			{
				Name:        "WordPress Login Attempts",
				Description: "Detects repeated failed login attempts to WordPress admin",
				LogFormat:   "apache",
				Regex:       `^([\d\.]+) .* "POST .*wp-login\.php.*" (200|403) .*`,
				Threshold:   5,
				Duration:    10 * time.Minute,
				Enabled:     true,
			},
			{
				Name:        "SQL Injection Attempts",
				Description: "Detects basic SQL injection attempts in URLs",
				LogFormat:   "all",
				Regex:       `^([\d\.]+) .* "GET .*(?:union\s+select|select\s*\*|drop\s+table|--\s|;\s*--\s|'|%27).*" .*`,
				Threshold:   2,
				Duration:    5 * time.Minute,
				Enabled:     true,
			},
			{
				Name:        "WordPress File Probing",
				Description: "Detects attempts to access common WordPress files that don't exist",
				LogFormat:   "apache",
				Regex:       `^([\d\.]+) .* "GET .*(?:wp-includes|wp-content|wp-admin).*" (403|404) .*`,
				Threshold:   3,
				Duration:    5 * time.Minute,
				Enabled:     true,
			},
		},
	}
	
	// Marshal to JSON
	data, err := json.MarshalIndent(defaultRules, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default rules: %v", err)
	}
	
	// Write to file
	if err := os.WriteFile(rulesFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write default rules file: %v", err)
	}
	
	log.Printf("Created default rules file at %s", rulesFilePath)
	return nil
}

// matchRule checks if a log line matches a rule and returns the IP address and reason if it does
func matchRule(line string, format string) (string, string, bool) {
	if verbose {
		log.Printf("Matching rules for log format: %s", format)
	}
	
	for _, rule := range rules {
		// Skip rules that don't apply to this log format
		if rule.LogFormat != "all" && rule.LogFormat != format {
			if verbose {
				log.Printf("Skipping rule %s (format mismatch: %s)", rule.Name, rule.LogFormat)
			}
			continue
		}
		
		// Skip disabled rules
		if !rule.Enabled || rule.compiledRegex == nil {
			if verbose {
				log.Printf("Skipping rule %s (disabled or invalid regex)", rule.Name)
			}
			continue
		}
		
		if verbose {
			log.Printf("Trying rule %s with regex: %s", rule.Name, rule.Regex)
		}
		
		// Check if the line matches the rule
		matches := rule.compiledRegex.FindStringSubmatch(line)
		if matches != nil {
			if verbose {
				log.Printf("Rule %s matched! Capture groups: %v", rule.Name, matches)
			}
			
			// For Apache-style rules, the IP is typically the first capture group
			if format == "apache" && len(matches) > 1 {
				ip := matches[1]
				reason := rule.Name
				if len(matches) > 2 {
					reason += " " + matches[2]
				}
				
				if verbose {
					log.Printf("Apache match: IP=%s, Reason=%s", ip, reason)
				}
				
				return ip, reason, true
			}
			
			// For Caddy, we need to parse the JSON to get the IP
			if format == "caddy" {
				var entry CaddyLogEntry
				if err := json.Unmarshal([]byte(line), &entry); err == nil {
					// Check if the URI matches our rule (already confirmed by regex)
					// Include 301 status code for redirect detection
					if (entry.Status == 403 || entry.Status == 404 || entry.Status == 301) && 
					   entry.Request.ClientIP != "" {
						reason := rule.Name + " " + fmt.Sprint(entry.Status)
						
						if verbose {
							log.Printf("Caddy match: IP=%s, Reason=%s", entry.Request.ClientIP, reason)
						}
						
						return entry.Request.ClientIP, reason, true
					} else if verbose {
						log.Printf("Caddy match but status (%d) or ClientIP (%s) not valid", 
							entry.Status, entry.Request.ClientIP)
					}
				} else if verbose {
					log.Printf("Failed to parse Caddy JSON: %v", err)
				}
			}
		} else if verbose {
			log.Printf("Rule %s did not match", rule.Name)
		}
	}
	
	if verbose {
		log.Printf("No rules matched for this line")
	}
	
	return "", "", false
}

// getRuleThreshold returns the threshold and duration for a rule by name
func getRuleThreshold(ruleName string) (int, time.Duration) {
	for _, rule := range rules {
		if rule.Name == ruleName || strings.HasPrefix(ruleName, rule.Name) {
			return rule.Threshold, rule.Duration
		}
	}
	
	// Default values if rule not found
	return threshold, expirationPeriod
}