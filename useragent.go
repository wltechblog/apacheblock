package main

import (
	"encoding/json"
	"regexp"
)

// Regular expression to extract User-Agent from Apache log entries
// This assumes the User-Agent is enclosed in double quotes after the HTTP version
var apacheUserAgentRegex = regexp.MustCompile(`"(?:GET|POST|HEAD|PUT|DELETE) [^"]+" \d+ \d+ "(?:[^"]*)" "([^"]*)"`)

// extractUserAgent extracts the User-Agent from a log entry
func extractUserAgent(line, format string) string {
	switch format {
	case "apache":
		return extractApacheUserAgent(line)
	case "caddy":
		return extractCaddyUserAgent(line)
	default:
		return ""
	}
}

// extractApacheUserAgent extracts the User-Agent from an Apache log entry
func extractApacheUserAgent(line string) string {
	matches := apacheUserAgentRegex.FindStringSubmatch(line)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// extractCaddyUserAgent extracts the User-Agent from a Caddy log entry
func extractCaddyUserAgent(line string) string {
	// Caddy logs are in JSON format with a "request" object containing "headers"
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return ""
	}

	// Try to navigate to the User-Agent header
	request, ok := data["request"].(map[string]interface{})
	if !ok {
		return ""
	}

	headers, ok := request["headers"].(map[string]interface{})
	if !ok {
		return ""
	}

	userAgent, ok := headers["User-Agent"].(string)
	if !ok {
		// Try lowercase version
		userAgent, ok = headers["user-agent"].(string)
		if !ok {
			return ""
		}
	}

	return userAgent
}
