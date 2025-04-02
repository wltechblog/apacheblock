package main

import (
	"encoding/json"
	"log"
	"regexp"
	"time"
)

// Common Apache log format timestamp pattern: [day/month/year:hour:minute:second zone]
var apacheTimestampRegex = regexp.MustCompile(`\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]`)

// extractTimestamp extracts the timestamp from a log entry
func extractTimestamp(line, format string) (time.Time, bool) {
	switch format {
	case "apache":
		return extractApacheTimestamp(line)
	case "caddy":
		return extractCaddyTimestamp(line)
	default:
		return time.Time{}, false
	}
}

// extractApacheTimestamp extracts the timestamp from an Apache log entry
func extractApacheTimestamp(line string) (time.Time, bool) {
	matches := apacheTimestampRegex.FindStringSubmatch(line)
	if len(matches) < 2 {
		if verbose {
			log.Printf("Failed to extract timestamp from Apache log entry: %s", line)
		}
		return time.Time{}, false
	}

	// Apache log format: 02/Jan/2006:15:04:05 -0700
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[1])
	if err != nil {
		// Log only if verbose
		if verbose {
			log.Printf("Failed to parse timestamp from Apache log entry: %s, error: %v", matches[1], err)
		}
		return time.Time{}, false
	}

	return timestamp, true
}

// extractCaddyTimestamp extracts the timestamp from a Caddy log entry
func extractCaddyTimestamp(line string) (time.Time, bool) {
	// Caddy logs are in JSON format with a "ts" field containing the timestamp
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		if verbose {
			log.Printf("Failed to parse Caddy JSON: %v", err)
		}
		return time.Time{}, false
	}

	// Check if the "ts" field exists
	tsValue, exists := data["ts"]
	if !exists {
		if verbose {
			log.Printf("Caddy log entry missing 'ts' field: %s", line)
		}
		return time.Time{}, false
	}

	// Try to parse the timestamp as a string
	tsString, ok := tsValue.(string)
	if ok {
		timestamp, err := time.Parse(time.RFC3339, tsString)
		if err != nil {
			// Log only if verbose
			if verbose {
				log.Printf("Failed to parse timestamp from Caddy log entry: %s, error: %v", tsString, err)
			}
			return time.Time{}, false
		}
		return timestamp, true
	}

	// Try to parse the timestamp as a float (Unix timestamp)
	tsFloat, ok := tsValue.(float64)
	if ok {
		timestamp := time.Unix(int64(tsFloat), 0)
		return timestamp, true
	}

	// Log only if verbose
	if verbose {
		log.Printf("Unsupported timestamp format in Caddy log entry: %v", tsValue)
	}
	return time.Time{}, false
}

// isNewerThan checks if a timestamp is newer than another timestamp
func isNewerThan(timestamp, reference time.Time) bool {
	// If reference is zero, any timestamp is newer
	if reference.IsZero() {
		return true
	}

	// Compare timestamps
	return timestamp.After(reference)
}
