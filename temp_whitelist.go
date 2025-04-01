package main

import (
	"log"
	"time"
)

// addTempWhitelist adds an IP address to the temporary whitelist.
func addTempWhitelist(ip string) {
	if !challengeEnable {
		return // Only use temp whitelist if challenge feature is enabled
	}

	expiry := time.Now().Add(challengeTempWhitelistDuration)
	tempWhitelistMutex.Lock()
	tempWhitelist[ip] = expiry
	tempWhitelistMutex.Unlock()

	if debug {
		log.Printf("Added %s to temporary whitelist until %s", ip, expiry.Format(time.RFC3339))
	}
}

// isTempWhitelisted checks if an IP address is currently in the temporary whitelist.
func isTempWhitelisted(ip string) bool {
	if !challengeEnable {
		return false // Only use temp whitelist if challenge feature is enabled
	}

	tempWhitelistMutex.Lock()
	expiry, exists := tempWhitelist[ip]
	tempWhitelistMutex.Unlock()

	if exists && time.Now().Before(expiry) {
		if debug {
			log.Printf("IP %s found in temporary whitelist (expires %s)", ip, expiry.Format(time.RFC3339))
		}
		return true
	}

	// If entry exists but is expired, it will be cleaned up by cleanupTempWhitelist
	return false
}

// cleanupTempWhitelist removes expired entries from the temporary whitelist.
func cleanupTempWhitelist() {
	if !challengeEnable {
		return // Only clean if challenge feature is enabled
	}

	now := time.Now()
	cleanedCount := 0

	tempWhitelistMutex.Lock()
	for ip, expiry := range tempWhitelist {
		if now.After(expiry) {
			delete(tempWhitelist, ip)
			cleanedCount++
		}
	}
	tempWhitelistMutex.Unlock()

	if cleanedCount > 0 && debug {
		log.Printf("Cleaned up %d expired entries from temporary whitelist", cleanedCount)
	}
}

// startTempWhitelistCleanupTask starts a periodic task to clean up the temporary whitelist.
func startTempWhitelistCleanupTask() {
	if !challengeEnable {
		return // Only run cleanup if challenge feature is enabled
	}

	// Run cleanup immediately at startup
	go cleanupTempWhitelist()

	// Schedule periodic cleanup (e.g., every minute)
	// The frequency can be adjusted based on expected load and whitelist duration.
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			cleanupTempWhitelist()
		}
	}()

	log.Println("Started periodic temporary whitelist cleanup task.")
}
