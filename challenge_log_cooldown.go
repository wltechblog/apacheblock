package main

import (
	"log"
	"sync"
	"time"
)

// Global variables for challenge logging cooldown
var (
	// Map to track IPs that have been logged recently
	challengeLoggedIPs      map[string]time.Time // Map IP to expiry time
	challengeLoggedIPsMutex sync.Mutex           // Mutex for logged IPs map

	// Default duration for which an IP remains in the logged state (10 minutes)
	challengeLogCooldownDuration time.Duration = 10 * time.Minute
)

func init() {
	// Initialize the map
	challengeLoggedIPs = make(map[string]time.Time)
}

// addChallengeLoggedIP adds an IP address to the logged IPs map with a 10-minute expiry.
// Returns true if the IP was newly added, false if it was already in the map.
func addChallengeLoggedIP(ip string) bool {
	challengeLoggedIPsMutex.Lock()
	defer challengeLoggedIPsMutex.Unlock()

	// Check if IP is already in the map and not expired
	expiry, exists := challengeLoggedIPs[ip]
	if exists && time.Now().Before(expiry) {
		// IP is already logged and not expired
		return false
	}

	// Add or update the IP with a new expiry time
	challengeLoggedIPs[ip] = time.Now().Add(challengeLogCooldownDuration)

	// Log addition only in debug mode
	if debug {
		log.Printf("Added %s to challenge logged IPs until %s",
			ip, challengeLoggedIPs[ip].Format(time.RFC3339))
	}

	return true
}

// cleanupChallengeLoggedIPs removes expired entries from the logged IPs map.
func cleanupChallengeLoggedIPs() {
	now := time.Now()
	cleanedCount := 0

	challengeLoggedIPsMutex.Lock()
	defer challengeLoggedIPsMutex.Unlock()

	for ip, expiry := range challengeLoggedIPs {
		if now.After(expiry) {
			delete(challengeLoggedIPs, ip)
			cleanedCount++
		}
	}

	// Log cleanup count only in debug mode
	if cleanedCount > 0 && debug {
		log.Printf("Cleaned up %d expired entries from challenge logged IPs", cleanedCount)
	}
}

// startChallengeLoggedIPsCleanupTask starts a periodic task to clean up the logged IPs map.
func startChallengeLoggedIPsCleanupTask() {
	// Run cleanup immediately at startup
	go cleanupChallengeLoggedIPs()

	// Schedule periodic cleanup (every minute)
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			cleanupChallengeLoggedIPs()
		}
	}()

	// Log task start only in debug mode
	if debug {
		log.Println("Started periodic challenge logged IPs cleanup task.")
	}
}
