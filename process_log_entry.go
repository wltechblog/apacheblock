package main

import (
	"log"
	"time"
)

// processLogEntry analyzes a log entry for suspicious activity
func processLogEntry(line, filePath string, state *FileState) {
	// Extract timestamp from the log entry
	timestamp, hasTimestamp := extractTimestamp(line, logFormat)

	// Skip processing if this entry is older than the last processed entry
	if hasTimestamp && state != nil && !isNewerThan(timestamp, state.LastTimestamp) {
		// if verbose { // This can be very noisy
		// 	log.Printf("Skipping older log entry: %s (timestamp: %s, last processed: %s)",
		// 		line, timestamp.Format(time.RFC3339), state.LastTimestamp.Format(time.RFC3339))
		// }
		return
	}

	// Use the rules system to match the log entry
	ip, reason, matched := matchRule(line, logFormat)

	if !matched {
		return
	}

	// // Skip if this is the same IP we just processed (helps avoid duplicates) - REMOVED - Rate limiting handled by ipAccessLog
	// if state != nil && ip == state.LastProcessedIP && !state.LastTimestamp.IsZero() {
	// 	// if verbose { log.Printf("Skipping duplicate IP: %s (already processed)", ip) } // Less important
	// 	return
	// }

	// Check IP whitelist
	if isWhitelisted(ip) {
		if debug {
			log.Printf("IP %s is whitelisted, ignoring", ip)
		} // Log skip in debug
		return
	}

	// Check domain whitelist
	if isDomainWhitelisted(ip) {
		if debug {
			log.Printf("IP %s belongs to a whitelisted domain, ignoring", ip)
		} // Log skip in debug
		return
	}

	// Check temporary challenge whitelist
	if isTempWhitelisted(ip) {
		if debug {
			log.Printf("IP %s is temporarily whitelisted after challenge, ignoring", ip)
		} // Log skip in debug
		return
	}

	// Check if IP or subnet is already blocked
	ipBlocked := false
	subnetBlocked := false
	subnet := getSubnet(ip)

	mu.Lock()
	if _, blocked := blockedIPs[ip]; blocked {
		ipBlocked = true
	}
	if _, blocked := blockedSubnets[subnet]; blocked {
		subnetBlocked = true
	}
	mu.Unlock()

	// If the IP is already blocked, just log it in debug mode and return
	if ipBlocked {
		if debug {
			log.Printf("IP %s is already blocked, skipping", ip)
		} // Log skip in debug
		// Update the timestamp and IP in the file state (only if needed for logic, not just logging)
		if hasTimestamp && state != nil {
			stateMutex.Lock()
			state.LastTimestamp = timestamp
			state.LastProcessedIP = ip
			stateMutex.Unlock()
		}
		return
	}

	// If the subnet is already blocked, just log it in debug mode and return
	if subnetBlocked {
		if debug {
			log.Printf("Subnet %s containing IP %s is already blocked, skipping", subnet, ip)
		} // Log skip in debug
		// Update the timestamp and IP in the file state (only if needed for logic, not just logging)
		if hasTimestamp && state != nil {
			stateMutex.Lock()
			state.LastTimestamp = timestamp
			state.LastProcessedIP = ip
			stateMutex.Unlock()
		}
		return
	}

	// Log the rule match - Keep this log as it's important
	log.Printf("Rule match: IP=%s, Reason=%s, File=%s", ip, reason, filePath)

	// Get the threshold and duration for this rule
	ruleThreshold, ruleDuration := getRuleThreshold(reason)

	mu.Lock()
	record, exists := ipAccessLog[ip]
	now := time.Now()
	if !exists {
		record = &AccessRecord{
			Count:       1,
			ExpiresAt:   now.Add(ruleDuration),
			LastUpdated: now,
			Reason:      reason,
		}
		ipAccessLog[ip] = record
	} else {
		// If this is a hit for the same rule, update the count
		if record.Reason == reason {
			record.Count++
			record.LastUpdated = now
			// If it's been a while since the last update, extend the expiration
			if now.Sub(record.LastUpdated) > time.Minute {
				record.ExpiresAt = now.Add(ruleDuration)
			}
		} else {
			// This is a hit for a different rule, create a new record
			// but keep the higher count between the two
			oldCount := record.Count
			record.Count = 1
			record.Reason = reason
			record.LastUpdated = now
			record.ExpiresAt = now.Add(ruleDuration)

			// If the old count was higher, keep it
			if oldCount > record.Count {
				record.Count = oldCount
			}
		}
	}
	mu.Unlock()

	// Check if we should block this IP
	if record.Count >= ruleThreshold {
		// Extract User-Agent if possible
		userAgent := extractUserAgent(line, logFormat)

		// Block the IP - blockIP logs the action
		blockIP(ip, filePath, reason, userAgent)

		// Check if we should block the subnet
		if subnet != "" && !disableSubnetBlocking {
			// Update subnet blocked IPs
			mu.Lock()
			if subnetBlockedIPs[subnet] == nil {
				subnetBlockedIPs[subnet] = make(map[string]struct{})
			}
			subnetBlockedIPs[subnet][ip] = struct{}{}
			count := len(subnetBlockedIPs[subnet])
			mu.Unlock()

			if debug { // Log subnet count only in debug
				log.Printf("Subnet %s has %d/%d unique IPs blocked",
					subnet, count, subnetThreshold)
			}

			if count >= subnetThreshold {
				// blockSubnet logs the action
				blockSubnet(subnet)
			}
		}
	} else if debug { // Only log count if debug enabled
		log.Printf("IP %s has %d/%d suspicious requests (%s)",
			ip, record.Count, ruleThreshold, record.Reason)
	}

	// Update the timestamp and IP in the file state
	if hasTimestamp && state != nil {
		stateMutex.Lock()
		state.LastTimestamp = timestamp
		state.LastProcessedIP = ip
		stateMutex.Unlock()

		if verbose { // Log timestamp update only in verbose
			log.Printf("Updated last processed timestamp to %s for file %s",
				timestamp.Format(time.RFC3339), filePath)
		}
	}
}
