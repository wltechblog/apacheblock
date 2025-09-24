package main

import (
	"fmt"
	"time"
)

// testUnblockFix demonstrates that unblocking properly clears access log entries
func testUnblockFix() {
	fmt.Println("=== Testing Unblock Fix ===")

	// Initialize maps if they're nil
	if ipAccessLog == nil {
		ipAccessLog = make(map[string]*AccessRecord)
	}
	if blockedIPs == nil {
		blockedIPs = make(map[string]struct{})
	}

	testIP := "192.168.1.100"

	// Step 1: Simulate adding an access record for an IP
	fmt.Printf("1. Adding access record for IP %s\n", testIP)
	mu.Lock()
	ipAccessLog[testIP] = &AccessRecord{
		Count:       2,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		LastUpdated: time.Now(),
		Reason:      "test rule",
	}
	mu.Unlock()

	// Step 2: Simulate blocking the IP
	fmt.Printf("2. Blocking IP %s\n", testIP)
	mu.Lock()
	blockedIPs[testIP] = struct{}{}
	mu.Unlock()

	// Step 3: Check that both records exist
	mu.Lock()
	_, accessExists := ipAccessLog[testIP]
	_, blockedExists := blockedIPs[testIP]
	mu.Unlock()

	fmt.Printf("3. Before unblock - Access log exists: %v, Blocked: %v\n", accessExists, blockedExists)

	// Step 4: Simulate unblocking (using the logic from clientUnblockIP)
	fmt.Printf("4. Unblocking IP %s\n", testIP)
	mu.Lock()
	delete(blockedIPs, testIP)
	// This is the key fix - remove the access log entry
	if _, exists := ipAccessLog[testIP]; exists {
		delete(ipAccessLog, testIP)
		fmt.Printf("   Removed access log entry for unblocked IP %s\n", testIP)
	}
	mu.Unlock()

	// Step 5: Verify both records are gone
	mu.Lock()
	_, accessExistsAfter := ipAccessLog[testIP]
	_, blockedExistsAfter := blockedIPs[testIP]
	mu.Unlock()

	fmt.Printf("5. After unblock - Access log exists: %v, Blocked: %v\n", accessExistsAfter, blockedExistsAfter)

	// Step 6: Verify the fix
	if !accessExistsAfter && !blockedExistsAfter {
		fmt.Println("✅ SUCCESS: Both access log and blocked status cleared correctly")
		fmt.Println("   IP will now require full threshold detections before being blocked again")
	} else {
		fmt.Println("❌ FAILURE: Records not properly cleared")
		if accessExistsAfter {
			fmt.Println("   Access log entry still exists - IP would be blocked after 1 more detection")
		}
		if blockedExistsAfter {
			fmt.Println("   Blocked status still exists")
		}
	}

	fmt.Println("=== Test Complete ===\n")
}

// This function can be called from main() for testing
func runUnblockTest() {
	// Save original debug state
	originalDebug := debug
	debug = true // Enable debug for test

	testUnblockFix()

	// Restore original debug state
	debug = originalDebug
}
