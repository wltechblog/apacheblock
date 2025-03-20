package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// processExistingLogs finds and processes existing log files
func processExistingLogs() {
	// Track which files we've seen in this run
	seenFiles := make(map[string]bool)
	
	// Use logpath instead of hardcoded logDir
	files, err := filepath.Glob(filepath.Join(logpath, "*"+fileSuffix))
	if err != nil {
		log.Printf("Failed to list log files: %v", err)
		return
	}

	if debug {
		log.Printf("Found %d log files with suffix %s", len(files), fileSuffix)
	}

	for _, file := range files {
		seenFiles[file] = true
		if debug {
			log.Printf("Found log file: %s", file)
		}
		
		// Check if we're already monitoring this file
		stateMutex.Lock()
		_, exists := fileStates[file]
		stateMutex.Unlock()
		
		if !exists {
			if debug {
				log.Printf("New log file found: %s", file)
			}
			handleLogFile(file)
		} else if debug {
			log.Printf("Already monitoring log file: %s", file)
		}
	}
	
	// Also check subdirectories if they exist
	subdirs, err := os.ReadDir(logpath)
	if err != nil {
		log.Printf("Failed to read log directory: %v", err)
		return
	}
	
	for _, entry := range subdirs {
		if entry.IsDir() {
			subdir := filepath.Join(logpath, entry.Name())
			subfiles, err := filepath.Glob(filepath.Join(subdir, "*"+fileSuffix))
			if err != nil {
				log.Printf("Failed to list log files in subdirectory %s: %v", subdir, err)
				continue
			}
			
			if debug && len(subfiles) > 0 {
				log.Printf("Found %d log files in subdirectory %s", len(subfiles), subdir)
			}
			
			for _, file := range subfiles {
				seenFiles[file] = true
				if debug {
					log.Printf("Found log file in subdirectory: %s", file)
				}
				
				// Check if we're already monitoring this file
				stateMutex.Lock()
				_, exists := fileStates[file]
				stateMutex.Unlock()
				
				if !exists {
					if debug {
						log.Printf("New log file found in subdirectory: %s", file)
					}
					handleLogFile(file)
				} else if debug {
					log.Printf("Already monitoring log file in subdirectory: %s", file)
				}
			}
		}
	}
	
	// Check for files that have been removed
	stateMutex.Lock()
	for file := range fileStates {
		if !seenFiles[file] {
			if debug {
				log.Printf("Log file no longer exists: %s", file)
			}
			// Close the file and remove it from our state
			fileStates[file].File.Close()
			delete(fileStates, file)
		}
	}
	stateMutex.Unlock()
}

// handleLogFile processes a log file (new or existing)
func handleLogFile(filePath string) {
	if !strings.HasSuffix(filePath, fileSuffix) {
		return
	}
	
	// Get file info to check if it's a regular file
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if debug {
			log.Printf("Error getting file info for %s: %v", filePath, err)
		}
		return
	}
	
	// Skip directories and non-regular files
	if !fileInfo.Mode().IsRegular() {
		return
	}
	
	stateMutex.Lock()
	defer stateMutex.Unlock()

	// Check if we're already monitoring this file
	state, exists := fileStates[filePath]
	if exists {
		// Check if the file has been rotated (inode changed)
		existingFileInfo, err := state.File.Stat()
		if err != nil {
			log.Printf("Error getting stats for existing file %s: %v", filePath, err)
			// Close the old file and open a new one
			state.File.Close()
			delete(fileStates, filePath)
		} else if os.SameFile(existingFileInfo, fileInfo) {
			// Same file, check if it has grown
			if fileInfo.Size() > state.Size {
				if debug {
					log.Printf("File %s has grown from %d to %d bytes", 
						filePath, state.Size, fileInfo.Size())
				}
				// Update the size and process new content
				state.Size = fileInfo.Size()
				state.LastMod = fileInfo.ModTime()
				go readNewContent(filePath, state)
			}
			return
		} else {
			// Different file with same name (rotated)
			if debug {
				log.Printf("Log file rotated: %s", filePath)
			}
			state.File.Close()
			delete(fileStates, filePath)
		}
	}

	// Open the file and create a new state
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", filePath, err)
		return
	}

	// Create a new file state
	newState := &FileState{
		File:     file,
		Size:     fileInfo.Size(),
		LastMod:  fileInfo.ModTime(),
		Position: 0,
	}
	fileStates[filePath] = newState

	if debug {
		log.Printf("Starting to monitor log file: %s (size: %d bytes)", filePath, newState.Size)
	}

	// Start processing the file
	go processLogFile(filePath, newState)
}

// processLogFile processes a log file from the beginning or from the last N lines
func processLogFile(filePath string, state *FileState) {
	defer func() {
		stateMutex.Lock()
		state.File.Close()
		delete(fileStates, filePath)
		stateMutex.Unlock()
		if debug {
			log.Printf("Stopped monitoring file: %s", filePath)
		}
	}()

	// Skip to the last N lines if configured
	if startupLines > 0 {
		if err := skipToLastLines(state.File, startupLines); err != nil {
			log.Printf("Error skipping lines for file %s: %v", filePath, err)
		}
		
		// Update position after skipping
		pos, err := state.File.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Error getting file position: %v", err)
			return
		}
		state.Position = pos
	}

	// Process the file
	reader := bufio.NewReader(state.File)
	
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Check if file still exists
				if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
					if debug {
						log.Printf("Log file no longer exists: %s", filePath)
					}
					return
				}
				
				// Update position
				pos, posErr := state.File.Seek(0, io.SeekCurrent)
				if posErr != nil {
					log.Printf("Error getting file position: %v", posErr)
					return
				}
				
				stateMutex.Lock()
				state.Position = pos
				stateMutex.Unlock()
				
				// Wait a bit before trying again
				time.Sleep(1 * time.Second)
				continue
			}
			
			// Some other error occurred
			log.Printf("Error reading from file %s: %v", filePath, err)
			time.Sleep(1 * time.Second)
			continue
		}

		// Process the line
		trimmedLine := strings.TrimSpace(line)
		if verbose {
			log.Printf("Processing log line from %s: %s", filePath, trimmedLine)
		}
		processLogEntry(trimmedLine, filePath)
		
		// Update position
		pos, err := state.File.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Error getting file position: %v", err)
			return
		}
		
		stateMutex.Lock()
		state.Position = pos
		stateMutex.Unlock()
	}
}

// readNewContent reads new content from a file that has grown
func readNewContent(filePath string, state *FileState) {
	stateMutex.Lock()
	// Seek to the last known position
	_, err := state.File.Seek(state.Position, io.SeekStart)
	if err != nil {
		log.Printf("Error seeking to position %d in file %s: %v", state.Position, filePath, err)
		stateMutex.Unlock()
		return
	}
	stateMutex.Unlock()
	
	reader := bufio.NewReader(state.File)
	
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Update position
				pos, posErr := state.File.Seek(0, io.SeekCurrent)
				if posErr != nil {
					log.Printf("Error getting file position: %v", posErr)
					return
				}
				
				stateMutex.Lock()
				state.Position = pos
				stateMutex.Unlock()
				
				return
			}
			
			log.Printf("Error reading from file %s: %v", filePath, err)
			return
		}

		// Process the line
		trimmedLine := strings.TrimSpace(line)
		if verbose {
			log.Printf("Processing new log line from %s: %s", filePath, trimmedLine)
		}
		processLogEntry(trimmedLine, filePath)
		
		// Update position
		pos, err := state.File.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Error getting file position: %v", err)
			return
		}
		
		stateMutex.Lock()
		state.Position = pos
		stateMutex.Unlock()
	}
}

// checkNewSubdirectories checks for new subdirectories in the log path and adds them to the watcher
func checkNewSubdirectories(watcher *fsnotify.Watcher) {
	// Check for new subdirectories
	subdirs, err := os.ReadDir(logpath)
	if err != nil {
		log.Printf("Warning: Failed to read log directory for subdirectories: %v", err)
		return
	}
	
	for _, entry := range subdirs {
		if entry.IsDir() {
			subdir := filepath.Join(logpath, entry.Name())
			// Try to add the directory to the watcher
			// If it's already being watched, this will return an error
			if err := watcher.Add(subdir); err != nil {
				if debug {
					log.Printf("Directory already watched or error: %s - %v", subdir, err)
				}
			} else if debug {
				log.Printf("Added new subdirectory to watcher: %s", subdir)
			}
		}
	}
}

// setupLogWatcher sets up the file system watcher for log files
func setupLogWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Start the watcher goroutine
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				
				// Only log file system events in debug mode to reduce noise
				if debug {
					log.Printf("File system event: %s on %s", event.Op.String(), event.Name)
				}
				
				// Handle file creation and modification
				if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
					handleLogFile(event.Name)
				}
				
				// Handle file removal or renaming
				if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
					// The file watcher will handle this by detecting EOF and checking if the file exists
					if debug {
						log.Printf("File removed or renamed: %s", event.Name)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v\n", err)
			}
		}
	}()

	// Add the main log directory to the watcher
	if err := watcher.Add(logpath); err != nil {
		return nil, err
	}
	
	// Also watch subdirectories
	subdirs, err := os.ReadDir(logpath)
	if err != nil {
		log.Printf("Warning: Failed to read log directory for subdirectories: %v", err)
	} else {
		for _, entry := range subdirs {
			if entry.IsDir() {
				subdir := filepath.Join(logpath, entry.Name())
				if err := watcher.Add(subdir); err != nil {
					log.Printf("Warning: Failed to add subdirectory to watcher: %v", err)
				} else if debug {
					log.Printf("Added subdirectory to watcher: %s", subdir)
				}
			}
		}
	}

	return watcher, nil
}

// startPeriodicTasks starts periodic tasks like checking for new log files
func startPeriodicTasks(watcher *fsnotify.Watcher) {
	// Start a periodic check for new log files and directories
	go func() {
		// Use a longer interval for checking log files to reduce processing overhead
		logCheckTicker := time.NewTicker(5 * time.Minute)
		// Use a shorter interval for saving the blocklist and cleaning up records
		saveBlocklistTicker := time.NewTicker(1 * time.Minute)
		defer logCheckTicker.Stop()
		defer saveBlocklistTicker.Stop()
		
		for {
			select {
			case <-logCheckTicker.C:
				if debug {
					log.Println("Performing periodic check for new log files and directories")
				}
				// Check for new subdirectories to watch
				checkNewSubdirectories(watcher)
				// Process existing logs
				processExistingLogs()
				
			case <-saveBlocklistTicker.C:
				if debug {
					log.Println("Performing periodic blocklist save and cleanup")
				}
				// Periodically save the blocklist to ensure we don't lose any blocks
				if err := saveBlockList(); err != nil && debug {
					log.Printf("Warning: Failed to save blocklist during periodic check: %v", err)
				}
				// Clean up expired records
				cleanupExpiredRecords()
			}
		}
	}()
}

// processLogEntry analyzes a log entry for suspicious activity
func processLogEntry(line, filePath string) {
	// Use the rules system to match the log entry
	ip, reason, matched := matchRule(line, logFormat)
	
	if !matched {
		return
	}
	
	// Always log rule matches, even when not in verbose mode
	log.Printf("Rule match: IP=%s, Reason=%s, File=%s", ip, reason, filePath)
	
	// Check whitelist
	if isWhitelisted(ip) {
		if debug {
			log.Printf("IP %s is whitelisted, ignoring", ip)
		}
		return
	}
	
	// Check if IP or subnet is already blocked, but don't return early
	// This allows us to continue counting hits for subnet blocking
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
	
	if ipBlocked {
		if debug {
			log.Printf("IP %s is already blocked, continuing to count for subnet analysis", ip)
		}
	}
	
	if subnetBlocked {
		if debug {
			log.Printf("Subnet %s is already blocked, continuing to count for metrics", subnet)
		}
	}
	
	// If both IP and subnet are already blocked, we can skip further processing
	if ipBlocked && subnetBlocked {
		if debug {
			log.Printf("Both IP %s and subnet %s are already blocked, skipping further processing", ip, subnet)
		}
		return
	}

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
		// Always log blocking actions, even when not in verbose mode
		log.Printf("Blocking IP %s: %d/%d suspicious requests (%s)",
			ip, record.Count, ruleThreshold, record.Reason)
		
		// Only block the IP if it's not already blocked
		if !ipBlocked {
			blockIP(ip, filePath, reason)
		} else {
			log.Printf("IP %s is already blocked, ensuring firewall rule exists", ip)
			// Ensure the firewall rule exists - don't lock the mutex here
			if err := addBlockRule(ip); err != nil {
				log.Printf("Failed to ensure block rule for IP %s: %v", ip, err)
			}
		}
		
		// We already have the subnet variable from earlier
		if subnet != "" && !subnetBlocked {
			// Update subnet access count
			var count int
			mu.Lock()
			subnetAccessCount[subnet]++
			count = subnetAccessCount[subnet]
			mu.Unlock()
			
			log.Printf("Subnet %s has %d/%d IPs with suspicious activity",
				subnet, count, subnetThreshold)
			
			if count >= subnetThreshold {
				// Always log subnet blocking actions, even when not in verbose mode
				log.Printf("Blocking subnet %s: %d/%d IPs with suspicious activity",
					subnet, count, subnetThreshold)
				
				// Don't hold the mutex while calling blockSubnet
				blockSubnet(subnet)
			}
		}
	} else if debug {
		log.Printf("IP %s has %d/%d suspicious requests (%s)",
			ip, record.Count, ruleThreshold, record.Reason)
	}
}