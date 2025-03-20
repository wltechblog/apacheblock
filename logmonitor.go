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
		if debug {
			log.Printf("Found log file: %s", file)
		}
		go handleNewOrModifiedLog(file)
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
				if debug {
					log.Printf("Found log file in subdirectory: %s", file)
				}
				go handleNewOrModifiedLog(file)
			}
		}
	}
}

// handleNewOrModifiedLog processes a new or modified log file
func handleNewOrModifiedLog(filePath string) {
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
	
	mu.Lock()
	defer mu.Unlock()

	// Check if we're already monitoring this file
	if existingFile, exists := activeFiles[filePath]; exists {
		// Check if the file has been rotated (inode changed)
		existingFileInfo, err := existingFile.Stat()
		if err != nil {
			log.Printf("Error getting stats for existing file %s: %v", filePath, err)
			// Close the old file and open a new one
			existingFile.Close()
			delete(activeFiles, filePath)
		} else if os.SameFile(existingFileInfo, fileInfo) {
			// Same file, already monitoring
			return
		} else {
			// Different file with same name (rotated)
			if debug {
				log.Printf("Log file rotated: %s", filePath)
			}
			existingFile.Close()
			delete(activeFiles, filePath)
		}
	}

	if debug {
		log.Printf("Starting to monitor log file: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", filePath, err)
		return
	}
	activeFiles[filePath] = file

	go followLogFile(filePath, file)
}

// followLogFile continuously reads from a log file
func followLogFile(filePath string, file *os.File) {
	defer func() {
		file.Close()
		mu.Lock()
		delete(activeFiles, filePath)
		mu.Unlock()
		if debug {
			log.Printf("Stopped following file: %s", filePath)
		}
	}()

	if err := skipToLastLines(file, startupLines); err != nil {
		log.Printf("Error skipping lines for file %s: %v", filePath, err)
	}

	reader := bufio.NewReader(file)
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
				
				// Check if file has been truncated
				currentInfo, statErr := file.Stat()
				if statErr != nil {
					log.Printf("Error getting file stats: %v", statErr)
					return
				}
				
				if currentInfo.Size() == 0 {
					if debug {
						log.Printf("Log file has been truncated: %s", filePath)
					}
					// Seek to beginning of file
					file.Seek(0, io.SeekStart)
					reader = bufio.NewReader(file)
				}
				
				// Wait a bit before trying again
				time.Sleep(1 * time.Second)
				continue
			}
			
			// Some other error occurred
			log.Printf("Error reading from file %s: %v", filePath, err)
			time.Sleep(1 * time.Second)
			continue
		}

		processLogEntry(strings.TrimSpace(line), filePath)
	}
}

// processLogEntry analyzes a log entry for suspicious activity
func processLogEntry(line, filePath string) {
	// Use the rules system to match the log entry
	ip, reason, matched := matchRule(line, logFormat)
	
	if !matched {
		return
	}
	
	if debug {
		log.Printf("hit on ip %s for %s in %s", ip, reason, filePath)
	}
	
	// Check whitelist
	if isWhitelisted(ip) {
		return
	}
	
	if _, blocked := blockedIPs[ip]; blocked {
		return
	}
	if _, blocked := blockedSubnets[getSubnet(ip)]; blocked {
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
		blockIP(ip, filePath, reason)
		
		// Check if we should block the subnet
		subnet := getSubnet(ip)
		if subnet != "" {
			mu.Lock()
			subnetAccessCount[subnet]++
			count := subnetAccessCount[subnet]
			mu.Unlock()
			
			if count >= subnetThreshold {
				blockSubnet(subnet)
			}
		}
	}
}

// checkNewSubdirectories checks for new subdirectories in the log path and adds them to the watcher
func checkNewSubdirectories(watcher *fsnotify.Watcher) {
	// We need to use a mutex to protect this map
	mu.Lock()
	defer mu.Unlock()
	
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
				if debug {
					log.Printf("File system event: %s on %s", event.Op.String(), event.Name)
				}
				
				// Handle file creation and modification
				if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
					go handleNewOrModifiedLog(event.Name)
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
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				if debug {
					log.Println("Performing periodic check for new log files and directories")
				}
				// Check for new subdirectories to watch
				checkNewSubdirectories(watcher)
				// Process existing logs
				processExistingLogs()
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