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

	// Only log count if debug enabled
	if debug {
		log.Printf("Found %d log files with suffix %s", len(files), fileSuffix)
	}

	for _, file := range files {
		seenFiles[file] = true
		if debug {
			log.Printf("Found log file: %s", file)
		} // Log file finding in debug

		// Check if we're already monitoring this file
		stateMutex.Lock()
		_, exists := fileStates[file]
		stateMutex.Unlock()

		if !exists {
			if debug {
				log.Printf("New log file found: %s", file)
			} // Log new file in debug
			handleLogFile(file)
		} else if debug {
			log.Printf("Already monitoring log file: %s", file)
		} // Log already monitoring in debug
	}

	// Also check subdirectories if they exist
	subdirs, err := os.ReadDir(logpath)
	if err != nil {
		log.Printf("Warning: Failed to read log directory: %v", err) // Keep warning
		return
	}

	for _, entry := range subdirs {
		if entry.IsDir() {
			subdir := filepath.Join(logpath, entry.Name())
			subfiles, err := filepath.Glob(filepath.Join(subdir, "*"+fileSuffix))
			if err != nil {
				log.Printf("Warning: Failed to list log files in subdirectory %s: %v", subdir, err) // Keep warning
				continue
			}

			// if debug && len(subfiles) > 0 { // Less important
			// 	log.Printf("Found %d log files in subdirectory %s", len(subfiles), subdir)
			// }

			for _, file := range subfiles {
				seenFiles[file] = true
				if debug {
					log.Printf("Found log file in subdirectory: %s", file)
				} // Log file finding in debug

				// Check if we're already monitoring this file
				stateMutex.Lock()
				_, exists := fileStates[file]
				stateMutex.Unlock()

				if !exists {
					if debug {
						log.Printf("New log file found in subdirectory: %s", file)
					} // Log new file in debug
					handleLogFile(file)
				} else if debug {
					log.Printf("Already monitoring log file in subdirectory: %s", file)
				} // Log already monitoring in debug
			}
		}
	}

	// Check for files that have been removed
	stateMutex.Lock()
	for file := range fileStates {
		if !seenFiles[file] {
			if debug {
				log.Printf("Log file no longer exists: %s", file)
			} // Log removal in debug
			// Close the file and remove it from our state
			if state, ok := fileStates[file]; ok {
				state.File.Close()
			}
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
		} // Log error in debug
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
			log.Printf("Error getting stats for existing file %s: %v", filePath, err) // Keep error
			// Close the old file and open a new one
			state.File.Close()
			delete(fileStates, filePath)
		} else if os.SameFile(existingFileInfo, fileInfo) {
			// Same file, check if it has grown
			if fileInfo.Size() > state.Size {
				if debug { // Log growth only in debug
					log.Printf("File %s has grown from %d to %d bytes",
						filePath, state.Size, fileInfo.Size())
				}
				// Update the size and process new content
				// The processLogFile goroutine will handle reading new content via its polling loop.
				// No need to explicitly call readNewContent here.
				// state.Size = fileInfo.Size() // Size update happens within processLogFile implicitly
				// state.LastMod = fileInfo.ModTime()
			}
			return
		} else {
			// Different file with same name (rotated)
			// Keep this log as rotation is important
			log.Printf("Log file rotated: %s", filePath)
			state.File.Close()
			delete(fileStates, filePath)
		}
	}

	// Open the file and create a new state
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", filePath, err) // Keep error
		return
	}

	// Create a new file state
	newState := &FileState{
		File:            file,
		Size:            fileInfo.Size(),
		LastMod:         fileInfo.ModTime(),
		Position:        0,
		LastTimestamp:   time.Time{},
		LastProcessedIP: "",
		stopChan:        make(chan struct{}), // Initialize the stop channel
	}
	fileStates[filePath] = newState

	// Keep this log as it confirms monitoring start
	log.Printf("Starting to monitor log file: %s (size: %d bytes)", filePath, newState.Size)

	// Start processing the file
	go processLogFile(filePath, newState)
}

// processLogFile processes a log file from the beginning or from the last N lines
func processLogFile(filePath string, state *FileState) {
	defer func() {
		stateMutex.Lock()
		if state.File != nil { // Check if file is already closed
			state.File.Close()
		}
		delete(fileStates, filePath)
		stateMutex.Unlock()
		// Keep this log as it confirms monitoring stop
		log.Printf("Stopped monitoring file: %s", filePath)
	}()

	// Skip to the last N lines if configured
	if startupLines > 0 {
		if err := skipToLastLines(state.File, startupLines); err != nil {
			log.Printf("Error skipping lines for file %s: %v", filePath, err) // Keep error
		}

		// Update position after skipping
		pos, err := state.File.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Error getting file position: %v", err) // Keep error
			return
		}
		state.Position = pos
	}

	// Process the file
	reader := bufio.NewReader(state.File)
	ticker := time.NewTicker(1 * time.Second) // Ticker for periodic checks when at EOF
	defer ticker.Stop()

	for {
		// Check if we should stop before trying to read
		select {
		case <-state.stopChan:
			log.Printf("Stop signal received for %s, exiting goroutine.", filePath)
			return // Exit gracefully
		default:
			// Continue processing
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// --- Handle EOF ---
				// Use ticker to wait before next check, but also check stopChan
				select {
				case <-state.stopChan:
					log.Printf("Stop signal received during EOF wait for %s, exiting goroutine.", filePath)
					return
				case <-ticker.C:
					// Ticker fired, proceed with EOF checks
				}

				// Check current file status
				currentFileInfo, statErr := os.Stat(filePath)
				if os.IsNotExist(statErr) {
					if debug {
						log.Printf("Log file %s no longer exists.", filePath)
					}
					return // Exit goroutine if file is gone
				}
				if statErr != nil {
					log.Printf("Error getting stats for %s during EOF check: %v", filePath, statErr)
					time.Sleep(5 * time.Second) // Wait longer on stat error
					continue
				}

				// Check for rotation (inode change)
				existingFileInfo, err := state.File.Stat()
				if err != nil {
					log.Printf("Error getting stats for existing file handle %s: %v", filePath, err)
					time.Sleep(5 * time.Second) // Wait longer on stat error
					continue
				}

				if !os.SameFile(existingFileInfo, currentFileInfo) {
					// --- Handle Rotation ---
					log.Printf("Log file rotated: %s", filePath)
					state.File.Close() // Close the old file handle

					newFile, openErr := os.Open(filePath)
					if openErr != nil {
						log.Printf("Failed to open rotated log file %s: %v", filePath, openErr)
						return // Exit goroutine if we can't open the new file
					}

					// Update state with new file handle and info
					stateMutex.Lock()
					state.File = newFile
					state.Size = currentFileInfo.Size()
					state.LastMod = currentFileInfo.ModTime()
					state.Position = 0 // Start from beginning of new file
					stateMutex.Unlock()

					reader = bufio.NewReader(newFile) // Use new reader
					if debug {
						log.Printf("Reopened rotated log file: %s", filePath)
					}
					continue // Continue reading from the new file
				} else {
					// --- Handle No Rotation ---
					// File still exists and is the same inode. Check if it has grown.
					stateMutex.Lock() // Lock for state access
					currentPosition := state.Position
					currentSize := state.Size
					stateMutex.Unlock() // Unlock after reading

					if currentFileInfo.Size() > currentSize {
						// File has grown, update state and continue reading
						if debug {
							log.Printf("File %s grew, continuing read from position %d", filePath, currentPosition)
						}
						stateMutex.Lock()
						state.Size = currentFileInfo.Size()
						state.LastMod = currentFileInfo.ModTime()
						// Ensure reader is positioned correctly (Seek might be redundant if ReadString advanced it)
						// _, seekErr := state.File.Seek(currentPosition, io.SeekStart)
						// if seekErr != nil {
						// 	log.Printf("Error seeking to %d in %s after growth detection: %v", currentPosition, filePath, seekErr)
						//   // Decide how to handle seek error, maybe reset reader?
						// }
						stateMutex.Unlock()
						// No sleep, continue loop immediately to read new content
					} else {
						// File hasn't grown, continue loop to wait on ticker/stopChan
					}
					continue // Continue the loop (will wait on ticker/stopChan at the top)
				}
			}

			// --- Handle Other Read Errors ---
			// Check stop signal before sleeping on error
			select {
			case <-state.stopChan:
				log.Printf("Stop signal received after read error for %s, exiting goroutine.", filePath)
				return
			default:
				// No stop signal, proceed with logging and sleeping
			}
			log.Printf("Error reading from file %s: %v", filePath, err) // Keep error
			time.Sleep(1 * time.Second)
			continue
		}

		// Process the line
		trimmedLine := strings.TrimSpace(line)
		// Only log every line if verbose is enabled
		if verbose {
			log.Printf("Processing log line from %s: %s", filePath, trimmedLine)
		}
		processLogEntry(trimmedLine, filePath, state)

		// Update position and size after successful read
		pos, err := state.File.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Error getting file position after reading line in %s: %v", filePath, err)
			// Consider if we should continue or return on position error
		} else {
			stateMutex.Lock()
			state.Position = pos
			// Update size based on current position (approximation of bytes read)
			if pos > state.Size {
				state.Size = pos
			}
			stateMutex.Unlock()
		}
	}
}

// [Removed readNewContent function]
/*
func readNewContent(filePath string, state *FileState) {
	// ... entire function content removed ...
}
*/

// checkNewSubdirectories checks for new subdirectories in the log path and adds them to the watcher
func checkNewSubdirectories(watcher *fsnotify.Watcher) {
	// Check for new subdirectories
	subdirs, err := os.ReadDir(logpath)
	if err != nil {
		log.Printf("Warning: Failed to read log directory for subdirectories: %v", err) // Keep warning
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
				} // Log error in debug
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

				// Handle file removal or renaming - Close the handle and remove state
				if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
					if debug {
						log.Printf("File removed or renamed event detected: %s", event.Name)
					}
					stateMutex.Lock()
					if state, exists := fileStates[event.Name]; exists {
						log.Printf("Signaling goroutine, closing handle, and removing state for removed/renamed file: %s", event.Name)
						// Signal the goroutine to stop *before* closing the file handle
						if state.stopChan != nil {
							close(state.stopChan)
						}
						// Now close the file handle
						if state.File != nil {
							state.File.Close()
						}
						delete(fileStates, event.Name) // Remove from monitored states
					} else if debug {
						// This might happen if the event is for a file we weren't monitoring (e.g., temp file)
						log.Printf("Received remove/rename for non-monitored file: %s", event.Name)
					}
					stateMutex.Unlock()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v\n", err) // Keep watcher errors
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
		log.Printf("Warning: Failed to read log directory for subdirectories: %v", err) // Keep warning
	} else {
		for _, entry := range subdirs {
			if entry.IsDir() {
				subdir := filepath.Join(logpath, entry.Name())
				if err := watcher.Add(subdir); err != nil {
					log.Printf("Warning: Failed to add subdirectory %s to watcher: %v", subdir, err) // Keep warning
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
				} // Log periodic check in debug
				// Check for new subdirectories to watch
				checkNewSubdirectories(watcher)
				// Process existing logs
				processExistingLogs()

			case <-saveBlocklistTicker.C:
				if debug {
					log.Println("Performing periodic blocklist save and cleanup")
				} // Log periodic save/cleanup in debug
				// Periodically save the blocklist to ensure we don't lose any blocks
				if err := saveBlockList(); err != nil && debug {
					log.Printf("Warning: Failed to save blocklist during periodic check: %v", err)
				}
				// Clean up expired records
				cleanupExpiredRecords()
				// Clean up expired temporary whitelist entries
				cleanupTempWhitelist()
			}
		}
	}()

	// Start the temporary whitelist cleanup task separately
	// startTempWhitelistCleanupTask logs its own start message
	startTempWhitelistCleanupTask()
	// Keep this log as it confirms periodic tasks are running
	log.Println("Started periodic background tasks (log check, cleanup).")
}
