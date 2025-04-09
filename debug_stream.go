package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Global variables for debug streaming
var (
	// Debug stream clients
	debugStreamClients      = make(map[chan string]struct{})
	debugStreamClientsMutex sync.Mutex

	// Original log writer
	originalLogWriter *os.File

	// Debug stream initialized flag
	debugStreamInitialized bool = false
)

// Custom log writer that captures log output
type debugLogWriter struct {
	originalWriter *os.File
}

// Write implements the io.Writer interface
func (w *debugLogWriter) Write(p []byte) (n int, err error) {
	// Write to the original log writer
	n, err = w.originalWriter.Write(p)
	if err != nil {
		return n, err
	}

	// Send to all debug stream clients
	debugStreamClientsMutex.Lock()
	for client := range debugStreamClients {
		select {
		case client <- string(p):
			// Successfully sent
		default:
			// Channel is full or closed, remove it
			delete(debugStreamClients, client)
		}
	}
	debugStreamClientsMutex.Unlock()

	return n, nil
}

// initDebugStream initializes the debug stream
func initDebugStream() {
	if debugStreamInitialized {
		return
	}

	// Save the original log writer
	originalLogWriter = log.Writer().(*os.File)

	// Create a new log writer that captures output
	customWriter := &debugLogWriter{
		originalWriter: originalLogWriter,
	}

	// Set the new log writer
	log.SetOutput(customWriter)

	debugStreamInitialized = true
	log.Println("Debug stream initialized")
}

// addDebugStreamClient adds a new client to receive debug stream
func addDebugStreamClient() chan string {
	// Initialize the debug stream if not already done
	if !debugStreamInitialized {
		initDebugStream()
	}

	// Create a buffered channel for the client
	client := make(chan string, 100)

	// Add the client to the map
	debugStreamClientsMutex.Lock()
	debugStreamClients[client] = struct{}{}
	clientCount := len(debugStreamClients)
	debugStreamClientsMutex.Unlock()

	log.Printf("New debug stream client connected (total: %d)", clientCount)

	return client
}

// removeDebugStreamClient removes a client from the debug stream
func removeDebugStreamClient(client chan string) {
	debugStreamClientsMutex.Lock()
	delete(debugStreamClients, client)
	clientCount := len(debugStreamClients)
	debugStreamClientsMutex.Unlock()

	// Close the channel
	close(client)

	log.Printf("Debug stream client disconnected (remaining: %d)", clientCount)
}

// sendHeartbeat sends a periodic heartbeat to all debug stream clients
// to keep the connection alive and verify it's still working
func startDebugStreamHeartbeat() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			debugStreamClientsMutex.Lock()
			clientCount := len(debugStreamClients)
			if clientCount > 0 {
				heartbeatMsg := fmt.Sprintf("[HEARTBEAT] Debug stream active with %d client(s)\n", clientCount)
				for client := range debugStreamClients {
					select {
					case client <- heartbeatMsg:
						// Successfully sent
					default:
						// Channel is full or closed, remove it
						delete(debugStreamClients, client)
					}
				}
			}
			debugStreamClientsMutex.Unlock()
		}
	}()
}
