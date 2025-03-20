package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
)

const (
	// SocketPath is the path to the Unix domain socket
	SocketPath = "/var/run/apacheblock.sock"
)

// Message represents a command sent over the socket
type Message struct {
	Command string `json:"command"`
	Target  string `json:"target,omitempty"`
	Result  string `json:"result,omitempty"`
	Success bool   `json:"success"`
}

// startSocketServer starts a Unix domain socket server to listen for commands
func startSocketServer() error {
	// Remove the socket file if it already exists
	if _, err := os.Stat(SocketPath); err == nil {
		if err := os.Remove(SocketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket: %v", err)
		}
	}

	// Ensure the directory exists
	socketDir := filepath.Dir(SocketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	// Create the socket
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}

	// Set permissions on the socket
	if err := os.Chmod(SocketPath, 0660); err != nil {
		return fmt.Errorf("failed to set socket permissions: %v", err)
	}

	log.Printf("Socket server listening on %s", SocketPath)

	// Handle connections in a goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			go handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a client connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the message
	decoder := json.NewDecoder(conn)
	var msg Message
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("Error decoding message: %v", err)
		return
	}

	if debug {
		log.Printf("Received command: %s, target: %s", msg.Command, msg.Target)
	}

	// Process the command
	response := processCommand(msg)

	// Send the response
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// processCommand processes a command received over the socket
func processCommand(msg Message) Message {
	var response Message
	response.Command = msg.Command
	response.Target = msg.Target
	response.Success = false

	switch msg.Command {
	case string(BlockCommand):
		if err := clientBlockIP(msg.Target); err != nil {
			response.Result = fmt.Sprintf("Failed to block %s: %v", msg.Target, err)
		} else {
			response.Result = fmt.Sprintf("Successfully blocked %s", msg.Target)
			response.Success = true
		}

	case string(UnblockCommand):
		if err := clientUnblockIP(msg.Target); err != nil {
			response.Result = fmt.Sprintf("Failed to unblock %s: %v", msg.Target, err)
		} else {
			response.Result = fmt.Sprintf("Successfully unblocked %s", msg.Target)
			response.Success = true
		}

	case string(CheckCommand):
		isBlocked, err := isIPBlocked(msg.Target)
		if err != nil {
			response.Result = fmt.Sprintf("Failed to check %s: %v", msg.Target, err)
		} else if isBlocked {
			response.Result = fmt.Sprintf("%s is blocked", msg.Target)
			response.Success = true
		} else {
			response.Result = fmt.Sprintf("%s is not blocked", msg.Target)
			response.Success = true
		}

	case string(ListCommand):
		mu.Lock()
		ips := make([]string, 0, len(blockedIPs))
		subnets := make([]string, 0, len(blockedSubnets))
		
		for ip := range blockedIPs {
			ips = append(ips, ip)
		}
		
		for subnet := range blockedSubnets {
			subnets = append(subnets, subnet)
		}
		mu.Unlock()
		
		if len(ips) == 0 && len(subnets) == 0 {
			response.Result = "No IPs or subnets are currently blocked"
		} else {
			result := "Blocked IPs and subnets:\n"
			for _, ip := range ips {
				result += fmt.Sprintf("IP: %s\n", ip)
			}
			for _, subnet := range subnets {
				result += fmt.Sprintf("Subnet: %s\n", subnet)
			}
			response.Result = result
		}
		response.Success = true

	default:
		response.Result = fmt.Sprintf("Unknown command: %s", msg.Command)
	}

	return response
}

// sendCommand sends a command to the server over the socket
func sendCommand(command ClientCommand, target string) error {
	// Check if the socket exists
	if _, err := os.Stat(SocketPath); os.IsNotExist(err) {
		return fmt.Errorf("server socket not found at %s, server may not be running", SocketPath)
	}

	// Connect to the socket
	conn, err := net.Dial("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Create the message
	msg := Message{
		Command: string(command),
		Target:  target,
	}

	// Send the message
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return fmt.Errorf("failed to send command: %v", err)
	}

	// Read the response
	decoder := json.NewDecoder(conn)
	var response Message
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Print the result
	fmt.Println(response.Result)

	return nil
}