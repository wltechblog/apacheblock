package main

import (
	"net"
	"os"
	"time"
)

// getSubnet extracts the /24 subnet from an IP address
func getSubnet(ip string) string {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return ""
	}
	mask := net.CIDRMask(24, 32)
	return ipAddr.Mask(mask).String() + "/24"
}

// skipToLastLines skips to the last n lines of a file
func skipToLastLines(file *os.File, lines int) error {
	bufferSize := int64(4096)
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fileSize := fileInfo.Size()
	if fileSize == 0 {
		return nil
	}

	// Start from the end of the file
	position := fileSize - 1
	lineCount := 0
	buffer := make([]byte, bufferSize)

	// Read backwards until we find the desired number of lines
	for position > 0 && lineCount < lines {
		readSize := bufferSize
		if position < bufferSize {
			readSize = int64(position)
			position = 0
		} else {
			position -= bufferSize
		}

		_, err := file.Seek(position, 0)
		if err != nil {
			return err
		}

		bytesRead, err := file.Read(buffer[:readSize])
		if err != nil {
			return err
		}

		// Count newlines in the buffer
		for i := bytesRead - 1; i >= 0; i-- {
			if buffer[i] == '\n' {
				lineCount++
				if lineCount >= lines {
					// Seek to this position
					_, err = file.Seek(position+int64(i)+1, 0)
					return err
				}
			}
		}
	}

	// If we get here, we've read the entire file
	_, err = file.Seek(0, 0)
	return err
}

// cleanupExpiredRecords removes expired records from the ipAccessLog
func cleanupExpiredRecords() {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	for ip, record := range ipAccessLog {
		if now.After(record.ExpiresAt) {
			delete(ipAccessLog, ip)
		}
	}
}