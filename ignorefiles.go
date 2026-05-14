package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func readIgnoreFilesFile(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open ignore files list: %v", err)
	}
	defer f.Close()

	ignoredFilesMu.Lock()
	defer ignoredFilesMu.Unlock()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ignoredFiles[line] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading ignore files list: %v", err)
	}

	if debug {
		log.Printf("Loaded %d ignored file patterns from %s", len(ignoredFiles), filePath)
	}
	return nil
}

func isIgnoredFile(path string) bool {
	ignoredFilesMu.RLock()
	defer ignoredFilesMu.RUnlock()

	if ignoredFiles[path] {
		return true
	}

	base := filepath.Base(path)
	return ignoredFiles[base]
}

func createExampleIgnoreFilesFile(filePath string) error {
	content := `# Apache Block Ignored Log Files
# Add filenames (basenames) or full paths, one per line.
# Lines starting with # are comments and will be ignored.
# Examples:

# Ignore by basename (matches any file with this name in any directory)
# error.log
# access.log.1

# Ignore by full path
# /var/customers/logs/example.com/error.log
`
	return os.WriteFile(filePath, []byte(content), 0644)
}
