#!/bin/bash

# Fix the processLogEntry function calls in logmonitor.go
sed -i 's/processLogEntry(trimmedLine, filePath)/processLogEntry(trimmedLine, filePath, state)/g' logmonitor.go

# Fix the FileState struct in handleLogFile function
sed -i 's/newState := \&FileState{\n\t\t\tFile:     file,\n\t\t\tSize:     fileInfo.Size(),\n\t\t\tLastMod:  fileInfo.ModTime(),\n\t\t\tPosition: 0,\n\t\t}/newState := \&FileState{\n\t\t\tFile:            file,\n\t\t\tSize:            fileInfo.Size(),\n\t\t\tLastMod:         fileInfo.ModTime(),\n\t\t\tPosition:        0,\n\t\t\tLastTimestamp:   time.Time{},\n\t\t\tLastProcessedIP: "",\n\t\t}/g' logmonitor.go

echo "Fixed logmonitor.go"