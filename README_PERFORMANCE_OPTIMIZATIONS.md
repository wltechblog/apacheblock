# Apache Block Performance Optimizations

This document describes performance optimizations to improve the startup time of Apache Block.

## Problem

Apache Block takes a very long time to start up, especially when there are many log files or large log files to process.

## Root Causes

1. **Sequential processing of log files**: Each log file is processed one after another
2. **Inefficient log file scanning**: The `skipToLastLines` function reads the file backwards in small chunks
3. **Processing too many log lines at startup**: The default is set to 5000 lines per log file
4. **Synchronous processing in the main thread**: The `processExistingLogs` function runs in the main thread
5. **Excessive file system operations**: Multiple directory scans and file operations

## Optimizations

### 1. Concurrent Log File Processing

The `optimizedProcessExistingLogs` function processes log files concurrently with a limit on the number of concurrent operations to avoid overwhelming the system.

### 2. Improved Line Skipping

The `improvedSkipToLastLines` function uses a more efficient approach for large line counts:
- For small line counts (≤1000), it uses the original method
- For larger line counts, it estimates the position based on average line length and seeks to that position

### 3. Reduced Default Startup Lines

The default number of log lines to process at startup has been reduced from 5000 to 1000.

### 4. Optimized File Reading

The `optimizedProcessLogFile` function uses:
- A larger buffer (64KB instead of 4KB) for better read performance
- Less frequent position updates (every 100 lines instead of every line)
- Performance metrics logging to help identify bottlenecks

### 5. Fast Startup Option

A new `-fastStartup` flag (enabled by default) allows users to choose between the optimized startup method and the original method.

## How to Apply These Optimizations

### Option 1: Replace Files

1. Replace `main.go` with `main_optimized.go`:
   ```bash
   cp main_optimized.go main.go
   ```

2. Add the optimized functions to your codebase:
   ```bash
   # Add the optimized startup functions
   cat optimized_startup.go >> logmonitor.go
   
   # Add the optimized log processing function
   cat logmonitor_optimized.go >> logmonitor.go
   ```

3. Update the `handleLogFile` function to use the optimized process function:
   ```go
   // Start processing the file
   go optimizedProcessLogFile(filePath, newState)
   ```

### Option 2: Modify Existing Files

1. Add the new functions from `optimized_startup.go` and `logmonitor_optimized.go` to your codebase.

2. Update `main.go` to include the new `-fastStartup` flag and use the optimized functions when enabled.

3. Update the `handleLogFile` function to use the optimized process function.

## Expected Results

- **Faster Startup**: The application should start up significantly faster, especially with many log files
- **Lower CPU Usage**: More efficient processing should reduce CPU usage during startup
- **Better Scalability**: The application should handle larger log directories more gracefully

## Configuration Options

- `-startupLines=1000`: Reduce this value for faster startup (at the cost of potentially missing older suspicious activity)
- `-fastStartup=true`: Set to false to use the original startup method
- The `maxConcurrentFileProcessing` constant (default: 5) can be adjusted based on your system's capabilities

## Monitoring Performance

The optimized code includes performance logging that will show:
- How long it takes to process each log file
- The processing rate (lines per second)
- Total startup time

This information can help you fine-tune the configuration for your specific environment.