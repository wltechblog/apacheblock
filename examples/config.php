<?php
/**
 * Apache Block Manager Configuration
 *
 * This file contains configuration settings for the Apache Block Manager web interface.
 */

$config = [
    // API key for authentication (must match the key used when starting apacheblock)
    'apiKey' => 'your-secret-key',

    // Path to the apacheblock socket
    'socketPath' => '/var/run/apacheblock.sock',

    // Path to the apacheblock executable (used as fallback if socket communication fails)
    'executablePath' => '/usr/local/bin/apacheblock',

    // Enable debug mode (logs commands to error log)
    'debug' => false,

    // Allow fallback to executable if socket fails
    'allowExecutableFallback' => false
];