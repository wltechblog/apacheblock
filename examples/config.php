<?php
/**
 * Apache Block Manager Configuration
 * 
 * This file contains configuration settings for the Apache Block Manager web interface.
 */

// API Key for authentication with the apacheblock service
// This must match the key used when starting apacheblock with the -apiKey flag
$config = [
    'apiKey' => 'your-secret-key',
    
    // Path to the apacheblock executable
    'executablePath' => '/usr/local/bin/apacheblock',
    
    // Enable debug mode (set to true to see additional information)
    'debug' => false
];