<?php
/**
 * Apache Block Manager Web Interface
 *
 * A web interface for managing IP blocking with the apacheblock tool.
 */

// Load configuration
if (file_exists(__DIR__ . '/config.php')) {
    require_once __DIR__ . '/config.php';
} else {
    die('Configuration file not found. Please create config.php.');
}

// Function to execute apacheblock command via socket with fallback to executable
function executeCommand($command, $target = "") {
    global $config;

    // Try socket communication first
    $socketResult = executeCommandViaSocket($command, $target);

    // If socket communication failed and fallback is enabled, try executable
    if (!$socketResult['success'] && !empty($config['allowExecutableFallback']) && $config['allowExecutableFallback']) {
        if ($config['debug']) {
            error_log("Socket communication failed, falling back to executable");
        }
        return executeCommandViaExecutable($command, $target);
    }

    return $socketResult;
}

// Function to execute apacheblock command via socket
function executeCommandViaSocket($command, $target = "") {
    global $config;

    // Check if socket path is configured
    if (empty($config['socketPath'])) {
        return [
            'success' => false,
            'output' => "Error: Socket path not configured"
        ];
    }

    // Create message for socket communication
    $message = [
        'command' => $command,
        'target' => $target,
        'api_key' => $config['apiKey'] ?? ''
    ];

    if ($config['debug']) {
        $logMessage = json_encode($message);
        // Redact API key for logging
        $logMessage = preg_replace('/"api_key":"[^"]+/', '"api_key":"[REDACTED]', $logMessage);
        error_log("Sending command via socket: " . $logMessage);
    }

    // Connect to the socket
    $socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
    if (!$socket) {
        $errorCode = socket_last_error();
        $errorMessage = socket_strerror($errorCode);
        return [
            'success' => false,
            'output' => "Error creating socket: [$errorCode] $errorMessage"
        ];
    }

    // Set timeout to prevent hanging
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
    socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);

    // Connect to the socket
    $result = @socket_connect($socket, $config['socketPath']);
    if (!$result) {
        $errorCode = socket_last_error($socket);
        $errorMessage = socket_strerror($errorCode);
        socket_close($socket);

        // If socket connection fails, try to check if the server is running
        if ($config['debug']) {
            error_log("Socket connection failed: [$errorCode] $errorMessage");
            error_log("Socket path: " . $config['socketPath']);
            error_log("Checking if socket file exists: " . (file_exists($config['socketPath']) ? 'Yes' : 'No'));
        }

        return [
            'success' => false,
            'output' => "Error connecting to apacheblock service: [$errorCode] $errorMessage\n\nThe apacheblock service may not be running."
        ];
    }

    // Send the message
    $jsonMessage = json_encode($message) . "\n";
    $writeResult = @socket_write($socket, $jsonMessage, strlen($jsonMessage));

    if ($writeResult === false) {
        $errorCode = socket_last_error($socket);
        $errorMessage = socket_strerror($errorCode);
        socket_close($socket);

        if ($config['debug']) {
            error_log("Socket write failed: [$errorCode] $errorMessage");
        }

        return [
            'success' => false,
            'output' => "Error sending command to apacheblock service: [$errorCode] $errorMessage"
        ];
    }

    // Read the response with timeout
    $response = '';
    $readResult = false;

    // Read with a timeout
    $read = [$socket];
    $write = $except = [];
    if (@socket_select($read, $write, $except, 5)) {
        while ($out = @socket_read($socket, 2048)) {
            $response .= $out;
            $readResult = true;
            if (strlen($out) < 2048) break; // If we got less than the buffer size, we're done
        }
    }

    // Close the socket
    socket_close($socket);

    if (!$readResult) {
        return [
            'success' => false,
            'output' => "No response received from apacheblock service. The service may be busy or unresponsive."
        ];
    }

    // Parse the response
    $responseData = @json_decode($response, true);
    if (!$responseData) {
        return [
            'success' => false,
            'output' => "Error parsing response from server: " . $response
        ];
    }

    return [
        'success' => $responseData['success'],
        'output' => $responseData['result']
    ];
}

// Function to execute apacheblock command via executable (fallback method)
function executeCommandViaExecutable($command, $target = "") {
    global $config;

    // Check if executable path is configured
    if (empty($config['executablePath'])) {
        return [
            'success' => false,
            'output' => "Error: Executable path not configured"
        ];
    }

    $cmd = "sudo " . $config['executablePath'] . " -{$command}";

    if (!empty($target)) {
        $cmd .= " " . escapeshellarg($target);
    }

    if (!empty($config['apiKey'])) {
        $cmd .= " -apiKey " . escapeshellarg($config['apiKey']);
    }

    if (!empty($config['socketPath'])) {
        $cmd .= " -socketPath " . escapeshellarg($config['socketPath']);
    }

    if ($config['debug']) {
        error_log("Executing command (fallback): " . preg_replace('/-apiKey\s+[^\s]+/', '-apiKey [REDACTED]', $cmd));
    }

    exec($cmd, $output, $returnCode);

    return [
        'success' => ($returnCode === 0),
        'output' => implode("\n", $output)
    ];
}

// Handle form submission
$result = null;
$action = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = isset($_POST['action']) ? $_POST['action'] : '';
    $ip = isset($_POST['ip']) ? $_POST['ip'] : '';

    switch ($action) {
        case 'block':
            $result = executeCommand('block', $ip);
            break;
        case 'unblock':
            $result = executeCommand('unblock', $ip);
            break;
        case 'check':
            $result = executeCommand('check', $ip);
            break;
        case 'list':
            $result = executeCommand('list');
            break;
        case 'refresh':
            // Just refresh the page to check service status again
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
            break;
    }
}

// Check if the apacheblock service is running
$serviceStatus = checkServiceStatus();

// Add a small delay to ensure socket is fully closed before next command
usleep(100000); // 100ms delay

// Get current list of blocked IPs
$blockedList = executeCommand('list');

// Parse the blocked list output to create a structured array
$blockedIPs = [];
$blockedSubnets = [];
if ($blockedList['success']) {
    $lines = explode("\n", $blockedList['output']);
    foreach ($lines as $line) {
        if (strpos($line, 'IP: ') === 0) {
            $blockedIPs[] = trim(substr($line, 4));
        } elseif (strpos($line, 'Subnet: ') === 0) {
            $blockedSubnets[] = trim(substr($line, 8));
        }
    }
}

// Function to check if the apacheblock service is running
function checkServiceStatus() {
    global $config;

    $debug = !empty($config['debug']) && $config['debug'];

    // Check if socket exists and is accessible
    if (empty($config['socketPath'])) {
        if ($debug) error_log("Status check: Socket path not configured");
        return [
            'running' => false,
            'message' => 'Socket path not configured'
        ];
    }

    // Check if socket file exists
    if (!file_exists($config['socketPath'])) {
        if ($debug) error_log("Status check: Socket file not found at " . $config['socketPath']);
        return [
            'running' => false,
            'message' => 'Socket file not found'
        ];
    }

    if ($debug) error_log("Status check: Socket file exists at " . $config['socketPath']);

    // Instead of just checking if the socket file exists and can be connected to,
    // let's actually try to send a simple command to verify the service is working

    // Create a test message (list command is lightweight)
    $message = [
        'command' => 'list',
        'target' => '',
        'api_key' => $config['apiKey'] ?? ''
    ];

    if ($debug) error_log("Status check: Creating socket");

    // Try to connect to the socket
    $socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
    if (!$socket) {
        $errorCode = socket_last_error();
        $errorMessage = socket_strerror($errorCode);
        if ($debug) error_log("Status check: Could not create socket: [$errorCode] $errorMessage");
        return [
            'running' => false,
            'message' => 'Could not create socket'
        ];
    }

    // Set a short timeout
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 2, 'usec' => 0]);
    socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 2, 'usec' => 0]);

    if ($debug) error_log("Status check: Connecting to socket");

    // Try to connect
    $result = @socket_connect($socket, $config['socketPath']);
    if (!$result) {
        $errorCode = socket_last_error($socket);
        $errorMessage = socket_strerror($errorCode);
        socket_close($socket);
        if ($debug) error_log("Status check: Could not connect to socket: [$errorCode] $errorMessage");
        return [
            'running' => false,
            'message' => 'Could not connect to socket'
        ];
    }

    if ($debug) error_log("Status check: Connected to socket, sending test message");

    // Send the test message
    $jsonMessage = json_encode($message) . "\n";
    $writeResult = @socket_write($socket, $jsonMessage, strlen($jsonMessage));

    if ($writeResult === false) {
        $errorCode = socket_last_error($socket);
        $errorMessage = socket_strerror($errorCode);
        socket_close($socket);
        if ($debug) error_log("Status check: Could not write to socket: [$errorCode] $errorMessage");
        return [
            'running' => false,
            'message' => 'Could not write to socket'
        ];
    }

    if ($debug) error_log("Status check: Message sent, waiting for response");

    // Try to read the response
    $response = '';
    $readResult = false;

    // Read with a timeout
    $read = [$socket];
    $write = $except = [];
    if (@socket_select($read, $write, $except, 2)) {
        while ($out = @socket_read($socket, 2048)) {
            $response .= $out;
            $readResult = true;
            if (strlen($out) < 2048) break; // If we got less than the buffer size, we're done
        }
    }

    socket_close($socket);

    if (!$readResult) {
        if ($debug) error_log("Status check: No response from service");
        return [
            'running' => false,
            'message' => 'No response from service'
        ];
    }

    if ($debug) error_log("Status check: Response received: " . substr($response, 0, 100) . (strlen($response) > 100 ? '...' : ''));

    // Try to parse the response
    $responseData = @json_decode($response, true);
    if (!$responseData) {
        if ($debug) error_log("Status check: Invalid response from service");
        return [
            'running' => false,
            'message' => 'Invalid response from service'
        ];
    }

    // If we got here, the service is running and responding
    if ($debug) error_log("Status check: Service is running");
    return [
        'running' => true,
        'message' => 'Service is running'
    ];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Apache Block Manager</title>
    <!-- Tailwind CSS via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Material Icons -->
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <!-- Custom Tailwind Config -->
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: {
                            50: '#eff6ff',
                            100: '#dbeafe',
                            200: '#bfdbfe',
                            300: '#93c5fd',
                            400: '#60a5fa',
                            500: '#3b82f6',
                            600: '#2563eb',
                            700: '#1d4ed8',
                            800: '#1e40af',
                            900: '#1e3a8a',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        /* Additional custom styles */
        .material-icons {
            vertical-align: middle;
            margin-right: 0.25rem;
        }

        /* Ripple effect for buttons */
        .ripple {
            position: relative;
            overflow: hidden;
            transform: translate3d(0, 0, 0);
        }

        .ripple:after {
            content: "";
            display: block;
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            pointer-events: none;
            background-image: radial-gradient(circle, #fff 10%, transparent 10.01%);
            background-repeat: no-repeat;
            background-position: 50%;
            transform: scale(10, 10);
            opacity: 0;
            transition: transform .5s, opacity 1s;
        }

        .ripple:active:after {
            transform: scale(0, 0);
            opacity: .3;
            transition: 0s;
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <!-- Header -->
        <header class="bg-white shadow-md rounded-lg p-6 mb-6">
            <div class="flex items-center justify-between">
                <div class="flex items-center">
                    <span class="material-icons text-4xl text-primary-600 mr-3">security</span>
                    <div>
                        <h1 class="text-2xl font-bold text-gray-800">Apache Block Manager</h1>
                        <p class="text-gray-600 mt-1">Manage blocked IP addresses and subnets</p>
                    </div>
                </div>
                <div class="flex items-center">
                    <div class="flex items-center <?php echo $serviceStatus['running'] ? 'text-green-600' : 'text-red-600'; ?> mr-2">
                        <span class="material-icons mr-1"><?php echo $serviceStatus['running'] ? 'check_circle' : 'error'; ?></span>
                        <span class="text-sm font-medium">
                            <?php echo $serviceStatus['running'] ? 'Service Running' : 'Service Not Running'; ?>
                        </span>
                    </div>
                    <?php if (!$serviceStatus['running'] && !empty($config['allowExecutableFallback']) && $config['allowExecutableFallback']): ?>
                    <div class="text-amber-600 text-sm flex items-center mr-2">
                        <span class="material-icons mr-1 text-sm">warning</span>
                        <span>Using fallback mode</span>
                    </div>
                    <?php endif; ?>
                    <form method="post" class="ml-2">
                        <input type="hidden" name="action" value="refresh">
                        <button type="submit" class="text-gray-600 hover:text-primary-600 flex items-center text-sm">
                            <span class="material-icons text-sm mr-1">refresh</span>
                            <span>Refresh</span>
                        </button>
                    </form>
                </div>
            </div>
        </header>

        <?php if (!$serviceStatus['running']): ?>
        <!-- Service Warning -->
        <div class="bg-amber-50 border-l-4 border-amber-500 text-amber-700 p-4 mb-6 rounded shadow-sm">
            <div class="flex items-center">
                <span class="material-icons mr-2">warning</span>
                <div>
                    <p class="font-bold">Warning: Apache Block Manager service is not running</p>
                    <p class="text-sm">
                        <?php if (!empty($config['allowExecutableFallback']) && $config['allowExecutableFallback']): ?>
                            Using fallback mode with direct command execution. Some features may be limited.
                        <?php else: ?>
                            Unable to communicate with the service. Please start the service or enable fallback mode in config.php.
                        <?php endif; ?>
                    </p>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- IP Management Card -->
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
            <h2 class="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <span class="material-icons mr-2">manage_accounts</span>
                Manage IP Addresses
            </h2>

            <form method="post" class="mb-4">
                <div class="mb-4">
                    <label for="ip" class="block text-sm font-medium text-gray-700 mb-1">IP Address or CIDR Range:</label>
                    <input type="text" id="ip" name="ip"
                           class="w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                           placeholder="e.g., 192.168.1.100 or 192.168.1.0/24" required>
                </div>

                <div class="flex flex-wrap gap-2">
                    <button type="submit" name="action" value="block"
                            class="ripple flex items-center px-4 py-2 bg-green-600 text-white rounded-md shadow-sm hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition-colors">
                        <span class="material-icons mr-1">block</span> Block IP
                    </button>

                    <button type="submit" name="action" value="unblock"
                            class="ripple flex items-center px-4 py-2 bg-red-600 text-white rounded-md shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition-colors">
                        <span class="material-icons mr-1">remove_circle</span> Unblock IP
                    </button>

                    <button type="submit" name="action" value="check"
                            class="ripple flex items-center px-4 py-2 bg-blue-600 text-white rounded-md shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors">
                        <span class="material-icons mr-1">search</span> Check IP
                    </button>
                </div>
            </form>

            <form method="post">
                <button type="submit" name="action" value="list"
                        class="ripple flex items-center px-4 py-2 bg-gray-600 text-white rounded-md shadow-sm hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-colors">
                    <span class="material-icons mr-1">list</span> Refresh Blocked IPs
                </button>
            </form>
        </div>

        <?php if ($result): ?>
        <!-- Result Card -->
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
            <h2 class="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <span class="material-icons mr-2"><?php echo $result['success'] ? 'check_circle' : 'error'; ?></span>
                Result
            </h2>
            <div class="<?php echo $result['success'] ? 'text-green-600' : 'text-red-600'; ?>">
                <pre class="bg-gray-100 p-4 rounded-md overflow-x-auto text-sm"><?php echo htmlspecialchars($result['output']); ?></pre>
            </div>
        </div>
        <?php endif; ?>

        <!-- Blocked IPs Card -->
        <div class="bg-white shadow-md rounded-lg p-6">
            <h2 class="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <span class="material-icons mr-2">security</span>
                Currently Blocked IPs and Subnets
            </h2>

            <?php if (empty($blockedIPs) && empty($blockedSubnets)): ?>
                <p class="text-gray-600 italic">No IPs or subnets are currently blocked.</p>
            <?php else: ?>
                <div class="grid md:grid-cols-2 gap-6">
                    <!-- Blocked IPs -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-800 mb-2">IP Addresses</h3>
                        <?php if (empty($blockedIPs)): ?>
                            <p class="text-gray-600 italic">No individual IPs blocked</p>
                        <?php else: ?>
                            <ul class="bg-gray-100 rounded-md p-3">
                                <?php foreach ($blockedIPs as $ip): ?>
                                <li class="flex justify-between items-center py-2 px-3 hover:bg-gray-200 rounded">
                                    <span class="font-mono"><?php echo htmlspecialchars($ip); ?></span>
                                    <form method="post" class="inline">
                                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
                                        <button type="submit" name="action" value="unblock"
                                                class="text-red-600 hover:text-red-800" title="Unblock this IP">
                                            <span class="material-icons">delete</span>
                                        </button>
                                    </form>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>

                    <!-- Blocked Subnets -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-800 mb-2">Subnets</h3>
                        <?php if (empty($blockedSubnets)): ?>
                            <p class="text-gray-600 italic">No subnets blocked</p>
                        <?php else: ?>
                            <ul class="bg-gray-100 rounded-md p-3">
                                <?php foreach ($blockedSubnets as $subnet): ?>
                                <li class="flex justify-between items-center py-2 px-3 hover:bg-gray-200 rounded">
                                    <span class="font-mono"><?php echo htmlspecialchars($subnet); ?></span>
                                    <form method="post" class="inline">
                                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($subnet); ?>">
                                        <button type="submit" name="action" value="unblock"
                                                class="text-red-600 hover:text-red-800" title="Unblock this subnet">
                                            <span class="material-icons">delete</span>
                                        </button>
                                    </form>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <!-- Footer -->
        <footer class="mt-8 text-center text-gray-500 text-sm">
            <p>Apache Block Manager &copy; <?php echo date('Y'); ?></p>
        </footer>
    </div>
</body>
</html>