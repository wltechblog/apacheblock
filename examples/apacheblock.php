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

// Function to execute apacheblock command
function executeCommand($command, $target = "") {
    global $config;

    $cmd = "sudo " . $config['executablePath'] . " -{$command}";

    if (!empty($target)) {
        $cmd .= " " . escapeshellarg($target);
    }

    if (!empty($config['apiKey'])) {
        $cmd .= " -apiKey " . escapeshellarg($config['apiKey']);
    }

    if ($config['debug']) {
        error_log("Executing command: " . preg_replace('/-apiKey\s+[^\s]+/', '-apiKey [REDACTED]', $cmd));
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
    }
}

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
            <div class="flex items-center">
                <span class="material-icons text-4xl text-primary-600 mr-3">security</span>
                <h1 class="text-2xl font-bold text-gray-800">Apache Block Manager</h1>
            </div>
            <p class="text-gray-600 mt-2">Manage blocked IP addresses and subnets</p>
        </header>

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