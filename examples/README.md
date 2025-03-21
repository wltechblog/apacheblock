# Apache Block Manager Web Interface

This directory contains a PHP web interface for managing IP blocking with the apacheblock tool.

## Features

- Block and unblock IP addresses and CIDR ranges
- Check if an IP is blocked
- View a list of all blocked IPs and subnets
- Service status indicator
- Socket communication with the apacheblock service
- Optional fallback to direct command execution

## Installation

1. Copy the `apacheblock.php` and `config.php` files to your web server directory.
2. Edit `config.php` to configure your settings:
   - Set the API key to match the one used by your apacheblock service
   - Set the socket path (default: `/var/run/apacheblock.sock`)
   - Configure fallback options if needed

## Configuration Options

In `config.php`, you can set the following options:

- `apiKey`: The API key for authentication (must match the key used when starting apacheblock)
- `socketPath`: Path to the apacheblock socket (default: `/var/run/apacheblock.sock`)
- `executablePath`: Path to the apacheblock executable (used as fallback if socket communication fails)
- `debug`: Enable debug mode to log commands to the error log
- `allowExecutableFallback`: Allow fallback to executable if socket communication fails

## Socket Communication

By default, the web interface communicates with the apacheblock service via a Unix domain socket. This provides several advantages:

1. No need for sudo permissions for the web server user
2. Direct communication with the running apacheblock service
3. No need to manage firewall rules from the web interface
4. Better security by not requiring shell execution

## Fallback Mode

If the apacheblock service is not running or the socket is not accessible, the web interface can optionally fall back to executing the apacheblock binary directly. This requires:

1. The web server user to have sudo permissions for the apacheblock binary
2. Setting `allowExecutableFallback` to `true` in `config.php`

Note that fallback mode is less secure and should only be used when necessary.

## Security Considerations

- Ensure that the web server user has appropriate permissions to access the socket file
- If using fallback mode, limit sudo permissions to only the necessary commands
- Protect access to the web interface using HTTP authentication or other access controls
- Consider running the web interface over HTTPS to protect API keys and other sensitive data

## Troubleshooting

If you encounter issues:

1. Check if the apacheblock service is running
2. Verify that the socket file exists and has the correct permissions
3. Check the web server error log for debug messages
4. Ensure that the API key in `config.php` matches the one used by the apacheblock service