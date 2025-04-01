# Tech Context: ApacheBlock

## Core Technologies

-   **Programming Language:** Go (as indicated by `.go` files, `go.mod`, `go.sum`).
-   **Firewall Interaction:** System commands (`iptables`, `nftables` - specific tool might be configurable or detected). Requires appropriate permissions for the service.
-   **Configuration:** Format not explicitly defined yet (could be JSON, YAML, TOML). `config.go` handles loading.
-   **Logging:** Standard Go `log` package or a third-party library. Output likely goes to stdout/stderr or a configured log file.
-   **(Proposed) HTTPS Server:** Go standard library (`net/http`, `crypto/tls`).
-   **(Proposed) Certificate Handling:** Reading `.key` and `.crt` files from the filesystem. Requires SNI support.
-   **(Proposed) External API:** Google reCAPTCHA v2 ("I'm not a robot" checkbox) verification API (`https://www.google.com/recaptcha/api/siteverify`). Requires HTTP client functionality.
-   **(Proposed) Frontend:** Basic HTML, CSS, and JavaScript for the challenge page served by the internal HTTPS server.

## Development Environment

-   **Build System:** Go modules (`go build`, `go install`).
-   **Dependencies:** Managed via `go.mod` and `go.sum`. Specific dependencies need inspection (e.g., file watching libraries, potential config parsers).
-   **Operating System:** Developed on Linux (based on typical firewall tools like iptables/nftables and common Go development environments). The service file `apacheblock.service` suggests systemd integration.
-   **Testing:** No dedicated test files visible in the root directory listing. Testing strategy is unclear.

## Technical Constraints

-   Requires sufficient privileges to execute firewall commands.
-   Needs read access to Apache log files.
-   **(Proposed):** Needs read access to SSL certificate files.
-   **(Proposed):** Needs network access to reach the Google reCAPTCHA API endpoint.
-   **(Proposed):** The challenge server port must be available and firewall rules must correctly redirect traffic to it.
-   Go version compatibility as defined in `go.mod`.
