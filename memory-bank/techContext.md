# Tech Context: ApacheBlock

## Core Technologies

-   **Programming Language:** Go (as indicated by `.go` files, `go.mod`, `go.sum`).
-   **Firewall Interaction:** System commands (`iptables`, `nftables` - specific tool might be configurable or detected). Requires appropriate permissions for the service.
-   **Configuration:** Simple key=value format parsed by `config.go`. Example file `apacheblock.conf` generated if missing.
-   **Logging:** Standard Go `log` package. Output goes to stdout/stderr. Debug/verbose flags control level.
-   **(Challenge) HTTPS Server:** Go standard library (`net/http`, `crypto/tls`).
-   **(Challenge) Certificate Handling:** Reads private key (`.key`) and certificate (`.crt`) files from `challengeCertPath` based on SNI (strips `www.`). Uses `tls.LoadX509KeyPair`. **Crucially, the `.crt` file MUST contain the full certificate chain (server certificate followed by any intermediate certificates), especially when using certificates from CAs like Let's Encrypt (ACME).** Typically, this means the `.crt` file should be the `fullchain.pem` file provided by the ACME client. Generates and uses an in-memory self-signed certificate as a fallback if domain-specific certs fail to load or are misconfigured.
-   **(Challenge) External API:** Google reCAPTCHA v2 verification API (`https://www.google.com/recaptcha/api/siteverify`). Uses standard Go `net/http` client.
-   **(Challenge) Frontend:** Basic HTML/CSS served via an embedded Go `html/template` string in `challenge_server.go`. Includes reCAPTCHA JS API. Uses no-cache headers and cache-busting link.
-   **(Challenge) Temporary Whitelist:** In-memory map (`map[string]time.Time`) protected by `sync.Mutex`.

## Development Environment

-   **Build System:** Go modules (`go build`, `go install`).
-   **Dependencies:** Managed via `go.mod` and `go.sum`. Specific dependencies need inspection (e.g., file watching libraries, potential config parsers).
-   **Operating System:** Developed on Linux (based on typical firewall tools like iptables/nftables and common Go development environments). The service file `apacheblock.service` suggests systemd integration.
-   **Testing:** No dedicated test files visible in the root directory listing. Testing strategy is unclear. (Unit/integration tests for challenge feature are pending).

## Technical Constraints

-   Requires sufficient privileges to execute firewall commands (`iptables`).
-   Needs read access to Apache/Caddy log files specified in `logPath`.
-   **(Challenge):** Needs read access to SSL certificate files (`[domain].key` and `[domain].crt`) in `challengeCertPath` if using domain-specific certs. The `.crt` file must contain the full certificate chain.
-   **(Challenge):** Needs network access to reach the Google reCAPTCHA API endpoint (`www.google.com`).
-   **(Challenge):** The `challengePort` must be available and firewall rules must correctly redirect traffic to it (requires `firewallType=iptables`).
-   **(Challenge):** In-memory snakeoil certificate generation relies on system entropy (`crypto/rand`), moved later in startup to mitigate potential hangs.
-   Go version compatibility as defined in `go.mod`.
