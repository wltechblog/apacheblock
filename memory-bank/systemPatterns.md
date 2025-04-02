# System Patterns: ApacheBlock

## Architecture Overview

ApacheBlock operates as a background service that monitors web server logs and interacts with the system firewall.

```mermaid
graph TD
    subgraph ApacheBlock Service
        direction LR
        Config[config.go] --> Main[main.go]
        LogMonitor[logmonitor.go] --> Main
        Processor[process_log_entry.go] --> LogMonitor
        Rules[rules.go] --> Processor
        Firewall[firewall.go] --> Main
        Blocklist[blocklist.go] --> Firewall
        Whitelist[whitelist.go] --> Firewall
        DomainWhitelist[domainwhitelist.go] --> Firewall
        TempWhitelist[temp_whitelist.go] --> Processor // Added
        ChallengeServer[challenge_server.go] --> Main
        ChallengeServer --> Firewall
        ChallengeServer --> TempWhitelist // Added
    end

    LogFile[/var/log/apache2/access.log] --> LogMonitor
    Main --> SystemFirewall[System Firewall (iptables/nftables)]
    User --> SystemFirewall
    SystemFirewall -- Blocked Traffic --> ChallengeServer
    ChallengeServer -- Verify --> GoogleRecaptcha[Google reCAPTCHA API]

    style GoogleRecaptcha fill:#f9f,stroke:#333,stroke-width:2px
```

## Key Components & Patterns

1.  **Configuration (`config.go`):** Loads settings from a configuration file (e.g., `config.yaml` or `config.json`). Likely uses a struct to hold configuration values.
2.  **Log Monitoring (`logmonitor.go`):** Tails or periodically reads Apache log files. Uses techniques like file watching or polling. Passes log lines to the processor.
3.  **Log Processing (`process_log_entry.go`):** Parses log lines (likely using regex or structured parsing). Extracts relevant information (IP, timestamp, request path, user agent).
4.  **Rule Engine (`rules.go`):** Evaluates extracted log data against configured rules. Rules might involve thresholds (e.g., requests per minute), specific path patterns, or user agent matching. Determines if an IP should be blocked.
5.  **Firewall Interaction (`firewall.go`):**
    *   **Legacy Mode:** Executes system commands (`iptables`, `nft`) to add/remove DROP rules for specific IPs in the `filter` table (`firewallChain`). Uses a delete-then-insert pattern (`addBlockRule`) to prevent duplicates.
    *   **Challenge Mode:** Executes system commands (`iptables`) to add/remove REDIRECT rules for specific IPs in the `nat` table (`PREROUTING` chain) targeting the `challengePort`. Uses a delete-then-insert pattern (`addRedirectRule`) to prevent duplicates. Also includes `removeRedirectRule` for unblocking.
6.  **IP/Domain Management (`blocklist.go`, `whitelist.go`, `domainwhitelist.go`):** Maintains in-memory lists or persistent storage of IPs/domains that are explicitly blocked, whitelisted (never blocked), or domain-whitelisted. Log processing checks against these lists.
7.  **Temporary Whitelist (`temp_whitelist.go` - New):**
    *   Maintains an in-memory map of IPs to expiry times.
    *   Provides functions `addTempWhitelist`, `isTempWhitelisted`, and `cleanupTempWhitelist`.
    *   Used after successful challenge completion to prevent immediate re-blocking.
    *   Log processing (`process_log_entry.go`) checks this before evaluating block rules.
8.  **Challenge Server (`challenge_server.go`):**
    *   Starts an HTTPS server listening on `challengePort` if `challengeEnable` is true.
    *   Generates an in-memory snakeoil certificate at startup (`generateAndLoadSnakeoilCert`).
    *   Uses `crypto/tls.Config.GetCertificate` for SNI: attempts to load domain-specific certs (stripping `www.`), falls back to snakeoil cert if needed.
    *   Handles requests to `/` by issuing a 302 redirect to `/recaptcha-challenge`.
    *   Serves the actual HTML challenge page on `/recaptcha-challenge` with no-cache headers and the reCAPTCHA widget.
    *   Handles verification requests (`/verify`): validates reCAPTCHA with Google, calls `removeRedirectRule`, adds IP to temporary whitelist (`addTempWhitelist`), and serves a success page with no-cache headers and cache-busting link.
    *   Suppresses TLS handshake errors via `http.Server.ErrorLog`.
9.  **Main Orchestration (`main.go`):** Initializes components, loads configuration, generates snakeoil cert (if challenge enabled), starts the log monitor, socket server, challenge server (if enabled), and periodic tasks (including temp whitelist cleanup), handles graceful shutdown.

## Technical Decisions

-   **Language:** Go (chosen for performance, concurrency, and suitability for system-level tasks).
-   **Firewall:** Interacts directly with system firewall tools (iptables/nftables) via command execution. Requires sufficient privileges. Redirect feature currently only supports `iptables`. Uses delete-then-insert pattern for adding rules to prevent duplicates.
-   **Concurrency:** Uses goroutines for log monitoring, processing, challenge server requests, socket server connections, and periodic tasks. Mutexes (`sync.Mutex`) protect shared state (blocklists, temporary whitelist, file states).
-   **State Management:** Blocked IPs/subnets persisted to JSON (`blocklist.json`). Temporary whitelist is in-memory only. Log file processing state (`fileStates`) is in-memory.
-   **(Challenge) HTTPS Handling:** Standard Go `net/http` and `crypto/tls`. Uses `GetCertificate` for SNI and in-memory snakeoil certificate generation/fallback. Suppresses `http.Server` errors (including TLS handshake) via `ErrorLog`.
-   **(Challenge) reCAPTCHA:** Server-side verification flow using Google's v2 API.
-   **(Challenge) Caching:** Uses a 302 redirect from `/` to `/recaptcha-challenge` to prevent caching of the initial blocked response. The challenge page (`/recaptcha-challenge`) and success page (`/verify` response) use no-cache HTTP headers. The success page link includes a timestamp query parameter for cache busting.
