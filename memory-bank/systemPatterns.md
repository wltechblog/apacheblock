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
        ChallengeServer[(challenge_server.go - Proposed)] --> Main
        ChallengeServer --> Firewall
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
    *   **Current:** Executes system commands (`iptables`, `nft`) to add/remove DROP rules for specific IPs. Manages the lifecycle of these rules.
    *   **Proposed:** Executes system commands to add/remove REDIRECT or DNAT rules targeting a specific port listened to by ApacheBlock. Needs functions for adding redirect, removing redirect, and potentially checking existing rules.
6.  **IP/Domain Management (`blocklist.go`, `whitelist.go`, `domainwhitelist.go`):** Maintains in-memory lists or persistent storage of IPs/domains that are explicitly blocked, whitelisted (never blocked), or domain-whitelisted. Firewall interaction checks against these lists.
7.  **Challenge Server (`challenge_server.go` - Proposed):**
    *   Starts an HTTPS server listening on the configured redirect port.
    *   Uses `crypto/tls` and `GetCertificate` callback for SNI support, dynamically loading certificates based on the requested domain from the configured certificate path (`[domain].key`, `[domain].crt`).
    *   Serves a static HTML page containing the reCAPTCHA widget (using the configured site key).
    *   Provides an endpoint (e.g., `/verify`) to handle the POST request from the reCAPTCHA form.
    *   Validates the `g-recaptcha-response` token by making a request to the Google reCAPTCHA API (`https://www.google.com/recaptcha/api/siteverify`) using the configured secret key.
    *   If verification is successful, calls the Firewall Interaction component to remove the redirect rule for the client's IP address.
    *   Handles potential errors (invalid certificates, reCAPTCHA verification failure).
8.  **Main Orchestration (`main.go`):** Initializes components, loads configuration, starts the log monitor and the challenge server (proposed), and handles graceful shutdown.

## Technical Decisions

-   **Language:** Go (chosen for performance, concurrency, and suitability for system-level tasks).
-   **Firewall:** Interacts directly with system firewall tools (iptables/nftables) via command execution. This avoids complex kernel-level programming but requires the service to run with sufficient privileges.
-   **Concurrency:** Likely uses goroutines for log monitoring, processing, and potentially handling challenge server requests concurrently.
-   **State Management:** Blocked IPs and rules might be managed in memory, potentially with persistence or reconciliation on startup.
-   **(Proposed) HTTPS Handling:** Standard Go `net/http` and `crypto/tls` libraries for the challenge server.
-   **(Proposed) reCAPTCHA:** Server-side verification flow using Google's API.
