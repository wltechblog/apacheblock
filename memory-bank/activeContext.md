# Active Context: ApacheBlock - reCAPTCHA Challenge Implementation

## Current Focus

The primary goal is to implement the reCAPTCHA-based unblocking mechanism as requested by the user. This involves replacing the current IP DROP firewall action with a REDIRECT action and building an internal HTTPS server within ApacheBlock to serve the challenge page.

## Recent Changes

-   Initialized the Memory Bank and `.clinerules`.
-   Implemented core reCAPTCHA challenge feature:
    -   Added configuration options (`challengeEnable`, `challengePort`, `challengeCertPath`, `recaptchaSiteKey`, `recaptchaSecretKey`, `firewallType`, `challengeTempWhitelistDuration`).
    -   Created `challenge_server.go` with HTTPS listener, SNI handling, reCAPTCHA verification, and firewall interaction.
    -   Modified `firewall.go` to add/remove `iptables` REDIRECT rules.
    -   Integrated server start into `main.go`.
    -   Updated unblocking logic in `main.go` and `socket.go`.
-   **Refinements & Fixes:**
    -   Fixed `removeRedirectRule` to handle potential duplicate rules (`firewall.go`).
    -   Updated challenge server certificate loading to strip `www.` prefix (`challenge_server.go`).
    -   Added no-cache headers to challenge/success pages (`challenge_server.go`).
    -   Implemented temporary whitelist (`temp_whitelist.go`, `types.go`, `config.go`, `process_log_entry.go`, `challenge_server.go`, `logmonitor.go`) to prevent immediate re-blocking.
    -   Added snakeoil certificate generation/fallback (`challenge_server.go`, `main.go`).
    -   Suppressed TLS handshake errors (`challenge_server.go`).
    -   Fixed startup hang by moving snakeoil generation later (`main.go`).
    -   Fixed deadlock in `applyBlockList` by removing redundant checks (`firewall.go`).
    -   Corrected firewall rule addition logic to use delete-then-insert (`firewall.go`).
    -   Fixed various compiler/syntax errors during development.
-   Updated `README.md` with feature documentation.
-   Updated Memory Bank files (`productContext.md`, `systemPatterns.md`, `techContext.md`).

## Next Steps

1.  **Update `progress.md`:** Reflect the completed implementation and fixes.
2.  **Testing:** Implement unit/integration tests for the challenge server and firewall interactions.
3.  **Commit Changes:** Commit Memory Bank updates.
4.  **Present Completion:** Inform the user of the completed implementation and documentation updates.

## Active Decisions & Considerations

-   **Firewall Tool:** Redirect feature currently only supports `iptables`. `nftables` support would require implementing equivalent NAT redirect rules.
-   **Certificate Loading:** Snakeoil fallback implemented, but relies on successful in-memory generation at startup.
-   **reCAPTCHA Version:** Using reCAPTCHA v2.
-   **HTML Template:** Currently embedded in Go code.
-   **Temporary Whitelisting:** Implemented with configurable duration.
-   **Duplicate Rule Prevention:** Delete-then-insert pattern implemented for adding rules.
