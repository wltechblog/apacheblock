# Progress: ApacheBlock - reCAPTCHA Challenge Implementation

## Current Status (Feature Implemented & Refined)

-   **reCAPTCHA Challenge Feature:** Implemented and refined with fixes.
-   **Configuration:** Added all challenge options (`challengeEnable`, `challengePort`, `challengeCertPath`, `recaptchaSiteKey`, `recaptchaSecretKey`, `firewallType`, `challengeTempWhitelistDuration`). Renamed `firewallTable` to `firewallChain`.
-   **Firewall Logic:** `firewall.go` updated with robust `addRedirectRule`/`removeRedirectRule` (using delete-then-insert) and `addBlockRule` (using delete-then-insert). Blocking functions use correct rule type based on `challengeEnable`. Deadlock issue resolved.
-   **Challenge Server:** `challenge_server.go` created and enhanced: HTTPS server with SNI (strips `www.`), snakeoil fallback cert generation, HTML template serving (with no-cache headers), reCAPTCHA verification, calls `removeRedirectRule`, adds IP to temporary whitelist, serves success page (with cache-busting link), suppresses TLS errors.
-   **Temporary Whitelist:** Implemented (`temp_whitelist.go`) with configuration, add/check/cleanup functions, integrated into log processing and periodic tasks.
-   **Unblocking:** Logic updated in `main.go` (client mode) and `socket.go` (server mode) to remove correct rule type.
-   **Integration:** `main.go` calls snakeoil generation and starts challenge server/temp whitelist cleanup correctly. Startup hang issue resolved.
-   **Memory Bank:** Core files initialized and updated.
-   **Documentation:** `README.md` updated with feature details and configuration.

## What Works

-   Core log monitoring and rule-based IP blocking (using either DROP or REDIRECT based on `challengeEnable`).
-   Configuration loading, including all new challenge options.
-   Whitelist/Blocklist management.
-   Challenge server starts reliably, serves HTML, handles SNI/certs (including `www.` and snakeoil fallback), handles reCAPTCHA verification, removes redirect rules correctly, adds to temporary whitelist, and serves success page with cache controls.
-   Temporary whitelist prevents immediate re-blocking.
-   Manual unblocking via command line or socket correctly removes either block or redirect rules.
-   Duplicate firewall rules are prevented.

## What's Left to Build

1.  **Testing:** Implement unit tests (e.g., for `verifyRecaptcha`, `temp_whitelist`) and potentially integration tests for the challenge server flow and firewall interactions.
2.  **(Optional) nftables Support:** Implement redirect rule logic for `nftables` in `firewall.go` based on `firewallType`.

## Known Issues / Blockers

-   Need clarity on the specific firewall tool (iptables/nftables) being used or how it's configured/detected to implement the correct REDIRECT/DNAT commands. Will assume `iptables` for now.
-   Requires Google reCAPTCHA v2 Site Key and Secret Key to be obtained by the administrator.
-   Requires SSL certificates (`.key`, `.crt`, potentially `.fullchain`) for each domain to be placed in the configured directory.
