# Progress: ApacheBlock - reCAPTCHA Challenge Implementation

## Current Status (Feature Implemented)

-   **reCAPTCHA Challenge Feature:** Core logic implemented.
-   **Configuration:** Added `challengeEnable`, `challengePort`, `challengeCertPath`, `recaptchaSiteKey`, `recaptchaSecretKey`, `firewallType` options to `types.go`, `config.go` parser, and example config. Renamed `firewallTable` to `firewallChain`.
-   **Firewall Logic:** `firewall.go` updated with `addRedirectRule` and `removeRedirectRule` for iptables. `blockIP`, `blockSubnet`, `applyBlockList` now use redirect rules when `challengeEnable` is true.
-   **Challenge Server:** `challenge_server.go` created. Includes HTTPS server with SNI, HTML template serving, reCAPTCHA verification via Google API, and calls `removeRedirectRule` on success.
-   **Unblocking:** Logic updated in `main.go` (client mode) and `socket.go` (server mode) to remove redirect rules when `challengeEnable` is true.
-   **Integration:** `main.go` now calls `startChallengeServer()` on startup.
-   **Memory Bank:** Core files initialized and updated to reflect current state.

## What Works

-   Core log monitoring and rule-based IP blocking (using either DROP or REDIRECT based on `challengeEnable`).
-   Configuration loading, including new challenge options.
-   Whitelist/Blocklist management.
-   Challenge server starts, serves HTML, handles reCAPTCHA verification, and removes redirect rules on success.
-   Manual unblocking via command line or socket correctly removes either block or redirect rules.

## What's Left to Build

1.  **Documentation:** Update README with new configuration options and feature description.
2.  **Testing:** Implement unit tests for `verifyRecaptcha` and potentially integration tests for the challenge server flow and firewall interactions.
3.  **(Optional) Temporary Whitelisting:** Implement logic in `whitelist.go` and `challenge_server.go` to temporarily whitelist IPs after successful verification.
4.  **(Optional) nftables Support:** Implement redirect rule logic for `nftables` in `firewall.go` based on `firewallType`.

## Known Issues / Blockers

-   Need clarity on the specific firewall tool (iptables/nftables) being used or how it's configured/detected to implement the correct REDIRECT/DNAT commands. Will assume `iptables` for now.
-   Requires Google reCAPTCHA v2 Site Key and Secret Key to be obtained by the administrator.
-   Requires SSL certificates (`.key`, `.crt`, potentially `.fullchain`) for each domain to be placed in the configured directory.
