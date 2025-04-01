# Active Context: ApacheBlock - reCAPTCHA Challenge Implementation

## Current Focus

The primary goal is to implement the reCAPTCHA-based unblocking mechanism as requested by the user. This involves replacing the current IP DROP firewall action with a REDIRECT action and building an internal HTTPS server within ApacheBlock to serve the challenge page.

## Recent Changes

-   Initialized the Memory Bank (`projectbrief.md`, `productContext.md`, `systemPatterns.md`, `techContext.md`, `activeContext.md`, `progress.md`) and `.clinerules`.
-   **Configuration:** Added challenge feature settings (`challengeEnable`, `challengePort`, `challengeCertPath`, `recaptchaSiteKey`, `recaptchaSecretKey`, `firewallType`) to `types.go` and updated `config.go` parser and example file. Renamed `firewallTable` to `firewallChain` globally. Fixed associated redeclaration errors.
-   **Firewall Logic (`firewall.go`):**
    *   Added `addRedirectRule` and `removeRedirectRule` functions for `iptables` NAT PREROUTING.
    *   Modified `blockIP`, `blockSubnet`, and `applyBlockList` to use redirect rules when `challengeEnable` is true.
-   **Challenge Server (`challenge_server.go`):** Created the file with:
    *   HTTPS server using SNI (`GetCertificate`) to load domain-specific certs.
    *   Handler (`handleChallengeRequest`) serving an HTML page with the reCAPTCHA widget.
    *   Verification endpoint (`handleVerifyRequest`) that calls Google's API (`verifyRecaptcha`) and uses `removeRedirectRule` on success.
-   **Integration (`main.go`):** Added call to `startChallengeServer()` during server startup sequence.
-   **Unblocking Logic:** Updated `clientUnblockIP` (in `main.go`) and `processCommand` (in `socket.go`) to correctly remove either redirect or block rules based on `challengeEnable`.

## Next Steps

1.  **Update `progress.md`:** Reflect the completed implementation steps.
2.  **Update README:** Add documentation for the new configuration options and feature behavior.
3.  **Testing:** Implement unit/integration tests for the challenge server and firewall interactions.
4.  **Commit Changes:** Commit the implemented feature.
5.  **Present Completion:** Inform the user of the completed implementation.

## Active Decisions & Considerations

-   **Firewall Tool:** Need to confirm how `firewall.go` currently determines which tool (iptables/nftables) to use, or add configuration for it. The redirect/DNAT commands differ significantly. Assuming `iptables` for now unless specified otherwise.
-   **Certificate Loading:** Ensure robust error handling for missing or invalid certificates.
-   **reCAPTCHA Version:** Using reCAPTCHA v2 ("I'm not a robot" checkbox) as it's simpler for this server-side flow.
-   **HTML Template:** Embedding the HTML directly in the Go code might be simpler than managing separate template files for this single page.
-   **Temporary Whitelisting:** Consider adding the successfully verified IP to a temporary whitelist in `whitelist.go` to prevent immediate re-blocking if they trigger rules again shortly after verification.
