# Product Context: ApacheBlock

## Problem Solved

Web servers are constantly under attack from malicious actors attempting various exploits (e.g., brute force, vulnerability scanning, DDoS). Manually identifying and blocking these attackers is time-consuming and inefficient. ApacheBlock automates this process by monitoring logs and applying firewall rules.

However, automated blocking can sometimes lead to false positives, blocking legitimate users or services. The current system offers no easy way for a mistakenly blocked user to regain access without manual intervention from an administrator.

## How It Should Work

1.  **Log Monitoring:** ApacheBlock continuously monitors Apache access logs.
2.  **Threat Detection:** It applies configured rules to identify patterns indicative of malicious activity originating from specific IP addresses.
3.  **Blocking Action:**
    *   **(Legacy):** Adds the malicious IP to a system firewall block rule (e.g., `iptables DROP`).
    *   **(Challenge Mode):** If `challengeEnable` is true, adds firewall rules (e.g., `iptables REDIRECT` in `nat` table) to redirect traffic (port 80/443) from the blocked IP to the `challengePort` listened to by ApacheBlock.
4.  **Challenge Flow (Challenge Mode):**
    *   ApacheBlock listens on the configured `challengePort` (HTTPS) and `challengeHTTPPort` (HTTP).
    *   HTTP requests are redirected (301) to HTTPS.
    *   Initial HTTPS requests to `/` (or any path, due to firewall redirect) are met with an HTTP 302 redirect to `/recaptcha-challenge`. This prevents caching of the block page itself.
    *   The server uses SNI to identify the requested domain for the `/recaptcha-challenge` request, strips any `www.` prefix, and attempts to load the corresponding certificate (`[domain].crt`, `[domain].key`) from `challengeCertPath`.
    *   If a domain-specific certificate isn't found, it serves a self-signed "snakeoil" certificate generated in memory at startup (this will cause browser warnings).
    *   The `/recaptcha-challenge` path serves an HTML page (with no-cache headers) explaining the block and embedding a Google reCAPTCHA v2 challenge using the configured `recaptchaSiteKey`.
    *   If a previous verification attempt failed, an error message may be displayed on this page (passed via query parameter).
5.  **Unblocking (Challenge Mode):**
    *   User submits the reCAPTCHA form from `/recaptcha-challenge` to the `/verify` endpoint on the challenge server.
    *   The server verifies the reCAPTCHA response with Google using the configured `recaptchaSecretKey`. If verification fails, it redirects back to `/recaptcha-challenge` with an error query parameter.
    *   If verification succeeds, ApacheBlock removes the redirect rule(s) for the user's IP from the firewall.
    *   The user's IP is added to a temporary whitelist for the duration specified by `challengeTempWhitelistDuration` to prevent immediate re-blocking by subsequent log entries.
    *   A success page (served with no-cache headers and a cache-busting link) is displayed.
6.  **Configuration:** Administrators can configure log paths, detection rules, blocking thresholds, whitelist/blocklist IPs, firewall type/chain, and optionally enable the challenge feature with its specific settings (`challengeEnable`, `challengePort`, `challengeCertPath`, `recaptchaSiteKey`, `recaptchaSecretKey`, `challengeTempWhitelistDuration`).

## User Experience Goals

-   **Administrators:** Easy configuration, reliable blocking, clear logging, minimal false positives.
-   **Blocked Users (Legitimate):** A clear explanation of why they were blocked and a straightforward way to unblock themselves via reCAPTCHA without needing administrator help.
