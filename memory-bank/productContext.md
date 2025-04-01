# Product Context: ApacheBlock

## Problem Solved

Web servers are constantly under attack from malicious actors attempting various exploits (e.g., brute force, vulnerability scanning, DDoS). Manually identifying and blocking these attackers is time-consuming and inefficient. ApacheBlock automates this process by monitoring logs and applying firewall rules.

However, automated blocking can sometimes lead to false positives, blocking legitimate users or services. The current system offers no easy way for a mistakenly blocked user to regain access without manual intervention from an administrator.

## How It Should Work

1.  **Log Monitoring:** ApacheBlock continuously monitors Apache access logs.
2.  **Threat Detection:** It applies configured rules to identify patterns indicative of malicious activity originating from specific IP addresses.
3.  **Blocking Action:**
    *   **(Current):** Adds the malicious IP to a system firewall block rule (e.g., `iptables DROP`).
    *   **(Proposed):** Modifies the firewall rule to redirect traffic from the blocked IP to a specific port listened to by ApacheBlock itself.
4.  **Challenge Page (Proposed):**
    *   ApacheBlock listens on the designated redirect port.
    *   It uses SNI to identify the requested domain and serves a valid HTTPS response using certificates stored locally (e.g., `/path/to/certs/[domain].key`, `/path/to/certs/[domain].crt`).
    *   It presents an HTML page explaining the block and embedding a Google reCAPTCHA challenge.
5.  **Unblocking (Proposed):**
    *   If the user successfully solves the reCAPTCHA, ApacheBlock receives verification from Google.
    *   ApacheBlock removes the redirect rule for the user's IP from the firewall, restoring normal access.
    *   The IP might be temporarily whitelisted to prevent immediate re-blocking.
6.  **Configuration:** Administrators can configure log paths, detection rules, blocking thresholds, whitelist/blocklist IPs, the redirect port, certificate paths, and reCAPTCHA keys.

## User Experience Goals

-   **Administrators:** Easy configuration, reliable blocking, clear logging, minimal false positives.
-   **Blocked Users (Legitimate):** A clear explanation of why they were blocked and a straightforward way to unblock themselves via reCAPTCHA without needing administrator help.
