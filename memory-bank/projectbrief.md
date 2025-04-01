# Project Brief: ApacheBlock

## Core Purpose

ApacheBlock is a security tool designed to protect Apache web servers by monitoring access logs, identifying potentially malicious IP addresses based on configurable rules, and automatically blocking them using system firewall rules.

## Key Goals

-   Monitor Apache access logs in real-time or near real-time.
-   Identify suspicious activity based on predefined or custom rules (e.g., excessive requests, probing for vulnerabilities, specific user agents).
-   Automatically block offending IP addresses using the system firewall (e.g., iptables, nftables).
-   Provide configuration options for rules, thresholds, whitelist/blocklist management, and logging.
-   Minimize false positives and provide mechanisms for legitimate users to regain access if mistakenly blocked.

## Scope

-   Log parsing and analysis.
-   Rule engine for identifying malicious behavior.
-   Firewall interaction for blocking/unblocking IPs.
-   Configuration management.
-   (New) Interactive challenge (reCAPTCHA) for self-unblocking.
