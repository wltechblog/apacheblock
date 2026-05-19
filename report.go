package main

import (
	"fmt"
	"log"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

func sendFalsePositiveReport(clientIP, userAgent, domainName string, blockInfo *BlockInfo) error {
	if reportEmail == "" || reportSMTPHost == "" {
		log.Printf("Warning: false positive report skipped - reportEmail and reportSMTPHost must be configured")
		return fmt.Errorf("email reporting not configured")
	}

	addr := fmt.Sprintf("%s:%d", reportSMTPHost, reportSMTPPort)
	from := reportSMTPFrom
	if from == "" {
		from = reportSMTPUser
	}

	var body strings.Builder
	body.WriteString("A blocked user has reported their block as a false positive.\r\n\r\n")
	body.WriteString("--- Client Details ---\r\n")
	body.WriteString(fmt.Sprintf("IP Address:    %s\r\n", clientIP))
	body.WriteString(fmt.Sprintf("Domain:        %s\r\n", domainName))
	body.WriteString(fmt.Sprintf("User-Agent:    %s\r\n", userAgent))
	body.WriteString(fmt.Sprintf("Reported At:   %s\r\n", time.Now().Format(time.RFC3339)))
	body.WriteString("\r\n--- Block Details ---\r\n")
	if blockInfo != nil {
		body.WriteString(fmt.Sprintf("Rule:          %s\r\n", blockInfo.Rule))
		body.WriteString(fmt.Sprintf("Blocked At:    %s\r\n", blockInfo.BlockedAt.Format(time.RFC3339)))
		body.WriteString(fmt.Sprintf("Source File:   %s\r\n", blockInfo.FilePath))
		if blockInfo.Subnet != "" {
			body.WriteString(fmt.Sprintf("Subnet Block:  %s\r\n", blockInfo.Subnet))
		}
		if blockInfo.UserAgent != "" {
			body.WriteString(fmt.Sprintf("Block UA:      %s\r\n", blockInfo.UserAgent))
		}
		body.WriteString(fmt.Sprintf("\r\n--- Triggering Log Entry ---\r\n%s\r\n", blockInfo.TriggeringRequest))
	} else {
		body.WriteString("No block metadata available (may have been blocked before startup or via manual command).\r\n")
	}

	subject := reportSubject
	if strings.Contains(subject, "{ip}") {
		subject = strings.ReplaceAll(subject, "{ip}", clientIP)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		from, reportEmail, subject, time.Now().Format(time.RFC1123Z), body.String())

	var auth smtp.Auth
	if reportSMTPUser != "" {
		auth = smtp.PlainAuth("", reportSMTPUser, reportSMTPPass, reportSMTPHost)
	}

	err := smtp.SendMail(addr, auth, from, []string{reportEmail}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send report email: %w", err)
	}

	log.Printf("Sent false positive report email for IP %s to %s", clientIP, reportEmail)
	return nil
}

func isReportingEnabled() bool {
	return reportEmail != "" && reportSMTPHost != ""
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func queryEscape(s string) string {
	return url.QueryEscape(s)
}
