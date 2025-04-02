package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Global variable to hold the in-memory snakeoil certificate
var snakeoilCertificate tls.Certificate

const challengeHTMLTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied - Verification Required</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background-color: #f0f0f0; }
        .container { background-color: #fff; padding: 30px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h1 { color: #cc0000; }
        p { line-height: 1.6; }
        .g-recaptcha { margin-top: 20px; margin-bottom: 20px; }
        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .error { color: red; margin-top: 10px; }
    </style>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <div class="container">
        <h1>Access Temporarily Restricted</h1>
        <p>Our system has detected unusual activity from your IP address ({{.IPAddress}}). To protect the service, access has been temporarily restricted.</p>
        <p>Please complete the challenge below to regain access.</p>
        
        <form action="/verify" method="POST">
            <div class="g-recaptcha" data-sitekey="{{.RecaptchaSiteKey}}"></div>
            <button type="submit">Verify</button>
        </form>
        {{if .ErrorMessage}}
        <p class="error">{{.ErrorMessage}}</p>
        {{end}}
    </div>
</body>
</html>
`

var compiledTemplate *template.Template

// Initialize the template
func init() {
	var err error
	compiledTemplate, err = template.New("challenge").Parse(challengeHTMLTemplate)
	if err != nil {
		log.Fatalf("Failed to parse challenge HTML template: %v", err)
	}
}

// generateAndLoadSnakeoilCert generates a self-signed certificate and key in memory
// and loads it into the global snakeoilCertificate variable.
func generateAndLoadSnakeoilCert() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	// Make cert valid for 10 years, similar to openssl command
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ApacheBlock SnakeOil"},
			CommonName:   "localhost", // Common fallback CN
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate and key to PEM format in memory
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Load the PEM data into a tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to load generated key pair: %w", err)
	}

	snakeoilCertificate = cert
	log.Println("Successfully generated and loaded in-memory snakeoil certificate.")
	return nil
}

// startChallengeServer initializes and starts the HTTPS challenge server.
// Assumes generateAndLoadSnakeoilCert() has already been called successfully.
func startChallengeServer() {
	if !challengeEnable {
		log.Println("Challenge server disabled by configuration.")
		return
	}
	if recaptchaSiteKey == "" || recaptchaSecretKey == "" {
		log.Println("Challenge server disabled: reCAPTCHA keys not configured.")
		return
	}
	if challengeCertPath == "" {
		log.Println("Challenge server disabled: Certificate path not configured.")
		return
	}

	// Check if cert path exists
	if _, err := os.Stat(challengeCertPath); os.IsNotExist(err) {
		log.Printf("Challenge server disabled: Certificate path '%s' does not exist.", challengeCertPath)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleChallengeRequest)
	mux.HandleFunc("/verify", handleVerifyRequest)

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Dynamically load certificate based on SNI, stripping www. prefix
			serverName := hello.ServerName
			baseDomain := serverName
			if strings.HasPrefix(serverName, "www.") {
				baseDomain = strings.TrimPrefix(serverName, "www.")
				if debug {
					log.Printf("Challenge Server: Stripped 'www.' prefix from SNI '%s', using base domain '%s'", serverName, baseDomain)
				}
			}

			certPath := filepath.Join(challengeCertPath, baseDomain+".crt")
			keyPath := filepath.Join(challengeCertPath, baseDomain+".key")

			if debug {
				log.Printf("Challenge Server: Attempting to load cert for SNI '%s' (using base domain '%s') from %s and %s", serverName, baseDomain, certPath, keyPath)
			}

			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				// Log the specific error if debug is enabled
				if debug {
					log.Printf("Challenge Server: Failed to load key pair for SNI '%s' (using base domain '%s'): %v. Falling back to snakeoil.", serverName, baseDomain, err)
				}
				// Fallback to the generated snakeoil certificate
				return &snakeoilCertificate, nil
			}
			if debug {
				log.Printf("Challenge Server: Successfully loaded specific cert for SNI '%s' (using base domain '%s')", serverName, baseDomain)
			}
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12, // Enforce modern TLS versions
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", challengePort),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		// Suppress TLS handshake errors by redirecting the server's error log
		ErrorLog: log.New(io.Discard, "", 0),
	}

	log.Printf("Starting Challenge HTTPS server on port %d", challengePort)
	go func() {
		// Pass snakeoil cert/key paths as placeholders; GetCertificate handles the actual loading.
		// Using ListenAndServeTLS directly with GetCertificate is preferred.
		err := server.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			// Log fatal errors unless it's the expected server closed error.
			log.Printf("Challenge server ListenAndServeTLS error: %v", err)
		}
	}()
}

// handleChallengeRequest serves the HTML page with the reCAPTCHA challenge.
func handleChallengeRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract client IP - handle potential proxies later if needed
	clientIP := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	} else if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// Take the first IP in the list
		parts := strings.Split(forwardedFor, ",")
		clientIP = strings.TrimSpace(parts[0])
	}
	// Remove port if present
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	data := struct {
		IPAddress        string
		RecaptchaSiteKey string
		ErrorMessage     string // Optional: For displaying errors after failed verification redirect
	}{
		IPAddress:        clientIP,
		RecaptchaSiteKey: recaptchaSiteKey,
		ErrorMessage:     r.URL.Query().Get("error"), // Get error from query param
	}

	// Set cache-control headers
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := compiledTemplate.Execute(w, data)
	if err != nil {
		log.Printf("Error executing challenge template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleVerifyRequest handles the POST request from the reCAPTCHA form.
func handleVerifyRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract client IP (consistent with handleChallengeRequest)
	clientIP := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	} else if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		clientIP = strings.TrimSpace(parts[0])
	}
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	recaptchaResponse := r.FormValue("g-recaptcha-response")
	if recaptchaResponse == "" {
		log.Printf("Verification failed for %s: No reCAPTCHA response", clientIP)
		http.Redirect(w, r, "/?error=Missing+reCAPTCHA+response", http.StatusSeeOther)
		return
	}

	// Verify the reCAPTCHA response with Google
	verified, err := verifyRecaptcha(recaptchaResponse, clientIP)
	if err != nil {
		log.Printf("Error verifying reCAPTCHA for %s: %v", clientIP, err)
		http.Redirect(w, r, "/?error=Verification+error", http.StatusSeeOther)
		return
	}

	if !verified {
		log.Printf("Verification failed for %s: Invalid reCAPTCHA response", clientIP)
		http.Redirect(w, r, "/?error=Invalid+reCAPTCHA", http.StatusSeeOther)
		return
	}

	// --- Verification Successful ---
	log.Printf("Verification successful for IP: %s", clientIP)

	// Remove the redirect rule for this IP
	err = removeRedirectRule(clientIP)
	if err != nil {
		log.Printf("Failed to remove redirect rule for %s after verification: %v", clientIP, err)
		// Inform user, but maybe don't redirect back to challenge?
		http.Error(w, "Verification successful, but failed to update firewall rules. Please contact administrator.", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully removed redirect rule for %s", clientIP)

	// Add IP to temporary whitelist
	addTempWhitelist(clientIP)

	// Display success message with cache-control headers
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
        <!DOCTYPE html>
        <html>
        <head><title>Access Restored</title><style>body { font-family: sans-serif; margin: 40px; }</style></head>
        <body>
            <h1>Access Restored</h1>
            <p>Your access has been successfully restored. You can now browse normally.</p>
            <p><a href="/">Return to site</a></p> 
        </body>
        </html>
    `) // Consider redirecting to original destination if possible/needed
}

// verifyRecaptcha sends the verification request to Google.
func verifyRecaptcha(response, remoteIP string) (bool, error) {
	apiURL := "https://www.google.com/recaptcha/api/siteverify"
	data := url.Values{}
	data.Set("secret", recaptchaSecretKey)
	data.Set("response", response)
	data.Set("remoteip", remoteIP) // Optional, but recommended

	if debug {
		log.Printf("Verifying reCAPTCHA for IP %s", remoteIP)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(apiURL, data)
	if err != nil {
		return false, fmt.Errorf("failed to contact reCAPTCHA verification server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read reCAPTCHA response body: %w", err)
	}

	if debug {
		log.Printf("reCAPTCHA verification response body: %s", string(body))
	}

	var result struct {
		Success     bool      `json:"success"`
		ChallengeTS time.Time `json:"challenge_ts"`
		Hostname    string    `json:"hostname"`
		ErrorCodes  []string  `json:"error-codes"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse reCAPTCHA response JSON: %w", err)
	}

	if !result.Success {
		log.Printf("reCAPTCHA verification failed with error codes: %v", result.ErrorCodes)
	}

	return result.Success, nil
}
