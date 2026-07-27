package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	crlf = "\r\n"
	maxMessageSize = 64 * 1024

	LETSENCRYPT_LIVE_DIR    = "/etc/letsencrypt/live/"
	LETSENCRYPT_ARCHIVE_DIR = "/etc/letsencrypt/archive/"

	rateLimitPerIP    = 10
	rateLimitBurst    = 20
	cleanupInterval   = 5 * time.Minute
)

var (
	whitelistFile   string
	blacklistFile   string
	allowedDomains  []string
	blockedDomains  []string
	allowedEmails   []string
	blockedEmails   []string
	fixedFrom       string
	messageIDDomain string
	certPath        string
	keyPath         string

	rateLimiters   = make(map[string]*rate.Limiter)
	rateLimitersMu sync.Mutex
)

type UploadResponse struct {
	Status string `json:"status"`
}

func getRateLimiter(ip string) *rate.Limiter {
	rateLimitersMu.Lock()
	defer rateLimitersMu.Unlock()

	if limiter, exists := rateLimiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Limit(rateLimitPerIP), rateLimitBurst)
	rateLimiters[ip] = limiter
	return limiter
}

func cleanupOldRateLimiters() {
	ticker := time.NewTicker(cleanupInterval)
	go func() {
		for range ticker.C {
			rateLimitersMu.Lock()
			for ip := range rateLimiters {
				delete(rateLimiters, ip)
			}
			rateLimitersMu.Unlock()
		}
	}()
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func main() {
	flag.StringVar(&whitelistFile, "w", "", "Whitelist file (one email/domain per line)")
	flag.StringVar(&blacklistFile, "b", "", "Blacklist file (one email/domain per line)")
	flag.StringVar(&fixedFrom, "f", "Hermes <noreply@oc2mx.net>", "Fixed From header address")
	flag.StringVar(&messageIDDomain, "m", "oc2mx.net", "Domain for Message-ID generation")
	flag.StringVar(&certPath, "cert", "", "Path to certificate file (overrides auto-detection)")
	flag.StringVar(&keyPath, "key", "", "Path to private key file (overrides auto-detection)")
	flag.Parse()

	if whitelistFile != "" {
		loadWhitelist(whitelistFile)
	}
	if blacklistFile != "" {
		loadBlacklist(blacklistFile)
	}

	cleanupOldRateLimiters()

	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/health", healthCheck)

	startHTTPServer()
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

func loadWhitelist(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening whitelist file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "@") {
			allowedEmails = append(allowedEmails, strings.ToLower(line))
		} else {
			allowedDomains = append(allowedDomains, strings.ToLower(line))
		}
	}
}

func loadBlacklist(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening blacklist file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "@") {
			blockedEmails = append(blockedEmails, strings.ToLower(line))
		} else {
			blockedDomains = append(blockedDomains, strings.ToLower(line))
		}
	}
}

func isAllowed(recipient string) bool {
	recipient = strings.ToLower(recipient)

	if blacklistFile != "" {
		for _, blocked := range blockedEmails {
			if blocked == recipient {
				return false
			}
		}
		parts := strings.Split(recipient, "@")
		if len(parts) == 2 {
			for _, domain := range blockedDomains {
				if domain == parts[1] {
					return false
				}
			}
		}
		return true
	}

	if whitelistFile != "" {
		for _, allowed := range allowedEmails {
			if allowed == recipient {
				return true
			}
		}
		parts := strings.Split(recipient, "@")
		if len(parts) == 2 {
			for _, domain := range allowedDomains {
				if domain == parts[1] {
					return true
				}
			}
		}
		return false
	}

	return true
}

func generateMessageID() string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	randomBytes := make([]byte, 21)
	rand.Read(randomBytes)

	var randomPart strings.Builder
	randomPart.Grow(21)
	for _, b := range randomBytes {
		randomPart.WriteByte(chars[b%byte(len(chars))])
	}

	return fmt.Sprintf("<%s@%s>", randomPart.String(), messageIDDomain)
}

func formatUTCDate() string {
	return time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
}

func modifyHeaders(original []byte) []byte {
	var buffer bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(original))

	hasMimeVersion := false
	hasContentType := false
	hasContentTransferEncoding := false
	hasSubject := false
	hasReferences := false

	var subjectHeader strings.Builder
	var referencesHeader strings.Builder
	var toHeader strings.Builder
	var otherHeaders bytes.Buffer

	inSubject := false
	inReferences := false
	inTo := false

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			break
		}

		isFolded := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')

		if isFolded {
			if inSubject {
				subjectHeader.WriteString(crlf + line)
				continue
			} else if inReferences {
				referencesHeader.WriteString(crlf + line)
				continue
			} else if inTo {
				toHeader.WriteString(" " + strings.TrimSpace(line))
				continue
			}
			otherHeaders.WriteString(crlf + line)
			continue
		}

		inSubject = false
		inReferences = false
		inTo = false

		lowerLine := strings.ToLower(line)

		if strings.HasPrefix(lowerLine, "subject:") {
			inSubject = true
			hasSubject = true
			subjectHeader.WriteString(line)
			continue
		}

		if strings.HasPrefix(lowerLine, "references:") {
			inReferences = true
			hasReferences = true
			referencesHeader.WriteString(line)
			continue
		}

		if strings.HasPrefix(lowerLine, "to:") {
			inTo = true
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				toHeader.WriteString(strings.TrimSpace(parts[1]))
			}
			continue
		}

		if strings.HasPrefix(lowerLine, "from:") ||
			strings.HasPrefix(lowerLine, "message-id:") ||
			strings.HasPrefix(lowerLine, "date:") ||
			strings.HasPrefix(lowerLine, "tx:") {
			continue
		}

		otherHeaders.WriteString(line + crlf)

		if strings.HasPrefix(lowerLine, "mime-version:") {
			hasMimeVersion = true
		}
		if strings.HasPrefix(lowerLine, "content-type:") {
			hasContentType = true
		}
		if strings.HasPrefix(lowerLine, "content-transfer-encoding:") {
			hasContentTransferEncoding = true
		}
	}

	buffer.WriteString("From: " + fixedFrom + crlf)

	if toHeader.Len() > 0 {
		buffer.WriteString("To: " + toHeader.String() + crlf)
	}

	buffer.WriteString("Comment: This message did not originate from the sender address above." + crlf)
	buffer.WriteString("\t It was sent anonymously via the Nym Mixnet." + crlf)
	buffer.WriteString("Contact: info@oc2mx.net" + crlf)

	if hasSubject {
		buffer.WriteString(subjectHeader.String() + crlf)
	}
	if hasReferences {
		buffer.WriteString(referencesHeader.String() + crlf)
	}

	buffer.WriteString("Message-ID: " + generateMessageID() + crlf)
	buffer.WriteString("Date: " + formatUTCDate() + crlf)

	buffer.WriteString(otherHeaders.String())

	if !hasMimeVersion {
		buffer.WriteString("MIME-Version: 1.0" + crlf)
	}
	if !hasContentType {
		buffer.WriteString("Content-Type: text/plain; charset=UTF-8" + crlf)
	}
	if !hasContentTransferEncoding {
		buffer.WriteString("Content-Transfer-Encoding: 8bit" + crlf)
	}

	buffer.WriteString(crlf)

	for scanner.Scan() {
		buffer.WriteString(scanner.Text() + crlf)
	}

	return buffer.Bytes()
}

func normalizeLineEndings(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte(crlf))
	return data
}

func writeJSONResponse(w http.ResponseWriter, statusCode int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(UploadResponse{Status: status})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)
	limiter := getRateLimiter(clientIP)
	if !limiter.Allow() {
		writeJSONResponse(w, http.StatusTooManyRequests, "rate_limit_exceeded")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMessageSize)
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "error")
		return
	}
	defer r.Body.Close()

	if len(content) == 0 {
		writeJSONResponse(w, http.StatusBadRequest, "error")
		return
	}

	normalized := normalizeLineEndings(content)
	modified := modifyHeaders(normalized)

	if err := forwardToPostfix(modified); err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, "error")
		return
	}

	writeJSONResponse(w, http.StatusOK, "success")
}

func parseEmailAddresses(toField string) []string {
	var addresses []string
	var current strings.Builder
	inQuote := false
	angleBracketDepth := 0

	for i := 0; i < len(toField); i++ {
		ch := toField[i]

		switch ch {
		case '"':
			inQuote = !inQuote
			current.WriteByte(ch)
		case '<':
			if !inQuote {
				angleBracketDepth++
			}
			current.WriteByte(ch)
		case '>':
			if !inQuote && angleBracketDepth > 0 {
				angleBracketDepth--
			}
			current.WriteByte(ch)
		case ',':
			if !inQuote && angleBracketDepth == 0 {
				addr := strings.TrimSpace(current.String())
				if addr != "" {
					addresses = append(addresses, addr)
				}
				current.Reset()
				continue
			}
			current.WriteByte(ch)
		default:
			current.WriteByte(ch)
		}
	}

	if addr := strings.TrimSpace(current.String()); addr != "" {
		addresses = append(addresses, addr)
	}

	return addresses
}

func extractAllRecipients(message []byte) []string {
	var recipients []string
	scanner := bufio.NewScanner(bytes.NewReader(message))
	inTo := false
	var toField strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			break
		}

		isFolded := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')

		if isFolded && inTo {
			toField.WriteString(" " + strings.TrimSpace(line))
			continue
		}

		lowerLine := strings.ToLower(line)

		if strings.HasPrefix(lowerLine, "to:") {
			inTo = true
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				toField.WriteString(strings.TrimSpace(parts[1]))
			}
			continue
		}

		if inTo {
			break
		}
	}

	if toField.Len() > 0 {
		addresses := parseEmailAddresses(toField.String())

		for _, addr := range addresses {
			email := extractEmailFromAddress(addr)
			if email != "" {
				recipients = append(recipients, email)
			}
		}
	}

	return recipients
}

func extractEmailFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)

	if idx := strings.Index(addr, "<"); idx != -1 {
		if idx2 := strings.Index(addr, ">"); idx2 != -1 {
			return strings.TrimSpace(addr[idx+1 : idx2])
		}
	}

	return addr
}

func forwardToPostfix(message []byte) error {
	recipients := extractAllRecipients(message)

	if len(recipients) == 0 {
		return fmt.Errorf("no recipient found")
	}

	var allowedRecipients []string
	for _, recipient := range recipients {
		if isAllowed(recipient) {
			allowedRecipients = append(allowedRecipients, recipient)
		}
	}

	if len(allowedRecipients) == 0 {
		return fmt.Errorf("no allowed recipients found")
	}

	host := "127.0.0.1"
	port := ":25"

	client, err := smtp.Dial(host + port)
	if err != nil {
		return fmt.Errorf("connect to Postfix: %v", err)
	}
	defer client.Quit()

	if err := client.Hello("localhost"); err != nil {
		return fmt.Errorf("EHLO: %v", err)
	}

	if err := client.Mail("noreply@oc2mx.net"); err != nil {
		return fmt.Errorf("MAIL FROM: %v", err)
	}

	for _, recipient := range allowedRecipients {
		client.Rcpt(recipient)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %v", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("write: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("close: %v", err)
	}

	return nil
}

func findLetsEncryptCert() (certFile, keyFile, domain string) {
	if _, err := os.Stat(LETSENCRYPT_LIVE_DIR); os.IsNotExist(err) {
		return "", "", ""
	}

	domains, err := os.ReadDir(LETSENCRYPT_LIVE_DIR)
	if err != nil {
		return "", "", ""
	}

	for _, d := range domains {
		if !d.IsDir() {
			continue
		}

		currentDomain := d.Name()

		possibleLocations := []struct {
			certPath string
			keyPath  string
		}{
			{
				certPath: fmt.Sprintf("%s%s/fullchain.pem", LETSENCRYPT_LIVE_DIR, currentDomain),
				keyPath:  fmt.Sprintf("%s%s/privkey.pem", LETSENCRYPT_LIVE_DIR, currentDomain),
			},
			{
				certPath: fmt.Sprintf("%s%s/%s/fullchain.pem", LETSENCRYPT_LIVE_DIR, currentDomain, currentDomain),
				keyPath:  fmt.Sprintf("%s%s/%s/privkey.pem", LETSENCRYPT_LIVE_DIR, currentDomain, currentDomain),
			},
			{
				certPath: fmt.Sprintf("%s%s/cert1.pem", LETSENCRYPT_ARCHIVE_DIR, currentDomain),
				keyPath:  fmt.Sprintf("%s%s/privkey1.pem", LETSENCRYPT_ARCHIVE_DIR, currentDomain),
			},
		}

		for _, loc := range possibleLocations {
			certInfo, err := os.Stat(loc.certPath)
			if err != nil {
				continue
			}

			keyInfo, err := os.Stat(loc.keyPath)
			if err != nil {
				continue
			}

			if certInfo.Size() == 0 || keyInfo.Size() == 0 {
				continue
			}

			return loc.certPath, loc.keyPath, currentDomain
		}
	}

	return "", "", ""
}

func validateCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	if time.Now().After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired on %s", x509Cert.NotAfter)
	}

	return nil
}

func startHTTPServer() {
	var certFile, keyFile string

	if certPath != "" && keyPath != "" {
		certFile = certPath
		keyFile = keyPath
	} else {
		certFile, keyFile, _ = findLetsEncryptCert()

		if certFile == "" || keyFile == "" {
			specificCert := "/etc/letsencrypt/live/host.domain.tld/host.domain.tld/fullchain.pem"
			specificKey := "/etc/letsencrypt/live/host.domain.tld/host.domain.tld/privkey.pem"

			if _, err := os.Stat(specificCert); err == nil {
				if _, err := os.Stat(specificKey); err == nil {
					certFile = specificCert
					keyFile = specificKey
				}
			}
		}
	}

	if certFile == "" || keyFile == "" {
		log.Fatal("No SSL certificates found. Please specify with -cert and -key flags.")
	}

	if err := validateCertificate(certFile, keyFile); err != nil {
		log.Fatalf("Certificate validation failed: %v", err)
	}

	tlsConfig := &tls.Config{
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	httpsServer := &http.Server{
		Addr:         ":443",
		Handler:      nil,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return ctx
		},
	}

	if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("HTTPS server error: %v", err)
	}
}
