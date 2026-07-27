package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/rand"
    "crypto/sha3"
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "image"
    "image/color"
    "mime"
    "net"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "sync"
    "time"

    _ "github.com/mattn/go-sqlite3"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/net/proxy"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/canvas"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/dialog"
    "fyne.io/fyne/v2/layout"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2/widget"
)

type purpleThemeWrapper struct {
    base fyne.Theme
}

func (g *purpleThemeWrapper) Font(s fyne.TextStyle) fyne.Resource {
    if s.Bold && !s.Italic && !s.Monospace {
        if resourceLabGrotesqueBoldTtf != nil {
            return resourceLabGrotesqueBoldTtf
        }
    }
    return theme.DefaultTheme().Font(s)
}

func (g *purpleThemeWrapper) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
    switch name {
    case theme.ColorNamePrimary:
        return color.NRGBA{R: 122, G: 110, B: 243, A: 255}
    case theme.ColorNameForegroundOnPrimary:
        return color.NRGBA{R: 255, G: 255, B: 255, A: 255}
    case theme.ColorNameHyperlink:
        return color.NRGBA{R: 122, G: 110, B: 243, A: 255}
    default:
        return g.base.Color(name, variant)
    }
}

func (g *purpleThemeWrapper) Icon(name fyne.ThemeIconName) fyne.Resource {
    return g.base.Icon(name)
}

func (g *purpleThemeWrapper) Size(name fyne.ThemeSizeName) float32 {
    return g.base.Size(name)
}

const (
    connectionTimeout  = 60 * time.Second
    chunkSize          = 1024 * 2
    maxMessageSize     = 8 * 1024
    proxyAddress       = "127.0.0.1:1080"
    configFileName     = "Castor.json"
    maxRetries         = 3
    retryDelay         = 1 * time.Second
    DEFAULT_SERVER_URL = "https://iria.oc2mx.net/upload"
)

type FileInfo struct {
    Type   string `json:"type"`
    Name   string `json:"name"`
    Size   int64  `json:"size"`
    Chunks int    `json:"chunks"`
}

type FileChunk struct {
    Type   string `json:"type"`
    Index  int    `json:"index"`
    Total  int    `json:"total"`
    Data   []byte `json:"data"`
    IsLast bool   `json:"is_last"`
}

type UnifiedConfig struct {
    CastorURL        string     `json:"Castor_url"`
    LocalArticleDir  string     `json:"local_article_dir"`
    NNTPConfig       NNTPConfig `json:"nntp_config"`
    SavedNymXEmail    string     `json:"saved_nymx_email"`
}

type NNTPConfig struct {
    Server      string `json:"server"`
    Port        int    `json:"port"`
    Newsgroup   string `json:"newsgroup"`
    LastArticle int    `json:"last_article"`
}

type ConnectionPool struct {
    dialer proxy.Dialer
    mu     sync.Mutex
}

type FocusAwareEntry struct {
    widget.Entry
    onFocusChanged func(bool)
}

type FocusAwareMultiLineEntry struct {
    widget.Entry
    onFocusChanged func(bool)
}

type esub struct {
    key     string
    subject string
}

type fileFilter struct {
    name     string
    patterns []string
}

type Attachment struct {
    Data        []byte
    Filename    string
    ContentType string
}

type YamnOutfile struct {
    PooledDate string
    To         string
    From       string
    Subject    string
    Remailer   string
    Body       string
}

type Castor struct {
    app               fyne.App
    window            fyne.Window
    toEntry           *FocusAwareEntry
    nymxEntry          *FocusAwareEntry
    subjectEntry      *FocusAwareEntry
    followupToEntry   *FocusAwareEntry
    referencesEntry   *FocusAwareEntry
    newsgroupsEntry   *FocusAwareEntry
    textArea          *FocusAwareMultiLineEntry
    isDarkTheme       bool
    statusLabel       *widget.Label
    statusDetail      *widget.Label
    targetURL         string
    targetDomain      string
    mainScroll        *container.Scroll
    headerSection     fyne.CanvasObject
    bottomSection     fyne.CanvasObject
    bottomVisible     bool
    hideTimer         *time.Timer
    themeSwitch       *widget.Button
    infoBtn           *widget.Button
    configBtn         *widget.Button
    unifiedConfig     *UnifiedConfig
    pool              *ConnectionPool
    db                *sql.DB
    replayCache       map[string]bool
    dbMutex           sync.RWMutex
    progressBar       *widget.ProgressBar
    progressLabel     *widget.Label
    progressContainer *fyne.Container
    statusResetTimer  *time.Timer
    currentAttachment *Attachment
}

var pool = &ConnectionPool{}
var ErrNoNewArticles = errors.New("no new articles to fetch")

func initProxy() error {
    p, err := proxy.SOCKS5("tcp", proxyAddress, nil, proxy.Direct)
    if err != nil {
        return fmt.Errorf("failed to initialize SOCKS5 proxy: %v", err)
    }
    pool.dialer = p
    return nil
}

func (p *ConnectionPool) getConnection(target string) (net.Conn, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.dialer == nil {
        if err := initProxy(); err != nil {
            return nil, err
        }
    }

    for i := 0; i < maxRetries; i++ {
        conn, err := p.dialer.Dial("tcp", target)
        if err == nil {
            conn.SetDeadline(time.Now().Add(connectionTimeout))
            return conn, nil
        }
        if i < maxRetries-1 {
            time.Sleep(retryDelay)
        }
    }
    return nil, fmt.Errorf("connecting to %s via proxy after %d attempts", target, maxRetries)
}

func writeJSON(conn net.Conn, v interface{}) error {
    data, err := json.Marshal(v)
    if err != nil {
        return err
    }
    _, err = conn.Write(append(data, '\n'))
    return err
}

func readJSON(conn net.Conn, v interface{}) error {
    conn.SetReadDeadline(time.Now().Add(connectionTimeout))
    scanner := bufio.NewScanner(conn)
    if scanner.Scan() {
        return json.Unmarshal(scanner.Bytes(), v)
    }
    return scanner.Err()
}

func NewFocusAwareEntry() *FocusAwareEntry {
    entry := &FocusAwareEntry{}
    entry.ExtendBaseWidget(entry)
    return entry
}

func (e *FocusAwareEntry) FocusGained() {
    e.Entry.FocusGained()
    if e.onFocusChanged != nil {
        e.onFocusChanged(true)
    }
}

func (e *FocusAwareEntry) FocusLost() {
    e.Entry.FocusLost()
    if e.onFocusChanged != nil {
        e.onFocusChanged(false)
    }
}

func (e *FocusAwareEntry) SetOnFocusChanged(callback func(bool)) {
    e.onFocusChanged = callback
}

func NewFocusAwareMultiLineEntry() *FocusAwareMultiLineEntry {
    entry := &FocusAwareMultiLineEntry{}
    entry.MultiLine = true
    entry.Wrapping = fyne.TextWrapOff
    entry.TextStyle = fyne.TextStyle{Monospace: true}
    entry.ExtendBaseWidget(entry)
    return entry
}

func (e *FocusAwareMultiLineEntry) FocusGained() {
    e.Entry.FocusGained()
    if e.onFocusChanged != nil {
        e.onFocusChanged(true)
    }
}

func (e *FocusAwareMultiLineEntry) FocusLost() {
    e.Entry.FocusLost()
    if e.onFocusChanged != nil {
        e.onFocusChanged(false)
    }
}

func (e *FocusAwareMultiLineEntry) SetOnFocusChanged(callback func(bool)) {
    e.onFocusChanged = callback
}

func isValidEmail(email string) bool {
    pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
    matched, _ := regexp.MatchString(pattern, email)
    return matched
}

func encodeMIMESubject(input string) string {
    if input == "" {
        return ""
    }
    encoded := mime.BEncoding.Encode("UTF-8", input)
    parts := strings.Split(encoded, "?=")
    if len(parts) <= 1 {
        return encoded
    }
    var result string
    for i, part := range parts[:len(parts)-1] {
        if i > 0 {
            result += ""
        }
        result += part + "?=\n"
    }
    result += parts[len(parts)-1]
    return strings.TrimSuffix(result, "\n")
}

func wrapText(text string, maxLineLength int) string {
    if len(text) <= maxLineLength {
        return text
    }
    var result strings.Builder
    words := strings.Fields(text)
    currentLineLength := 0
    for i, word := range words {
        if i > 0 {
            word = " " + word
        }
        if currentLineLength+len(word) > maxLineLength && currentLineLength > 0 {
            result.WriteString("\n")
            result.WriteString(word[1:])
            currentLineLength = len(word) - 1
        } else {
            result.WriteString(word)
            currentLineLength += len(word)
        }
    }
    return result.String()
}

func (n *Castor) updateStatus(status string, detail string) {
    fyne.Do(func() {
        if n.statusResetTimer != nil {
            n.statusResetTimer.Stop()
            n.statusResetTimer = nil
        }

        n.statusLabel.SetText(status)
        if len(detail) > 76 {
            detail = wrapText(detail, 76)
        }
        n.statusDetail.SetText(detail)

        if status == "Complete" || status == "Error" {
            n.statusResetTimer = time.AfterFunc(5*time.Second, func() {
                fyne.Do(func() {
                    if n.statusLabel.Text == status {
                        n.statusLabel.SetText("Ready")
                        n.statusDetail.SetText("Castor ready")
                    }
                    n.statusResetTimer = nil
                })
            })
        }
    })
}

func (n *Castor) resetStatus() {
    fyne.Do(func() {
        currentText := n.statusLabel.Text
        if currentText == "Ready" || currentText == "" {
            n.statusLabel.SetText("Ready")
            currentDetail := n.statusDetail.Text
            if currentDetail != "Castor ready" && currentDetail != "" {
                n.statusDetail.SetText("Castor ready")
            }
        }
    })
}

func (n *Castor) periodicStatusReset() {
    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
            if n.window != nil {
                n.resetStatus()
            } else {
                return
            }
        }
    }()
}

func (n *Castor) getNymXHeaderForMessage() string {
    currentNymX := strings.TrimSpace(n.nymxEntry.Text)
    if currentNymX != "" {
        return currentNymX
    }
    return ""
}

func (n *Castor) buildMessage(bodyText string) string {
    var message strings.Builder

    message.WriteString("To: " + strings.TrimSpace(n.toEntry.Text) + "\n")

    if nymx := n.getNymXHeaderForMessage(); nymx != "" {
        message.WriteString("NOM: " + nymx + "\n")
    }
    if subject := strings.TrimSpace(n.subjectEntry.Text); subject != "" {
        encodedSubject := encodeMIMESubject(subject)
        message.WriteString("Subject: " + encodedSubject + "\n")
    }
    if followupTo := strings.TrimSpace(n.followupToEntry.Text); followupTo != "" {
        message.WriteString("Followup-To: " + followupTo + "\n")
    }
    if references := strings.TrimSpace(n.referencesEntry.Text); references != "" {
        message.WriteString("References: " + references + "\n")
    }
    if newsgroups := strings.TrimSpace(n.newsgroupsEntry.Text); newsgroups != "" {
        message.WriteString("Newsgroups: " + newsgroups + "\n")
    }

    message.WriteString("\n")
    message.WriteString(bodyText)

    return message.String()
}

func extractDomainFromURL(rawURL string) (string, error) {
    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        return "", err
    }
    host := parsedURL.Hostname()
    if host == "" {
        return "", fmt.Errorf("could not extract hostname from URL")
    }
    return host, nil
}

func (n *Castor) createTLSConfig() *tls.Config {
    rootCAs, err := x509.SystemCertPool()
    if err != nil {
        rootCAs = x509.NewCertPool()
    }
    return &tls.Config{
        ServerName:         n.targetDomain,
        RootCAs:            rootCAs,
        InsecureSkipVerify: false,
        MinVersion:         tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{
            tls.CurveP256,
            tls.X25519,
        },
    }
}

func (n *Castor) getProxyDialer() (proxy.Dialer, error) {
    return proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
}

func (n *Castor) uploadMessage(message string) (time.Duration, error) {
    startTime := time.Now()
    data := []byte(message)

    dialer, err := n.getProxyDialer()
    if err != nil {
        return 0, fmt.Errorf("failed to create dialer: %w", err)
    }

    tlsConfig := n.createTLSConfig()
    
    httpTransport := &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            return dialer.Dial(network, addr)
        },
        TLSClientConfig:       tlsConfig,
        ResponseHeaderTimeout: 60 * time.Second,
        ExpectContinueTimeout: 10 * time.Second,
        IdleConnTimeout:       90 * time.Second,
        TLSHandshakeTimeout:   10 * time.Second,
        MaxIdleConns:          10,
        MaxIdleConnsPerHost:   5,
        DisableKeepAlives:     true,
    }

    client := &http.Client{
        Transport: httpTransport,
        Timeout:   180 * time.Second,
    }

    request, err := http.NewRequest("POST", n.targetURL, bytes.NewReader(data))
    if err != nil {
        return 0, fmt.Errorf("request creation failed: %w", err)
    }

    request.Header.Set("Content-Type", "message/rfc822")
    request.Header.Set("User-Agent", "Castor")

    response, err := client.Do(request)
    if err != nil {
        if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
            return 0, fmt.Errorf("TLS ERROR: Server certificate not trusted. Please ensure MTA uses a valid certificate from a trusted Certificate Authority. Server: %s", n.targetDomain)
        }
        if strings.Contains(err.Error(), "x509: certificate is valid for") {
            return 0, fmt.Errorf("TLS ERROR: Certificate hostname mismatch. Server certificate does not match domain %s.", n.targetDomain)
        }
        if strings.Contains(err.Error(), "x509: certificate has expired") {
            return 0, fmt.Errorf("TLS ERROR: Server certificate at %s has expired.", n.targetDomain)
        }
        if strings.Contains(err.Error(), "x509: certificate is not yet valid") {
            return 0, fmt.Errorf("TLS ERROR: Server certificate at %s is not yet valid.", n.targetDomain)
        }
        if strings.Contains(err.Error(), "certificate") {
            return 0, fmt.Errorf("TLS certificate error: %v", err)
        }
        if strings.Contains(err.Error(), "EOF") {
            return 0, fmt.Errorf("server closed connection unexpectedly")
        }
        if strings.Contains(err.Error(), "connection refused") {
            return 0, fmt.Errorf("connection refused. Is nym-socks5-client running?")
        }
        if strings.Contains(err.Error(), "timeout") {
            return 0, fmt.Errorf("request timeout")
        }
        return 0, fmt.Errorf("HTTP request failed: %w", err)
    }
    defer response.Body.Close()

    responseBody, err := io.ReadAll(response.Body)
    if err != nil {
        return 0, fmt.Errorf("failed to read response: %w", err)
    }

    if response.StatusCode != http.StatusOK {
        errorDetail := string(responseBody)
        if len(errorDetail) > 150 {
            errorDetail = errorDetail[:150] + "..."
        }
        return 0, fmt.Errorf("server error %d: %s", response.StatusCode, errorDetail)
    }

    var ackResponse struct {
        Status string `json:"status"`
    }

    if err := json.Unmarshal(responseBody, &ackResponse); err != nil {
        elapsed := time.Since(startTime)
        return elapsed, nil
    }

    if ackResponse.Status == "success" {
        elapsed := time.Since(startTime)
        return elapsed, nil
    }

    return 0, fmt.Errorf("unexpected response status: %s", ackResponse.Status)
}

func (n *Castor) formatDuration(d time.Duration) string {
    d = d.Round(time.Millisecond)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second
    ms := (d % time.Second) / time.Millisecond
    if h > 0 {
        return fmt.Sprintf("%02d:%02d:%02d.%03d", h, m, s, ms)
    }
    return fmt.Sprintf("%02d:%02d.%03d", m, s, ms)
}

func (n *Castor) clearContent() {
    fyne.Do(func() {
        savedNymX := n.nymxEntry.Text

        n.toEntry.SetText("")
        n.subjectEntry.SetText("")
        n.followupToEntry.SetText("")
        n.referencesEntry.SetText("")
        n.newsgroupsEntry.SetText("")
        n.textArea.SetText("")
        n.currentAttachment = nil

        n.nymxEntry.SetText(savedNymX)

        if clipboard := n.window.Clipboard(); clipboard != nil {
            clipboard.SetContent("")
        }
        n.updateStatus("Ready", "All content cleared and clipboard emptied")
    })
}

func (n *Castor) generateRandomBoundary() (string, error) {
    const boundaryChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    boundary := make([]byte, 24)
    for i := range boundary {
        randomByte := make([]byte, 1)
        _, err := rand.Read(randomByte)
        if err != nil {
            return "", err
        }
        boundary[i] = boundaryChars[int(randomByte[0])%len(boundaryChars)]
    }
    return string(boundary), nil
}

func (n *Castor) createMIMETextPart(plainText string) string {
    var textPart strings.Builder

    textPart.WriteString("Content-Type: text/plain; charset=UTF-8\n")
    textPart.WriteString("Content-Transfer-Encoding: 8bit\n")
    textPart.WriteString("\n")

    if plainText != "" {
        textPart.WriteString(plainText + "\n")
    } else {
        textPart.WriteString("(No text message)\n")
    }
    textPart.WriteString("\n")

    return textPart.String()
}

func (n *Castor) createMIMEAttachmentPart(attachment *Attachment) (string, error) {
    if attachment == nil {
        return "", nil
    }

    var attachmentPart strings.Builder

    attachmentPart.WriteString("Content-Type: " + attachment.ContentType + "; name=\"" + attachment.Filename + "\"\n")
    attachmentPart.WriteString("Content-Disposition: attachment; filename=\"" + attachment.Filename + "\"\n")
    attachmentPart.WriteString("Content-Transfer-Encoding: base64\n")
    attachmentPart.WriteString("\n")

    encoded := base64.StdEncoding.EncodeToString(attachment.Data)
    for i := 0; i < len(encoded); i += 76 {
        end := i + 76
        if end > len(encoded) {
            end = len(encoded)
        }
        attachmentPart.WriteString(encoded[i:end] + "\n")
    }
    attachmentPart.WriteString("\n")

    return attachmentPart.String(), nil
}

func (n *Castor) buildCompleteMIMEMessage(plainText string, attachment *Attachment) (string, error) {
    var message strings.Builder

    boundary, err := n.generateRandomBoundary()
    if err != nil {
        return "", fmt.Errorf("failed to generate boundary: %v", err)
    }

    message.WriteString("To: " + strings.TrimSpace(n.toEntry.Text) + "\n")

    if nymx := n.getNymXHeaderForMessage(); nymx != "" {
        message.WriteString("NOM: " + nymx + "\n")
    }
    if subject := strings.TrimSpace(n.subjectEntry.Text); subject != "" {
        encodedSubject := encodeMIMESubject(subject)
        message.WriteString("Subject: " + encodedSubject + "\n")
    }
    if followupTo := strings.TrimSpace(n.followupToEntry.Text); followupTo != "" {
        message.WriteString("Followup-To: " + followupTo + "\n")
    }
    if references := strings.TrimSpace(n.referencesEntry.Text); references != "" {
        message.WriteString("References: " + references + "\n")
    }
    if newsgroups := strings.TrimSpace(n.newsgroupsEntry.Text); newsgroups != "" {
        message.WriteString("Newsgroups: " + newsgroups + "\n")
    }

    message.WriteString("MIME-Version: 1.0\n")
    message.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\n")
    message.WriteString("Content-Transfer-Encoding: 8bit\n")
    message.WriteString("\n")

    message.WriteString("This is a multi-part message in MIME format.\n")
    message.WriteString("\n")

    message.WriteString("--" + boundary + "\n")
    message.WriteString(n.createMIMETextPart(plainText))

    if attachment != nil {
        message.WriteString("--" + boundary + "\n")
        attachmentPart, err := n.createMIMEAttachmentPart(attachment)
        if err != nil {
            return "", err
        }
        message.WriteString(attachmentPart)
    }

    message.WriteString("--" + boundary + "--\n")

    return message.String(), nil
}

func (n *Castor) isYamnOutfile(filename string) bool {
    ext := filepath.Ext(filename)
    if ext != "" {
        return false
    }
    
    if len(filename) != 15 {
        return false
    }
    
    if !strings.HasPrefix(filename, "m") {
        return false
    }
    
    for _, char := range filename {
        if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
            return false
        }
    }
    
    return true
}

func (n *Castor) parseYamnOutfile(data []byte) (*YamnOutfile, error) {
    lines := strings.Split(string(data), "\n")
    
    result := &YamnOutfile{
        Body: string(data),
    }
    
    var headerEnd int
    var inHeaders = true
    var foundSeparator bool
    
    for i, line := range lines {
        if !inHeaders {
            continue
        }
        
        if line == "::" {
            inHeaders = false
            foundSeparator = true
            headerEnd = i
            continue
        }
        
        if line == "" && inHeaders {
            continue
        }
        
        if inHeaders {
            if strings.HasPrefix(line, "Yamn-Pooled-Date:") {
                result.PooledDate = strings.TrimSpace(strings.TrimPrefix(line, "Yamn-Pooled-Date:"))
            } else if strings.HasPrefix(line, "To:") {
                result.To = strings.TrimSpace(strings.TrimPrefix(line, "To:"))
            } else if strings.HasPrefix(line, "From:") {
                result.From = strings.TrimSpace(strings.TrimPrefix(line, "From:"))
            } else if strings.HasPrefix(line, "Subject:") {
                result.Subject = strings.TrimSpace(strings.TrimPrefix(line, "Subject:"))
            } else if strings.HasPrefix(line, "Remailer-Type:") {
                result.Remailer = strings.TrimSpace(strings.TrimPrefix(line, "Remailer-Type:"))
            }
        }
    }
    
    if foundSeparator && headerEnd > 0 && headerEnd < len(lines) {
        var bodyLines []string
        for i := headerEnd; i < len(lines); i++ {
            bodyLines = append(bodyLines, lines[i])
        }
        result.Body = strings.Join(bodyLines, "\n")
    } else if !foundSeparator {
        for i, line := range lines {
            if line == "" && i > 0 {
                var bodyLines []string
                for j := i + 1; j < len(lines); j++ {
                    bodyLines = append(bodyLines, lines[j])
                }
                result.Body = strings.Join(bodyLines, "\n")
                break
            }
        }
    }
    
    if result.To == "" {
        return nil, fmt.Errorf("no 'To:' address found in YAMN outfile")
    }
    
    if !isValidEmail(result.To) {
        return nil, fmt.Errorf("invalid email in 'To:' field: %s", result.To)
    }
    
    return result, nil
}

func (n *Castor) attachImageHandler() {
    fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
        if err != nil {
            n.updateStatus("Error", fmt.Sprintf("File error: %v", err))
            return
        }
        if reader == nil {
            return
        }
        defer reader.Close()

        fileData, err := io.ReadAll(reader)
        if err != nil {
            n.updateStatus("Error", fmt.Sprintf("Error reading file: %v", err))
            return
        }

        filename := filepath.Base(reader.URI().Path())
        
        isYamnOutfile := n.isYamnOutfile(filename)
        
        if isYamnOutfile {
            yamnData, err := n.parseYamnOutfile(fileData)
            if err != nil {
                n.updateStatus("Error", fmt.Sprintf("Error parsing YAMN outfile: %v", err))
                return
            }
            
            n.toEntry.SetText(yamnData.To)
            n.subjectEntry.SetText(yamnData.Subject)
            n.textArea.SetText(yamnData.Body)
            n.currentAttachment = nil
            
            n.updateStatus("Complete", fmt.Sprintf("YAMN outfile loaded: %s. To: %s", filename, yamnData.To))
        } else {
            if len(fileData) < 768 {
                n.updateStatus("Error", fmt.Sprintf("Image too small: %d bytes (min. 768 bytes)", len(fileData)))
                return
            }

            contentType := "image/jpeg"
            if len(fileData) >= 8 && fileData[0] == 0x89 && fileData[1] == 0x50 &&
                fileData[2] == 0x4E && fileData[3] == 0x47 {
                contentType = "image/png"
            }

            n.currentAttachment = &Attachment{
                Data:        fileData,
                Filename:    filename,
                ContentType: contentType,
            }

            n.updateStatus("Complete", fmt.Sprintf("Attachment ready: %s (%d bytes). Press Send to attach.", filename, len(fileData)))
        }
    }, n.window)

    fd.SetFilter(&fileFilterAll{})
    fd.Show()
}

type fileFilterAll struct{}

func (f *fileFilterAll) Matches(uri fyne.URI) bool {
    return true
}

func (n *Castor) viewArticle() {
    fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
        if err != nil {
            dialog.ShowError(err, n.window)
            return
        }
        if reader == nil {
            return
        }
        defer reader.Close()

        content, err := io.ReadAll(reader)
        if err != nil {
            dialog.ShowError(fmt.Errorf("error reading file: %v", err), n.window)
            return
        }

        articleStr := string(content)
        separator := "---\n"
        sepIdx := strings.Index(articleStr, separator)
        if sepIdx != -1 {
            articleStr = articleStr[sepIdx+len(separator):]
        }

        images, err := n.decodeMultipartImages(articleStr)
        if err != nil {
            dialog.ShowError(fmt.Errorf("error decoding: %v", err), n.window)
            return
        }

        if len(images) == 0 {
            dialog.ShowInformation("No Images", "No AEC images found in article.", n.window)
            return
        }

        n.showImageDialog(images[0], len(images))
    }, n.window)
    fd.Show()
}

func (n *Castor) decodeMultipartImages(article string) ([][]byte, error) {
    var images [][]byte
    boundary := ""
    lines := strings.Split(article, "\n")

    for _, line := range lines {
        if strings.HasPrefix(line, "Content-Type: multipart/") {
            if idx := strings.Index(line, "boundary="); idx != -1 {
                boundaryPart := line[idx+9:]
                boundary = strings.Trim(boundaryPart, "\"")
                break
            }
        }
    }

    if boundary == "" {
        for _, line := range lines {
            if strings.HasPrefix(line, "----=_Part") {
                boundary = strings.TrimSpace(line)
                break
            }
        }
    }

    if boundary == "" {
        return nil, errors.New("multipart boundary not found")
    }

    parts := strings.Split(article, boundary)
    for _, part := range parts {
        if strings.Contains(part, "Content-Type: image/png") {
            imageData, err := n.extractPNGFromPart(part)
            if err == nil && len(imageData) > 0 {
                images = append(images, imageData)
            }
        }
    }

    return images, nil
}

func (n *Castor) extractPNGFromPart(part string) ([]byte, error) {
    lines := strings.Split(part, "\n")
    var base64Lines []string
    inData := false

    for _, line := range lines {
        line = strings.TrimRight(line, "\r")
        if strings.HasPrefix(line, "Content-Transfer-Encoding: base64") {
            inData = true
            continue
        }
        if inData && line == "" {
            continue
        }
        if inData && !strings.HasPrefix(line, "Content-") && line != "" && !strings.HasPrefix(line, "--") {
            base64Lines = append(base64Lines, line)
        }
        if inData && strings.HasPrefix(line, "Content-Type:") {
            break
        }
    }

    if len(base64Lines) == 0 {
        return nil, errors.New("no base64 data found")
    }

    base64Str := strings.Join(base64Lines, "")
    return base64.StdEncoding.DecodeString(base64Str)
}

func (n *Castor) showImageDialog(imageData []byte, totalImages int) {
    img, _, err := image.Decode(bytes.NewReader(imageData))
    if err != nil {
        dialog.ShowError(fmt.Errorf("error decoding PNG: %v", err), n.window)
        return
    }

    bounds := img.Bounds()
    scaledImg := image.NewRGBA(image.Rect(0, 0, 512, 512))
    for y := 0; y < 512; y++ {
        srcY := y * bounds.Dy() / 512
        for x := 0; x < 512; x++ {
            srcX := x * bounds.Dx() / 512
            scaledImg.Set(x, y, img.At(srcX, srcY))
        }
    }

    fyneImg := canvas.NewImageFromImage(scaledImg)
    fyneImg.FillMode = canvas.ImageFillContain
    fyneImg.SetMinSize(fyne.NewSize(512, 512))

    infoText := "AEC Image"
    if totalImages > 1 {
        infoText = fmt.Sprintf("AEC Image 1 of %d", totalImages)
    }

    imageWindow := n.app.NewWindow("Article Image")

    closeBtn := widget.NewButton("Close", func() {
        imageWindow.Close()
    })
    closeBtn.Importance = widget.HighImportance

    content := container.NewVBox(
        widget.NewLabel(infoText),
        fyneImg,
        container.NewCenter(closeBtn),
    )

    imageWindow.Resize(fyne.NewSize(600, 700))
    imageWindow.SetContent(content)
    imageWindow.CenterOnScreen()
    imageWindow.Show()
}

func (n *Castor) sendMail() {
    bodyText := n.textArea.Text

    toText := strings.TrimSpace(n.toEntry.Text)
    if toText == "" {
        n.updateStatus("Error", "To: field cannot be empty")
        return
    }

    if strings.Contains(toText, ",") {
        n.updateStatus("Error", "Only one recipient allowed per transaction. Please remove commas.")
        return
    }

    recipient := strings.TrimSpace(toText)
    if recipient == "" {
        n.updateStatus("Error", "To: field cannot be empty")
        return
    }

    if !isValidEmail(recipient) {
        n.updateStatus("Error", fmt.Sprintf("Invalid recipient email format: %s", recipient))
        return
    }

    var finalMessage string
    var err error

    isYamnBody := strings.Contains(bodyText, "-----BEGIN REMAILER MESSAGE-----") && 
                  strings.Contains(bodyText, "-----END REMAILER MESSAGE-----")

    if n.currentAttachment != nil {
        finalMessage, err = n.buildCompleteMIMEMessage(bodyText, n.currentAttachment)
        if err != nil {
            n.updateStatus("Error", fmt.Sprintf("Failed to build MIME message: %v", err))
            return
        }
        n.updateStatus("Sending", fmt.Sprintf("Sending MIME message with attachment to %s...", recipient))
        defer func() { n.currentAttachment = nil }()
    } else {
        if strings.TrimSpace(bodyText) == "" {
            n.updateStatus("Error", "Message body cannot be empty")
            return
        }
        
        if !isYamnBody && strings.TrimSpace(n.subjectEntry.Text) == "" {
            n.updateStatus("Error", "Subject cannot be empty for email")
            return
        }
        
        finalMessage = n.buildMessage(bodyText)
        
        if isYamnBody {
            n.updateStatus("Sending", fmt.Sprintf("Sending YAMN outfile to %s...", recipient))
        } else {
            n.updateStatus("Sending", fmt.Sprintf("Sending to %s...", recipient))
        }
    }

    go func() {
        elapsed, err := n.uploadMessage(finalMessage)
        if err != nil {
            fyne.Do(func() {
                n.updateStatus("Error", fmt.Sprintf("Failed to send: %v", err))
            })
        } else {
            fyne.Do(func() {
                n.updateStatus("Complete", fmt.Sprintf("Successfully sent in %s", n.formatDuration(elapsed)))
            })
        }
    }()
}

func (n *Castor) applyPurpleTheme() {
    n.app.Settings().SetTheme(&purpleThemeWrapper{base: n.app.Settings().Theme()})
}

func (n *Castor) toggleTheme() {
    fyne.Do(func() {
        if n.isDarkTheme {
            n.app.Settings().SetTheme(theme.LightTheme())
            n.isDarkTheme = false
            n.themeSwitch.SetText("🌙")
        } else {
            n.app.Settings().SetTheme(theme.DarkTheme())
            n.isDarkTheme = true
            n.themeSwitch.SetText("☀️")
        }
        n.applyPurpleTheme()
        n.window.Content().Refresh()
    })
}

func (n *Castor) showInfoPopup() {
    projURL, _ := url.Parse("https://github.com/Ch1ffr3punk/Castor")
    projectLink := widget.NewHyperlink("An Open Source project", projURL)
    okButton := widget.NewButton("OK", func() {
        if overlays := n.window.Canvas().Overlays(); overlays.Top() != nil {
            overlays.Remove(overlays.Top())
        }
    })
    okButton.Importance = widget.HighImportance
    content := container.NewVBox(
        widget.NewLabelWithStyle("Castor v0.1.0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
        widget.NewSeparator(),
        container.NewHBox(layout.NewSpacer(), projectLink, layout.NewSpacer()),
        widget.NewLabelWithStyle("released under the Apache 2.0 license", fyne.TextAlignCenter, fyne.TextStyle{}),
        widget.NewLabelWithStyle("© 2026 Ch1ffr3punk", fyne.TextAlignCenter, fyne.TextStyle{}),
        container.NewHBox(layout.NewSpacer(), okButton, layout.NewSpacer()),
    )
    dialog.ShowCustomWithoutButtons("", content, n.window)
}

func (n *Castor) saveUnifiedConfig() error {
    configPath := getConfigPath()
    data, err := json.MarshalIndent(n.unifiedConfig, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(configPath, data, 0644)
}

func getConfigPath() string {
    return filepath.Join(".", configFileName)
}

func createDefaultUnifiedConfig(configPath string) error {
    defaultConfig := UnifiedConfig{
        CastorURL:       DEFAULT_SERVER_URL,
        LocalArticleDir: "articles",
        SavedNymXEmail:   "",
        NNTPConfig: NNTPConfig{
            Server:      "",
            Port:        119,
            Newsgroup:   "",
            LastArticle: 0,
        },
    }
    data, err := json.MarshalIndent(defaultConfig, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(configPath, data, 0644)
}

func loadOrCreateUnifiedConfig() (*UnifiedConfig, error) {
    configPath := getConfigPath()
    if _, err := os.Stat(configPath); os.IsNotExist(err) {
        if err := createDefaultUnifiedConfig(configPath); err != nil {
            return nil, err
        }
    }
    data, err := os.ReadFile(configPath)
    if err != nil {
        return nil, err
    }
    var config UnifiedConfig
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    if config.CastorURL == "" {
        config.CastorURL = DEFAULT_SERVER_URL
    }
    if config.LocalArticleDir == "" {
        config.LocalArticleDir = "articles"
    }
    return &config, nil
}

func (n *Castor) loadSavedNymXEmail() {
    if n.unifiedConfig.SavedNymXEmail != "" {
        n.nymxEntry.SetText(n.unifiedConfig.SavedNymXEmail)
    }
}

func (n *Castor) saveNymXEmail(email string) {
    n.unifiedConfig.SavedNymXEmail = email
    if err := n.saveUnifiedConfig(); err != nil {
        n.updateStatus("Error", fmt.Sprintf("Failed to save NOM: %v", err))
    }
}

func (n *Castor) handleNymXEntryChange() {
    go func() {
        lastValue := n.nymxEntry.Text
        ticker := time.NewTicker(500 * time.Millisecond)
        defer ticker.Stop()
        for range ticker.C {
            currentValue := strings.TrimSpace(n.nymxEntry.Text)
            if currentValue != lastValue {
                lastValue = currentValue
                if currentValue != "" && isValidEmail(currentValue) {
                    n.saveNymXEmail(currentValue)
                } else if currentValue == "" {
                    n.updateStatus("NOM", "No NOM header for this message")
                }
            }
        }
    }()
}

func (n *Castor) getMaxLabelWidth() float32 {
    labels := []string{"To:", "NOM:", "Subject:", "Followup-To:", "References:", "Newsgroups:"}
    var maxWidth float32 = 0
    for _, labelText := range labels {
        tmpLabel := widget.NewLabel(labelText)
        tmpLabel.TextStyle = fyne.TextStyle{Bold: true}
        if width := tmpLabel.MinSize().Width; width > maxWidth {
            maxWidth = width
        }
    }
    return maxWidth + 5
}

func (n *Castor) createCompactField(labelText string, entry fyne.CanvasObject) fyne.CanvasObject {
    labelWidget := widget.NewLabel(labelText + ":")
    labelWidget.TextStyle = fyne.TextStyle{Bold: true}
    labelWidget.Alignment = fyne.TextAlignTrailing
    maxLabelWidth := n.getMaxLabelWidth()
    return container.NewBorder(nil, nil, container.New(&fixedWidthLayout{width: maxLabelWidth}, labelWidget), nil, entry)
}

type fixedWidthLayout struct {
    width float32
}

func (f *fixedWidthLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
    if len(objects) > 0 {
        objects[0].Resize(fyne.NewSize(f.width, objects[0].MinSize().Height))
        objects[0].Move(fyne.NewPos(0, 0))
    }
}

func (f *fixedWidthLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
    if len(objects) > 0 {
        return fyne.NewSize(f.width, objects[0].MinSize().Height)
    }
    return fyne.NewSize(f.width, 0)
}

func (n *Castor) hideNonEssentialUI() {
    if !n.bottomVisible {
        return
    }
    fyne.Do(func() {
        if n.mainScroll != nil {
            n.mainScroll.Content = container.NewBorder(n.headerSection, nil, nil, nil, n.textArea)
            n.mainScroll.Refresh()
            n.bottomVisible = false
        }
    })
}

func (n *Castor) showAllUI() {
    if n.bottomVisible {
        return
    }
    fyne.Do(func() {
        if n.mainScroll != nil {
            n.mainScroll.Content = container.NewBorder(n.headerSection, n.bottomSection, nil, nil, n.textArea)
            n.mainScroll.Refresh()
            n.bottomVisible = true
        }
    })
}

func (n *Castor) setupFocusHandlers() {
    focusHandler := func(focused bool) {
        if focused {
            if n.hideTimer != nil {
                n.hideTimer.Stop()
                n.hideTimer = nil
            }
            n.hideNonEssentialUI()
        } else {
            if n.hideTimer != nil {
                n.hideTimer.Stop()
            }
            n.hideTimer = time.AfterFunc(500*time.Millisecond, func() {
                fyne.Do(func() { n.showAllUI() })
            })
        }
    }
    n.toEntry.SetOnFocusChanged(focusHandler)
    n.nymxEntry.SetOnFocusChanged(focusHandler)
    n.subjectEntry.SetOnFocusChanged(focusHandler)
    n.followupToEntry.SetOnFocusChanged(focusHandler)
    n.referencesEntry.SetOnFocusChanged(focusHandler)
    n.newsgroupsEntry.SetOnFocusChanged(focusHandler)
    n.textArea.SetOnFocusChanged(focusHandler)
}

func (n *Castor) getAdaptivePadding() float32 {
    scale := fyne.CurrentApp().Settings().Scale()
    padding := float32(8) * scale
    if padding < 6 {
        return 6
    }
    if padding > 16 {
        return 16
    }
    return padding
}

func (n *Castor) initDB() error {
    dbPath := "./esub_rc.db"
    os.MkdirAll(filepath.Dir(dbPath), 0755)
    var err error
    n.db, err = sql.Open("sqlite3", dbPath)
    if err != nil {
        return err
    }
    _, err = n.db.Exec(`CREATE TABLE IF NOT EXISTS esubs (esub_hex TEXT PRIMARY KEY, first_seen TEXT NOT NULL, article_id INTEGER, newsgroup TEXT)`)
    if err != nil {
        return err
    }
    rows, err := n.db.Query("SELECT esub_hex FROM esubs")
    if err != nil {
        return err
    }
    defer rows.Close()
    n.replayCache = make(map[string]bool)
    for rows.Next() {
        var esubHex string
        if scanErr := rows.Scan(&esubHex); scanErr != nil {
            return scanErr
        }
        n.replayCache[esubHex] = true
    }
    return nil
}

func (e *esub) deriveKey() []byte {
    pepper := []byte("fixed-pepper-1234")
    return argon2.IDKey([]byte(e.key), pepper, 3, 64*1024, 4, 32)
}

func (e *esub) esubgen() string {
    nonce := make([]byte, 12)
    _, _ = rand.Read(nonce)
    key := e.deriveKey()
    cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
    textHash := sha3.Sum256([]byte("text"))
    ciphertext := make([]byte, 12)
    cipher.XORKeyStream(ciphertext, textHash[:12])
    return hex.EncodeToString(append(nonce, ciphertext...))
}

func (e *esub) esubtest() bool {
    if len(e.subject) != 48 {
        return false
    }
    esubBytes, err := hex.DecodeString(e.subject)
    if err != nil || len(esubBytes) != 24 {
        return false
    }
    nonce := esubBytes[:12]
    receivedCiphertext := esubBytes[12:]
    key := e.deriveKey()
    cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
    textHash := sha3.Sum256([]byte("text"))
    expectedCiphertext := make([]byte, 12)
    cipher.XORKeyStream(expectedCiphertext, textHash[:12])
    return hex.EncodeToString(expectedCiphertext) == hex.EncodeToString(receivedCiphertext)
}

func (e *esub) checkReplayCache(app *Castor) bool {
    if app.db == nil {
        return false
    }
    app.dbMutex.RLock()
    defer app.dbMutex.RUnlock()
    if _, exists := app.replayCache[e.subject]; exists {
        return true
    }
    var count int
    _ = app.db.QueryRow("SELECT COUNT(*) FROM esubs WHERE esub_hex = ?", e.subject).Scan(&count)
    return count > 0
}

func (e *esub) addToReplayCache(app *Castor, articleID int, newsgroup string) error {
    if app.db == nil {
        return nil
    }
    if e.checkReplayCache(app) {
        return nil
    }
    app.dbMutex.Lock()
    defer app.dbMutex.Unlock()
    _, err := app.db.Exec("INSERT INTO esubs (esub_hex, first_seen, article_id, newsgroup) VALUES (?, ?, ?, ?)",
        e.subject, time.Now().Format(time.RFC3339), articleID, newsgroup)
    if err != nil {
        return err
    }
    app.replayCache[e.subject] = true
    return nil
}

func (n *Castor) connectToNNTP(config *NNTPConfig) (net.Conn, *bufio.Reader, error) {
    addr := fmt.Sprintf("%s:%d", config.Server, config.Port)

    dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, proxy.Direct)
    if err != nil {
        return nil, nil, fmt.Errorf("SOCKS5 dialer error: %v", err)
    }
    conn, err := dialer.Dial("tcp", addr)
    if err != nil {
        return nil, nil, fmt.Errorf("proxy connection failed: %v", err)
    }

    reader := bufio.NewReader(conn)

    response, err := reader.ReadString('\n')
    if err != nil {
        conn.Close()
        return nil, nil, err
    }

    if !strings.HasPrefix(response, "200") && !strings.HasPrefix(response, "201") {
        conn.Close()
        return nil, nil, fmt.Errorf("NNTP server error: %s", response)
    }

    return conn, reader, nil
}

func (n *Castor) fetchArticlesFromNewsgroup() {
    config := &n.unifiedConfig.NNTPConfig

    if config.Server == "" || config.Newsgroup == "" {
        dialog.ShowError(errors.New("Please configure NNTP server and Newsgroup in Settings"), n.window)
        return
    }

    keyEntry := widget.NewPasswordEntry()
    keyEntry.SetPlaceHolder("")

    items := []*widget.FormItem{
        {Text: "Password", Widget: keyEntry},
    }

    dialog.ShowForm("", "Start", "Cancel", items, func(confirmed bool) {
        if !confirmed {
            return
        }

        key := strings.TrimSpace(keyEntry.Text)
        if key == "" {
            dialog.ShowError(errors.New("Password cannot be empty"), n.window)
            return
        }

        n.progressContainer.Show()
        n.progressBar.SetValue(0)
        n.progressLabel.SetText("0%")
        n.updateStatus("Fetch", "Connecting to NNTP server...")

        go func() {
            err := n.processNewsgroup(config, key)
            fyne.Do(func() {
                if err != nil {
                    if errors.Is(err, ErrNoNewArticles) {
                        n.updateStatus("Complete", "No new articles to fetch")
                        n.progressContainer.Hide()
                    } else {
                        n.updateStatus("Error", fmt.Sprintf(" %v", err))
                        n.progressContainer.Hide()
                    }
                } else {
                    n.updateStatus("Complete", fmt.Sprintf("Articles saved to %s", n.unifiedConfig.LocalArticleDir))
                    n.progressBar.SetValue(1)
                    n.progressLabel.SetText("100%")
                    time.AfterFunc(3*time.Second, func() {
                        fyne.Do(func() {
                            n.progressContainer.Hide()
                        })
                    })
                }
            })
        }()
    }, n.window)
}

func (n *Castor) processNewsgroup(config *NNTPConfig, key string) error {
    conn, reader, err := n.connectToNNTP(config)
    if err != nil {
        return err
    }
    defer conn.Close()

    fmt.Fprintf(conn, "GROUP %s\r\n", config.Newsgroup)
    response, err := reader.ReadString('\n')
    if err != nil {
        return err
    }

    var articleCount, first, last int
    _, err = fmt.Sscanf(response, "211 %d %d %d", &articleCount, &first, &last)
    if err != nil {
        return fmt.Errorf("failed to parse GROUP response: %v", err)
    }

    if first == 0 || last == 0 {
        return fmt.Errorf("no articles in Newsgroup")
    }

    startArticle := first

    if config.LastArticle > 0 {
        if config.LastArticle >= last {
            return ErrNoNewArticles
        }
        if config.LastArticle >= first {
            startArticle = config.LastArticle + 1
            fyne.Do(func() {
                n.updateStatus("Fetch", fmt.Sprintf("Resuming from article %d", startArticle))
            })
            time.Sleep(2 * time.Second)
        }
    }

    totalArticles := last - startArticle + 1
    if totalArticles <= 0 {
        return ErrNoNewArticles
    }

    current := 0

    fyne.Do(func() {
        n.updateStatus("Fetch", fmt.Sprintf("Fetching %d articles...", totalArticles))
        n.progressBar.SetValue(0)
        n.progressLabel.SetText("0%")
    })

    articlesDir := n.unifiedConfig.LocalArticleDir
    if articlesDir == "" {
        articlesDir = "articles"
    }
    if err := os.MkdirAll(articlesDir, 0755); err != nil {
        return err
    }

    foundCount := 0
    maxProcessed := startArticle - 1

    for msgID := startArticle; msgID <= last; msgID++ {
        current++
        percent := float64(current) / float64(totalArticles)

        if msgID > maxProcessed {
            maxProcessed = msgID
        }

        fyne.Do(func() {
            n.progressBar.SetValue(percent)
            n.progressLabel.SetText(fmt.Sprintf("%d%%", int(percent*100)))
            n.updateStatus("Fetch", fmt.Sprintf("Article %d/%d", msgID, last))
        })

        fmt.Fprintf(conn, "ARTICLE %d\r\n", msgID)
        response, err := reader.ReadString('\n')
        if err != nil {
            continue
        }

        if !strings.HasPrefix(response, "220") {
            continue
        }

        var article strings.Builder
        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                break
            }
            if line == ".\r\n" {
                break
            }
            if strings.HasPrefix(line, "..") {
                line = line[1:]
            }
            article.WriteString(line)
        }

        articleStr := article.String()
        var subject string

        lines := strings.Split(articleStr, "\n")
        for _, line := range lines {
            if strings.HasPrefix(line, "Subject:") {
                parts := strings.SplitN(line, ":", 2)
                if len(parts) == 2 {
                    subject = strings.TrimSpace(parts[1])
                    break
                }
            }
            if strings.HasPrefix(line, "X-Esub:") {
                parts := strings.SplitN(line, ":", 2)
                if len(parts) == 2 {
                    subject = strings.TrimSpace(parts[1])
                    break
                }
            }
        }

        if subject != "" && len(subject) == 48 {
            e := &esub{key: key, subject: subject}
            if e.esubtest() {
                if e.checkReplayCache(n) {
                    continue
                }

                outputFileName := filepath.Join(articlesDir, fmt.Sprintf("article_%d_%s.txt", msgID, e.subject))
                outputFile, err := os.Create(outputFileName)
                if err != nil {
                    return err
                }

                outputFile.WriteString(fmt.Sprintf("Article-ID: %d\n", msgID))
                outputFile.WriteString(fmt.Sprintf("esub: %s\n", e.subject))
                outputFile.WriteString("---\n")
                outputFile.WriteString(articleStr)
                outputFile.Close()

                e.addToReplayCache(n, msgID, config.Newsgroup)
                foundCount++

                fyne.Do(func() {
                    n.updateStatus("Fetch", fmt.Sprintf("Found %d esub(s)", foundCount))
                })
            }
        }

        time.Sleep(100 * time.Millisecond)

        if msgID%100 == 0 {
            config.LastArticle = maxProcessed
            n.saveUnifiedConfig()
        }
    }

    if maxProcessed > startArticle-1 {
        config.LastArticle = maxProcessed
        n.saveUnifiedConfig()
    }

    if foundCount == 0 && startArticle == first {
        return fmt.Errorf("No valid esub(s) found in %s", config.Newsgroup)
    } else if foundCount == 0 && startArticle > first {
        return fmt.Errorf("No new valid esub(s) found (last: %d)", startArticle-1)
    }

    return nil
}

func (n *Castor) createEsub() {
    keyEntry := widget.NewPasswordEntry()
    keyEntry.SetPlaceHolder("")

    dialog.ShowForm("", "Generate", "Cancel", []*widget.FormItem{{Text: "Password", Widget: keyEntry}}, func(confirmed bool) {
        if !confirmed {
            return
        }
        key := strings.TrimSpace(keyEntry.Text)
        if key == "" {
            dialog.ShowError(errors.New("Password cannot be empty"), n.window)
            return
        }

        e := &esub{key: key}
        generated := e.esubgen()
        e.subject = generated
        if e.esubtest() {
            n.window.Clipboard().SetContent(generated)
            dialog.ShowInformation("", fmt.Sprintf("esub: %s\n\nCopied to clipboard!", generated), n.window)
            n.updateStatus("Esub", "Created")
        }
    }, n.window)
}

func (n *Castor) showUnifiedConfig() {
    HermesURLEntry := widget.NewEntry()

    if n.unifiedConfig.CastorURL == DEFAULT_SERVER_URL {
        HermesURLEntry.SetText("")
        HermesURLEntry.PlaceHolder = DEFAULT_SERVER_URL
    } else {
        HermesURLEntry.SetText(n.unifiedConfig.CastorURL)
    }

    localArticleDirEntry := widget.NewEntry()
    localArticleDirEntry.SetText(n.unifiedConfig.LocalArticleDir)
    nntpServerEntry := widget.NewEntry()
    nntpServerEntry.SetText(n.unifiedConfig.NNTPConfig.Server)
    nntpPortEntry := widget.NewEntry()
    nntpPortEntry.SetText(fmt.Sprintf("%d", n.unifiedConfig.NNTPConfig.Port))
    newsgroupEntry := widget.NewEntry()
    newsgroupEntry.SetText(n.unifiedConfig.NNTPConfig.Newsgroup)
    savedNymXEntry := widget.NewEntry()
    savedNymXEntry.SetText(n.unifiedConfig.SavedNymXEmail)
    savedNymXEntry.PlaceHolder = "Optional NOM address"

    resetCacheBtn := widget.NewButton("Reset Esub Cache", func() {
        dialog.ShowConfirm("Reset Cache", "Delete all cached esubs?", func(confirmed bool) {
            if confirmed && n.db != nil {
                _, _ = n.db.Exec("DELETE FROM esubs")
                n.replayCache = make(map[string]bool)
                n.unifiedConfig.NNTPConfig.LastArticle = 0
                n.saveUnifiedConfig()
                dialog.ShowInformation("", "Cache cleared!", n.window)
            }
        }, n.window)
    })
    resetCacheBtn.Importance = widget.LowImportance

    formItems := []*widget.FormItem{
        {Text: "Hermes Server URL", Widget: HermesURLEntry},
        {Text: "Local Article Dir", Widget: localArticleDirEntry},
        {Text: "", Widget: widget.NewSeparator()},
        {Text: "NNTP Server", Widget: nntpServerEntry},
        {Text: "NNTP Port", Widget: nntpPortEntry},
        {Text: "Newsgroup", Widget: newsgroupEntry},
        {Text: "", Widget: widget.NewSeparator()},
        {Text: "Saved NOM", Widget: savedNymXEntry},
        {Text: "", Widget: resetCacheBtn},
    }

    var customDialog *dialog.CustomDialog
    
    saveBtn := widget.NewButtonWithIcon("Save", theme.ConfirmIcon(), func() {
        CastorURL := strings.TrimSpace(HermesURLEntry.Text)
        if CastorURL == "" {
            CastorURL = DEFAULT_SERVER_URL
        }
        if !strings.HasPrefix(CastorURL, "http://") && !strings.HasPrefix(CastorURL, "https://") {
            CastorURL = "https://" + CastorURL
        }
        CastorURL = strings.TrimSuffix(CastorURL, "/")
        if !strings.HasSuffix(CastorURL, "/upload") {
            CastorURL = CastorURL + "/upload"
        }

        var nntpPort int
        _, _ = fmt.Sscanf(nntpPortEntry.Text, "%d", &nntpPort)
        if nntpPort == 0 {
            nntpPort = 119
        }

        savedNymX := strings.TrimSpace(savedNymXEntry.Text)

        n.unifiedConfig.CastorURL = CastorURL
        n.unifiedConfig.LocalArticleDir = strings.TrimSpace(localArticleDirEntry.Text)
        n.unifiedConfig.NNTPConfig.Server = strings.TrimSpace(nntpServerEntry.Text)
        n.unifiedConfig.NNTPConfig.Port = nntpPort
        n.unifiedConfig.NNTPConfig.Newsgroup = strings.TrimSpace(newsgroupEntry.Text)
        n.unifiedConfig.SavedNymXEmail = savedNymX
        n.saveUnifiedConfig()
        n.targetURL = CastorURL

        if domain, err := extractDomainFromURL(CastorURL); err == nil {
            n.targetDomain = domain
        }

        n.loadSavedNymXEmail()

        n.updateStatus("Settings", "Saved")
        dialog.ShowInformation("Success", "Configuration saved!", n.window)

        if customDialog != nil {
            customDialog.Hide()
        }
        if overlays := n.window.Canvas().Overlays(); overlays.Top() != nil {
            overlays.Remove(overlays.Top())
        }
    })
    saveBtn.Importance = widget.HighImportance

    cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
        if overlays := n.window.Canvas().Overlays(); overlays.Top() != nil {
            overlays.Remove(overlays.Top())
        }
    })

    buttons := container.NewHBox(layout.NewSpacer(), cancelBtn, saveBtn, layout.NewSpacer())

    content := container.NewVBox(
        widget.NewLabelWithStyle("Configuration", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
        widget.NewSeparator(),
        widget.NewForm(formItems...),
        widget.NewSeparator(),
        buttons,
    )

    customDialog = dialog.NewCustomWithoutButtons("", content, n.window)
    customDialog.Show()
}

func NewFileFilter(name string, patterns ...string) *fileFilter {
    return &fileFilter{name: name, patterns: patterns}
}

func (f *fileFilter) Matches(uri fyne.URI) bool {
    ext := strings.ToLower(filepath.Ext(uri.Path()))
    for _, pattern := range f.patterns {
        if ext == pattern {
            return true
        }
    }
    return false
}

func (n *Castor) setupResponsiveUI() fyne.CanvasObject {
    toEntry := NewFocusAwareEntry()
    toEntry.PlaceHolder = "Recipient"
    nymxEntry := NewFocusAwareEntry()
    nymxEntry.PlaceHolder = "NOM (optional)"
    subjectEntry := NewFocusAwareEntry()
    subjectEntry.PlaceHolder = "Subject"
    followupToEntry := NewFocusAwareEntry()
    followupToEntry.PlaceHolder = "Followup-To (optional)"
    referencesEntry := NewFocusAwareEntry()
    referencesEntry.PlaceHolder = "Message-ID (optional)"
    newsgroupsEntry := NewFocusAwareEntry()
    newsgroupsEntry.PlaceHolder = "Newsgroups (optional)"
    textArea := NewFocusAwareMultiLineEntry()
    textArea.PlaceHolder = "Enter your message here..."

    n.toEntry = toEntry
    n.nymxEntry = nymxEntry
    n.subjectEntry = subjectEntry
    n.followupToEntry = followupToEntry
    n.referencesEntry = referencesEntry
    n.newsgroupsEntry = newsgroupsEntry
    n.textArea = textArea
    n.statusLabel = widget.NewLabel("Ready")
    n.statusLabel.TextStyle = fyne.TextStyle{Bold: true}
    n.statusDetail = widget.NewLabel("Castor ready")

    statusBar := container.NewVBox(widget.NewSeparator(), container.NewHBox(n.statusLabel, layout.NewSpacer()), n.statusDetail)

    n.themeSwitch = widget.NewButton("☀️", n.toggleTheme)
    n.configBtn = widget.NewButtonWithIcon("", theme.SettingsIcon(), n.showUnifiedConfig)
    n.infoBtn = widget.NewButtonWithIcon("", theme.InfoIcon(), n.showInfoPopup)

    clearButton := widget.NewButtonWithIcon("", theme.ContentClearIcon(), n.clearContent)
    
    topBar := container.NewHBox(n.configBtn, layout.NewSpacer(), n.infoBtn, layout.NewSpacer(), clearButton, layout.NewSpacer(), n.themeSwitch)

    attachmentButton := widget.NewButton("Attach", n.attachImageHandler)
    attachmentButton.Importance = widget.HighImportance

    sendButton := widget.NewButton("Send", n.sendMail)
    sendButton.Importance = widget.HighImportance

    createEsubButton := widget.NewButton("Esub", n.createEsub)
    createEsubButton.Importance = widget.HighImportance
    fetchArticlesButton := widget.NewButton("Fetch", n.fetchArticlesFromNewsgroup)
    fetchArticlesButton.Importance = widget.HighImportance

    viewButton := widget.NewButton("View", n.viewArticle)
    viewButton.Importance = widget.HighImportance

    n.progressBar = widget.NewProgressBar()
    n.progressLabel = widget.NewLabel("0%")
    n.progressContainer = container.NewVBox(widget.NewLabel("Progress:"), n.progressBar, n.progressLabel)
    n.progressContainer.Hide()

    buttonContainer := container.New(layout.NewGridLayoutWithColumns(5), attachmentButton, sendButton, createEsubButton, fetchArticlesButton, viewButton)
    headerSection := container.NewVBox(
        topBar,
        widget.NewSeparator(),
        n.createCompactField("To", toEntry),
        n.createCompactField("NOM", nymxEntry),
        n.createCompactField("Subject", subjectEntry),
        n.createCompactField("Followup-To", followupToEntry),
        n.createCompactField("References", referencesEntry),
        n.createCompactField("Newsgroups", newsgroupsEntry),
        widget.NewSeparator(),
    )
    bottomSection := container.NewVBox(buttonContainer, n.progressContainer, widget.NewSeparator(), statusBar)

    n.headerSection = headerSection
    n.bottomSection = bottomSection
    n.bottomVisible = true

    n.loadSavedNymXEmail()
    n.handleNymXEntryChange()

    textScroll := container.NewScroll(textArea)
    textScroll.Direction = container.ScrollBoth

    mainContent := container.NewBorder(headerSection, bottomSection, nil, nil, textScroll)
    n.mainScroll = container.NewScroll(mainContent)
    paddedContent := container.New(layout.NewCustomPaddedLayout(n.getAdaptivePadding(), n.getAdaptivePadding(), n.getAdaptivePadding(), n.getAdaptivePadding()), n.mainScroll)
    n.setupFocusHandlers()
    return paddedContent
}

func main() {
    myApp := app.New()
    window := myApp.NewWindow("Castor")

    unifiedConfig, err := loadOrCreateUnifiedConfig()
    if err != nil {
        fmt.Printf("Config error: %v\n", err)
        os.Exit(1)
    }

    myApp.Settings().SetTheme(&purpleThemeWrapper{
        base: theme.DarkTheme(),
    })

    castorInstance := &Castor{
        app:           myApp,
        window:        window,
        isDarkTheme:   true,
        unifiedConfig: unifiedConfig,
        pool:          pool,
    }

    castorInstance.applyPurpleTheme()

    castorInstance.initDB()
    castorInstance.targetURL = castorInstance.unifiedConfig.CastorURL
    if castorInstance.targetURL == "" {
        castorInstance.targetURL = DEFAULT_SERVER_URL
    }
    if !strings.HasSuffix(castorInstance.targetURL, "/upload") {
        castorInstance.targetURL = castorInstance.targetURL + "/upload"
    }
    if domain, err := extractDomainFromURL(castorInstance.targetURL); err == nil {
        castorInstance.targetDomain = domain
    }

    window.SetContent(castorInstance.setupResponsiveUI())
    window.SetPadded(true)
    window.SetMaster()
    window.Resize(fyne.NewSize(700, 800))
    window.CenterOnScreen()
    castorInstance.periodicStatusReset()
    castorInstance.resetStatus()
    window.ShowAndRun()
}
