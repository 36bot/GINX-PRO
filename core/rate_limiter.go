package core

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	// Global limits - VERY PERMISSIVE to prevent blocking legitimate traffic
	maxConcurrentRequests  = 10000            // Max simultaneous requests (high limit)
	maxRequestsPerSecond   = 5000             // Global requests per second limit (high)
	maxRequestsPerIP       = 500              // Requests per IP per window (permissive)
	ipRateLimitWindow      = 10 * time.Second // IP rate limit window
	
	// Per-IP connection limits
	maxConnectionsPerIP    = 100              // Max concurrent connections per IP (high)
	
	// Cleanup intervals
	ipCleanupInterval      = 1 * time.Minute  // Clean up old IP entries more frequently
	ipEntryTTL             = 10 * time.Minute // Shorter TTL to reduce memory usage
)

// ipTracker tracks request statistics per IP
type ipTracker struct {
	requests    int64     // Request count in current window
	connections int32     // Current active connections
	windowStart time.Time // Start of current rate limit window
	lastSeen    time.Time // Last activity time
	blocked     bool      // IP is temporarily blocked
	blockUntil  time.Time // Block expiry time
}

// RateLimiter provides traffic management and DDoS protection
type RateLimiter struct {
	ipTrackers      map[string]*ipTracker
	mu              sync.RWMutex
	activeRequests  int32           // Current number of active requests
	totalRequests   int64           // Total requests (for rate calculation)
	lastRateReset   time.Time       // Last time we reset the rate counter
	requestsInWindow int64          // Requests in current 1-second window
	stopChan        chan struct{}
	running         bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		ipTrackers:    make(map[string]*ipTracker),
		lastRateReset: time.Now(),
		stopChan:      make(chan struct{}),
	}
	return rl
}

// Start begins background cleanup goroutine
func (rl *RateLimiter) Start() {
	if rl.running {
		return
	}
	rl.running = true
	go rl.cleanupLoop()
	log.Info("[ratelimit] Started with limits: %d concurrent, %d/sec global, %d/IP per %v",
		maxConcurrentRequests, maxRequestsPerSecond, maxRequestsPerIP, ipRateLimitWindow)
}

// Stop terminates the rate limiter
func (rl *RateLimiter) Stop() {
	if rl.running {
		close(rl.stopChan)
		rl.running = false
	}
}

// cleanupLoop periodically removes stale IP entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(ipCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes expired IP tracker entries
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	expired := 0
	for ip, tracker := range rl.ipTrackers {
		if now.Sub(tracker.lastSeen) > ipEntryTTL {
			delete(rl.ipTrackers, ip)
			expired++
		}
	}
	if expired > 0 {
		log.Debug("[ratelimit] Cleaned up %d expired IP entries, %d remaining", expired, len(rl.ipTrackers))
	}
}

// AllowRequest checks if a request should be allowed
// Returns: allowed, reason (if blocked)
func (rl *RateLimiter) AllowRequest(ip string) (bool, string) {
	now := time.Now()

	// Check global concurrent request limit
	current := atomic.LoadInt32(&rl.activeRequests)
	if current >= maxConcurrentRequests {
		return false, "server overloaded"
	}

	// Check global rate limit (requests per second)
	rl.mu.Lock()
	if now.Sub(rl.lastRateReset) >= time.Second {
		rl.requestsInWindow = 0
		rl.lastRateReset = now
	}
	if rl.requestsInWindow >= maxRequestsPerSecond {
		rl.mu.Unlock()
		return false, "rate limit exceeded"
	}
	rl.requestsInWindow++
	
	// Get or create IP tracker
	tracker, exists := rl.ipTrackers[ip]
	if !exists {
		tracker = &ipTracker{
			windowStart: now,
			lastSeen:    now,
		}
		rl.ipTrackers[ip] = tracker
	}
	
	// Check if IP is blocked
	if tracker.blocked {
		if now.Before(tracker.blockUntil) {
			rl.mu.Unlock()
			return false, "IP temporarily blocked"
		}
		// Block expired, reset
		tracker.blocked = false
		tracker.requests = 0
		tracker.windowStart = now
	}
	
	// Check per-IP connection limit
	if tracker.connections >= maxConnectionsPerIP {
		rl.mu.Unlock()
		return false, "too many connections from IP"
	}
	
	// Check per-IP rate limit
	if now.Sub(tracker.windowStart) >= ipRateLimitWindow {
		// Reset window
		tracker.requests = 0
		tracker.windowStart = now
	}
	
	tracker.requests++
	tracker.lastSeen = now
	
	if tracker.requests > maxRequestsPerIP {
		// Block this IP temporarily
		tracker.blocked = true
		tracker.blockUntil = now.Add(60 * time.Second) // 60 second block
		rl.mu.Unlock()
		log.Warning("[ratelimit] IP %s blocked for excessive requests (%d in %v)", 
			maskIP(ip), tracker.requests, ipRateLimitWindow)
		return false, "rate limit exceeded for IP"
	}
	
	rl.mu.Unlock()
	return true, ""
}

// BeginRequest marks the start of a request
func (rl *RateLimiter) BeginRequest(ip string) {
	atomic.AddInt32(&rl.activeRequests, 1)
	atomic.AddInt64(&rl.totalRequests, 1)
	
	rl.mu.Lock()
	if tracker, exists := rl.ipTrackers[ip]; exists {
		atomic.AddInt32(&tracker.connections, 1)
	}
	rl.mu.Unlock()
}

// EndRequest marks the end of a request
func (rl *RateLimiter) EndRequest(ip string) {
	atomic.AddInt32(&rl.activeRequests, -1)
	
	rl.mu.Lock()
	if tracker, exists := rl.ipTrackers[ip]; exists {
		if tracker.connections > 0 {
			atomic.AddInt32(&tracker.connections, -1)
		}
	}
	rl.mu.Unlock()
}

// GetStats returns current rate limiter statistics
func (rl *RateLimiter) GetStats() (activeReqs int32, totalReqs int64, trackedIPs int) {
	rl.mu.RLock()
	trackedIPs = len(rl.ipTrackers)
	rl.mu.RUnlock()
	return atomic.LoadInt32(&rl.activeRequests), atomic.LoadInt64(&rl.totalRequests), trackedIPs
}

// RateLimitMiddleware wraps an http.Handler with rate limiting
func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		
		allowed, reason := rl.AllowRequest(ip)
		if !allowed {
			// Return 503 Service Unavailable (stealth - looks like server issue)
			w.Header().Set("Retry-After", "30")
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			log.Debug("[ratelimit] Blocked request from %s: %s", maskIP(ip), reason)
			return
		}
		
		rl.BeginRequest(ip)
		defer rl.EndRequest(ip)
		
		next.ServeHTTP(w, r)
	})
}

// extractIP gets the client IP from the request
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fallback to RemoteAddr
	ip := r.RemoteAddr
	// Strip port
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}

// maskIP masks an IP for logging (privacy)
func maskIP(ip string) string {
	if len(ip) <= 8 {
		return "xxx.xxx"
	}
	// Show first part only
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' && i > 0 {
			// Found first dot, show up to second dot
			for j := i + 1; j < len(ip); j++ {
				if ip[j] == '.' {
					return ip[:j] + ".xxx"
				}
			}
			return ip[:i] + ".xxx"
		}
	}
	return ip[:4] + "xxx"
}
