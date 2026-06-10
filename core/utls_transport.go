package core

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// utlsH2RoundTripper wraps goproxy's http.Transport with HTTP/2 support
// via golang.org/x/net/http2 and uTLS Chrome 120 fingerprint.
//
// When an outgoing TLS connection negotiates HTTP/2 (via ALPN h2),
// requests are forwarded using http2.ClientConn. Otherwise, standard
// HTTP/1.1 via Go's http.Transport is used.
//
// This is critical for Akamai Bot Manager which cross-validates:
//   - JA3/JA4 TLS fingerprint (including ALPN values)
//   - HTTP/2 SETTINGS frames
//   - User-Agent consistency
type utlsH2RoundTripper struct {
	h1       *http.Transport // fallback HTTP/1.1 transport
	origDial func(string, string) (net.Conn, error)

	mu    sync.Mutex
	conns map[string]*http2.ClientConn // addr -> h2 conn
}

// SetDial updates the underlying dial function used for raw TCP connections.
// Called when an upstream proxy is enabled/disabled at runtime so that
// uTLS connections also go through the proxy.
func (rt *utlsH2RoundTripper) SetDial(dialFn func(string, string) (net.Conn, error)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.origDial = dialFn
	// Flush cached h2 connections so new ones use the updated dial
	for addr, cc := range rt.conns {
		cc.Close()
		delete(rt.conns, addr)
	}
}

// setupUtlsTransport configures an http.Transport to use uTLS with a
// Chrome 120 TLS fingerprint for ALL outgoing TLS connections.
// HTTP/2 is supported via golang.org/x/net/http2 when the server negotiates h2.
func setupUtlsTransport(tr *http.Transport) {
	rt := &utlsH2RoundTripper{
		h1:       tr,
		origDial: tr.Dial,
		conns:    make(map[string]*http2.ClientConn),
	}

	// Set up HTTP/1.1 fallback with utls (ALPN: http/1.1 only)
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return rt.dialUtls(ctx, network, addr, false)
	}

	// Store the round tripper for use in the proxy
	_utlsRT = rt
}

// Global reference so the proxy can use it
var _utlsRT *utlsH2RoundTripper

// GetUtlsRoundTripper returns the HTTP/2-capable round tripper.
// Returns nil if not yet initialized.
func GetUtlsRoundTripper() *utlsH2RoundTripper {
	return _utlsRT
}

var _httpClient *http.Client
var _httpClientOnce sync.Once

// GetHttpClient returns a centralized http.Client that uses the uTLS transport.
// This client automatically respects the configured outbound proxy.
func GetHttpClient() *http.Client {
	_httpClientOnce.Do(func() {
		tr := GetUtlsRoundTripper()
		if tr == nil {
			log.Error("utls transport: GetHttpClient called before initialization! Fallback to standard transport.")
			_httpClient = &http.Client{
				Timeout: 30 * time.Second,
			}
			return
		}
		_httpClient = &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		}
	})
	return _httpClient
}

// RoundTrip implements http.RoundTripper with HTTP/2 support.
// For HTTPS requests, it tries HTTP/2 first, then falls back to HTTP/1.1.
func (rt *utlsH2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return rt.h1.RoundTrip(req)
	}

	addr := req.URL.Host
	if !hasPort(addr) {
		addr = addr + ":443"
	}

	// Try existing h2 connection
	rt.mu.Lock()
	cc, ok := rt.conns[addr]
	rt.mu.Unlock()

	if ok {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// Connection gone, remove and try fresh
		rt.mu.Lock()
		delete(rt.conns, addr)
		rt.mu.Unlock()
		log.Debug("utls-h2: recycled stale connection for %s", addr)
	}

	// Dial fresh utls connection with h2 ALPN
	conn, err := rt.dialUtls(req.Context(), "tcp", addr, true)
	if err != nil {
		return nil, err
	}

	// Check negotiated protocol
	uconn, isUtls := conn.(*utls.UConn)
	if isUtls && uconn.ConnectionState().NegotiatedProtocol == "h2" {
		// HTTP/2 negotiated — use http2.ClientConn
		h2t := &http2.Transport{}
		h2cc, err := h2t.NewClientConn(conn)
		if err != nil {
			conn.Close()
			log.Debug("utls-h2: failed to create h2 conn for %s: %v", addr, err)
			// Fall back to h1
			return rt.h1.RoundTrip(req)
		}

		rt.mu.Lock()
		rt.conns[addr] = h2cc
		rt.mu.Unlock()

		log.Debug("utls-h2: HTTP/2 connection established for %s", addr)
		return h2cc.RoundTrip(req)
	}

	// HTTP/1.1 — close this conn (h1 transport manages its own pool)
	conn.Close()
	return rt.h1.RoundTrip(req)
}

// dialUtls establishes a uTLS connection with Chrome 120 fingerprint.
// If withH2 is true, ALPN includes both h2 and http/1.1 (Chrome-like).
// If false, ALPN is http/1.1 only (for Go's http.Transport compatibility).
func (rt *utlsH2RoundTripper) dialUtls(ctx context.Context, network, addr string, withH2 bool) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Establish raw TCP connection (through proxy if configured)
	// Use optimized dialer with TCP keep-alive for connection reuse
	var rawConn net.Conn
	if rt.origDial != nil {
		rawConn, err = rt.origDial(network, addr)
	} else {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second, // Connection timeout
			KeepAlive: 30 * time.Second, // TCP keep-alive interval
		}
		rawConn, err = dialer.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}

	// Set TCP buffer sizes for better throughput
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)           // Disable Nagle's algorithm (reduce latency)
		tcpConn.SetReadBuffer(256 * 1024)  // 256KB read buffer
		tcpConn.SetWriteBuffer(256 * 1024) // 256KB write buffer
	}

	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	tlsConn := utls.UClient(rawConn, config, utls.HelloChrome_120)

	if !withH2 {
		// Patch ALPN to http/1.1 only for Go's http.Transport
		if err := tlsConn.BuildHandshakeState(); err == nil {
			for _, ext := range tlsConn.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					break
				}
			}
		}
	}
	// When withH2 is true, Chrome 120's default ALPN (h2, http/1.1) is preserved

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	proto := tlsConn.ConnectionState().NegotiatedProtocol
	log.Debug("utls: Chrome TLS fingerprint for %s (ALPN: %s, h2=%v)",
		addr, proto, withH2)

	return tlsConn, nil
}

// CloseIdleConnections closes idle HTTP/2 connections.
func (rt *utlsH2RoundTripper) CloseIdleConnections() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for addr, cc := range rt.conns {
		cc.Close()
		delete(rt.conns, addr)
	}
	rt.h1.CloseIdleConnections()
}

func hasPort(s string) bool {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] == ':' {
			return true
		}
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return false
}

// utlsHandshake is kept for backward compatibility (HTTP/1.1 only).
func utlsHandshake(rawConn net.Conn, host, addr string) (net.Conn, error) {
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	tlsConn := utls.UClient(rawConn, config, utls.HelloChrome_120)

	if err := tlsConn.BuildHandshakeState(); err == nil {
		for _, ext := range tlsConn.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
				break
			}
		}
	}

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	log.Debug("utls: Chrome TLS fingerprint for %s (ALPN: %s)",
		addr, tlsConn.ConnectionState().NegotiatedProtocol)

	return tlsConn, nil
}

// Ensure unused import is used
var _ = tls.VersionTLS12
