package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/libdns/libdns"
)

// DNSProvider interface defines methods for external DNS management
type DNSProvider interface {
	// GetName returns the provider name
	GetName() string
	// SetCredentials sets API credentials
	SetCredentials(creds map[string]string) error
	// CreateRecord creates a DNS A record
	CreateRecord(domain, subdomain, recordType, value string, ttl int) error
	// DeleteRecord deletes a DNS record
	DeleteRecord(domain, subdomain, recordType string) error
	// ListRecords lists all DNS records for a domain
	ListRecords(domain string) ([]DNSRecord, error)
	// GetRecord gets a specific DNS record
	GetRecord(domain, subdomain, recordType string) (*DNSRecord, error)
	// UpdateRecord updates an existing DNS record
	UpdateRecord(domain, subdomain, recordType, value string, ttl int) error
	// IsConfigured returns true if the provider is properly configured
	IsConfigured() bool
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Content   string `json:"content"`
	TTL       int    `json:"ttl"`
	Proxied   bool   `json:"proxied,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// ExternalDNS manages DNS records through external providers
type ExternalDNS struct {
	providers map[string]DNSProvider
	domains   map[string]*DomainDNSConfig
	mu        sync.RWMutex
}

// DomainDNSConfig holds configuration for a domain's DNS
type DomainDNSConfig struct {
	Domain       string            `mapstructure:"domain" json:"domain" yaml:"domain"`
	Provider     string            `mapstructure:"provider" json:"provider" yaml:"provider"`
	Credentials  map[string]string `mapstructure:"credentials" json:"credentials" yaml:"credentials"`
	ManagedHosts []string          `mapstructure:"managed_hosts" json:"managed_hosts" yaml:"managed_hosts"`
}

// NewExternalDNS creates a new ExternalDNS manager
func NewExternalDNS() *ExternalDNS {
	return &ExternalDNS{
		providers: make(map[string]DNSProvider),
		domains:   make(map[string]*DomainDNSConfig),
	}
}

// RegisterProvider registers a DNS provider
func (e *ExternalDNS) RegisterProvider(name string, provider DNSProvider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.providers[name] = provider
}

// GetProvider returns a DNS provider by name
func (e *ExternalDNS) GetProvider(name string) (DNSProvider, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.providers[name]
	return p, ok
}

// AddDomain adds a domain with its DNS configuration
func (e *ExternalDNS) AddDomain(config *DomainDNSConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if config.Domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	e.domains[config.Domain] = config
	return nil
}

// GetDomainConfig returns the DNS configuration for a domain
func (e *ExternalDNS) GetDomainConfig(domain string) (*DomainDNSConfig, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cfg, ok := e.domains[domain]
	return cfg, ok
}

// RemoveDomain removes a domain configuration
func (e *ExternalDNS) RemoveDomain(domain string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.domains, domain)
}

// ListDomains returns all configured domains
func (e *ExternalDNS) ListDomains() []*DomainDNSConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	domains := make([]*DomainDNSConfig, 0, len(e.domains))
	for _, d := range e.domains {
		domains = append(domains, d)
	}
	return domains
}

// CreateARecord creates an A record for a hostname
func (e *ExternalDNS) CreateARecord(hostname, ip string, ttl int) error {
	domain, subdomain := e.splitHostname(hostname)
	if domain == "" {
		// No external DNS configured for this domain — internal nameserver will handle it
		return nil
	}

	cfg, ok := e.GetDomainConfig(domain)
	if !ok {
		return nil // Not configured for external DNS, internal handles it
	}

	if cfg.Provider == "internal" || cfg.Provider == "" {
		log.Debug("DNS: using internal nameserver for %s", hostname)
		return nil // Internal DNS, no action needed
	}

	provider, ok := e.GetProvider(cfg.Provider)
	if !ok {
		return fmt.Errorf("unknown DNS provider: %s", cfg.Provider)
	}

	// Set credentials for the provider
	if err := provider.SetCredentials(cfg.Credentials); err != nil {
		return fmt.Errorf("failed to set credentials: %v", err)
	}

	// Check if record exists
	existing, err := provider.GetRecord(domain, subdomain, "A")
	if err == nil && existing != nil {
		// Record exists, update it
		if existing.Content != ip {
			log.Info("DNS: updating A record %s -> %s", hostname, ip)
			return provider.UpdateRecord(domain, subdomain, "A", ip, ttl)
		}
		log.Debug("DNS: A record %s already exists with correct IP", hostname)
		return nil
	}

	// Create new record
	log.Info("DNS: creating A record %s -> %s", hostname, ip)
	err = provider.CreateRecord(domain, subdomain, "A", ip, ttl)
	if err != nil {
		return fmt.Errorf("failed to create DNS record: %v", err)
	}

	// Track managed host
	e.addManagedHost(domain, hostname)
	return nil
}

// DeleteARecord deletes an A record for a hostname
func (e *ExternalDNS) DeleteARecord(hostname string) error {
	domain, subdomain := e.splitHostname(hostname)
	if domain == "" {
		return nil // No external DNS configured, nothing to delete
	}

	cfg, ok := e.GetDomainConfig(domain)
	if !ok {
		return nil // Not configured, nothing to delete
	}

	if cfg.Provider == "internal" || cfg.Provider == "" {
		return nil // Internal DNS, no action needed
	}

	provider, ok := e.GetProvider(cfg.Provider)
	if !ok {
		return fmt.Errorf("unknown DNS provider: %s", cfg.Provider)
	}

	if err := provider.SetCredentials(cfg.Credentials); err != nil {
		return fmt.Errorf("failed to set credentials: %v", err)
	}

	log.Info("DNS: deleting A record for %s", hostname)
	err := provider.DeleteRecord(domain, subdomain, "A")
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %v", err)
	}

	e.removeManagedHost(domain, hostname)
	return nil
}

// splitHostname splits a hostname into domain and subdomain parts
func (e *ExternalDNS) splitHostname(hostname string) (domain, subdomain string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Find the matching configured domain
	for d := range e.domains {
		if hostname == d {
			return d, "@"
		}
		if strings.HasSuffix(hostname, "."+d) {
			subdomain = strings.TrimSuffix(hostname, "."+d)
			return d, subdomain
		}
	}
	return "", ""
}

// addManagedHost adds a hostname to the managed hosts list
func (e *ExternalDNS) addManagedHost(domain, hostname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cfg, ok := e.domains[domain]; ok {
		for _, h := range cfg.ManagedHosts {
			if h == hostname {
				return
			}
		}
		cfg.ManagedHosts = append(cfg.ManagedHosts, hostname)
	}
}

// removeManagedHost removes a hostname from the managed hosts list
func (e *ExternalDNS) removeManagedHost(domain, hostname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cfg, ok := e.domains[domain]; ok {
		for i, h := range cfg.ManagedHosts {
			if h == hostname {
				cfg.ManagedHosts = append(cfg.ManagedHosts[:i], cfg.ManagedHosts[i+1:]...)
				return
			}
		}
	}
}

// ============================================================================
// Cloudflare DNS Provider
// ============================================================================

type CloudflareDNS struct {
	apiToken string
	zoneIDs  map[string]string // domain -> zone ID cache
	client   *http.Client
}

func NewCloudflareDNS() *CloudflareDNS {
	return &CloudflareDNS{
		zoneIDs: make(map[string]string),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *CloudflareDNS) GetName() string {
	return "cloudflare"
}

func (c *CloudflareDNS) SetCredentials(creds map[string]string) error {
	token, ok := creds["api_token"]
	if !ok || token == "" {
		return fmt.Errorf("cloudflare requires 'api_token' credential")
	}
	c.apiToken = token
	return nil
}

func (c *CloudflareDNS) IsConfigured() bool {
	return c.apiToken != ""
}

func (c *CloudflareDNS) getZoneID(domain string) (string, error) {
	if zoneID, ok := c.zoneIDs[domain]; ok {
		return zoneID, nil
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if !result.Success || len(result.Result) == 0 {
		errMsg := "zone not found"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		return "", fmt.Errorf("cloudflare: %s", errMsg)
	}

	c.zoneIDs[domain] = result.Result[0].ID
	return result.Result[0].ID, nil
}

func (c *CloudflareDNS) CreateRecord(domain, subdomain, recordType, value string, ttl int) error {
	zoneID, err := c.getZoneID(domain)
	if err != nil {
		return err
	}

	name := domain
	if subdomain != "@" && subdomain != "" {
		name = subdomain + "." + domain
	}

	data := map[string]interface{}{
		"type":    recordType,
		"name":    name,
		"content": value,
		"ttl":     ttl,
		"proxied": false,
	}

	body, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if !result.Success {
		errMsg := "failed to create record"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		return fmt.Errorf("cloudflare: %s", errMsg)
	}

	return nil
}

func (c *CloudflareDNS) DeleteRecord(domain, subdomain, recordType string) error {
	// Delete ALL matching records, not just the first one
	// This is critical for TXT records which can have multiple values
	for {
		record, err := c.GetRecord(domain, subdomain, recordType)
		if err != nil {
			return err
		}
		if record == nil {
			return nil // No more records to delete
		}

		zoneID, err := c.getZoneID(domain)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("DELETE", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, record.ID), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var result struct {
			Success bool `json:"success"`
			Errors  []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		if !result.Success {
			errMsg := "failed to delete record"
			if len(result.Errors) > 0 {
				errMsg = result.Errors[0].Message
			}
			return fmt.Errorf("cloudflare: %s", errMsg)
		}

		log.Debug("cloudflare: deleted %s record %s.%s (ID: %s)", recordType, subdomain, domain, record.ID)
	}
}

func (c *CloudflareDNS) ListRecords(domain string) ([]DNSRecord, error) {
	zoneID, err := c.getZoneID(domain)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
			TTL     int    `json:"ttl"`
			Proxied bool   `json:"proxied"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.Success {
		errMsg := "failed to list records"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		return nil, fmt.Errorf("cloudflare: %s", errMsg)
	}

	records := make([]DNSRecord, len(result.Result))
	for i, r := range result.Result {
		records[i] = DNSRecord{
			ID:      r.ID,
			Name:    r.Name,
			Type:    r.Type,
			Content: r.Content,
			TTL:     r.TTL,
			Proxied: r.Proxied,
		}
	}

	return records, nil
}

func (c *CloudflareDNS) GetRecord(domain, subdomain, recordType string) (*DNSRecord, error) {
	zoneID, err := c.getZoneID(domain)
	if err != nil {
		return nil, err
	}

	name := domain
	if subdomain != "@" && subdomain != "" {
		name = subdomain + "." + domain
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=%s", zoneID, name, recordType), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
			TTL     int    `json:"ttl"`
			Proxied bool   `json:"proxied"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.Success {
		errMsg := "failed to get record"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		return nil, fmt.Errorf("cloudflare: %s", errMsg)
	}

	if len(result.Result) == 0 {
		return nil, nil
	}

	r := result.Result[0]
	return &DNSRecord{
		ID:      r.ID,
		Name:    r.Name,
		Type:    r.Type,
		Content: r.Content,
		TTL:     r.TTL,
		Proxied: r.Proxied,
	}, nil
}

func (c *CloudflareDNS) UpdateRecord(domain, subdomain, recordType, value string, ttl int) error {
	record, err := c.GetRecord(domain, subdomain, recordType)
	if err != nil {
		return err
	}
	if record == nil {
		return c.CreateRecord(domain, subdomain, recordType, value, ttl)
	}

	zoneID, err := c.getZoneID(domain)
	if err != nil {
		return err
	}

	name := domain
	if subdomain != "@" && subdomain != "" {
		name = subdomain + "." + domain
	}

	data := map[string]interface{}{
		"type":    recordType,
		"name":    name,
		"content": value,
		"ttl":     ttl,
		"proxied": false,
	}

	body, _ := json.Marshal(data)
	req, err := http.NewRequest("PUT", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, record.ID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if !result.Success {
		errMsg := "failed to update record"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		return fmt.Errorf("cloudflare: %s", errMsg)
	}

	return nil
}

// ============================================================================
// DigitalOcean DNS Provider
// ============================================================================

type DigitalOceanDNS struct {
	apiToken string
	client   *http.Client
}

func NewDigitalOceanDNS() *DigitalOceanDNS {
	return &DigitalOceanDNS{
		client: &http.Client{
			Transport: GetUtlsRoundTripper(),
			Timeout:   30 * time.Second,
		},
	}
}

func (d *DigitalOceanDNS) GetName() string {
	return "digitalocean"
}

func (d *DigitalOceanDNS) SetCredentials(creds map[string]string) error {
	token, ok := creds["api_token"]
	if !ok || token == "" {
		return fmt.Errorf("digitalocean requires 'api_token' credential")
	}
	d.apiToken = token
	return nil
}

func (d *DigitalOceanDNS) IsConfigured() bool {
	return d.apiToken != ""
}

func (d *DigitalOceanDNS) CreateRecord(domain, subdomain, recordType, value string, ttl int) error {
	name := subdomain
	if name == "" {
		name = "@"
	}

	data := map[string]interface{}{
		"type": recordType,
		"name": name,
		"data": value,
		"ttl":  ttl,
	}

	body, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s/records", domain), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("digitalocean: failed to create record: %s", string(bodyBytes))
	}

	return nil
}

func (d *DigitalOceanDNS) DeleteRecord(domain, subdomain, recordType string) error {
	// Delete ALL matching records, not just the first one
	// This is critical for TXT records which can have multiple values
	for {
		record, err := d.GetRecord(domain, subdomain, recordType)
		if err != nil {
			return err
		}
		if record == nil {
			return nil // No more records to delete
		}

		req, err := http.NewRequest("DELETE", fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s/records/%s", domain, record.ID), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+d.apiToken)

		resp, err := d.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 && resp.StatusCode != 404 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("digitalocean: failed to delete record: %s", string(bodyBytes))
		}

		log.Debug("digitalocean: deleted %s record %s.%s (ID: %s)", recordType, subdomain, domain, record.ID)
	}
}

func (d *DigitalOceanDNS) ListRecords(domain string) ([]DNSRecord, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s/records", domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("digitalocean: failed to list records: %s", string(bodyBytes))
	}

	var result struct {
		DomainRecords []struct {
			ID   int    `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
			Data string `json:"data"`
			TTL  int    `json:"ttl"`
		} `json:"domain_records"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	records := make([]DNSRecord, len(result.DomainRecords))
	for i, r := range result.DomainRecords {
		name := r.Name
		if name != "@" {
			name = r.Name + "." + domain
		} else {
			name = domain
		}
		records[i] = DNSRecord{
			ID:      fmt.Sprintf("%d", r.ID),
			Name:    name,
			Type:    r.Type,
			Content: r.Data,
			TTL:     r.TTL,
		}
	}

	return records, nil
}

func (d *DigitalOceanDNS) GetRecord(domain, subdomain, recordType string) (*DNSRecord, error) {
	records, err := d.ListRecords(domain)
	if err != nil {
		return nil, err
	}

	name := domain
	if subdomain != "@" && subdomain != "" {
		name = subdomain + "." + domain
	}

	for _, r := range records {
		if r.Name == name && r.Type == recordType {
			return &r, nil
		}
	}

	return nil, nil
}

func (d *DigitalOceanDNS) UpdateRecord(domain, subdomain, recordType, value string, ttl int) error {
	record, err := d.GetRecord(domain, subdomain, recordType)
	if err != nil {
		return err
	}
	if record == nil {
		return d.CreateRecord(domain, subdomain, recordType, value, ttl)
	}

	name := subdomain
	if name == "" {
		name = "@"
	}

	data := map[string]interface{}{
		"type": recordType,
		"name": name,
		"data": value,
		"ttl":  ttl,
	}

	body, _ := json.Marshal(data)
	req, err := http.NewRequest("PUT", fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s/records/%s", domain, record.ID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("digitalocean: failed to update record: %s", string(bodyBytes))
	}

	return nil
}

// ============================================================================
// Global instance and helper functions
// ============================================================================

var globalExternalDNS *ExternalDNS

func init() {
	globalExternalDNS = NewExternalDNS()
	globalExternalDNS.RegisterProvider("cloudflare", NewCloudflareDNS())
	globalExternalDNS.RegisterProvider("digitalocean", NewDigitalOceanDNS())
}

// GetExternalDNS returns the global ExternalDNS instance
func GetExternalDNS() *ExternalDNS {
	return globalExternalDNS
}

// GetAvailableDNSProviders returns a list of available DNS provider names
func GetAvailableDNSProviders() []string {
	return []string{"internal", "cloudflare", "digitalocean"}
}

// ============================================================================
// libdns-compatible DNS Provider for certmagic DNS-01 challenge
// This wrapper allows certmagic to use our existing DNS providers
// ============================================================================

// LibDNSProvider wraps our ExternalDNS to implement libdns interfaces
// required by certmagic for DNS-01 ACME challenges
type LibDNSProvider struct {
	externalDNS *ExternalDNS
	cfg         *Config
}

// NewLibDNSProvider creates a new libdns-compatible provider
func NewLibDNSProvider(externalDNS *ExternalDNS, cfg *Config) *LibDNSProvider {
	return &LibDNSProvider{
		externalDNS: externalDNS,
		cfg:         cfg,
	}
}

// AppendRecords implements libdns.RecordAppender
// This is used by certmagic to create the _acme-challenge TXT record
func (p *LibDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var created []libdns.Record

	// Normalize zone name (remove trailing dot if present)
	zone = strings.TrimSuffix(zone, ".")

	log.Debug("libdns: AppendRecords called for zone %s with %d records", zone, len(recs))

	for _, rec := range recs {
		// Get subdomain name (libdns uses relative names)
		subdomain := strings.TrimSuffix(rec.Name, ".")
		if subdomain == "@" || subdomain == "" {
			subdomain = "@"
		}

		log.Debug("libdns: Creating %s record: %s.%s = %s", rec.Type, subdomain, zone, rec.Value)

		// Get domain configuration
		domCfg, ok := p.externalDNS.GetDomainConfig(zone)
		if !ok {
			return nil, fmt.Errorf("domain %s not configured for external DNS", zone)
		}

		if domCfg.Provider == "internal" || domCfg.Provider == "" {
			return nil, fmt.Errorf("DNS-01 challenge requires external DNS provider, but domain %s uses internal DNS", zone)
		}

		provider, ok := p.externalDNS.GetProvider(domCfg.Provider)
		if !ok {
			return nil, fmt.Errorf("unknown DNS provider: %s", domCfg.Provider)
		}

		if err := provider.SetCredentials(domCfg.Credentials); err != nil {
			return nil, fmt.Errorf("failed to set credentials: %v", err)
		}

		// IMPORTANT: Delete ALL existing records with the same name FIRST
		// This clears stale _acme-challenge TXT records that cause DNS-01 failures
		log.Info("DNS-01: cleaning up existing %s records for %s.%s...", rec.Type, subdomain, zone)
		if err := provider.DeleteRecord(zone, subdomain, rec.Type); err != nil {
			log.Warning("DNS-01: failed to clean up existing records: %v", err)
		}

		// Wait for deletion to propagate
		time.Sleep(2 * time.Second)

		// Convert TTL to seconds (libdns uses time.Duration)
		ttl := int(rec.TTL.Seconds())
		if ttl == 0 {
			ttl = 60 // Short TTL for ACME challenges (1 minute)
		}

		// Create the record
		log.Info("DNS-01: creating %s record: %s.%s = %s", rec.Type, subdomain, zone, rec.Value)
		err := provider.CreateRecord(zone, subdomain, rec.Type, rec.Value, ttl)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS record: %v", err)
		}

		created = append(created, rec)
		log.Success("DNS-01: created %s record for %s.%s", rec.Type, subdomain, zone)

		// Wait for Cloudflare DNS propagation before validation
		log.Info("DNS-01: waiting 10 seconds for DNS propagation...")
		time.Sleep(10 * time.Second)
	}

	return created, nil
}

// DeleteRecords implements libdns.RecordDeleter
// This is used by certmagic to clean up the _acme-challenge TXT record
func (p *LibDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record

	// Normalize zone name (remove trailing dot if present)
	zone = strings.TrimSuffix(zone, ".")

	log.Debug("libdns: DeleteRecords called for zone %s with %d records", zone, len(recs))

	for _, rec := range recs {
		subdomain := strings.TrimSuffix(rec.Name, ".")
		if subdomain == "@" || subdomain == "" {
			subdomain = "@"
		}

		log.Debug("libdns: Deleting %s record: %s.%s", rec.Type, subdomain, zone)

		// Get domain configuration
		domCfg, ok := p.externalDNS.GetDomainConfig(zone)
		if !ok {
			log.Warning("libdns: domain %s not configured, skipping delete", zone)
			continue
		}

		if domCfg.Provider == "internal" || domCfg.Provider == "" {
			continue
		}

		provider, ok := p.externalDNS.GetProvider(domCfg.Provider)
		if !ok {
			log.Warning("libdns: unknown provider %s, skipping delete", domCfg.Provider)
			continue
		}

		if err := provider.SetCredentials(domCfg.Credentials); err != nil {
			log.Warning("libdns: failed to set credentials: %v", err)
			continue
		}

		// Delete the record
		err := provider.DeleteRecord(zone, subdomain, rec.Type)
		if err != nil {
			log.Warning("libdns: failed to delete record: %v", err)
			continue
		}

		deleted = append(deleted, rec)
		log.Info("DNS-01: deleted %s record for %s.%s", rec.Type, subdomain, zone)
	}

	return deleted, nil
}

// GetRecords implements libdns.RecordGetter (optional but useful)
func (p *LibDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	var records []libdns.Record

	// Normalize zone name
	zone = strings.TrimSuffix(zone, ".")

	domCfg, ok := p.externalDNS.GetDomainConfig(zone)
	if !ok {
		return nil, fmt.Errorf("domain %s not configured for external DNS", zone)
	}

	if domCfg.Provider == "internal" || domCfg.Provider == "" {
		return nil, fmt.Errorf("domain %s uses internal DNS", zone)
	}

	provider, ok := p.externalDNS.GetProvider(domCfg.Provider)
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider: %s", domCfg.Provider)
	}

	if err := provider.SetCredentials(domCfg.Credentials); err != nil {
		return nil, fmt.Errorf("failed to set credentials: %v", err)
	}

	// Get records from provider
	dnsRecords, err := provider.ListRecords(zone)
	if err != nil {
		return nil, err
	}

	// Convert to libdns format
	for _, rec := range dnsRecords {
		records = append(records, libdns.Record{
			ID:    rec.ID,
			Type:  rec.Type,
			Name:  rec.Name,
			Value: rec.Content,
			TTL:   time.Duration(rec.TTL) * time.Second,
		})
	}

	return records, nil
}

// CanUseExternalDNS checks if a domain is configured for external DNS
// and can be used for DNS-01 challenge (required for wildcard certs)
func CanUseExternalDNS(domain string) bool {
	domCfg, ok := GetExternalDNS().GetDomainConfig(domain)
	if !ok {
		return false
	}
	return domCfg.Provider != "internal" && domCfg.Provider != ""
}
