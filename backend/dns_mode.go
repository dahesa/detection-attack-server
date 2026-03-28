package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// DNSModeConfig configuration untuk DNS-based deployment
type DNSModeConfig struct {
	Enabled     bool            `json:"enabled"`
	DNSProvider string          `json:"dns_provider"` // cloudflare, route53, custom
	APIToken    string          `json:"api_token"`
	ZoneID      string          `json:"zone_id"`
	Proxied     bool            `json:"proxied"` // Cloudflare proxy
	AutoSSL     bool            `json:"auto_ssl"`
	Domains     []*DomainConfig `json:"domains"`
}

// DomainConfig configuration untuk domain
type DomainConfig struct {
	Domain       string `json:"domain"`
	Subdomain    string `json:"subdomain"`
	Target       string `json:"target"` // IP atau CNAME
	Type         string `json:"type"`   // A, AAAA, CNAME
	Proxied      bool   `json:"proxied"`
	SSLMode      string `json:"ssl_mode"` // off, flexible, full, strict
	AutoMinify   bool   `json:"auto_minify"`
	RocketLoader bool   `json:"rocket_loader"`
	WAFEnabled   bool   `json:"waf_enabled"`
}

// DNSMode handles DNS-based deployment
type DNSMode struct {
	config       *DNSModeConfig
	domains      map[string]*DomainConfig
	dnsProvider  DNSProvider
	mu           sync.RWMutex
	healthChecks map[string]*HealthCheck
}

// DNSProvider interface untuk DNS provider
type DNSProvider interface {
	CreateRecord(domain *DomainConfig) error
	UpdateRecord(domain *DomainConfig) error
	DeleteRecord(domain string) error
	GetRecords() ([]*DomainConfig, error)
}

// HealthCheck health check untuk domain
type HealthCheck struct {
	Domain       string
	URL          string
	Interval     time.Duration
	LastCheck    time.Time
	IsHealthy    bool
	ResponseTime time.Duration
}

// NewDNSMode creates new DNS mode
func NewDNSMode(config *DNSModeConfig) (*DNSMode, error) {
	dns := &DNSMode{
		config:       config,
		domains:      make(map[string]*DomainConfig),
		healthChecks: make(map[string]*HealthCheck),
	}

	// Initialize DNS provider
	var err error
	switch config.DNSProvider {
	case "cloudflare":
		dns.dnsProvider = NewCloudflareProvider(config.APIToken, config.ZoneID)
	case "route53":
		dns.dnsProvider = NewRoute53Provider(config.APIToken)
	case "custom":
		dns.dnsProvider = NewCustomDNSProvider()
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", config.DNSProvider)
	}

	// Load existing domains
	for _, domain := range config.Domains {
		dns.domains[domain.Domain] = domain
		dns.startHealthCheck(domain)
	}

	return dns, err
}

// AddDomain adds a new domain
func (dns *DNSMode) AddDomain(domain *DomainConfig) error {
	dns.mu.Lock()
	defer dns.mu.Unlock()

	// Create DNS record
	if err := dns.dnsProvider.CreateRecord(domain); err != nil {
		return fmt.Errorf("failed to create DNS record: %v", err)
	}

	dns.domains[domain.Domain] = domain
	dns.config.Domains = append(dns.config.Domains, domain)

	// Start health check
	dns.startHealthCheck(domain)

	log.Printf("✅ Domain added: %s -> %s", domain.Domain, domain.Target)
	return nil
}

// UpdateDomain updates domain configuration
func (dns *DNSMode) UpdateDomain(domain *DomainConfig) error {
	dns.mu.Lock()
	defer dns.mu.Unlock()

	if _, exists := dns.domains[domain.Domain]; !exists {
		return fmt.Errorf("domain not found: %s", domain.Domain)
	}

	// Update DNS record
	if err := dns.dnsProvider.UpdateRecord(domain); err != nil {
		return fmt.Errorf("failed to update DNS record: %v", err)
	}

	dns.domains[domain.Domain] = domain

	log.Printf("✅ Domain updated: %s", domain.Domain)
	return nil
}

// RemoveDomain removes a domain
func (dns *DNSMode) RemoveDomain(domain string) error {
	dns.mu.Lock()
	defer dns.mu.Unlock()

	if _, exists := dns.domains[domain]; !exists {
		return fmt.Errorf("domain not found: %s", domain)
	}

	// Delete DNS record
	if err := dns.dnsProvider.DeleteRecord(domain); err != nil {
		return fmt.Errorf("failed to delete DNS record: %v", err)
	}

	delete(dns.domains, domain)
	delete(dns.healthChecks, domain)

	log.Printf("✅ Domain removed: %s", domain)
	return nil
}

// ResolveDomain resolves domain to target
func (dns *DNSMode) ResolveDomain(host string) (*DomainConfig, error) {
	dns.mu.RLock()
	defer dns.mu.RUnlock()

	// Try exact match
	if domain, exists := dns.domains[host]; exists {
		return domain, nil
	}

	// Try subdomain match
	for _, domain := range dns.domains {
		if domain.Subdomain != "" {
			fullDomain := fmt.Sprintf("%s.%s", domain.Subdomain, domain.Domain)
			if fullDomain == host {
				return domain, nil
			}
		}
	}

	return nil, fmt.Errorf("domain not found: %s", host)
}

func (dns *DNSMode) startHealthCheck(domain *DomainConfig) {
	check := &HealthCheck{
		Domain:    domain.Domain,
		URL:       fmt.Sprintf("http://%s/health", domain.Target),
		Interval:  30 * time.Second,
		IsHealthy: true,
	}

	dns.healthChecks[domain.Domain] = check

	go func() {
		ticker := time.NewTicker(check.Interval)
		defer ticker.Stop()

		for range ticker.C {
			dns.performHealthCheck(check)
		}
	}()
}

func (dns *DNSMode) performHealthCheck(check *HealthCheck) {
	start := time.Now()
	resp, err := http.Get(check.URL)
	check.ResponseTime = time.Since(start)

	if err != nil {
		check.IsHealthy = false
		check.LastCheck = time.Now()
		return
	}
	defer resp.Body.Close()

	check.IsHealthy = resp.StatusCode < 500
	check.LastCheck = time.Now()
}

// Middleware untuk DNS mode
func (dns *DNSMode) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !dns.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		domain, err := dns.ResolveDomain(host)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Domain not found"}`))
			return
		}

		// Check health
		if check, exists := dns.healthChecks[domain.Domain]; exists && !check.IsHealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error": "Backend unavailable"}`))
			return
		}

		// Add domain headers
		r.Header.Set("X-Domain", domain.Domain)
		r.Header.Set("X-Target", domain.Target)
		w.Header().Set("X-DNS-Mode", "enabled")

		next.ServeHTTP(w, r)
	})
}

// CloudflareProvider Cloudflare DNS provider
type CloudflareProvider struct {
	apiToken string
	zoneID   string
}

func NewCloudflareProvider(apiToken, zoneID string) *CloudflareProvider {
	return &CloudflareProvider{
		apiToken: apiToken,
		zoneID:   zoneID,
	}
}

func (cf *CloudflareProvider) CreateRecord(domain *DomainConfig) error {
	// In production, make actual API call to Cloudflare
	log.Printf("🌐 Creating Cloudflare DNS record: %s -> %s", domain.Domain, domain.Target)
	return nil
}

func (cf *CloudflareProvider) UpdateRecord(domain *DomainConfig) error {
	log.Printf("🌐 Updating Cloudflare DNS record: %s", domain.Domain)
	return nil
}

func (cf *CloudflareProvider) DeleteRecord(domain string) error {
	log.Printf("🌐 Deleting Cloudflare DNS record: %s", domain)
	return nil
}

func (cf *CloudflareProvider) GetRecords() ([]*DomainConfig, error) {
	return []*DomainConfig{}, nil
}

// Route53Provider AWS Route53 provider
type Route53Provider struct {
	apiToken string
}

func NewRoute53Provider(apiToken string) *Route53Provider {
	return &Route53Provider{apiToken: apiToken}
}

func (r53 *Route53Provider) CreateRecord(domain *DomainConfig) error {
	log.Printf("🌐 Creating Route53 DNS record: %s -> %s", domain.Domain, domain.Target)
	return nil
}

func (r53 *Route53Provider) UpdateRecord(domain *DomainConfig) error {
	log.Printf("🌐 Updating Route53 DNS record: %s", domain.Domain)
	return nil
}

func (r53 *Route53Provider) DeleteRecord(domain string) error {
	log.Printf("🌐 Deleting Route53 DNS record: %s", domain)
	return nil
}

func (r53 *Route53Provider) GetRecords() ([]*DomainConfig, error) {
	return []*DomainConfig{}, nil
}

// CustomDNSProvider custom DNS provider
type CustomDNSProvider struct{}

func NewCustomDNSProvider() *CustomDNSProvider {
	return &CustomDNSProvider{}
}

func (c *CustomDNSProvider) CreateRecord(domain *DomainConfig) error {
	log.Printf("🌐 Creating custom DNS record: %s -> %s", domain.Domain, domain.Target)
	return nil
}

func (c *CustomDNSProvider) UpdateRecord(domain *DomainConfig) error {
	log.Printf("🌐 Updating custom DNS record: %s", domain.Domain)
	return nil
}

func (c *CustomDNSProvider) DeleteRecord(domain string) error {
	log.Printf("🌐 Deleting custom DNS record: %s", domain)
	return nil
}

func (c *CustomDNSProvider) GetRecords() ([]*DomainConfig, error) {
	return []*DomainConfig{}, nil
}

// GetStats returns DNS mode statistics
func (dns *DNSMode) GetStats() map[string]interface{} {
	dns.mu.RLock()
	defer dns.mu.RUnlock()

	healthyCount := 0
	for _, check := range dns.healthChecks {
		if check.IsHealthy {
			healthyCount++
		}
	}

	return map[string]interface{}{
		"enabled":         dns.config.Enabled,
		"total_domains":   len(dns.domains),
		"healthy_domains": healthyCount,
		"dns_provider":    dns.config.DNSProvider,
	}
}
