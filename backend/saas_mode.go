package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Tenant represents a SaaS tenant
type Tenant struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Domain      string                 `json:"domain"`
	Status      string                 `json:"status"` // active, suspended, trial
	Plan        string                 `json:"plan"`   // free, pro, enterprise
	CreatedAt   time.Time              `json:"created_at"`
	Config      map[string]interface{} `json:"config"`
	RateLimit   int                    `json:"rate_limit"`
	CustomRules string                 `json:"custom_rules"`
	SSLEnabled  bool                   `json:"ssl_enabled"`
	BackendURL  string                 `json:"backend_url"`
	APIKey      string                 `json:"api_key"`
}

// SaaSConfig holds SaaS mode configuration
type SaaSConfig struct {
	Enabled       bool   `json:"enabled"`
	DefaultPlan   string `json:"default_plan"`
	TrialDays     int    `json:"trial_days"`
	MultiDomain   bool   `json:"multi_domain"`
	CustomDomain  bool   `json:"custom_domain"`
	AutoProvision bool   `json:"auto_provision"`
}

// SaaSMode handles multi-tenant SaaS operations
type SaaSMode struct {
	config      *SaaSConfig
	tenants     map[string]*Tenant // domain -> tenant
	tenantsByID map[string]*Tenant // id -> tenant
	mu          sync.RWMutex
	stats       *SaaSStats
}

// SaaSStats holds SaaS statistics
type SaaSStats struct {
	TotalTenants  int64     `json:"total_tenants"`
	ActiveTenants int64     `json:"active_tenants"`
	TrialTenants  int64     `json:"trial_tenants"`
	RequestsToday int64     `json:"requests_today"`
	BlockedToday  int64     `json:"blocked_today"`
	LastUpdated   time.Time `json:"last_updated"`
}

// NewSaaSMode creates a new SaaS mode instance
func NewSaaSMode(config *SaaSConfig) *SaaSMode {
	return &SaaSMode{
		config:      config,
		tenants:     make(map[string]*Tenant),
		tenantsByID: make(map[string]*Tenant),
		stats: &SaaSStats{
			LastUpdated: time.Now(),
		},
	}
}

// GetTenantByDomain gets tenant by domain
func (sm *SaaSMode) GetTenantByDomain(domain string) (*Tenant, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	tenant, exists := sm.tenants[domain]
	if !exists {
		return nil, fmt.Errorf("tenant not found for domain: %s", domain)
	}

	if tenant.Status != "active" {
		return nil, fmt.Errorf("tenant is %s", tenant.Status)
	}

	return tenant, nil
}

// GetTenantByID gets tenant by ID
func (sm *SaaSMode) GetTenantByID(id string) (*Tenant, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	tenant, exists := sm.tenantsByID[id]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", id)
	}

	return tenant, nil
}

// CreateTenant creates a new tenant
func (sm *SaaSMode) CreateTenant(name, domain, plan string) (*Tenant, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if domain already exists
	if _, exists := sm.tenants[domain]; exists {
		return nil, fmt.Errorf("domain already exists: %s", domain)
	}

	tenantID := generateTenantID(domain)
	tenant := &Tenant{
		ID:         tenantID,
		Name:       name,
		Domain:     domain,
		Status:     "trial",
		Plan:       plan,
		CreatedAt:  time.Now(),
		Config:     make(map[string]interface{}),
		RateLimit:  getPlanRateLimit(plan),
		SSLEnabled: true,
		APIKey:     generateAPIKey(tenantID),
	}

	sm.tenants[domain] = tenant
	sm.tenantsByID[tenantID] = tenant
	sm.updateStats()

	log.Printf("✅ Created tenant: %s (%s)", name, domain)
	return tenant, nil
}

// UpdateTenant updates tenant configuration
func (sm *SaaSMode) UpdateTenant(tenantID string, updates map[string]interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	tenant, exists := sm.tenantsByID[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}

	// Update fields
	if name, ok := updates["name"].(string); ok {
		tenant.Name = name
	}
	if status, ok := updates["status"].(string); ok {
		tenant.Status = status
	}
	if plan, ok := updates["plan"].(string); ok {
		tenant.Plan = plan
		tenant.RateLimit = getPlanRateLimit(plan)
	}
	if backendURL, ok := updates["backend_url"].(string); ok {
		tenant.BackendURL = backendURL
	}
	if customRules, ok := updates["custom_rules"].(string); ok {
		tenant.CustomRules = customRules
	}
	if sslEnabled, ok := updates["ssl_enabled"].(bool); ok {
		tenant.SSLEnabled = sslEnabled
	}

	sm.updateStats()
	return nil
}

// DeleteTenant deletes a tenant
func (sm *SaaSMode) DeleteTenant(tenantID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	tenant, exists := sm.tenantsByID[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}

	delete(sm.tenants, tenant.Domain)
	delete(sm.tenantsByID, tenantID)
	sm.updateStats()

	log.Printf("🗑️ Deleted tenant: %s", tenantID)
	return nil
}

// ResolveTenant resolves tenant from request
func (sm *SaaSMode) ResolveTenant(r *http.Request) (*Tenant, error) {
	if !sm.config.Enabled {
		return nil, nil // SaaS mode disabled
	}

	// Try to get tenant from domain
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	tenant, err := sm.GetTenantByDomain(host)
	if err == nil {
		return tenant, nil
	}

	// Try API key
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		sm.mu.RLock()
		for _, t := range sm.tenants {
			if t.APIKey == apiKey {
				sm.mu.RUnlock()
				return t, nil
			}
		}
		sm.mu.RUnlock()
	}

	// Try subdomain
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		_ = parts[0] // subdomain
		baseDomain := strings.Join(parts[1:], ".")
		tenant, err = sm.GetTenantByDomain(baseDomain)
		if err == nil && sm.config.MultiDomain {
			return tenant, nil
		}
	}

	return nil, fmt.Errorf("tenant not found")
}

// Middleware handles SaaS mode tenant resolution
func (sm *SaaSMode) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sm.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		tenant, err := sm.ResolveTenant(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Tenant not found",
				"message": err.Error(),
			})
			return
		}

		if tenant != nil {
			// Add tenant info to headers
			r.Header.Set("X-Tenant-ID", tenant.ID)
			r.Header.Set("X-Tenant-Plan", tenant.Plan)
			w.Header().Set("X-Zein-SaaS-Mode", "enabled")
			w.Header().Set("X-Tenant-ID", tenant.ID)
		}

		next.ServeHTTP(w, r)
	})
}

// GetStats returns SaaS statistics
func (sm *SaaSMode) GetStats() *SaaSStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.stats
}

// updateStats updates SaaS statistics
func (sm *SaaSMode) updateStats() {
	activeCount := int64(0)
	trialCount := int64(0)

	for _, tenant := range sm.tenants {
		if tenant.Status == "active" {
			activeCount++
		} else if tenant.Status == "trial" {
			trialCount++
		}
	}

	sm.stats.TotalTenants = int64(len(sm.tenants))
	sm.stats.ActiveTenants = activeCount
	sm.stats.TrialTenants = trialCount
	sm.stats.LastUpdated = time.Now()
}

func generateTenantID(domain string) string {
	hash := sha256.Sum256([]byte(domain + time.Now().String()))
	return fmt.Sprintf("tnt_%x", hash[:8])
}

func getPlanRateLimit(plan string) int {
	switch plan {
	case "enterprise":
		return 100000 // 100k req/min
	case "pro":
		return 10000 // 10k req/min
	case "free":
		return 1000 // 1k req/min
	default:
		return 1000
	}
}
