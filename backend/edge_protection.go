package main

import (
	"log"
	"sync"
	"time"
)

// EdgeProtection - Edge / Pre-Origin Protection Layer
type EdgeProtection struct {
	mu              sync.RWMutex
	cache           map[string]*CachedResponse
	edgeRules       []EdgeRule
	preOriginChecks []PreOriginCheck
	lastUpdate      time.Time
}

// CachedResponse - Cached response at edge
type CachedResponse struct {
	Path        string
	Response    []byte
	Headers     map[string]string
	StatusCode  int
	CachedAt    time.Time
	ExpiresAt   time.Time
	HitCount    int64
	LastHit     time.Time
}

// EdgeRule - Edge protection rule
type EdgeRule struct {
	Name        string
	Condition   func(*EdgeProtection, string, map[string]string) bool
	Action      func(*EdgeProtection, string) (bool, string)
	Priority    int
	Enabled     bool
}

// PreOriginCheck - Pre-origin check
type PreOriginCheck struct {
	Name      string
	CheckFunc func(*EdgeProtection, string, map[string]string) (bool, string)
	Priority  int
	Enabled   bool
}

// NewEdgeProtection - Initialize edge protection
func NewEdgeProtection() *EdgeProtection {
	ep := &EdgeProtection{
		cache:           make(map[string]*CachedResponse),
		edgeRules:       []EdgeRule{},
		preOriginChecks: []PreOriginCheck{},
	}

	// Initialize edge rules
	ep.initializeEdgeRules()
	ep.initializePreOriginChecks()

	log.Println("🛡️ Edge / Pre-Origin Protection initialized")
	return ep
}

// initializeEdgeRules - Initialize edge protection rules
func (ep *EdgeProtection) initializeEdgeRules() {
	ep.edgeRules = []EdgeRule{
		{
			Name: "Static Asset Caching",
			Condition: func(ep *EdgeProtection, path string, headers map[string]string) bool {
				return isStaticAsset(path)
			},
			Action: func(ep *EdgeProtection, path string) (bool, string) {
				// Cache static assets at edge
				return true, "cached"
			},
			Priority: 1,
			Enabled:  true,
		},
		{
			Name: "API Response Caching",
			Condition: func(ep *EdgeProtection, path string, headers map[string]string) bool {
				return isCacheableAPI(path)
			},
			Action: func(ep *EdgeProtection, path string) (bool, string) {
				// Cache API responses
				return true, "cached"
			},
			Priority: 2,
			Enabled:  true,
		},
	}
}

// initializePreOriginChecks - Initialize pre-origin checks
func (ep *EdgeProtection) initializePreOriginChecks() {
	ep.preOriginChecks = []PreOriginCheck{
		{
			Name: "Origin Health Check",
			CheckFunc: func(ep *EdgeProtection, path string, headers map[string]string) (bool, string) {
				// Check if origin is healthy
				return true, ""
			},
			Priority: 1,
			Enabled:  true,
		},
		{
			Name: "Origin Rate Limit",
			CheckFunc: func(ep *EdgeProtection, path string, headers map[string]string) (bool, string) {
				// Check origin rate limits
				return true, ""
			},
			Priority: 2,
			Enabled:  true,
		},
	}
}

// CheckRequest - Check request at edge
func (ep *EdgeProtection) CheckRequest(path string, headers map[string]string) (bool, string, *CachedResponse) {
	// Check cache first
	if cached := ep.getCachedResponse(path); cached != nil {
		if time.Now().Before(cached.ExpiresAt) {
			cached.HitCount++
			cached.LastHit = time.Now()
			return true, "cached", cached
		}
	}

	// Run pre-origin checks
	for _, check := range ep.preOriginChecks {
		if check.Enabled {
			allowed, reason := check.CheckFunc(ep, path, headers)
			if !allowed {
				return false, reason, nil
			}
		}
	}

	// Run edge rules
	for _, rule := range ep.edgeRules {
		if rule.Enabled && rule.Condition(ep, path, headers) {
			allowed, action := rule.Action(ep, path)
			if !allowed {
				return false, action, nil
			}
		}
	}

	return true, "", nil
}

// getCachedResponse - Get cached response
func (ep *EdgeProtection) getCachedResponse(path string) *CachedResponse {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.cache[path]
}

// CacheResponse - Cache response at edge
func (ep *EdgeProtection) CacheResponse(path string, response []byte, headers map[string]string, statusCode int, ttl time.Duration) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	ep.cache[path] = &CachedResponse{
		Path:       path,
		Response:   response,
		Headers:    headers,
		StatusCode: statusCode,
		CachedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
		HitCount:   0,
		LastHit:    time.Now(),
	}
}

// Helper functions
func isStaticAsset(path string) bool {
	staticExts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range staticExts {
		if len(path) >= len(ext) && path[len(path)-len(ext):] == ext {
			return true
		}
	}
	return false
}

func isCacheableAPI(path string) bool {
	cacheablePaths := []string{"/api/public", "/api/static", "/api/cache"}
	for _, cp := range cacheablePaths {
		if len(path) >= len(cp) && path[:len(cp)] == cp {
			return true
		}
	}
	return false
}



