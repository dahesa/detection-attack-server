package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DDoSMitigation engine untuk mitigasi DDoS real-time
type DDoSMitigation struct {
	mu              sync.RWMutex
	rateLimiters    map[string]*RateLimiter
	ipTrackers      map[string]*IPTracker
	attackDetectors map[string]*AttackDetector
	mitigationRules []*MitigationRule
	stats           *DDoSStats
}

// IPTracker tracks IP request patterns
type IPTracker struct {
	IP           string
	RequestCount int64
	RequestRate  float64
	LastRequest  time.Time
	FirstRequest time.Time
	WindowStart  time.Time
	IsAttacking  bool
	AttackType   string
	Blocked      bool
	BlockedUntil time.Time
}

// AttackDetector detects attack patterns
type AttackDetector struct {
	Pattern      string
	Threshold    int64
	Window       time.Duration
	CurrentCount int64
	LastDetected time.Time
	Mitigation   string
}

// MitigationRule rule untuk mitigasi
type MitigationRule struct {
	Name      string
	Condition string
	Action    string
	Threshold int64
	Window    time.Duration
	Enabled   bool
}

// DDoSStats statistics
type DDoSStats struct {
	TotalRequests   int64
	BlockedRequests int64
	ActiveAttacks   int64
	Mitigations     int64
	LastAttack      time.Time
}

// NewDDoSMitigation creates new DDoS mitigation engine
func NewDDoSMitigation() *DDoSMitigation {
	ddos := &DDoSMitigation{
		rateLimiters:    make(map[string]*RateLimiter),
		ipTrackers:      make(map[string]*IPTracker),
		attackDetectors: make(map[string]*AttackDetector),
		mitigationRules: make([]*MitigationRule, 0),
		stats:           &DDoSStats{},
	}

	// Initialize default mitigation rules
	ddos.initDefaultRules()

	// Start background monitoring
	go ddos.startMonitoring()

	return ddos
}

// AnalyzeRequest analyzes request untuk DDoS detection
func (ddos *DDoSMitigation) AnalyzeRequest(ip string, r *http.Request) *DDoSResponse {
	ddos.mu.Lock()
	defer ddos.mu.Unlock()

	ddos.stats.TotalRequests++

	// Get or create IP tracker
	tracker := ddos.getOrCreateTracker(ip)

	// Update tracker
	tracker.RequestCount++
	tracker.LastRequest = time.Now()

	// Calculate request rate
	ddos.updateRequestRate(tracker)

	// Check for attacks
	attackDetected := ddos.detectAttack(tracker, r)

	if attackDetected {
		ddos.stats.ActiveAttacks++
		ddos.stats.LastAttack = time.Now()
		ddos.stats.BlockedRequests++

		// Apply mitigation
		mitigation := ddos.applyMitigation(tracker)
		ddos.stats.Mitigations++

		return &DDoSResponse{
			Blocked:    true,
			Reason:     tracker.AttackType,
			Mitigation: mitigation,
			RetryAfter: ddos.calculateRetryAfter(tracker),
		}
	}

	return &DDoSResponse{
		Blocked: false,
	}
}

// DDoSResponse response dari DDoS mitigation
type DDoSResponse struct {
	Blocked    bool
	Reason     string
	Mitigation string
	RetryAfter time.Duration
}

func (ddos *DDoSMitigation) getOrCreateTracker(ip string) *IPTracker {
	if tracker, exists := ddos.ipTrackers[ip]; exists {
		return tracker
	}

	tracker := &IPTracker{
		IP:           ip,
		RequestCount: 0,
		RequestRate:  0.0,
		FirstRequest: time.Now(),
		WindowStart:  time.Now(),
		IsAttacking:  false,
		Blocked:      false,
	}

	ddos.ipTrackers[ip] = tracker
	return tracker
}

func (ddos *DDoSMitigation) updateRequestRate(tracker *IPTracker) {
	now := time.Now()
	window := now.Sub(tracker.WindowStart)

	if window >= 1*time.Second {
		tracker.RequestRate = float64(tracker.RequestCount) / window.Seconds()
		tracker.WindowStart = now
		tracker.RequestCount = 0
	}
}

func (ddos *DDoSMitigation) detectAttack(tracker *IPTracker, r *http.Request) bool {
	// Check multiple attack patterns
	attackPatterns := []struct {
		name      string
		threshold float64
		check     func(*IPTracker) bool
	}{
		{
			name:      "HIGH_RATE",
			threshold: 100.0, // 100 req/sec
			check: func(t *IPTracker) bool {
				return t.RequestRate > 100.0
			},
		},
		{
			name:      "BURST",
			threshold: 1000.0, // 1000 req in 10 sec
			check: func(t *IPTracker) bool {
				window := time.Now().Sub(t.WindowStart)
				return t.RequestCount > 1000 && window < 10*time.Second
			},
		},
		{
			name:      "SYN_FLOOD",
			threshold: 50.0,
			check: func(t *IPTracker) bool {
				// Check for SYN flood pattern
				return t.RequestRate > 50.0 && r.Method == "GET"
			},
		},
		{
			name:      "SLOW_LORIS",
			threshold: 10.0,
			check: func(t *IPTracker) bool {
				// Check for slow loris pattern
				return t.RequestRate < 0.1 && t.RequestCount > 10
			},
		},
	}

	for _, pattern := range attackPatterns {
		if pattern.check(tracker) {
			tracker.IsAttacking = true
			tracker.AttackType = pattern.name
			tracker.Blocked = true
			tracker.BlockedUntil = time.Now().Add(5 * time.Minute)
			return true
		}
	}

	return false
}

func (ddos *DDoSMitigation) applyMitigation(tracker *IPTracker) string {
	// Apply mitigation based on attack type
	switch tracker.AttackType {
	case "HIGH_RATE":
		return "RATE_LIMIT"
	case "BURST":
		return "BURST_PROTECTION"
	case "SYN_FLOOD":
		return "SYN_COOKIE"
	case "SLOW_LORIS":
		return "CONNECTION_LIMIT"
	default:
		return "AUTO_BLOCK"
	}
}

func (ddos *DDoSMitigation) calculateRetryAfter(tracker *IPTracker) time.Duration {
	if tracker.BlockedUntil.After(time.Now()) {
		return tracker.BlockedUntil.Sub(time.Now())
	}
	return 0
}

func (ddos *DDoSMitigation) initDefaultRules() {
	ddos.mitigationRules = []*MitigationRule{
		{
			Name:      "High Rate Protection",
			Condition: "rate > 100 req/sec",
			Action:    "BLOCK",
			Threshold: 100,
			Window:    1 * time.Second,
			Enabled:   true,
		},
		{
			Name:      "Burst Protection",
			Condition: "requests > 1000 in 10s",
			Action:    "THROTTLE",
			Threshold: 1000,
			Window:    10 * time.Second,
			Enabled:   true,
		},
		{
			Name:      "Connection Limit",
			Condition: "connections > 50",
			Action:    "LIMIT",
			Threshold: 50,
			Window:    1 * time.Minute,
			Enabled:   true,
		},
	}
}

func (ddos *DDoSMitigation) startMonitoring() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ddos.cleanupTrackers()
		ddos.updateStats()
	}
}

func (ddos *DDoSMitigation) cleanupTrackers() {
	ddos.mu.Lock()
	defer ddos.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for ip, tracker := range ddos.ipTrackers {
		if tracker.LastRequest.Before(cutoff) && !tracker.Blocked {
			delete(ddos.ipTrackers, ip)
		}
	}
}

func (ddos *DDoSMitigation) updateStats() {
	ddos.mu.RLock()
	defer ddos.mu.RUnlock()

	activeAttacks := int64(0)
	for _, tracker := range ddos.ipTrackers {
		if tracker.IsAttacking && tracker.BlockedUntil.After(time.Now()) {
			activeAttacks++
		}
	}

	ddos.stats.ActiveAttacks = activeAttacks
}

// IsBlocked checks if IP is blocked
func (ddos *DDoSMitigation) IsBlocked(ip string) bool {
	ddos.mu.RLock()
	defer ddos.mu.RUnlock()

	tracker, exists := ddos.ipTrackers[ip]
	if !exists {
		return false
	}

	if tracker.Blocked && tracker.BlockedUntil.After(time.Now()) {
		return true
	}

	// Auto-unblock if expired
	if tracker.BlockedUntil.Before(time.Now()) {
		tracker.Blocked = false
		tracker.IsAttacking = false
	}

	return false
}

// GetStats returns DDoS mitigation statistics
func (ddos *DDoSMitigation) GetStats() *DDoSStats {
	ddos.mu.RLock()
	defer ddos.mu.RUnlock()

	return &DDoSStats{
		TotalRequests:   ddos.stats.TotalRequests,
		BlockedRequests: ddos.stats.BlockedRequests,
		ActiveAttacks:   ddos.stats.ActiveAttacks,
		Mitigations:     ddos.stats.Mitigations,
		LastAttack:      ddos.stats.LastAttack,
	}
}

// Middleware untuk DDoS protection
func (ddos *DDoSMitigation) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		// Check if blocked
		if ddos.IsBlocked(ip) {
			w.Header().Set("Retry-After", "300")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "Too many requests", "message": "Rate limit exceeded"}`))
			return
		}

		// Analyze request
		response := ddos.AnalyzeRequest(ip, r)

		if response.Blocked {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", response.RetryAfter.Seconds()))
			w.Header().Set("X-DDoS-Mitigation", response.Mitigation)
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(fmt.Sprintf(`{"error": "DDoS protection", "reason": "%s", "retry_after": %.0f}`, response.Reason, response.RetryAfter.Seconds())))
			return
		}

		next.ServeHTTP(w, r)
	})
}
