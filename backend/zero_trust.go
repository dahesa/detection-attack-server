package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ZeroTrustEngine engine untuk Zero Trust Network Access
type ZeroTrustEngine struct {
	mu       sync.RWMutex
	devices  map[string]*Device
	users    map[string]*ZeroTrustUser
	policies []*AccessPolicy
	sessions map[string]*Session
	stats    *ZeroTrustStats
}

// Device represents a device
type Device struct {
	ID          string
	Name        string
	Type        string // desktop, mobile, server
	OS          string
	IP          string
	MAC         string
	IsTrusted   bool
	LastSeen    time.Time
	Certificate string
}

// ZeroTrustUser represents a user for Zero Trust
type ZeroTrustUser struct {
	ID         string
	Email      string
	Role       string
	IsVerified bool
	MFAEnabled bool
	LastLogin  time.Time
	Devices    []string
}

// AccessPolicy access policy
type AccessPolicy struct {
	ID         string
	Name       string
	Resource   string
	Users      []string
	Devices    []string
	Conditions map[string]interface{}
	Action     string // allow, deny, require_mfa
	Enabled    bool
}

// Session represents a session
type Session struct {
	ID          string
	UserID      string
	DeviceID    string
	Token       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	IP          string
	IsActive    bool
	MFAVerified bool
}

// ZeroTrustStats statistics
type ZeroTrustStats struct {
	TotalDevices   int64
	TrustedDevices int64
	ActiveSessions int64
	PolicyChecks   int64
	DeniedAccess   int64
}

// NewZeroTrustEngine creates new Zero Trust engine
func NewZeroTrustEngine() *ZeroTrustEngine {
	zt := &ZeroTrustEngine{
		devices:  make(map[string]*Device),
		users:    make(map[string]*ZeroTrustUser),
		policies: make([]*AccessPolicy, 0),
		sessions: make(map[string]*Session),
		stats:    &ZeroTrustStats{},
	}

	// Initialize default policies
	zt.initDefaultPolicies()

	// Start session cleanup
	go zt.startSessionCleanup()

	return zt
}

// AuthenticateDevice authenticates a device
func (zt *ZeroTrustEngine) AuthenticateDevice(deviceID, certificate string) (*Device, error) {
	zt.mu.Lock()
	defer zt.mu.Unlock()

	device, exists := zt.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}

	// Verify certificate
	if device.Certificate != certificate {
		return nil, fmt.Errorf("invalid certificate")
	}

	device.IsTrusted = true
	device.LastSeen = time.Now()

	return device, nil
}

// AuthenticateUser authenticates a user
func (zt *ZeroTrustEngine) AuthenticateUser(userID, password string, mfaCode string) (*Session, error) {
	zt.mu.RLock()
	user, exists := zt.users[userID]
	zt.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	// Verify MFA if enabled
	if user.MFAEnabled && mfaCode == "" {
		return nil, fmt.Errorf("MFA required")
	}

	// Create session
	session := &Session{
		ID:          generateSessionID(),
		UserID:      userID,
		Token:       generateToken(),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		IsActive:    true,
		MFAVerified: user.MFAEnabled && mfaCode != "",
	}

	zt.mu.Lock()
	zt.sessions[session.ID] = session
	zt.stats.ActiveSessions++
	zt.mu.Unlock()

	user.LastLogin = time.Now()

	return session, nil
}

// CheckAccess checks if access is allowed
func (zt *ZeroTrustEngine) CheckAccess(sessionID, resource string) (bool, string) {
	zt.mu.RLock()
	defer zt.mu.RUnlock()

	session, exists := zt.sessions[sessionID]
	if !exists || !session.IsActive {
		zt.stats.DeniedAccess++
		return false, "INVALID_SESSION"
	}

	if time.Now().After(session.ExpiresAt) {
		zt.stats.DeniedAccess++
		return false, "SESSION_EXPIRED"
	}

	// Check policies
	for _, policy := range zt.policies {
		if !policy.Enabled {
			continue
		}

		if policy.Resource != resource && policy.Resource != "*" {
			continue
		}

		// Check user
		userAllowed := false
		for _, uid := range policy.Users {
			if uid == session.UserID || uid == "*" {
				userAllowed = true
				break
			}
		}

		if !userAllowed {
			continue
		}

		// Check device
		deviceAllowed := true
		if len(policy.Devices) > 0 {
			deviceAllowed = false
			device, _ := zt.devices[session.DeviceID]
			if device != nil {
				for _, did := range policy.Devices {
					if did == session.DeviceID || did == "*" {
						deviceAllowed = true
						break
					}
				}
			}
		}

		if !deviceAllowed {
			continue
		}

		// Check conditions
		if zt.checkConditions(policy.Conditions, session) {
			zt.stats.PolicyChecks++
			if policy.Action == "deny" {
				zt.stats.DeniedAccess++
				return false, "POLICY_DENIED"
			}
			if policy.Action == "require_mfa" && !session.MFAVerified {
				zt.stats.DeniedAccess++
				return false, "MFA_REQUIRED"
			}
			return true, "ALLOWED"
		}
	}

	zt.stats.DeniedAccess++
	return false, "NO_POLICY_MATCH"
}

func (zt *ZeroTrustEngine) checkConditions(conditions map[string]interface{}, session *Session) bool {
	// Check time-based conditions
	if timeWindow, ok := conditions["time_window"].(map[string]interface{}); ok {
		now := time.Now().Hour()
		start, _ := timeWindow["start"].(int)
		end, _ := timeWindow["end"].(int)
		if now < start || now > end {
			return false
		}
	}

	// Check IP-based conditions
	if allowedIPs, ok := conditions["allowed_ips"].([]interface{}); ok {
		ipAllowed := false
		for _, ip := range allowedIPs {
			if ipStr, ok := ip.(string); ok && ipStr == session.IP {
				ipAllowed = true
				break
			}
		}
		if !ipAllowed && len(allowedIPs) > 0 {
			return false
		}
	}

	return true
}

func (zt *ZeroTrustEngine) initDefaultPolicies() {
	zt.policies = []*AccessPolicy{
		{
			ID:       "default-admin",
			Name:     "Admin Access",
			Resource: "/admin/*",
			Users:    []string{"admin"},
			Action:   "require_mfa",
			Enabled:  true,
		},
		{
			ID:       "default-api",
			Name:     "API Access",
			Resource: "/api/*",
			Users:    []string{"*"},
			Action:   "allow",
			Enabled:  true,
		},
	}
}

func (zt *ZeroTrustEngine) startSessionCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		zt.cleanupExpiredSessions()
	}
}

func (zt *ZeroTrustEngine) cleanupExpiredSessions() {
	zt.mu.Lock()
	defer zt.mu.Unlock()

	now := time.Now()
	for id, session := range zt.sessions {
		if now.After(session.ExpiresAt) {
			delete(zt.sessions, id)
			zt.stats.ActiveSessions--
		}
	}
}

// Middleware untuk Zero Trust
func (zt *ZeroTrustEngine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			sessionID = r.URL.Query().Get("session_id")
		}

		if sessionID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Session required"})
			return
		}

		resource := r.URL.Path
		allowed, reason := zt.CheckAccess(sessionID, resource)

		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":  "Access denied",
				"reason": reason,
			})
			return
		}

		w.Header().Set("X-Zero-Trust", "enabled")
		next.ServeHTTP(w, r)
	})
}

// GetStats returns Zero Trust statistics
func (zt *ZeroTrustEngine) GetStats() *ZeroTrustStats {
	zt.mu.RLock()
	defer zt.mu.RUnlock()

	return &ZeroTrustStats{
		TotalDevices:   int64(len(zt.devices)),
		TrustedDevices: zt.countTrustedDevices(),
		ActiveSessions: zt.stats.ActiveSessions,
		PolicyChecks:   zt.stats.PolicyChecks,
		DeniedAccess:   zt.stats.DeniedAccess,
	}
}

func (zt *ZeroTrustEngine) countTrustedDevices() int64 {
	count := int64(0)
	for _, device := range zt.devices {
		if device.IsTrusted {
			count++
		}
	}
	return count
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
