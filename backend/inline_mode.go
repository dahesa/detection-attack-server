package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
)

// InlineModeConfig holds configuration for inline mode
type InlineModeConfig struct {
	Enabled          bool     `json:"enabled"`
	InternalNetworks []string `json:"internal_networks"` // CIDR notation
	BypassIPs        []string `json:"bypass_ips"`
	LogOnly          bool     `json:"log_only"` // Log threats but don't block
	StrictMode       bool     `json:"strict_mode"`
}

// InlineMode handles inline network protection
type InlineMode struct {
	config     *InlineModeConfig
	mu         sync.RWMutex
	ipNetworks []*net.IPNet
	bypassIPs  map[string]bool
}

// NewInlineMode creates a new inline mode instance
func NewInlineMode(config *InlineModeConfig) (*InlineMode, error) {
	im := &InlineMode{
		config:    config,
		bypassIPs: make(map[string]bool),
	}

	// Parse internal networks
	im.ipNetworks = make([]*net.IPNet, 0, len(config.InternalNetworks))
	for _, cidr := range config.InternalNetworks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("⚠️ Invalid CIDR: %s: %v", cidr, err)
			continue
		}
		im.ipNetworks = append(im.ipNetworks, ipNet)
	}

	// Parse bypass IPs
	for _, ip := range config.BypassIPs {
		im.bypassIPs[ip] = true
	}

	return im, nil
}

// IsInternalIP checks if an IP is in the internal network
func (im *InlineMode) IsInternalIP(ip string) bool {
	im.mu.RLock()
	defer im.mu.RUnlock()

	// Check bypass list first
	if im.bypassIPs[ip] {
		return true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is in any internal network
	for _, ipNet := range im.ipNetworks {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// ShouldBypass checks if request should bypass WAF
func (im *InlineMode) ShouldBypass(r *http.Request) bool {
	if !im.config.Enabled {
		return false
	}

	ip := getClientIP(r)
	return im.IsInternalIP(ip)
}

// HandleRequest processes request in inline mode
func (im *InlineMode) HandleRequest(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !im.config.Enabled {
		next(w, r)
		return
	}

	ip := getClientIP(r)
	isInternal := im.IsInternalIP(ip)

	// Add headers for tracking
	w.Header().Set("X-Zein-Inline-Mode", "enabled")
	if isInternal {
		w.Header().Set("X-Zein-Internal-IP", "true")
	}

	// In strict mode, apply WAF to all traffic
	if im.config.StrictMode {
		next(w, r)
		return
	}

	// In log-only mode, log but don't block
	if im.config.LogOnly {
		// Log request but allow it through
		log.Printf("📝 Inline mode (log-only): %s %s from %s", r.Method, r.URL.Path, ip)
		next(w, r)
		return
	}

	// Normal inline mode - apply WAF
	next(w, r)
}

// UpdateConfig updates inline mode configuration
func (im *InlineMode) UpdateConfig(config *InlineModeConfig) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Rebuild IP networks
	im.ipNetworks = make([]*net.IPNet, 0, len(config.InternalNetworks))
	for _, cidr := range config.InternalNetworks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %v", cidr, err)
		}
		im.ipNetworks = append(im.ipNetworks, ipNet)
	}

	// Rebuild bypass IPs
	im.bypassIPs = make(map[string]bool)
	for _, ip := range config.BypassIPs {
		im.bypassIPs[ip] = true
	}

	im.config = config
	return nil
}

// GetConfig returns current configuration
func (im *InlineMode) GetConfig() *InlineModeConfig {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.config
}

// GetStats returns inline mode statistics
func (im *InlineMode) GetStats() map[string]interface{} {
	im.mu.RLock()
	defer im.mu.RUnlock()

	return map[string]interface{}{
		"enabled":           im.config.Enabled,
		"internal_networks": len(im.ipNetworks),
		"bypass_ips":        len(im.bypassIPs),
		"log_only":          im.config.LogOnly,
		"strict_mode":       im.config.StrictMode,
	}
}
