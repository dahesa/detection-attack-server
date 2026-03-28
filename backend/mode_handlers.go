package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Mode configuration handlers

// getModeConfig returns current deployment mode configuration
func (z *ZeinSecuritySystem) getModeConfig(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"current_mode":  z.currentMode,
		"reverse_proxy": nil,
		"inline":        nil,
		"api":           nil,
		"saas":          nil,
	}

	// Reverse Proxy config
	if z.reverseProxy != nil {
		response["reverse_proxy"] = map[string]interface{}{
			"enabled":     true,
			"backend_url": z.reverseProxy.GetBackendURL(),
			"health":      z.reverseProxy.healthCheck.GetStatus(),
		}
	} else {
		response["reverse_proxy"] = map[string]interface{}{
			"enabled": false,
		}
	}

	// Inline Mode config
	if z.inlineMode != nil {
		response["inline"] = z.inlineMode.GetStats()
	} else {
		response["inline"] = map[string]interface{}{
			"enabled": false,
		}
	}

	// API Mode config
	if z.apiMode != nil {
		response["api"] = map[string]interface{}{
			"enabled":          z.apiMode.config.Enabled,
			"api_key_required": z.apiMode.config.APIKeyRequired,
			"sdk_version":      z.apiMode.config.SDKVersion,
		}
	} else {
		response["api"] = map[string]interface{}{
			"enabled": false,
		}
	}

	// SaaS Mode config
	if z.saasMode != nil {
		stats := z.saasMode.GetStats()
		response["saas"] = map[string]interface{}{
			"enabled":        z.saasMode.config.Enabled,
			"total_tenants":  stats.TotalTenants,
			"active_tenants": stats.ActiveTenants,
			"trial_tenants":  stats.TrialTenants,
		}
	} else {
		response["saas"] = map[string]interface{}{
			"enabled": false,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateReverseProxyConfig updates reverse proxy configuration
func (z *ZeinSecuritySystem) updateReverseProxyConfig(w http.ResponseWriter, r *http.Request) {
	var configData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	backendURL := getString(configData, "backend_url", "")
	if backendURL == "" {
		http.Error(w, `{"error": "backend_url required"}`, http.StatusBadRequest)
		return
	}

	proxyConfig := &ReverseProxyConfig{
		BackendURL:      backendURL,
		BackendHost:     getString(configData, "backend_host", ""),
		PreserveHost:    getBool(configData, "preserve_host", false),
		FlushInterval:   100 * time.Millisecond,
		Timeout:         30 * time.Second,
		MaxIdleConns:    getInt(configData, "max_idle_conns", 100),
		MaxIdlePerHost:  getInt(configData, "max_idle_per_host", 10),
		IdleConnTimeout: 90 * time.Second,
		Headers:         make(map[string]string),
		SSLVerify:       getBool(configData, "ssl_verify", true),
		RetryAttempts:   getInt(configData, "retry_attempts", 3),
		HealthCheckURL:  getString(configData, "health_check_url", backendURL+"/health"),
	}

	var err error
	z.reverseProxy, err = NewReverseProxy(proxyConfig)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to create reverse proxy: %v"}`, err), http.StatusInternalServerError)
		return
	}

	z.currentMode = ModeReverseProxy

	response := map[string]interface{}{
		"status":  "success",
		"message": "Reverse proxy configured successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateInlineConfig updates inline mode configuration
func (z *ZeinSecuritySystem) updateInlineConfig(w http.ResponseWriter, r *http.Request) {
	var configData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	inlineConfig := &InlineModeConfig{
		Enabled:          getBool(configData, "enabled", false),
		InternalNetworks: getStringSlice(configData, "internal_networks"),
		BypassIPs:        getStringSlice(configData, "bypass_ips"),
		LogOnly:          getBool(configData, "log_only", false),
		StrictMode:       getBool(configData, "strict_mode", false),
	}

	var err error
	z.inlineMode, err = NewInlineMode(inlineConfig)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to configure inline mode: %v"}`, err), http.StatusInternalServerError)
		return
	}

	if inlineConfig.Enabled {
		z.currentMode = ModeInline
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Inline mode configured successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateAPIConfig updates API mode configuration
func (z *ZeinSecuritySystem) updateAPIConfig(w http.ResponseWriter, r *http.Request) {
	var configData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	z.apiMode.config.Enabled = getBool(configData, "enabled", false)
	z.apiMode.config.APIKeyRequired = getBool(configData, "api_key_required", true)
	z.apiMode.config.AllowedOrigins = getStringSlice(configData, "allowed_origins")

	if z.apiMode.config.Enabled {
		z.currentMode = ModeAPI
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "API mode configured successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// createTenant creates a new SaaS tenant
func (z *ZeinSecuritySystem) createTenant(w http.ResponseWriter, r *http.Request) {
	var tenantData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&tenantData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	name := getString(tenantData, "name", "")
	domain := getString(tenantData, "domain", "")
	plan := getString(tenantData, "plan", "free")

	if name == "" || domain == "" {
		http.Error(w, `{"error": "name and domain required"}`, http.StatusBadRequest)
		return
	}

	tenant, err := z.saasMode.CreateTenant(name, domain, plan)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

// getTenants returns list of tenants
func (z *ZeinSecuritySystem) getTenants(w http.ResponseWriter, r *http.Request) {
	z.saasMode.mu.RLock()
	tenants := make([]*Tenant, 0, len(z.saasMode.tenants))
	for _, tenant := range z.saasMode.tenants {
		tenants = append(tenants, tenant)
	}
	z.saasMode.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenants)
}

// Helper functions
func getStringSlice(data map[string]interface{}, key string) []string {
	if val, ok := data[key].([]interface{}); ok {
		result := make([]string, 0, len(val))
		for _, v := range val {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return []string{}
}






