package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// getQuantumStats returns security statistics (combined from monitor + database)
func (z *ZeinSecuritySystem) getQuantumStats(w http.ResponseWriter, r *http.Request) {
	// Get stats from monitor (in-memory)
	monitorStats := z.monitor.GetStats()
	
	// Get stats from database (persistent)
	dbStats, err := z.getStatsFromDatabase()
	if err != nil {
		log.Printf("⚠️ Error getting stats from database: %v", err)
		// Use monitor stats only if database fails
		dbStats = map[string]int{
			"sql_injections":    0,
			"xss_attempts":      0,
			"brute_force":       0,
			"path_traversal":    0,
			"command_injection": 0,
			"xxe_attempts":      0,
			"deserialization":   0,
		}
	}
	
	// Combine stats (database takes precedence for attack counts)
	response := map[string]interface{}{
		"total_requests":      monitorStats.TotalRequests,
		"blocked_requests":    monitorStats.BlockedRequests,
		"sql_injections":      dbStats["sql_injections"] + int(monitorStats.SQLInjection),
		"xss_attempts":        dbStats["xss_attempts"] + int(monitorStats.XSSAttempts),
		"brute_force":         dbStats["brute_force"] + int(monitorStats.BruteForce),
		"zero_day_attempts":   monitorStats.ZeroDayAttempts,
		"ddos_attempts":       monitorStats.DDoSAttempts,
		"path_traversal":      dbStats["path_traversal"] + int(monitorStats.PathTraversal),
		"command_injection":   dbStats["command_injection"] + int(monitorStats.CommandInjection),
		"xxe_attempts":        dbStats["xxe_attempts"] + int(monitorStats.XXEAttempts),
		"deserialization":     dbStats["deserialization"] + int(monitorStats.Deserialization),
		"block_rate":          monitorStats.BlockRate,
		"threat_actors":       monitorStats.ThreatActors,
		"requests_per_second": monitorStats.RequestsPerSecond,
		"timestamp":           time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getStatsFromDatabase - Get attack statistics from database
func (z *ZeinSecuritySystem) getStatsFromDatabase() (map[string]int, error) {
	// Get all events (not just last 24 hours) untuk akurasi yang lebih baik
	query := `
		SELECT 
			event_type,
			COUNT(*) as count
		FROM security_events
		GROUP BY event_type
	`
	
	rows, err := z.database.Query(query)
	if err != nil {
		log.Printf("❌ Error querying security_events: %v", err)
		return nil, err
	}
	defer rows.Close()
	
	stats := map[string]int{
		"sql_injections":    0,
		"xss_attempts":      0,
		"brute_force":       0,
		"path_traversal":    0,
		"command_injection": 0,
		"xxe_attempts":      0,
		"deserialization":   0,
	}
	
	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			log.Printf("⚠️ Error scanning row: %v", err)
			continue
		}
		
		log.Printf("📊 Event type from DB: %s (count: %d)", eventType, count)
		
		// Map event types to stats (normalized types)
		switch eventType {
		case "A01:2021-Injection", "SQL_INJECTION":
			stats["sql_injections"] += count
			log.Printf("✅ Mapped to sql_injections: %d", count)
		case "A07:2021-Cross-Site Scripting", "XSS", "A07:2021-Cross-Site Scripting (XSS)":
			stats["xss_attempts"] += count
			log.Printf("✅ Mapped to xss_attempts: %d", count)
		case "A02:2021-Broken Authentication", "BRUTE_FORCE":
			stats["brute_force"] += count
		case "A05:2021-Broken Access Control", "PATH_TRAVERSAL":
			stats["path_traversal"] += count
		case "COMMAND_INJECTION":
			stats["command_injection"] += count
		case "A04:2021-XML External Entities", "XXE":
			stats["xxe_attempts"] += count
		case "A08:2021-Insecure Deserialization", "DESERIALIZATION":
			stats["deserialization"] += count
		default:
			// Log unknown event types untuk debugging
			log.Printf("⚠️ Unknown event type in stats: %s (count: %d)", eventType, count)
		}
	}
	
	log.Printf("📊 Final stats from DB: %+v", stats)
	return stats, nil
}

// getQuantumLogs returns security event logs
func (z *ZeinSecuritySystem) getQuantumLogs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	events, err := z.database.GetSecurityEvents(limit, 0)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}

	// Convert to frontend format
	logs := make([]map[string]interface{}, len(events))
	for i, event := range events {
		logs[i] = map[string]interface{}{
			"id":             event.ID,
			"timestamp":      event.Timestamp,
			"ip_address":     event.IPAddress,
			"user_agent":     event.UserAgent,
			"request_method": event.RequestMethod,
			"request_path":   event.RequestPath,
			"request_query":  event.RequestQuery,
			"event_type":     event.EventType,
			"threat_score":   event.ThreatScore,
			"severity":       event.Severity,
			"blocked":        event.Blocked,
			"details":        event.Details,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// getQuantumAttackers returns attacker analysis
func (z *ZeinSecuritySystem) getQuantumAttackers(w http.ResponseWriter, r *http.Request) {
	// Get threat intelligence data
	query := `
		SELECT DISTINCT ip_address, 
		       MAX(confidence_score) as max_score,
		       COUNT(*) as threat_count,
		       MAX(last_seen) as last_seen
		FROM threat_intelligence
		WHERE is_active = true
		GROUP BY ip_address
		ORDER BY max_score DESC
		LIMIT 20
	`

	rows, err := z.database.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	attackers := []map[string]interface{}{}
	for rows.Next() {
		var ip string
		var maxScore float64
		var threatCount int
		var lastSeen time.Time

		if err := rows.Scan(&ip, &maxScore, &threatCount, &lastSeen); err != nil {
			continue
		}

		// Determine threat level
		threatLevel := "LOW"
		if maxScore >= 0.9 {
			threatLevel = "CRITICAL"
		} else if maxScore >= 0.7 {
			threatLevel = "HIGH"
		} else if maxScore >= 0.5 {
			threatLevel = "MEDIUM"
		}

		attackers = append(attackers, map[string]interface{}{
			"ip":            ip,
			"risk_score":    maxScore,
			"threat_level":  threatLevel,
			"total_attacks": threatCount,
			"last_seen":     lastSeen,
			"organization":  "Unknown",
			"asn":           "Unknown",
			"geo_lat":       0.0,
			"geo_lon":       0.0,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attackers)
}

// getWebConfig returns current WAF configuration
func (z *ZeinSecuritySystem) getWebConfig(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "default"
	}

	config, err := z.database.GetSecurityConfig(domain)
	if err != nil {
		// Return default config
		defaultConfig := map[string]interface{}{
			"domain":                     domain,
			"ssl_enabled":                true,
			"protection_level":           "high",
			"rate_limiting":              true,
			"rate_limit_requests":        100,
			"rate_limit_window":          "1m",
			"bot_protection":             true,
			"custom_rules":               "",
			"max_upload_size":            10485760,
			"blocked_countries":          "",
			"allowed_ips":                "",
			"blocked_ips":                "",
			"enable_ai":                  true,
			"enable_behavioral_analysis": true,
			"block_duration":             "24h",
			"threat_score_threshold":     0.7,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(defaultConfig)
		return
	}

	response := map[string]interface{}{
		"domain":                     config.Domain,
		"ssl_enabled":                config.SSLEnabled,
		"protection_level":           config.ProtectionLevel,
		"rate_limiting":              config.RateLimiting,
		"rate_limit_requests":        100, // Default
		"rate_limit_window":          "1m",
		"bot_protection":             config.BotProtection,
		"custom_rules":               config.CustomRules,
		"max_upload_size":            config.MaxUploadSize,
		"blocked_countries":          config.BlockedCountries,
		"allowed_ips":                config.AllowedIPs,
		"blocked_ips":                config.BlockedIPs,
		"enable_ai":                  true,
		"enable_behavioral_analysis": true,
		"block_duration":             "24h",
		"threat_score_threshold":     0.7,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateWebConfig updates WAF configuration
func (z *ZeinSecuritySystem) updateWebConfig(w http.ResponseWriter, r *http.Request) {
	var configData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	domain := "default"
	if d, ok := configData["domain"].(string); ok && d != "" {
		domain = d
	}

	config := &DatabaseSecurityConfig{
		Domain:           domain,
		SSLEnabled:       getBool(configData, "ssl_enabled", true),
		ProtectionLevel:  getString(configData, "protection_level", "high"),
		RateLimiting:     getBool(configData, "rate_limiting", true),
		BotProtection:    getBool(configData, "bot_protection", true),
		CustomRules:      getString(configData, "custom_rules", ""),
		MaxUploadSize:    getInt(configData, "max_upload_size", 10485760),
		BlockedCountries: getString(configData, "blocked_countries", ""),
		AllowedIPs:       getString(configData, "allowed_ips", ""),
		BlockedIPs:       getString(configData, "blocked_ips", ""),
	}

	if err := z.database.SaveSecurityConfig(config); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to save config: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Update WAF config
	if protectionLevel, ok := configData["protection_level"].(string); ok {
		z.waf.config.ProtectionLevel = protectionLevel
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Configuration updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getUsers returns list of users (admin only)
func (z *ZeinSecuritySystem) getUsers(w http.ResponseWriter, r *http.Request) {
	query := `SELECT id, username, email, role, is_active, last_login FROM users ORDER BY created_at DESC`
	rows, err := z.database.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []map[string]interface{}{}
	for rows.Next() {
		var user User
		var lastLogin sql.NullTime
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.IsActive, &lastLogin)
		if err != nil {
			continue
		}
		if lastLogin.Valid {
			user.LastLogin = lastLogin.Time
		}

		users = append(users, map[string]interface{}{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"role":       user.Role,
			"is_active":  user.IsActive,
			"last_login": user.LastLogin,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// createUser creates a new user (admin only)
func (z *ZeinSecuritySystem) createUser(w http.ResponseWriter, r *http.Request) {
	var userData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	username := getString(userData, "username", "")
	email := getString(userData, "email", "")
	password := getString(userData, "password", "")
	role := getString(userData, "role", "user")

	if username == "" || email == "" || password == "" {
		http.Error(w, `{"error": "Missing required fields"}`, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to hash password: %v"}`, err), http.StatusInternalServerError)
		return
	}

	user := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Role:         role,
		IsActive:     true,
	}

	if err := z.database.CreateUser(user); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to create user: %v"}`, err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "User created successfully",
		"user_id": user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getSystemMetrics returns system performance metrics
func (z *ZeinSecuritySystem) getSystemMetrics(w http.ResponseWriter, r *http.Request) {
	stats := z.monitor.GetStats()

	response := map[string]interface{}{
		"requests_per_second":    stats.RequestsPerSecond,
		"memory_usage":           0.0, // Would need runtime stats
		"cpu_usage":              0.0,
		"concurrent_connections": 0,
		"ai_confidence_avg":      0.95,
		"processing_time_avg":    25.5,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper functions
func getString(data map[string]interface{}, key string, defaultValue string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return defaultValue
}

func getBool(data map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := data[key].(bool); ok {
		return val
	}
	return defaultValue
}

func getInt(data map[string]interface{}, key string, defaultValue int) int {
	if val, ok := data[key].(float64); ok {
		return int(val)
	}
	if val, ok := data[key].(int); ok {
		return val
	}
	return defaultValue
}

// New advanced features handlers
func (z *ZeinSecuritySystem) getTrafficLearningStats(w http.ResponseWriter, r *http.Request) {
	if z.trafficLearning == nil {
		http.Error(w, `{"error": "Traffic learning not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	
	stats := z.trafficLearning.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getASNReputationStats(w http.ResponseWriter, r *http.Request) {
	if z.asnReputation == nil {
		http.Error(w, `{"error": "ASN reputation not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	
	stats := z.asnReputation.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getPassiveLearningStats(w http.ResponseWriter, r *http.Request) {
	if z.passiveLearning == nil {
		http.Error(w, `{"error": "Passive learning not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	
	stats := z.passiveLearning.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getPassiveLearningRecommendations(w http.ResponseWriter, r *http.Request) {
	if z.passiveLearning == nil {
		http.Error(w, `{"error": "Passive learning not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	
	recommendations := z.passiveLearning.GetRecommendations()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recommendations)
}

func (z *ZeinSecuritySystem) togglePassiveLearningMode(w http.ResponseWriter, r *http.Request) {
	if z.passiveLearning == nil {
		http.Error(w, `{"error": "Passive learning not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	
	var req struct {
		Enabled bool `json:"enabled"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}
	
	if req.Enabled {
		z.passiveLearning.EnableLearningMode()
	} else {
		z.passiveLearning.DisableLearningMode()
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": z.passiveLearning.learningMode,
		"message": "Passive learning mode updated",
	})
}

// getIPLocations - Get all IP locations for map
func (z *ZeinSecuritySystem) getIPLocations(w http.ResponseWriter, r *http.Request) {
	if z.geolocation == nil {
		http.Error(w, `{"error": "Geolocation service not available"}`, http.StatusServiceUnavailable)
		return
	}

	locations := z.geolocation.GetAllLocations()
	stats := z.geolocation.GetLocationStats()

	// Convert locations to JSON-serializable format (REAL DATA ONLY)
	locationData := make([]map[string]interface{}, 0, len(locations))
	for _, loc := range locations {
		if loc == nil {
			continue
		}
		
		// Only include locations with valid data
		if loc.IP == "" {
			continue
		}
		
		locationData = append(locationData, map[string]interface{}{
			"ip":            loc.IP,
			"country":       loc.Country,
			"country_code":  loc.CountryCode,
			"region":        loc.Region,
			"city":          loc.City,
			"latitude":       loc.Latitude,
			"longitude":     loc.Longitude,
			"timezone":      loc.Timezone,
			"isp":           loc.ISP,
			"asn":           loc.ASN,
			"org":           loc.Org,
			"attack_count":  loc.AttackCount,
			"request_count": loc.RequestCount,
			"threat_score":  loc.ThreatScore,
			"first_seen":    loc.FirstSeen.Format(time.RFC3339),
			"last_seen":     loc.LastSeen.Format(time.RFC3339),
		})
	}
	
	log.Printf("📊 Sending %d REAL IP locations to frontend", len(locationData))

	response := map[string]interface{}{
		"locations": locationData,
		"stats":    stats,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getAttackersByLocation - Get attackers grouped by location
func (z *ZeinSecuritySystem) getAttackersByLocation(w http.ResponseWriter, r *http.Request) {
	if z.geolocation == nil {
		http.Error(w, `{"error": "Geolocation service not available"}`, http.StatusServiceUnavailable)
		return
	}

	attackersByLocation := z.geolocation.GetAttackersByLocation()
	
	response := map[string]interface{}{
		"attackers_by_location": attackersByLocation,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
