package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// IP Blocking Handlers

// getBlockedIPs returns list of currently blocked IPs
func (z *ZeinSecuritySystem) getBlockedIPs(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT ip_address, reason, attack_type, threat_score, 
		       blocked_at, blocked_until, source, is_active
		FROM ip_blocks
		WHERE is_active = true AND blocked_until > NOW()
		ORDER BY blocked_at DESC
	`

	rows, err := z.database.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	blockedIPs := []map[string]interface{}{}
	for rows.Next() {
		var ip, reason, attackType, source string
		var threatScore float64
		var blockedAt, blockedUntil time.Time
		var isActive bool

		if err := rows.Scan(&ip, &reason, &attackType, &threatScore, &blockedAt, &blockedUntil, &source, &isActive); err != nil {
			continue
		}

		blockedIPs = append(blockedIPs, map[string]interface{}{
			"ip":            ip,
			"reason":        reason,
			"attack_type":   attackType,
			"threat_score":  threatScore,
			"blocked_at":    blockedAt,
			"blocked_until": blockedUntil,
			"source":        source,
			"is_active":     isActive,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blockedIPs)
}

// blockIP blocks an IP address
func (z *ZeinSecuritySystem) blockIP(w http.ResponseWriter, r *http.Request) {
	var blockData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&blockData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	ip := getString(blockData, "ip", "")
	reason := getString(blockData, "reason", "Manual block")
	attackType := getString(blockData, "attack_type", "MANUAL")
	durationStr := getString(blockData, "duration", "24h")
	threatScore := getFloat(blockData, "threat_score", 0.8)

	if ip == "" {
		http.Error(w, `{"error": "IP address required"}`, http.StatusBadRequest)
		return
	}

	// Parse duration
	var duration time.Duration
	switch durationStr {
	case "1h":
		duration = 1 * time.Hour
	case "6h":
		duration = 6 * time.Hour
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	case "permanent":
		duration = 365 * 24 * time.Hour // 1 year
	default:
		duration = 24 * time.Hour
	}

	// Block IP using WAF
	z.waf.ipBlockList.BlockIP(ip, reason, attackType, threatScore, duration)

	// Save to database
	query := `
		INSERT INTO ip_blocks (ip_address, reason, attack_type, threat_score, blocked_until, source, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) 
		DO UPDATE SET 
			reason = EXCLUDED.reason,
			attack_type = EXCLUDED.attack_type,
			threat_score = EXCLUDED.threat_score,
			blocked_until = EXCLUDED.blocked_until,
			source = EXCLUDED.source,
			is_active = true
	`

	_, err := z.database.Exec(query, ip, reason, attackType, threatScore, time.Now().Add(duration), "manual", true)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to save block: %v"}`, err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("IP %s blocked successfully", ip),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// unblockIP unblocks an IP address
func (z *ZeinSecuritySystem) unblockIP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]

	if ip == "" {
		http.Error(w, `{"error": "IP address required"}`, http.StatusBadRequest)
		return
	}

	// Remove from WAF block list
	z.waf.ipBlockList.UnblockIP(ip)

	// Update database
	query := `UPDATE ip_blocks SET is_active = false, unblocked_at = $1 WHERE ip_address = $2`
	_, err := z.database.Exec(query, time.Now(), ip)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to unblock: %v"}`, err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("IP %s unblocked successfully", ip),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// analyzeLogs runs AI log analysis
func (z *ZeinSecuritySystem) analyzeLogs(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	logData, ok := requestData["log_data"].([]interface{})
	if !ok {
		http.Error(w, `{"error": "log_data required"}`, http.StatusBadRequest)
		return
	}

	// Convert to LogEntry format
	logs := make([]LogEntry, 0, len(logData))
	for _, logItem := range logData {
		logMap, ok := logItem.(map[string]interface{})
		if !ok {
			continue
		}

		timestamp := time.Now()
		if ts, ok := logMap["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				timestamp = t
			}
		}

		logs = append(logs, LogEntry{
			Timestamp:     timestamp,
			IPAddress:     getString(logMap, "ip_address", ""),
			UserAgent:     getString(logMap, "user_agent", ""),
			RequestMethod: getString(logMap, "request_method", ""),
			RequestPath:   getString(logMap, "request_path", ""),
			RequestQuery:  getString(logMap, "request_query", ""),
			ThreatScore:   getFloat(logMap, "threat_score", 0.0),
			Details:       make(map[string]interface{}),
		})
	}

	// Use AI service to analyze
	if z.aiPython != nil {
		// Convert to AI client LogEntry format
		aiClientLogs := make([]struct {
			Timestamp     time.Time              `json:"timestamp"`
			IPAddress     string                 `json:"ip_address"`
			UserAgent     string                 `json:"user_agent"`
			RequestMethod string                 `json:"request_method"`
			RequestPath   string                 `json:"request_path"`
			RequestQuery  string                 `json:"request_query"`
			StatusCode    int                    `json:"status_code"`
			ThreatScore   float64                `json:"threat_score"`
			Details       map[string]interface{} `json:"details"`
		}, len(logs))

		for i, log := range logs {
			aiClientLogs[i] = struct {
				Timestamp     time.Time              `json:"timestamp"`
				IPAddress     string                 `json:"ip_address"`
				UserAgent     string                 `json:"user_agent"`
				RequestMethod string                 `json:"request_method"`
				RequestPath   string                 `json:"request_path"`
				RequestQuery  string                 `json:"request_query"`
				StatusCode    int                    `json:"status_code"`
				ThreatScore   float64                `json:"threat_score"`
				Details       map[string]interface{} `json:"details"`
			}{
				Timestamp:     log.Timestamp,
				IPAddress:     log.IPAddress,
				UserAgent:     log.UserAgent,
				RequestMethod: log.RequestMethod,
				RequestPath:   log.RequestPath,
				RequestQuery:  log.RequestQuery,
				StatusCode:    200,
				ThreatScore:   log.ThreatScore,
				Details:       log.Details,
			}
		}

		// Make direct HTTP call to AI service
		logDataJSON, _ := json.Marshal(map[string]interface{}{"log_data": aiClientLogs})
		client := &http.Client{Timeout: 30 * time.Second}
		aiEndpoint := "http://localhost:5000" // Default
		if z.config != nil {
			if aiConfig := z.config.Get("ai"); aiConfig != nil {
				if aiMap, ok := aiConfig.(map[string]interface{}); ok {
					if endpoint, ok := aiMap["python_endpoint"].(string); ok && endpoint != "" {
						aiEndpoint = endpoint
					}
				}
			}
		}
		resp, err := client.Post(aiEndpoint+"/analyze-logs", "application/json", bytes.NewBuffer(logDataJSON))
		if err == nil && resp != nil && resp.StatusCode == 200 {
			var aiResponse map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&aiResponse)
			resp.Body.Close()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(aiResponse)
			return
		}
	}

	// Fallback response
	response := map[string]interface{}{
		"threat_detected": false,
		"threat_score":    0.0,
		"risk_level":      "LOW",
		"suspicious_ips":  []interface{}{},
		"recommendations": []string{"No threats detected"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getFloat(data map[string]interface{}, key string, defaultValue float64) float64 {
	if val, ok := data[key].(float64); ok {
		return val
	}
	return defaultValue
}
