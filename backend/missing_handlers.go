package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Health check handler
func (z *ZeinSecuritySystem) healthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "5.0.0",
		"services": map[string]string{
			"database": "healthy",
			"redis":    "healthy",
			"waf":      "active",
			"ai":       "operational",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Readiness check handler
func (z *ZeinSecuritySystem) readyHandler(w http.ResponseWriter, r *http.Request) {
	ready := map[string]interface{}{
		"ready": true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ready)
}

// Demo login handler
func (z *ZeinSecuritySystem) demoLogin(w http.ResponseWriter, r *http.Request) {
	var loginData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Login processed (demo)",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Demo API handler
func (z *ZeinSecuritySystem) demoAPI(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "success",
		"message": "API request processed",
		"data":    []string{"item1", "item2", "item3"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Register handler
func (z *ZeinSecuritySystem) registerHandler(w http.ResponseWriter, r *http.Request) {
	var registerData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&registerData); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	username := getString(registerData, "username", "")
	email := getString(registerData, "email", "")
	password := getString(registerData, "password", "")

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
		Role:         "user",
		IsActive:     true,
	}

	if err := z.database.CreateUser(user); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to create user: %v"}`, err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "User registered successfully",
		"user_id": user.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// WebSocket handler (simplified - using HTTP long polling for now)
func (z *ZeinSecuritySystem) handleQuantumWebSocket(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	// Handle OPTIONS preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	// For now, use Server-Sent Events (SSE) instead of WebSocket
	// This is more compatible and easier to implement
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	
	// Send initial connection message
	fmt.Fprintf(w, "data: %s\n\n", `{"type":"connected","message":"Quantum WebSocket connected"}`)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	
	// Send periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send stats update
			stats := z.monitor.GetStats()
			update := map[string]interface{}{
				"type": "quantum_stats_update",
				"stats": map[string]interface{}{
					"total_requests":    stats.TotalRequests,
					"blocked_requests":  stats.BlockedRequests,
					"threat_actors":      stats.ThreatActors,
					"requests_per_second": stats.RequestsPerSecond,
				},
			}
			updateJSON, _ := json.Marshal(update)
			fmt.Fprintf(w, "data: %s\n\n", string(updateJSON))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

// Generate AI response (fallback)
func generateAIResponse(message string) string {
	messageLower := strings.ToLower(message)
	
	// Basic keyword matching for common questions
	if strings.Contains(messageLower, "sql injection") || strings.Contains(messageLower, "sql") {
		return "**SQL Injection** adalah serangan dimana penyerang menyisipkan kode SQL berbahaya ke dalam query database. Zein WAF mendeteksi dan memblokir serangan ini menggunakan pattern matching dan behavioral analysis."
	}
	if strings.Contains(messageLower, "xss") || strings.Contains(messageLower, "cross-site") {
		return "**Cross-Site Scripting (XSS)** memungkinkan penyerang menyuntikkan script client-side. Zein WAF menggunakan Content Security Policy dan input sanitization untuk mencegah serangan ini."
	}
	if strings.Contains(messageLower, "ddos") {
		return "**DDoS (Distributed Denial of Service)** mengganggu layanan dengan traffic berlebihan. Zein WAF menggunakan rate limiting, IP filtering, dan CDN untuk mitigasi."
	}
	if strings.Contains(messageLower, "cara pasang") || strings.Contains(messageLower, "setup") || strings.Contains(messageLower, "config") {
		return "**Panduan Setup WAF:**\n1. Set domain di tab Config Web\n2. Pilih level protection\n3. Enable SSL\n4. Deploy DNS records\n5. Monitor dashboard untuk aktivitas"
	}
	if strings.Contains(messageLower, "serangan") || strings.Contains(messageLower, "attack") || strings.Contains(messageLower, "threat") {
		return "**Zein Security WAF v5.0** melindungi dari berbagai ancaman:\n• SQL Injection\n• XSS\n• DDoS\n• Brute Force\n• Path Traversal\n• Bot Attacks\n\nGunakan dashboard untuk monitoring real-time."
	}
	
	return "Halo! Saya Zein AI Security Assistant. Saya bisa membantu dengan:\n\n🔍 **Analisis Ancaman** - SQL Injection, XSS, DDoS\n🛠️ **Konfigurasi WAF** - Panduan setup\n📊 **Monitoring** - Real-time threat intelligence\n\nCoba tanyakan tentang: SQL Injection, XSS, DDoS, atau cara setup WAF."
}

// Get client IP helper - removed duplicate, use the one in waf.go
