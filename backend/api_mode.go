package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// APIModeConfig holds configuration for API/SDK mode
type APIModeConfig struct {
	Enabled        bool              `json:"enabled"`
	APIKeyRequired bool              `json:"api_key_required"`
	RateLimit      map[string]int    `json:"rate_limit"` // endpoint -> requests per minute
	AllowedOrigins []string          `json:"allowed_origins"`
	Webhooks       map[string]string `json:"webhooks"` // event -> URL
	SDKVersion     string            `json:"sdk_version"`
}

// APIKey represents an API key
type APIKey struct {
	Key       string    `json:"key"`
	Secret    string    `json:"secret"`
	ClientID  string    `json:"client_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes"`
	RateLimit int       `json:"rate_limit"` // requests per minute
}

// APIMode handles API/SDK mode operations
type APIMode struct {
	config  *APIModeConfig
	apiKeys map[string]*APIKey
	mu      sync.RWMutex
	clients map[string]*APIClient // client_id -> client
}

// APIClient represents an API client
type APIClient struct {
	ClientID     string
	APIKey       string
	Secret       string
	CreatedAt    time.Time
	LastRequest  time.Time
	RequestCount int64
	RateLimit    int
	Scopes       []string
}

// NewAPIMode creates a new API mode instance
func NewAPIMode(config *APIModeConfig) *APIMode {
	return &APIMode{
		config:  config,
		apiKeys: make(map[string]*APIKey),
		clients: make(map[string]*APIClient),
	}
}

// AuthenticateRequest authenticates an API request
func (am *APIMode) AuthenticateRequest(r *http.Request) (*APIClient, error) {
	if !am.config.Enabled {
		return nil, nil // API mode disabled, allow
	}

	if !am.config.APIKeyRequired {
		return nil, nil // No auth required
	}

	// Get API key from header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		// Try Authorization header
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			apiKey = strings.TrimPrefix(auth, "Bearer ")
		} else if strings.HasPrefix(auth, "ApiKey ") {
			apiKey = strings.TrimPrefix(auth, "ApiKey ")
		}
	}

	if apiKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	am.mu.RLock()
	client, exists := am.clients[apiKey]
	am.mu.RUnlock()

	if !exists {
		// Try to find by key
		am.mu.RLock()
		for _, c := range am.clients {
			if c.APIKey == apiKey {
				client = c
				break
			}
		}
		am.mu.RUnlock()
	}

	if client == nil {
		return nil, fmt.Errorf("invalid API key")
	}

	// Verify signature if present
	signature := r.Header.Get("X-Signature")
	if signature != "" {
		if !am.verifySignature(r, client.Secret, signature) {
			return nil, fmt.Errorf("invalid signature")
		}
	}

	// Check rate limit
	if !am.checkRateLimit(client) {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Update last request
	am.mu.Lock()
	client.LastRequest = time.Now()
	client.RequestCount++
	am.mu.Unlock()

	return client, nil
}

// verifySignature verifies request signature
func (am *APIMode) verifySignature(r *http.Request, secret, signature string) bool {
	// Create signature from request
	timestamp := r.Header.Get("X-Timestamp")
	method := r.Method
	path := r.URL.Path
	body := ""

	if r.Body != nil {
		bodyBytes, _ := readBody(r)
		body = string(bodyBytes)
	}

	message := fmt.Sprintf("%s\n%s\n%s\n%s", method, path, timestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// checkRateLimit checks if client is within rate limit
func (am *APIMode) checkRateLimit(client *APIClient) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if client.RateLimit <= 0 {
		return true // No limit
	}

	// Simple rate limiting - check requests in last minute
	// In production, use a proper rate limiter
	now := time.Now()
	if now.Sub(client.LastRequest) > time.Minute {
		return true // Reset window
	}

	// This is simplified - use proper rate limiter in production
	return true
}

// RegisterClient registers a new API client
func (am *APIMode) RegisterClient(clientID string, scopes []string, rateLimit int) (*APIClient, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Generate API key
	apiKey := generateAPIKey(clientID)
	secret := generateSecret()

	client := &APIClient{
		ClientID:     clientID,
		APIKey:       apiKey,
		Secret:       secret,
		CreatedAt:    time.Now(),
		LastRequest:  time.Now(),
		RequestCount: 0,
		RateLimit:    rateLimit,
		Scopes:       scopes,
	}

	am.clients[apiKey] = client

	return client, nil
}

// HandleWebhook sends webhook notification
func (am *APIMode) HandleWebhook(event string, data interface{}) {
	am.mu.RLock()
	webhookURL, exists := am.config.Webhooks[event]
	am.mu.RUnlock()

	if !exists || webhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"event":     event,
		"data":      data,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("❌ Failed to marshal webhook: %v", err)
		return
	}

	// Send webhook asynchronously
	go func() {
		resp, err := http.Post(webhookURL, "application/json", strings.NewReader(string(jsonData)))
		if err != nil {
			log.Printf("❌ Webhook failed: %v", err)
			return
		}
		defer resp.Body.Close()
		log.Printf("✅ Webhook sent: %s", event)
	}()
}

// Middleware handles API mode authentication
func (am *APIMode) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !am.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check CORS
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := false
			for _, allowedOrigin := range am.config.AllowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Signature, X-Timestamp")
			}
		}

		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Authenticate
		client, err := am.AuthenticateRequest(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Authentication failed",
				"message": err.Error(),
			})
			return
		}

		// Add client info to context
		if client != nil {
			r.Header.Set("X-Client-ID", client.ClientID)
		}

		// Add API mode headers
		w.Header().Set("X-Zein-API-Mode", "enabled")
		w.Header().Set("X-Zein-SDK-Version", am.config.SDKVersion)

		next.ServeHTTP(w, r)
	})
}

func generateAPIKey(clientID string) string {
	data := fmt.Sprintf("%s-%d", clientID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])[:32]
}

func generateSecret() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return base64.URLEncoding.EncodeToString(hash[:])[:64]
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}
