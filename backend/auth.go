package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db         *Database
	redis      *RedisClient
	jwtSecret  []byte
	sessionExp time.Duration
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"` // For 2FA
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

type TwoFASecret struct {
	Secret    string    `json:"secret"`
	QRCode    string    `json:"qr_code"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

func NewAuthService(db *Database, redis *RedisClient, jwtSecret string) *AuthService {
	if jwtSecret == "" {
		jwtSecret = generateRandomSecret(32)
		log.Printf("🔑 Generated JWT secret: %s", jwtSecret)
	}
	return &AuthService{
		db:         db,
		redis:      redis,
		jwtSecret:  []byte(jwtSecret),
		sessionExp: 24 * time.Hour,
	}
}

func generateRandomSecret(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (a *AuthService) Login(loginReq LoginRequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Get user from database
	log.Printf("🔍 Attempting login for username: '%s'", loginReq.Username)
	user, err := a.db.GetUserByUsername(loginReq.Username)
	if err != nil {
		log.Printf("❌ GetUserByUsername failed for '%s': %v", loginReq.Username, err)
		a.logFailedLogin(loginReq.Username, ipAddress, "user_not_found")
		return nil, fmt.Errorf("invalid credentials")
	}
	log.Printf("✅ User found: id=%d, username=%s, role=%s, active=%v", user.ID, user.Username, user.Role, user.IsActive)

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginReq.Password)); err != nil {
		a.logFailedLogin(loginReq.Username, ipAddress, "invalid_password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if 2FA is required and verify
	if a.is2FARequired(user) {
		if !a.verify2FAToken(user.ID, loginReq.Token) {
			a.logFailedLogin(loginReq.Username, ipAddress, "invalid_2fa")
			return nil, fmt.Errorf("invalid 2FA token")
		}
	}

	// Generate JWT token
	token, expiresAt, err := a.generateToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}

	// Update last login
	if err := a.db.UpdateUserLastLogin(user.ID); err != nil {
		log.Printf("Warning: Failed to update last login: %v", err)
	}

	// Create audit log
	a.db.CreateAuditLog(&AuditLog{
		UserID:    user.ID,
		Action:    "login",
		Resource:  "auth",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details:   "User logged in successfully",
	})

	// Store session in Redis
	sessionKey := fmt.Sprintf("session:%d", user.ID)
	sessionData := map[string]interface{}{
		"user_id":    user.ID,
		"username":   user.Username,
		"role":       user.Role,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"login_time": time.Now(),
	}
	a.redis.SetJSON(sessionKey, sessionData, a.sessionExp)

	log.Printf("✅ User %s logged in from %s", user.Username, ipAddress)

	return &LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      *user,
	}, nil
}

func (a *AuthService) generateToken(user *User) (string, time.Time, error) {
	expiresAt := time.Now().Add(a.sessionExp)

	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   user.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(a.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

func (a *AuthService) VerifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check if session exists in Redis (optional additional validation)
		sessionKey := fmt.Sprintf("session:%d", claims.UserID)
		if exists := a.redis.Exists(sessionKey); !exists {
			return nil, fmt.Errorf("session expired")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (a *AuthService) Middleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Authorization header required"})
				return
			}

			// Extract token from "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid authorization format"})
				return
			}

			token := parts[1]
			claims, err := a.VerifyToken(token)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Invalid token: %v", err)})
				return
			}

			// Check role-based access
			if !a.hasPermission(claims.Role, requiredRole) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Insufficient permissions"})
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), "user", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a *AuthService) hasPermission(userRole, requiredRole string) bool {
	roleHierarchy := map[string]int{
		"user":  1,
		"admin": 2,
		"super": 3,
	}

	userLevel, userOk := roleHierarchy[userRole]
	requiredLevel, requiredOk := roleHierarchy[requiredRole]

	if !userOk || !requiredOk {
		return false
	}

	return userLevel >= requiredLevel
}

func (a *AuthService) is2FARequired(user *User) bool {
	// Check if user has 2FA enabled
	// This would typically check a database field
	return false // Simplified for this example
}

func (a *AuthService) verify2FAToken(userID int, token string) bool {
	// Implement TOTP verification
	// For now, return true for demo
	return true
}

func (a *AuthService) logFailedLogin(username, ipAddress, reason string) {
	// Log failed login attempt
	log.Printf("🚫 Failed login attempt: user=%s, ip=%s, reason=%s", username, ipAddress, reason)

	// Increment failed login counter in Redis
	key := fmt.Sprintf("failed_login:%s", ipAddress)
	count, _ := a.redis.Incr(key)
	a.redis.Expire(key, 15*time.Minute) // Reset after 15 minutes

	// If too many failed attempts, temporarily block IP
	if count >= 5 {
		blockKey := fmt.Sprintf("blocked_ip:%s", ipAddress)
		a.redis.Set(blockKey, "1", 30*time.Minute)
		log.Printf("🚫 IP %s temporarily blocked due to failed login attempts", ipAddress)
	}
}

func (a *AuthService) Logout(tokenString string) error {
	claims, err := a.VerifyToken(tokenString)
	if err != nil {
		return err
	}

	// Remove session from Redis
	sessionKey := fmt.Sprintf("session:%d", claims.UserID)
	a.redis.Del(sessionKey)

	// Add token to blacklist (until expiration)
	expiration := time.Unix(claims.ExpiresAt, 0).Sub(time.Now())
	if expiration > 0 {
		blacklistKey := fmt.Sprintf("blacklist:%s", tokenString)
		a.redis.Set(blacklistKey, "1", expiration)
	}

	return nil
}

func (a *AuthService) ChangePassword(userID int, oldPassword, newPassword string) error {
	// Get user from database
	// Verify old password
	// Hash new password and update
	// Create audit log
	return nil
}

func (a *AuthService) CreateAPIKey(userID int, name string, expiresIn time.Duration) (string, error) {
	// Generate random API key
	key := generateRandomSecret(32)

	// Hash the key for storage
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Store in database
	apiToken := &APIToken{
		UserID:    userID,
		Token:     string(hashedKey),
		Name:      name,
		ExpiresAt: time.Now().Add(expiresIn),
	}

	// Save to database (implementation needed)
	_ = apiToken // TODO: Implement CreateAPIToken in database
	// a.db.CreateAPIToken(apiToken)

	return key, nil
}

func (a *AuthService) VerifyAPIKey(apiKey string) (*User, error) {
	// Get all active API tokens for user
	// Verify the key against stored hashes
	// Return user if valid
	return nil, nil
}
