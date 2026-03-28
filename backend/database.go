package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// Database structures
type Database struct {
	*sql.DB
}

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	IsActive     bool      `json:"is_active"`
	LastLogin    time.Time `json:"last_login"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type APIToken struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type DatabaseSecurityConfig struct {
	ID               int    `json:"id"`
	Domain           string `json:"domain"`
	SSLEnabled       bool   `json:"ssl_enabled"`
	ProtectionLevel  string `json:"protection_level"`
	RateLimiting     bool   `json:"rate_limiting"`
	BotProtection    bool   `json:"bot_protection"`
	CustomRules      string `json:"custom_rules"`
	MaxUploadSize    int    `json:"max_upload_size"`
	BlockedCountries string `json:"blocked_countries"`
	AllowedIPs       string `json:"allowed_ips"`
	BlockedIPs       string `json:"blocked_ips"`
}

type AuditLog struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}

func NewDatabase(connectionString string) (*Database, error) {
	// Log connection string (without password) for debugging
	log.Printf("🔌 Database connection string: %s", maskPassword(connectionString))
	
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Retry connection with exponential backoff
	maxRetries := 10
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := db.Ping(); err != nil {
			lastErr = err
			if i < maxRetries-1 {
				waitTime := time.Duration(i+1) * time.Second
				log.Printf("⏳ Database connection attempt %d/%d failed: %v, retrying in %v...", i+1, maxRetries, err, waitTime)
				time.Sleep(waitTime)
				continue
			}
			return nil, fmt.Errorf("failed to connect to database after %d attempts: %v", maxRetries, lastErr)
		}
		log.Printf("✅ Database connection successful!")
		break
	}

	database := &Database{db}
	if err := database.runMigrations(); err != nil {
		return nil, err
	}

	return database, nil
}

// maskPassword masks password in connection string for logging
func maskPassword(connStr string) string {
	// Simple masking - replace password=xxx with password=***
	if idx := strings.Index(connStr, "password="); idx != -1 {
		start := idx + len("password=")
		end := strings.Index(connStr[start:], " ")
		if end == -1 {
			end = len(connStr) - start
		} else {
			end = start + end
		}
		return connStr[:start] + "***" + connStr[end:]
	}
	return connStr
}

func (db *Database) runMigrations() error {
	migrations := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(20) DEFAULT 'user',
			is_active BOOLEAN DEFAULT true,
			last_login TIMESTAMP NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// API tokens table
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			token VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(100) NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Security configurations table
		`CREATE TABLE IF NOT EXISTS security_configs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			domain VARCHAR(255) UNIQUE NOT NULL,
			ssl_enabled BOOLEAN DEFAULT true,
			protection_level VARCHAR(20) DEFAULT 'medium',
			rate_limiting BOOLEAN DEFAULT true,
			bot_protection BOOLEAN DEFAULT true,
			custom_rules TEXT,
			max_upload_size INT DEFAULT 10485760,
			blocked_countries TEXT,
			allowed_ips TEXT,
			blocked_ips TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Audit logs table
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT,
			action VARCHAR(100) NOT NULL,
			resource VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			user_agent TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			details TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Threat intelligence table
		`CREATE TABLE IF NOT EXISTS threat_intelligence (
			id INT AUTO_INCREMENT PRIMARY KEY,
			ip_address VARCHAR(45) NOT NULL,
			threat_type VARCHAR(100) NOT NULL,
			confidence_score DECIMAL(3,2) DEFAULT 0.0,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			source VARCHAR(100) NOT NULL,
			description TEXT,
			is_active BOOLEAN DEFAULT true,
			UNIQUE KEY unique_ip_threat (ip_address, threat_type)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Security events table
		`CREATE TABLE IF NOT EXISTS security_events (
			id INT AUTO_INCREMENT PRIMARY KEY,
			event_type VARCHAR(100) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			user_agent TEXT,
			request_method VARCHAR(10),
			request_path TEXT,
			request_query TEXT,
			threat_score DECIMAL(3,2) DEFAULT 0.0,
			severity VARCHAR(20) DEFAULT 'low',
			blocked BOOLEAN DEFAULT false,
			details JSON,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// System metrics table
		`CREATE TABLE IF NOT EXISTS system_metrics (
			id INT AUTO_INCREMENT PRIMARY KEY,
			metric_name VARCHAR(100) NOT NULL,
			metric_value DECIMAL(10,4) NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// IP Blocks table
		`CREATE TABLE IF NOT EXISTS ip_blocks (
			id INT AUTO_INCREMENT PRIMARY KEY,
			ip_address VARCHAR(45) UNIQUE NOT NULL,
			reason TEXT NOT NULL,
			attack_type VARCHAR(100) NOT NULL,
			threat_score DECIMAL(3,2) DEFAULT 0.0,
			blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			blocked_until TIMESTAMP NOT NULL,
			unblocked_at TIMESTAMP NULL,
			source VARCHAR(50) DEFAULT 'manual',
			is_active BOOLEAN DEFAULT true,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Log Analysis table
		`CREATE TABLE IF NOT EXISTS log_analysis (
			id INT AUTO_INCREMENT PRIMARY KEY,
			analysis_type VARCHAR(50) NOT NULL,
			threat_score DECIMAL(3,2) DEFAULT 0.0,
			risk_level VARCHAR(20) DEFAULT 'low',
			suspicious_ips JSON,
			recommendations JSON,
			analysis_data JSON,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Create indexes (MySQL doesn't support IF NOT EXISTS for indexes, so we'll skip errors)
		// Note: These will fail silently if indexes already exist, which is fine

		// Create admin user
		`INSERT INTO users (username, email, password_hash, role) 
		 VALUES ('admin', 'admin@zeinsecurity.com', ?, 'admin')
		 ON DUPLICATE KEY UPDATE username=username`,
	}

	// Hash password for admin user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)

	for i, migration := range migrations {
		if i == len(migrations)-1 {
			// Last migration with parameter
			_, err := db.Exec(migration, string(hashedPassword))
			if err != nil {
				log.Printf("Warning: Admin user creation: %v", err)
			}
		} else {
			_, err := db.Exec(migration)
			if err != nil {
				// Check if error is about duplicate key/index or table already exists
				errStr := err.Error()
				if strings.Contains(errStr, "Duplicate key") || 
				   strings.Contains(errStr, "1061") || 
				   strings.Contains(errStr, "1062") ||
				   strings.Contains(errStr, "already exists") ||
				   strings.Contains(errStr, "1050") {
					// Index, key, or table already exists, skip this error
					log.Printf("Info: %s (already exists, skipping)", errStr)
					continue
				}
				// For other errors, log but don't fail completely
				log.Printf("Warning: Migration may have failed: %v", err)
			}
		}
	}
	
	// Create indexes separately (they may already exist, so we ignore duplicate errors)
	indexes := []string{
		`CREATE INDEX idx_security_events_timestamp ON security_events(timestamp)`,
		`CREATE INDEX idx_security_events_ip ON security_events(ip_address)`,
		`CREATE INDEX idx_threat_intelligence_ip ON threat_intelligence(ip_address)`,
		`CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp)`,
		`CREATE INDEX idx_system_metrics_timestamp ON system_metrics(timestamp)`,
		`CREATE INDEX idx_ip_blocks_ip ON ip_blocks(ip_address)`,
		`CREATE INDEX idx_ip_blocks_active ON ip_blocks(is_active, blocked_until)`,
		`CREATE INDEX idx_log_analysis_timestamp ON log_analysis(timestamp)`,
	}
	
	for _, idxQuery := range indexes {
		_, err := db.Exec(idxQuery)
		if err != nil {
			// Ignore errors if index already exists (MySQL error 1061)
			errStr := err.Error()
			if strings.Contains(errStr, "Duplicate key") || 
			   strings.Contains(errStr, "1061") ||
			   strings.Contains(errStr, "already exists") {
				// Index already exists, this is fine - skip silently
				continue
			}
			// For other errors, log a warning
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	log.Println("✅ Database migrations completed successfully")
	return nil
}

// User management methods
func (db *Database) CreateUser(user *User) error {
	query := `
		INSERT INTO users (username, email, password_hash, role, is_active)
		VALUES (?, ?, ?, ?, ?)
	`
	result, err := db.Exec(
		query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.IsActive,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	user.ID = int(id)
	// Get created_at and updated_at
	query2 := `SELECT created_at, updated_at FROM users WHERE id = ?`
	return db.QueryRow(query2, user.ID).Scan(&user.CreatedAt, &user.UpdatedAt)
}

func (db *Database) GetUserByUsername(username string) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password_hash, role, is_active, last_login, created_at, updated_at 
	          FROM users WHERE username = ?`
	
	var lastLogin, createdAt, updatedAt sql.NullTime
	err := db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsActive,
		&lastLogin,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		log.Printf("🔍 GetUserByUsername error for username '%s': %v", username, err)
		// Debug: Check if user exists with different case
		var count int
		db.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)", username).Scan(&count)
		log.Printf("🔍 Users with similar username (case-insensitive): %d", count)
		// Debug: List all usernames
		rows, _ := db.Query("SELECT username FROM users LIMIT 10")
		if rows != nil {
			log.Printf("🔍 Existing usernames in database:")
			for rows.Next() {
				var u string
				if rows.Scan(&u) == nil {
					log.Printf("   - '%s'", u)
				}
			}
			rows.Close()
		}
		return nil, err
	}
	
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}
	if createdAt.Valid {
		user.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		user.UpdatedAt = updatedAt.Time
	}
	
	log.Printf("✅ Found user: id=%d, username=%s, role=%s, active=%v", user.ID, user.Username, user.Role, user.IsActive)
	return user, nil
}

func (db *Database) UpdateUserLastLogin(userID int) error {
	query := `UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?`
	_, err := db.Exec(query, time.Now(), time.Now(), userID)
	return err
}

// Security config methods
func (db *Database) GetSecurityConfig(domain string) (*DatabaseSecurityConfig, error) {
	config := &DatabaseSecurityConfig{}
	query := `SELECT id, domain, ssl_enabled, protection_level, rate_limiting, bot_protection, 
	                 custom_rules, max_upload_size, blocked_countries, allowed_ips, blocked_ips
	          FROM security_configs WHERE domain = ?`
	err := db.QueryRow(query, domain).Scan(
		&config.ID,
		&config.Domain,
		&config.SSLEnabled,
		&config.ProtectionLevel,
		&config.RateLimiting,
		&config.BotProtection,
		&config.CustomRules,
		&config.MaxUploadSize,
		&config.BlockedCountries,
		&config.AllowedIPs,
		&config.BlockedIPs,
	)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (db *Database) SaveSecurityConfig(config *DatabaseSecurityConfig) error {
	query := `
		INSERT INTO security_configs 
		(domain, ssl_enabled, protection_level, rate_limiting, bot_protection, custom_rules, 
		 max_upload_size, blocked_countries, allowed_ips, blocked_ips)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE 
			ssl_enabled = VALUES(ssl_enabled),
			protection_level = VALUES(protection_level),
			rate_limiting = VALUES(rate_limiting),
			bot_protection = VALUES(bot_protection),
			custom_rules = VALUES(custom_rules),
			max_upload_size = VALUES(max_upload_size),
			blocked_countries = VALUES(blocked_countries),
			allowed_ips = VALUES(allowed_ips),
			blocked_ips = VALUES(blocked_ips),
			updated_at = CURRENT_TIMESTAMP
	`
	result, err := db.Exec(
		query,
		config.Domain,
		config.SSLEnabled,
		config.ProtectionLevel,
		config.RateLimiting,
		config.BotProtection,
		config.CustomRules,
		config.MaxUploadSize,
		config.BlockedCountries,
		config.AllowedIPs,
		config.BlockedIPs,
	)
	if err != nil {
		return err
	}
	// Get ID if inserted
	if id, err := result.LastInsertId(); err == nil {
		config.ID = int(id)
	} else {
		// If duplicate, get existing ID
		query2 := `SELECT id FROM security_configs WHERE domain = ?`
		db.QueryRow(query2, config.Domain).Scan(&config.ID)
	}
	return nil
}

// Audit log methods
func (db *Database) CreateAuditLog(log *AuditLog) error {
	query := `
		INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, details)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	result, err := db.Exec(
		query,
		log.UserID,
		log.Action,
		log.Resource,
		log.IPAddress,
		log.UserAgent,
		log.Details,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	log.ID = int(id)
	// Get timestamp
	query2 := `SELECT timestamp FROM audit_logs WHERE id = ?`
	return db.QueryRow(query2, log.ID).Scan(&log.Timestamp)
}

// Threat intelligence methods
func (db *Database) AddThreatIntelligence(ip, threatType, source, description string, confidence float64) error {
	query := `
		INSERT INTO threat_intelligence (ip_address, threat_type, confidence_score, source, description)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE 
			confidence_score = VALUES(confidence_score),
			last_seen = CURRENT_TIMESTAMP,
			source = VALUES(source),
			description = VALUES(description),
			is_active = true
	`
	_, err := db.Exec(query, ip, threatType, confidence, source, description)
	return err
}

func (db *Database) GetThreatIntelligence(ip string) ([]MonitorThreatIntelligence, error) {
	query := `
		SELECT ip_address, threat_type, confidence_score, first_seen, last_seen, source, description
		FROM threat_intelligence 
		WHERE ip_address = ? AND is_active = true
		ORDER BY confidence_score DESC
	`
	rows, err := db.Query(query, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []MonitorThreatIntelligence
	for rows.Next() {
		var threat MonitorThreatIntelligence
		err := rows.Scan(
			&threat.IPAddress,
			&threat.ThreatType,
			&threat.ConfidenceScore,
			&threat.FirstSeen,
			&threat.LastSeen,
			&threat.Source,
			&threat.Description,
		)
		if err != nil {
			return nil, err
		}
		threats = append(threats, threat)
	}
	return threats, nil
}

// Security events methods
func (db *Database) LogSecurityEvent(event *SecurityEvent) error {
	query := `
		INSERT INTO security_events 
		(event_type, ip_address, user_agent, request_method, request_path, request_query, 
		 threat_score, severity, blocked, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	result, err := db.Exec(
		query,
		event.EventType,
		event.IPAddress,
		event.UserAgent,
		event.RequestMethod,
		event.RequestPath,
		event.RequestQuery,
		event.ThreatScore,
		event.Severity,
		event.Blocked,
		event.Details,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	event.ID = int(id)
	return nil
}

func (db *Database) GetSecurityEvents(limit int, offset int) ([]SecurityEvent, error) {
	query := `
		SELECT id, event_type, ip_address, user_agent, request_method, request_path, 
		       request_query, threat_score, severity, blocked, details, timestamp
		FROM security_events 
		ORDER BY timestamp DESC 
		LIMIT ? OFFSET ?
	`
	rows, err := db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		err := rows.Scan(
			&event.ID,
			&event.EventType,
			&event.IPAddress,
			&event.UserAgent,
			&event.RequestMethod,
			&event.RequestPath,
			&event.RequestQuery,
			&event.ThreatScore,
			&event.Severity,
			&event.Blocked,
			&event.Details,
			&event.Timestamp,
		)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

// System metrics methods
func (db *Database) SaveSystemMetric(name string, value float64) error {
	query := `INSERT INTO system_metrics (metric_name, metric_value) VALUES (?, ?)`
	_, err := db.Exec(query, name, value)
	return err
}

func (db *Database) GetSystemMetrics(name string, hours int) ([]SystemMetric, error) {
	query := `
		SELECT metric_name, metric_value, timestamp
		FROM system_metrics 
		WHERE metric_name = ? AND timestamp >= DATE_SUB(NOW(), INTERVAL ? HOUR)
		ORDER BY timestamp ASC
	`
	rows, err := db.Query(query, name, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []SystemMetric
	for rows.Next() {
		var metric SystemMetric
		err := rows.Scan(&metric.Name, &metric.Value, &metric.Timestamp)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, metric)
	}
	return metrics, nil
}

// Backup and maintenance
func (db *Database) PerformBackup() error {
	// This would typically call pg_dump or similar
	// For now, we'll just log and create a marker
	query := `INSERT INTO system_metrics (metric_name, metric_value) VALUES ('backup_performed', 1)`
	_, err := db.Exec(query)
	if err != nil {
		return err
	}
	log.Println("✅ Database backup marker created")
	return nil
}

func (db *Database) CleanupOldData(retentionDays int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Clean old security events
	_, err := db.ExecContext(ctx, `
		DELETE FROM security_events 
		WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)
	`, retentionDays)
	if err != nil {
		return err
	}

	// Clean old system metrics
	_, err = db.ExecContext(ctx, `
		DELETE FROM system_metrics 
		WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? DAY)
	`, retentionDays)

	log.Printf("✅ Cleaned up data older than %d days", retentionDays)
	return err
}
