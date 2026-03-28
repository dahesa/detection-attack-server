-- MySQL Database Schema for Zein Security WAF
-- Database: zein_security

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default admin user
INSERT INTO users (username, email, password_hash, role) 
VALUES ('admin', 'admin@zeinsecurity.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin')
ON DUPLICATE KEY UPDATE username=username;

-- API tokens table
CREATE TABLE IF NOT EXISTS api_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security configurations table
CREATE TABLE IF NOT EXISTS security_configs (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Threat intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security events table
CREATE TABLE IF NOT EXISTS security_events (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- System metrics table
CREATE TABLE IF NOT EXISTS system_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,4) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- IP Blocks table
CREATE TABLE IF NOT EXISTS ip_blocks (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Log Analysis table
CREATE TABLE IF NOT EXISTS log_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_type VARCHAR(50) NOT NULL,
    threat_score DECIMAL(3,2) DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'low',
    suspicious_ips JSON,
    recommendations JSON,
    analysis_data JSON,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create indexes
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_ip ON security_events(ip_address);
CREATE INDEX idx_threat_intelligence_ip ON threat_intelligence(ip_address);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_system_metrics_timestamp ON system_metrics(timestamp);
CREATE INDEX idx_ip_blocks_ip ON ip_blocks(ip_address);
CREATE INDEX idx_ip_blocks_active ON ip_blocks(is_active, blocked_until);
CREATE INDEX idx_log_analysis_timestamp ON log_analysis(timestamp);
