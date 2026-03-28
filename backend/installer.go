package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

type InstallerConfig struct {
	Database struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		Name     string `json:"name"`
	} `json:"database"`
	Redis struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Password string `json:"password"`
	} `json:"redis"`
	Server struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"server"`
	Security struct {
		JWTSecret string `json:"jwt_secret"`
	} `json:"security"`
	AI struct {
		Endpoint string `json:"endpoint"`
	} `json:"ai"`
}

type InstallerResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Config  string `json:"config,omitempty"`
}

func (z *ZeinSecuritySystem) installHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Serve installer page
		installerHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Zein Security WAF - Installer</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .installer-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        input, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .btn:active {
            transform: translateY(0);
        }
        .status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .status.info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        .two-column {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
    </style>
</head>
<body>
    <div class="installer-container">
        <h1>🛡️ Zein Security WAF</h1>
        <p class="subtitle">Advanced Web Application Firewall Installation</p>
        
        <form id="installForm">
            <div class="form-group">
                <label>Database Host</label>
                <input type="text" name="db_host" value="localhost" required>
            </div>
            
            <div class="two-column">
                <div class="form-group">
                    <label>Database Port</label>
                    <input type="number" name="db_port" value="5432" required>
                </div>
                <div class="form-group">
                    <label>Database Name</label>
                    <input type="text" name="db_name" value="zein_security" required>
                </div>
            </div>
            
            <div class="two-column">
                <div class="form-group">
                    <label>Database User</label>
                    <input type="text" name="db_user" value="zein_waf" required>
                </div>
                <div class="form-group">
                    <label>Database Password</label>
                    <input type="password" name="db_password" required>
                </div>
            </div>
            
            <div class="form-group">
                <label>Redis Host</label>
                <input type="text" name="redis_host" value="localhost" required>
            </div>
            
            <div class="two-column">
                <div class="form-group">
                    <label>Redis Port</label>
                    <input type="number" name="redis_port" value="6379" required>
                </div>
                <div class="form-group">
                    <label>Redis Password (optional)</label>
                    <input type="password" name="redis_password">
                </div>
            </div>
            
            <div class="two-column">
                <div class="form-group">
                    <label>Server Host</label>
                    <input type="text" name="server_host" value="0.0.0.0" required>
                </div>
                <div class="form-group">
                    <label>Server Port</label>
                    <input type="number" name="server_port" value="8080" required>
                </div>
            </div>
            
            <div class="form-group">
                <label>JWT Secret Key</label>
                <input type="text" name="jwt_secret" placeholder="Generate random secret" required>
            </div>
            
            <div class="form-group">
                <label>AI Service Endpoint</label>
                <input type="text" name="ai_endpoint" value="http://localhost:5000" required>
            </div>
            
            <button type="submit" class="btn">🚀 Install Zein Security WAF</button>
        </form>
        
        <div id="status" class="status"></div>
    </div>
    
    <script>
        document.getElementById('installForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            
            const statusDiv = document.getElementById('status');
            statusDiv.style.display = 'block';
            statusDiv.className = 'status info';
            statusDiv.textContent = 'Installing... Please wait...';
            
            try {
                const response = await fetch('/api/install', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    statusDiv.className = 'status success';
                    statusDiv.innerHTML = '✅ Installation successful!<br><br>' + result.message;
                } else {
                    statusDiv.className = 'status error';
                    statusDiv.textContent = '❌ Installation failed: ' + result.message;
                }
            } catch (error) {
                statusDiv.className = 'status error';
                statusDiv.textContent = '❌ Error: ' + error.message;
            }
        });
        
        // Generate random JWT secret
        document.querySelector('input[name="jwt_secret"]').addEventListener('focus', function() {
            if (!this.value) {
                this.value = generateSecret();
            }
        });
        
        function generateSecret() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let secret = '';
            for (let i = 0; i < 64; i++) {
                secret += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return secret;
        }
    </script>
</body>
</html>
`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(installerHTML))
		return
	}

	// Handle POST installation
	var config InstallerConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	// Generate config.json
	configJSON := map[string]interface{}{
		"environment": "production",
		"database": map[string]interface{}{
			"host":            config.Database.Host,
			"port":            config.Database.Port,
			"user":            config.Database.User,
			"password":        config.Database.Password,
			"name":            config.Database.Name,
			"ssl_mode":        "disable",
			"max_connections": 100,
		},
		"redis": map[string]interface{}{
			"host":     config.Redis.Host,
			"port":     config.Redis.Port,
			"password": config.Redis.Password,
			"db":       0,
		},
		"server": map[string]interface{}{
			"host":          config.Server.Host,
			"port":          config.Server.Port,
			"read_timeout":  "30s",
			"write_timeout": "30s",
			"idle_timeout":  "60s",
		},
		"security": map[string]interface{}{
			"jwt_secret":            config.Security.JWTSecret,
			"session_expiration":    "24h",
			"rate_limit_requests":   100,
			"rate_limit_window":     "1m",
			"max_request_body_size": 10485760,
			"cors_allowed_origins":  []string{"*"},
		},
		"ai": map[string]interface{}{
			"python_endpoint":      config.AI.Endpoint,
			"confidence_threshold": 0.7,
			"batch_size":           32,
		},
		"features": map[string]interface{}{
			"advanced_ai":         true,
			"blockchain_audit":    false,
			"threat_intelligence": true,
			"multi_tenant":        false,
			"api_gateway":         true,
		},
	}

	configBytes, err := json.MarshalIndent(configJSON, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to generate config: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Save config.json
	configPath := filepath.Join(".", "backend", "config.json")
	if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to save config: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Test database connection
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Database.Host, config.Database.Port, config.Database.User,
		config.Database.Password, config.Database.Name)

	testDB, err := NewDatabase(connStr)
	if err != nil {
		json.NewEncoder(w).Encode(InstallerResponse{
			Success: false,
			Message: fmt.Sprintf("Database connection failed: %v", err),
		})
		return
	}
	testDB.Close()

	// Create Docker Compose file if requested
	dockerCompose := generateDockerCompose(config)
	dockerPath := filepath.Join(".", "docker-compose.installer.yml")
	os.WriteFile(dockerPath, []byte(dockerCompose), 0644)

	json.NewEncoder(w).Encode(InstallerResponse{
		Success: true,
		Message: "Zein Security WAF installed successfully! Config saved to backend/config.json",
		Config:  string(configBytes),
	})
}

func generateDockerCompose(config InstallerConfig) string {
	return fmt.Sprintf(`version: '3.8'
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: %s
      POSTGRES_USER: %s
      POSTGRES_PASSWORD: %s
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
  
  ai-service:
    build: ./backend/ai-service
    ports:
      - "5000:5000"
  
  waf-backend:
    build: ./backend
    environment:
      - DB_HOST=postgres
      - DB_USER=%s
      - DB_PASSWORD=%s
      - DB_NAME=%s
      - REDIS_HOST=redis
      - AI_SERVICE_URL=http://ai-service:5000
    ports:
      - "%d:8080"
  
volumes:
  postgres_data:
`, config.Database.Name, config.Database.User, config.Database.Password,
		config.Database.User, config.Database.Password, config.Database.Name, config.Server.Port)
}
