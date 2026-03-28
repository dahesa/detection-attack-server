package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	mu           sync.RWMutex
	values       map[string]interface{}
	filePath     string
	lastModified time.Time
	watchers     []chan ConfigChange
}

type ConfigChange struct {
	Key  string      `json:"key"`
	Old  interface{} `json:"old_value"`
	New  interface{} `json:"new_value"`
	Time time.Time   `json:"time"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Name     string `json:"name"`
	SSLMode  string `json:"ssl_mode"`
	MaxConns int    `json:"max_connections"`
}

type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

// UnmarshalJSON implements custom unmarshaling for ServerConfig to handle duration strings
func (s *ServerConfig) UnmarshalJSON(data []byte) error {
	type Alias ServerConfig
	aux := &struct {
		ReadTimeout  string `json:"read_timeout"`
		WriteTimeout string `json:"write_timeout"`
		IdleTimeout  string `json:"idle_timeout"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	var err error
	if aux.ReadTimeout != "" {
		s.ReadTimeout, err = time.ParseDuration(aux.ReadTimeout)
		if err != nil {
			return fmt.Errorf("invalid read_timeout: %v", err)
		}
	}
	if aux.WriteTimeout != "" {
		s.WriteTimeout, err = time.ParseDuration(aux.WriteTimeout)
		if err != nil {
			return fmt.Errorf("invalid write_timeout: %v", err)
		}
	}
	if aux.IdleTimeout != "" {
		s.IdleTimeout, err = time.ParseDuration(aux.IdleTimeout)
		if err != nil {
			return fmt.Errorf("invalid idle_timeout: %v", err)
		}
	}
	
	return nil
}

type SecurityConfig struct {
	JWTSecret          string        `json:"jwt_secret"`
	SessionExpiration  time.Duration `json:"session_expiration"`
	RateLimitRequests  int           `json:"rate_limit_requests"`
	RateLimitWindow    time.Duration `json:"rate_limit_window"`
	MaxRequestBodySize int64         `json:"max_request_body_size"`
	CORSAllowedOrigins []string      `json:"cors_allowed_origins"`
}

// UnmarshalJSON implements custom unmarshaling for SecurityConfig to handle duration strings
func (s *SecurityConfig) UnmarshalJSON(data []byte) error {
	type Alias SecurityConfig
	aux := &struct {
		SessionExpiration string `json:"session_expiration"`
		RateLimitWindow   string `json:"rate_limit_window"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	var err error
	if aux.SessionExpiration != "" {
		s.SessionExpiration, err = time.ParseDuration(aux.SessionExpiration)
		if err != nil {
			return fmt.Errorf("invalid session_expiration: %v", err)
		}
	}
	if aux.RateLimitWindow != "" {
		s.RateLimitWindow, err = time.ParseDuration(aux.RateLimitWindow)
		if err != nil {
			return fmt.Errorf("invalid rate_limit_window: %v", err)
		}
	}
	
	return nil
}

type LoggingConfig struct {
	Level    string `json:"level"`
	Format   string `json:"format"`
	FilePath string `json:"file_path"`
}

type MonitoringConfig struct {
	Enabled      bool   `json:"enabled"`
	Prometheus   bool   `json:"prometheus"`
	MetricsPort  int    `json:"metrics_port"`
	HealthCheck  bool   `json:"health_check"`
	AlertWebhook string `json:"alert_webhook"`
}

type AIConfig struct {
	PythonEndpoint string  `json:"python_endpoint"`
	ModelPath      string  `json:"model_path"`
	Confidence     float64 `json:"confidence_threshold"`
	BatchSize      int     `json:"batch_size"`
}

type AppConfig struct {
	Environment string           `json:"environment"`
	Database    DatabaseConfig   `json:"database"`
	Redis       RedisConfig      `json:"redis"`
	Server      ServerConfig     `json:"server"`
	Security    SecurityConfig   `json:"security"`
	Logging     LoggingConfig    `json:"logging"`
	Monitoring  MonitoringConfig `json:"monitoring"`
	AI          AIConfig         `json:"ai"`
	Features    map[string]bool  `json:"features"`
}

func NewConfig(filePath string) (*Config, error) {
	config := &Config{
		values:   make(map[string]interface{}),
		filePath: filePath,
		watchers: make([]chan ConfigChange, 0),
	}

	if err := config.loadFromFile(); err != nil {
		return nil, err
	}

	// Set default values
	config.setDefaults()

	// Start file watcher
	go config.watchFile()

	return config, nil
}

func (c *Config) loadFromFile() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Open(c.filePath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}
	c.lastModified = fileInfo.ModTime()

	var appConfig AppConfig
	if err := json.NewDecoder(file).Decode(&appConfig); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	// Convert to flat map for easier access
	oldValues := make(map[string]interface{})
	for k, v := range c.values {
		oldValues[k] = v
	}

	c.values = c.flattenConfig(appConfig)

	// Notify watchers of changes
	c.notifyWatchers(oldValues, c.values)

	log.Println("✅ Configuration loaded successfully")
	return nil
}

func (c *Config) flattenConfig(config AppConfig) map[string]interface{} {
	flat := make(map[string]interface{})

	// Convert struct to JSON
	jsonData, _ := json.Marshal(config)
	var temp map[string]interface{}
	json.Unmarshal(jsonData, &temp)

	// Flatten nested structures
	var flatten func(prefix string, m map[string]interface{})
	flatten = func(prefix string, m map[string]interface{}) {
		for k, v := range m {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}

			if nested, ok := v.(map[string]interface{}); ok {
				flatten(key, nested)
			} else {
				flat[key] = v
			}
		}
	}

	flatten("", temp)
	return flat
}

func (c *Config) setDefaults() {
	defaults := map[string]interface{}{
		"environment":                    "development",
		"server.host":                    "0.0.0.0",
		"server.port":                    8080,
		"server.read_timeout":            "30s",
		"server.write_timeout":           "30s",
		"server.idle_timeout":            "60s",
		"security.rate_limit_requests":   100,
		"security.rate_limit_window":     "1m",
		"security.max_request_body_size": 10485760,
		"logging.level":                  "info",
		"logging.format":                 "json",
		"monitoring.enabled":             true,
		"monitoring.prometheus":          true,
		"monitoring.metrics_port":        9090,
		"ai.confidence_threshold":        0.7,
		"ai.batch_size":                  32,
	}

	for k, v := range defaults {
		if _, exists := c.values[k]; !exists {
			c.values[k] = v
		}
	}
}

func (c *Config) watchFile() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fileInfo, err := os.Stat(c.filePath)
		if err != nil {
			log.Printf("⚠️ Config file watch error: %v", err)
			continue
		}

		if fileInfo.ModTime().After(c.lastModified) {
			log.Println("🔄 Configuration file changed, reloading...")
			if err := c.loadFromFile(); err != nil {
				log.Printf("❌ Failed to reload config: %v", err)
			}
		}
	}
}

func (c *Config) notifyWatchers(oldValues, newValues map[string]interface{}) {
	for key, newVal := range newValues {
		oldVal, exists := oldValues[key]
		if !exists || oldVal != newVal {
			change := ConfigChange{
				Key:  key,
				Old:  oldVal,
				New:  newVal,
				Time: time.Now(),
			}

			for _, watcher := range c.watchers {
				select {
				case watcher <- change:
				default:
					// Skip if watcher is busy
				}
			}
		}
	}
}

func (c *Config) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.values[key]
}

func (c *Config) GetString(key string) string {
	value := c.Get(key)
	if value == nil {
		return ""
	}
	
	// Handle float64 to avoid scientific notation
	switch v := value.(type) {
	case float64:
		// Use %.0f for whole numbers, %f for decimals
		if v == float64(int64(v)) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%f", v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", value)
	}
}

func (c *Config) GetStringWithDefault(key string, defaultValue string) string {
	value := c.GetString(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func (c *Config) GetInt(key string) int {
	value := c.Get(key)
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}

func (c *Config) GetIntWithDefault(key string, defaultValue int) int {
	value := c.GetInt(key)
	if value == 0 {
		return defaultValue
	}
	return value
}

func (c *Config) GetBool(key string) bool {
	value := c.Get(key)
	if value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.ToLower(v) == "true"
	case int:
		return v != 0
	}
	return false
}

func (c *Config) GetDuration(key string) time.Duration {
	rawValue := c.Get(key)
	if rawValue == nil {
		return 0
	}

	// Handle different types
	var durationStr string
	switch v := rawValue.(type) {
	case string:
		// Check if it's scientific notation and convert
		if strings.Contains(v, "e+") || strings.Contains(v, "e-") {
			// Try to parse as float first
			if num, err := strconv.ParseFloat(v, 64); err == nil {
				// Assume it's nanoseconds if very large
				if num >= 1e9 {
					durationStr = fmt.Sprintf("%.0fns", num)
				} else {
					durationStr = fmt.Sprintf("%.0fs", num)
				}
			} else {
				durationStr = v
			}
		} else {
			durationStr = v
		}
	case float64:
		// If it's a number, it might be nanoseconds - convert to string with proper format
		// Avoid scientific notation by using %.0f for large numbers
		if v >= 1e9 {
			durationStr = fmt.Sprintf("%.0fns", v)
		} else {
			durationStr = fmt.Sprintf("%.0fs", v)
		}
	case int:
		durationStr = fmt.Sprintf("%ds", v)
	case int64:
		durationStr = fmt.Sprintf("%ds", v)
	default:
		strVal := fmt.Sprintf("%v", v)
		// Check for scientific notation in string representation
		if strings.Contains(strVal, "e+") || strings.Contains(strVal, "e-") {
			if num, err := strconv.ParseFloat(strVal, 64); err == nil {
				if num >= 1e9 {
					durationStr = fmt.Sprintf("%.0fns", num)
				} else {
					durationStr = fmt.Sprintf("%.0fs", num)
				}
			} else {
				durationStr = strVal
			}
		} else {
			durationStr = strVal
		}
	}

	if durationStr == "" {
		return 0
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		log.Printf("⚠️ Invalid duration for key %s: %v (value: %v, parsed as: %s)", key, err, rawValue, durationStr)
		return 0
	}
	return duration
}

func (c *Config) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldValue := c.values[key]
	c.values[key] = value

	// Notify watchers
	change := ConfigChange{
		Key:  key,
		Old:  oldValue,
		New:  value,
		Time: time.Now(),
	}

	for _, watcher := range c.watchers {
		select {
		case watcher <- change:
		default:
		}
	}

	log.Printf("⚙️ Configuration updated: %s = %v", key, value)
}

func (c *Config) Watch() <-chan ConfigChange {
	watcher := make(chan ConfigChange, 10)
	c.mu.Lock()
	c.watchers = append(c.watchers, watcher)
	c.mu.Unlock()
	return watcher
}

func (c *Config) GetAppConfig() *AppConfig {
	return &AppConfig{
		Environment: c.GetString("environment"),
		Database: DatabaseConfig{
			Host:     c.GetString("database.host"),
			Port:     c.GetInt("database.port"),
			User:     c.GetString("database.user"),
			Password: c.GetString("database.password"),
			Name:     c.GetString("database.name"),
			SSLMode:  c.GetString("database.ssl_mode"),
			MaxConns: c.GetInt("database.max_connections"),
		},
		Redis: RedisConfig{
			Host:     c.GetString("redis.host"),
			Port:     c.GetInt("redis.port"),
			Password: c.GetString("redis.password"),
			DB:       c.GetInt("redis.db"),
		},
		Server: ServerConfig{
			Host:         c.GetString("server.host"),
			Port:         c.GetInt("server.port"),
			ReadTimeout:  c.GetDuration("server.read_timeout"),
			WriteTimeout: c.GetDuration("server.write_timeout"),
			IdleTimeout:  c.GetDuration("server.idle_timeout"),
		},
		Security: SecurityConfig{
			JWTSecret:          c.GetString("security.jwt_secret"),
			SessionExpiration:  c.GetDuration("security.session_expiration"),
			RateLimitRequests:  c.GetInt("security.rate_limit_requests"),
			RateLimitWindow:    c.GetDuration("security.rate_limit_window"),
			MaxRequestBodySize: c.GetInt64("security.max_request_body_size"),
			CORSAllowedOrigins: c.getStringSlice("security.cors_allowed_origins"),
		},
		Logging: LoggingConfig{
			Level:    c.GetString("logging.level"),
			Format:   c.GetString("logging.format"),
			FilePath: c.GetString("logging.file_path"),
		},
		Monitoring: MonitoringConfig{
			Enabled:      c.GetBool("monitoring.enabled"),
			Prometheus:   c.GetBool("monitoring.prometheus"),
			MetricsPort:  c.GetInt("monitoring.metrics_port"),
			HealthCheck:  c.GetBool("monitoring.health_check"),
			AlertWebhook: c.GetString("monitoring.alert_webhook"),
		},
		AI: AIConfig{
			PythonEndpoint: c.GetString("ai.python_endpoint"),
			ModelPath:      c.GetString("ai.model_path"),
			Confidence:     c.GetFloat64("ai.confidence_threshold"),
			BatchSize:      c.GetInt("ai.batch_size"),
		},
	}
}

func (c *Config) GetStringSlice(key string) []string {
	return c.getStringSlice(key)
}

func (c *Config) getStringSlice(key string) []string {
	value := c.Get(key)
	if value == nil {
		return []string{}
	}

	switch v := value.(type) {
	case []string:
		return v
	case []interface{}:
		var result []string
		for _, item := range v {
			result = append(result, fmt.Sprintf("%v", item))
		}
		return result
	case string:
		return strings.Split(v, ",")
	}
	return []string{}
}

func (c *Config) GetBoolWithDefault(key string, defaultValue bool) bool {
	if val := c.GetBool(key); val {
		return val
	}
	return defaultValue
}

func (c *Config) GetFloat64(key string) float64 {
	value := c.Get(key)
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func (c *Config) GetInt64(key string) int64 {
	value := c.Get(key)
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// Validation methods
func (c *Config) Validate() error {
	required := []string{
		"database.host", "database.user", "database.name",
		"server.port", "security.jwt_secret",
	}

	for _, key := range required {
		if c.Get(key) == nil {
			return fmt.Errorf("required configuration missing: %s", key)
		}
	}

	// Validate ports
	if port := c.GetInt("server.port"); port < 1 || port > 65535 {
		return fmt.Errorf("invalid server port: %d", port)
	}

	return nil
}

// Save current configuration to file
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Create(c.filePath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(c.GetAppConfig()); err != nil {
		return fmt.Errorf("failed to encode config: %v", err)
	}

	c.lastModified = time.Now()
	log.Println("💾 Configuration saved to file")
	return nil
}
