package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ZeinSecuritySystem struct {
	config   *Config
	database *Database
	redis    *RedisClient
	auth     *AuthService
	waf      *ZeinSecurityUltimate
	monitor  *AdvancedMonitorEngine
	aiPython *AIPythonClient
	server   *http.Server
	metrics  *MetricsCollector
	// Deployment modes
	reverseProxy *ReverseProxy
	inlineMode   *InlineMode
	apiMode      *APIMode
	saasMode     *SaaSMode
	currentMode  ProxyMode
	// Advanced features
	threatIntel      *AdvancedThreatIntelligence
	botDetection     *BotDetectionEngine
	ddosMitigation   *DDoSMitigation
	dnsMode          *DNSMode
	cdn              *CDNEngine
	zeroTrust        *ZeroTrustEngine
	workers          *WorkersEngine
	// New advanced features
	trafficLearning  *TrafficLearningEngine
	asnReputation    *ASNReputationEngine
	passiveLearning  *PassiveLearningEngine
	// Enterprise features (Cloudflare Enterprise+ Level)
	edgeProtection    *EdgeProtection
	falsePositiveCtrl *FalsePositiveControl
	businessReporting *BusinessReporting
	tlsFingerprinting *TLSFingerprinting
	geolocation       *GeolocationService
}

type MetricsCollector struct {
	requestsTotal     prometheus.Counter
	requestsBlocked   prometheus.Counter
	threatsDetected   prometheus.Counter
	responseTime      prometheus.Histogram
	activeConnections prometheus.Gauge
	memoryUsage       prometheus.Gauge
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		requestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "zein_requests_total",
			Help: "Total number of requests processed",
		}),
		requestsBlocked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "zein_requests_blocked",
			Help: "Number of requests blocked by WAF",
		}),
		threatsDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "zein_threats_detected",
			Help: "Number of security threats detected",
		}),
		responseTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "zein_response_time_seconds",
			Help:    "Response time in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "zein_active_connections",
			Help: "Number of active connections",
		}),
		memoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "zein_memory_usage_bytes",
			Help: "Memory usage in bytes",
		}),
	}
}

func (m *MetricsCollector) Register() {
	prometheus.MustRegister(
		m.requestsTotal,
		m.requestsBlocked,
		m.threatsDetected,
		m.responseTime,
		m.activeConnections,
		m.memoryUsage,
	)
}

func NewZeinSecuritySystem() (*ZeinSecuritySystem, error) {
	// Load configuration
	config, err := NewConfig("config.json")
	if err != nil {
		// Create default config if file doesn't exist
		if os.IsNotExist(err) {
			config = createDefaultConfig()
			if err := config.Save(); err != nil {
				return nil, fmt.Errorf("failed to create default config: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load config: %v", err)
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %v", err)
	}

	// Initialize database
	dbConfig := config.GetAppConfig().Database
	// Force password to be correct (hardcoded to avoid config issues)
	password := "popyalena07"
	
	log.Printf("🔌 Connecting to database: host=%s port=%d user=%s dbname=%s password_length=%d", 
		dbConfig.Host, dbConfig.Port, dbConfig.User, dbConfig.Name, len(password))
	
	// Try connecting to 127.0.0.1 instead of localhost (more reliable)
	host := dbConfig.Host
	if host == "localhost" {
		host = "127.0.0.1"
	}
	
	// Use MySQL connection string format
	// Format: user:password@tcp(host:port)/dbname?parseTime=true
	connStr := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4",
		dbConfig.User, password, host, dbConfig.Port, dbConfig.Name)
	
	log.Printf("🔌 Using connection: host=%s (was: %s), format=URL", host, dbConfig.Host)

	database, err := NewDatabase(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Initialize Redis
	redisConfig := config.GetAppConfig().Redis
	redis, err := NewRedisClient(CacheConfig{
		Host:     redisConfig.Host,
		Port:     fmt.Sprintf("%d", redisConfig.Port),
		Password: redisConfig.Password,
		DB:       redisConfig.DB,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	// Initialize auth service
	auth := NewAuthService(database, redis, config.GetString("security.jwt_secret"))

	// Initialize WAF
	waf := InitZeinSecurityUltimate()
	
	// Clear all IP blocks on startup (untuk development/testing)
	// Di production, hapus baris ini atau buat conditional
	waf.ipBlockList.ClearAllBlocks()
	log.Println("🧹 Cleared all IP blocks on startup")

	// Initialize monitor
	monitor := NewAdvancedMonitorEngine()

	// Initialize AI Python client
	aiConfig := config.GetAppConfig().AI
	aiPython := NewAIPythonClient(aiConfig.PythonEndpoint)

	// Initialize metrics
	metrics := NewMetricsCollector()
	metrics.Register()

	// Initialize deployment modes
	// Reverse Proxy Mode
	reverseProxyConfig := &ReverseProxyConfig{
		BackendURL:      config.GetString("proxy.backend_url"),
		BackendHost:     config.GetString("proxy.backend_host"),
		PreserveHost:    config.GetBoolWithDefault("proxy.preserve_host", false),
		FlushInterval:   100 * time.Millisecond,
		Timeout:         30 * time.Second,
		MaxIdleConns:    100,
		MaxIdlePerHost:  10,
		IdleConnTimeout: 90 * time.Second,
		Headers:         make(map[string]string),
		SSLVerify:       config.GetBoolWithDefault("proxy.ssl_verify", true),
		RetryAttempts:   3,
		HealthCheckURL:  config.GetString("proxy.health_check_url"),
	}

	var reverseProxy *ReverseProxy
	if backendURL := reverseProxyConfig.BackendURL; backendURL != "" {
		var err error
		reverseProxy, err = NewReverseProxy(reverseProxyConfig)
		if err != nil {
			log.Printf("⚠️ Failed to initialize reverse proxy: %v", err)
		}
	}

	// Inline Mode
	inlineConfig := &InlineModeConfig{
		Enabled:          config.GetBoolWithDefault("inline.enabled", false),
		InternalNetworks: config.GetStringSlice("inline.internal_networks"),
		BypassIPs:        config.GetStringSlice("inline.bypass_ips"),
		LogOnly:          config.GetBoolWithDefault("inline.log_only", false),
		StrictMode:       config.GetBoolWithDefault("inline.strict_mode", false),
	}
	inlineMode, _ := NewInlineMode(inlineConfig)

	// API Mode
	apiConfig := &APIModeConfig{
		Enabled:        config.GetBoolWithDefault("api.enabled", false),
		APIKeyRequired: config.GetBoolWithDefault("api.api_key_required", true),
		RateLimit:      make(map[string]int),
		AllowedOrigins: config.GetStringSlice("api.allowed_origins"),
		Webhooks:       make(map[string]string),
		SDKVersion:     "1.0.0",
	}
	apiMode := NewAPIMode(apiConfig)

	// SaaS Mode
	saasConfig := &SaaSConfig{
		Enabled:       config.GetBoolWithDefault("saas.enabled", false),
		DefaultPlan:   config.GetStringWithDefault("saas.default_plan", "free"),
		TrialDays:     config.GetIntWithDefault("saas.trial_days", 14),
		MultiDomain:   config.GetBoolWithDefault("saas.multi_domain", false),
		CustomDomain:  config.GetBoolWithDefault("saas.custom_domain", false),
		AutoProvision: config.GetBoolWithDefault("saas.auto_provision", false),
	}
	saasMode := NewSaaSMode(saasConfig)

	// Determine current mode
	currentMode := ModeReverseProxy
	if config.GetBoolWithDefault("saas.enabled", false) {
		currentMode = ModeSaaS
	} else if config.GetBoolWithDefault("api.enabled", false) {
		currentMode = ModeAPI
	} else if config.GetBoolWithDefault("inline.enabled", false) {
		currentMode = ModeInline
	}

	// Initialize advanced features
	threatIntel := NewAdvancedThreatIntelligence()
	botDetection := NewBotDetectionEngine()
	ddosMitigation := NewDDoSMitigation()
	
	// DNS Mode
	dnsConfig := &DNSModeConfig{
		Enabled:     config.GetBoolWithDefault("dns.enabled", false),
		DNSProvider: config.GetStringWithDefault("dns.provider", "cloudflare"),
		APIToken:    config.GetStringWithDefault("dns.api_token", ""),
		ZoneID:      config.GetStringWithDefault("dns.zone_id", ""),
		Proxied:     config.GetBoolWithDefault("dns.proxied", true),
		AutoSSL:     config.GetBoolWithDefault("dns.auto_ssl", true),
		Domains:     []*DomainConfig{},
	}
	dnsMode, _ := NewDNSMode(dnsConfig)
	
	// CDN Engine
	cdnConfig := &CDNConfig{
		Enabled:       config.GetBoolWithDefault("cdn.enabled", false),
		CacheTTL:      30 * time.Minute,
		MaxCacheSize:  100 * 1024 * 1024, // 100MB
		Compression:    config.GetBoolWithDefault("cdn.compression", true),
		Minify:         config.GetBoolWithDefault("cdn.minify", true),
		EdgeLocations:  []string{},
		PurgeOnUpdate:  config.GetBoolWithDefault("cdn.purge_on_update", true),
	}
	cdn := NewCDNEngine(cdnConfig)
	
	// Zero Trust Engine
	zeroTrust := NewZeroTrustEngine()
	
	// Workers Engine
	workers := NewWorkersEngine()

	// New advanced features
	trafficLearning := NewTrafficLearningEngine()
	asnReputation := NewASNReputationEngine()
	passiveLearning := NewPassiveLearningEngine()
	passiveLearning.EnableLearningMode() // Enable by default

	// Enterprise features (Cloudflare Enterprise+ Level)
	edgeProtection := NewEdgeProtection()
	falsePositiveCtrl := NewFalsePositiveControl()
	businessReporting := NewBusinessReporting()
	tlsFingerprinting := NewTLSFingerprinting()

	system := &ZeinSecuritySystem{
		config:         config,
		database:       database,
		redis:          redis,
		auth:           auth,
		waf:            waf,
		monitor:        monitor,
		aiPython:       aiPython,
		metrics:        metrics,
		reverseProxy:   reverseProxy,
		inlineMode:     inlineMode,
		apiMode:        apiMode,
		saasMode:       saasMode,
		currentMode:    currentMode,
		threatIntel:    threatIntel,
		botDetection:   botDetection,
		ddosMitigation: ddosMitigation,
		dnsMode:        dnsMode,
		cdn:            cdn,
		zeroTrust:      zeroTrust,
		workers:        workers,
		trafficLearning: trafficLearning,
		asnReputation:   asnReputation,
		passiveLearning: passiveLearning,
		// Enterprise features
		edgeProtection:    edgeProtection,
		falsePositiveCtrl: falsePositiveCtrl,
		businessReporting: businessReporting,
		tlsFingerprinting: tlsFingerprinting,
		geolocation:       NewGeolocationService(),
	}

	return system, nil
}

func createDefaultConfig() *Config {
	config := &Config{
		values:   make(map[string]interface{}),
		filePath: "config.json",
		watchers: make([]chan ConfigChange, 0),
	}
	
	// Set default values
	defaults := map[string]interface{}{
		"environment":                    "development",
		"database.host":                  "127.0.0.1",
		"database.port":                  3306,
		"database.user":                  "zein_waf",
		"database.password":              "popyalena07",
		"database.name":                  "zein_security",
		"database.ssl_mode":              "disable",
		"database.max_connections":       100,
		"redis.host":                     "127.0.0.1",
		"redis.port":                     6379,
		"redis.password":                 "",
		"redis.db":                       0,
		"server.host":                    "0.0.0.0",
		"server.port":                    8080,
		"server.read_timeout":            "30s",
		"server.write_timeout":           "30s",
		"server.idle_timeout":             "60s",
		"security.jwt_secret":             "your-super-secret-jwt-key-here-change-in-production",
		"security.rate_limit_requests":   100,
		"security.rate_limit_window":      "1m",
		"security.max_request_body_size":  10485760,
		"security.cors_allowed_origins":   []string{"*"},
		"logging.level":                   "info",
		"logging.format":                  "json",
		"monitoring.enabled":              true,
		"monitoring.prometheus":           true,
		"monitoring.metrics_port":        9090,
		"ai.python_endpoint":              "http://localhost:5000",
		"ai.confidence_threshold":        0.7,
		"ai.batch_size":                  32,
	}
	
	for k, v := range defaults {
		config.values[k] = v
	}
	
	config.lastModified = time.Now()
	
	log.Println("✅ Created default configuration")
	return config
}

func (z *ZeinSecuritySystem) Start() error {
	// Create router
	router := mux.NewRouter()

	// Apply basic middleware (logging, recovery, CORS)
	router.Use(z.loggingMiddleware)
	router.Use(z.recoveryMiddleware)
	router.Use(z.corsMiddleware)

	// Health checks (bypass WAF for health monitoring - register BEFORE WAF)
	router.HandleFunc("/health", z.healthHandler).Methods("GET")
	router.HandleFunc("/ready", z.readyHandler).Methods("GET")
	router.Handle("/metrics", promhttp.Handler())
	
	// WebSocket - Register BEFORE WAF middleware to ensure it's whitelisted
	router.HandleFunc("/ws/quantum", z.handleQuantumWebSocket)

	// ========================================
	// 🛡️ WAF MIDDLEWARE - SEBELUM AUTH!
	// ========================================
	// Urutan: Client → WAF → Auth → Handler → DB
	// Semua request (kecuali health checks dan auth endpoints) akan melewati WAF terlebih dahulu
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Auth endpoints: SKIP WAF sepenuhnya (CEK PERTAMA!)
			// Login/register handler sudah aman:
			// - Prepared statements (aman dari SQL injection)
			// - Bcrypt password hashing (aman)
			// - Input validation di database
			// - Tidak ada HTML output (tidak ada XSS risk)
			if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/register" {
				log.Printf("✅ WAF SKIPPED for %s from IP %s", r.URL.Path, getClientIP(r))
				// Unblock IP jika ter-block (untuk allow login attempts)
				ip := getClientIP(r)
				if z.waf.ipBlockList.IsBlocked(ip) {
					log.Printf("⚠️ IP %s was blocked, unblocking for login attempt", ip)
					z.waf.ipBlockList.UnblockIP(ip)
				}
				next.ServeHTTP(w, r)
				return
			}
			
			// Whitelist: Skip WAF untuk health checks, metrics, WebSocket, dan AI endpoints
			whitelistPaths := []string{
				"/health",
				"/ready",
				"/metrics",
				"/install",
				"/api/install",
				"/api/quantum/ai-chat",  // AI chat endpoint - skip WAF
				"/ws/quantum",           // WebSocket endpoint - skip WAF
				"/ws/",                  // All WebSocket endpoints
			}
			
			// Check if path is whitelisted (exact match or prefix match for WebSocket)
			isWhitelisted := false
			for _, whitelistPath := range whitelistPaths {
				if r.URL.Path == whitelistPath || (whitelistPath == "/ws/" && strings.HasPrefix(r.URL.Path, "/ws/")) {
					isWhitelisted = true
					break
				}
			}
			
			if isWhitelisted {
				log.Printf("✅ WAF SKIPPED (whitelist) for %s from IP %s", r.URL.Path, getClientIP(r))
				next.ServeHTTP(w, r)
				return
			}
			
			// Semua request lain melewati WAF dengan mode penuh + advanced features
			log.Printf("🛡️ WAF checking %s from IP %s", r.URL.Path, getClientIP(r))
			
			// Enhanced WAF middleware dengan semua fitur advanced
			z.enhancedWAFMiddleware(next).ServeHTTP(w, r)
		})
	})

	// Installer route (public, before auth, but after WAF)
	router.HandleFunc("/install", z.installHandler).Methods("GET", "POST")
	router.HandleFunc("/api/install", z.installHandler).Methods("POST")

	// API routes (semua melewati WAF terlebih dahulu)
	api := router.PathPrefix("/api").Subrouter()

	// Public routes (WAF sudah di level router, jadi semua request sudah di-scan)
	api.HandleFunc("/auth/login", z.loginHandler).Methods("POST")
	api.HandleFunc("/auth/register", z.registerHandler).Methods("POST")

	// Protected routes (WAF → Auth → Handler)
	protected := api.PathPrefix("").Subrouter()
	protected.Use(z.auth.Middleware("user"))

	protected.HandleFunc("/quantum/stats", z.getQuantumStats).Methods("GET")
	protected.HandleFunc("/quantum/logs", z.getQuantumLogs).Methods("GET")
	protected.HandleFunc("/quantum/attackers", z.getQuantumAttackers).Methods("GET")
	protected.HandleFunc("/quantum/config", z.getWebConfig).Methods("GET")
	protected.HandleFunc("/quantum/config", z.updateWebConfig).Methods("POST")
	protected.HandleFunc("/quantum/ai-chat", z.handleAIChat).Methods("POST")

	// Admin routes
	admin := api.PathPrefix("/admin").Subrouter()
	admin.Use(z.auth.Middleware("admin"))

	admin.HandleFunc("/users", z.getUsers).Methods("GET")
	admin.HandleFunc("/users", z.createUser).Methods("POST")
	admin.HandleFunc("/system/metrics", z.getSystemMetrics).Methods("GET")
	admin.HandleFunc("/ip-blocks", z.getBlockedIPs).Methods("GET")
	admin.HandleFunc("/ip-blocks", z.blockIP).Methods("POST")
	admin.HandleFunc("/ip-blocks/{ip}", z.unblockIP).Methods("DELETE")

	// Log analysis endpoint
	protected.HandleFunc("/quantum/analyze-logs", z.analyzeLogs).Methods("POST")

	// Mode configuration endpoints
	protected.HandleFunc("/mode/config", z.getModeConfig).Methods("GET")
	protected.HandleFunc("/mode/reverse-proxy", z.updateReverseProxyConfig).Methods("POST")
	protected.HandleFunc("/mode/inline", z.updateInlineConfig).Methods("POST")
	protected.HandleFunc("/mode/api", z.updateAPIConfig).Methods("POST")

	// SaaS endpoints
	protected.HandleFunc("/saas/tenants", z.getTenants).Methods("GET")
	protected.HandleFunc("/saas/tenants", z.createTenant).Methods("POST")

	// Advanced features endpoints
	protected.HandleFunc("/threat-intel/stats", z.getThreatIntelStats).Methods("GET")
	protected.HandleFunc("/bot-detection/stats", z.getBotDetectionStats).Methods("GET")
	protected.HandleFunc("/ddos/stats", z.getDDoSStats).Methods("GET")
	protected.HandleFunc("/dns/domains", z.getDNSDomains).Methods("GET")
	protected.HandleFunc("/dns/domains", z.addDNSDomain).Methods("POST")
	protected.HandleFunc("/cdn/stats", z.getCDNStats).Methods("GET")
	protected.HandleFunc("/cdn/purge", z.purgeCDN).Methods("POST")
	protected.HandleFunc("/zero-trust/stats", z.getZeroTrustStats).Methods("GET")
	protected.HandleFunc("/workers", z.getWorkers).Methods("GET")
	protected.HandleFunc("/workers", z.createWorker).Methods("POST")
	
	// Geolocation endpoints (multiple paths for compatibility)
	protected.HandleFunc("/geolocation/ips", z.getIPLocations).Methods("GET")
	protected.HandleFunc("/quantum/geolocation/ips", z.getIPLocations).Methods("GET")
	protected.HandleFunc("/geolocation/attackers", z.getAttackersByLocation).Methods("GET")
	
	// New advanced features endpoints
	protected.HandleFunc("/traffic-learning/stats", z.getTrafficLearningStats).Methods("GET")
	protected.HandleFunc("/asn-reputation/stats", z.getASNReputationStats).Methods("GET")
	protected.HandleFunc("/passive-learning/stats", z.getPassiveLearningStats).Methods("GET")
	protected.HandleFunc("/passive-learning/recommendations", z.getPassiveLearningRecommendations).Methods("GET")
	protected.HandleFunc("/passive-learning/mode", z.togglePassiveLearningMode).Methods("POST")

	// WAF protected routes with mode support
	wafProtected := router.PathPrefix("").Subrouter()

	// Apply advanced features middleware (order matters!)
	if z.ddosMitigation != nil {
		wafProtected.Use(z.ddosMitigation.Middleware) // DDoS protection first
	}
	if z.cdn != nil {
		wafProtected.Use(z.cdn.Middleware) // CDN caching
	}
	if z.zeroTrust != nil {
		wafProtected.Use(z.zeroTrust.Middleware) // Zero Trust (if enabled)
	}

	// Apply mode-specific middleware
	if z.currentMode == ModeSaaS && z.saasMode != nil {
		wafProtected.Use(z.saasMode.Middleware)
	}
	if z.currentMode == ModeAPI && z.apiMode != nil {
		wafProtected.Use(z.apiMode.Middleware)
	}
	if z.inlineMode != nil {
		wafProtected.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				z.inlineMode.HandleRequest(w, r, next.ServeHTTP)
			})
		})
	}
	if z.dnsMode != nil && z.dnsMode.config.Enabled {
		wafProtected.Use(z.dnsMode.Middleware)
	}
	if z.workers != nil {
		wafProtected.Use(z.workers.Middleware) // Workers for custom logic
	}

	// Apply WAF middleware with advanced features
	wafProtected.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)

			// Advanced threat intelligence
			if z.threatIntel != nil {
				headers := make(map[string]string)
				for k, v := range r.Header {
					if len(v) > 0 {
						headers[k] = v[0]
					}
				}
				analysis := z.threatIntel.AnalyzeRequest(ip, r.UserAgent(), r.URL.Path, r.Method, headers)
				if analysis.IsThreat && analysis.ThreatScore > 0.8 {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf(`{"error": "Threat detected", "score": %.2f}`, analysis.ThreatScore)))
					return
				}
			}

			// Bot detection
			if z.botDetection != nil {
				sessionID := r.Header.Get("X-Session-ID")
				if sessionID == "" {
					sessionID = r.URL.Query().Get("session_id")
				}
				botAnalysis := z.botDetection.AnalyzeRequest(ip, r.UserAgent(), sessionID, time.Now(), nil)
				if botAnalysis.IsBot && botAnalysis.Confidence > 0.7 {
					w.Header().Set("X-Bot-Detected", "true")
					if botAnalysis.Confidence > 0.9 {
						w.WriteHeader(http.StatusForbidden)
						w.Write([]byte(`{"error": "Bot detected"}`))
						return
					}
				}
			}

			// WAF middleware
			z.waf.WAFMiddleware(next).ServeHTTP(w, r)

			// Workers after request
			if z.workers != nil {
				z.workers.TriggerWorkers("http_response", r, nil)
			}
		})
	})

	// Reverse proxy handler (if enabled)
	if z.currentMode == ModeReverseProxy && z.reverseProxy != nil {
		// Catch-all route for reverse proxy
		wafProtected.PathPrefix("/").Handler(z.reverseProxy)
	}

	// Demo applications
	wafProtected.HandleFunc("/api/login", z.demoLogin).Methods("POST")
	wafProtected.HandleFunc("/api/data", z.demoAPI).Methods("GET")

	// Start server
	serverConfig := z.config.GetAppConfig().Server
	z.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port),
		Handler:      router,
		ReadTimeout:  serverConfig.ReadTimeout,
		WriteTimeout: serverConfig.WriteTimeout,
		IdleTimeout:  serverConfig.IdleTimeout,
	}

	// Start background tasks
	go z.startBackgroundTasks()

	log.Printf("🚀 Zein Security WAF Quantum v5.0 starting on %s", z.server.Addr)
	log.Printf("📊 Dashboard: http://%s", z.server.Addr)
	log.Printf("🔌 WebSocket: ws://%s/ws/quantum", z.server.Addr)
	log.Printf("📈 Metrics: http://%s/metrics", z.server.Addr)

	// Start server in goroutine
	go func() {
		if err := z.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server failed: %v", err)
		}
	}()

	return z.waitForShutdown()
}

func (z *ZeinSecuritySystem) startBackgroundTasks() {
	// Configuration watcher
	go z.watchConfigChanges()

	// Metrics collector
	go z.collectMetrics()

	// Database maintenance
	go z.runDatabaseMaintenance()

	// Threat intelligence updates
	go z.updateThreatIntelligence()

	// System health monitoring
	go z.monitorSystemHealth()
}

func (z *ZeinSecuritySystem) watchConfigChanges() {
	watcher := z.config.Watch()
	for change := range watcher {
		log.Printf("⚙️ Configuration changed: %s = %v", change.Key, change.New)

		// Handle specific config changes
		switch change.Key {
		case "security.rate_limit_requests":
			// Update rate limiting settings
		case "ai.confidence_threshold":
			// Update AI settings
		}
	}
}

func (z *ZeinSecuritySystem) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update Prometheus metrics
		stats := z.monitor.GetStats()
		z.metrics.requestsTotal.Add(float64(stats.TotalRequests))
		z.metrics.requestsBlocked.Add(float64(stats.BlockedRequests))
		z.metrics.threatsDetected.Add(float64(stats.ThreatActors))

		// Collect system metrics
		z.collectSystemMetrics()
	}
}

func (z *ZeinSecuritySystem) collectSystemMetrics() {
	// Collect memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	z.metrics.memoryUsage.Set(float64(memStats.Alloc))

	// Save to database for historical tracking
	z.database.SaveSystemMetric("memory_usage", float64(memStats.Alloc))
	z.database.SaveSystemMetric("goroutines", float64(runtime.NumGoroutine()))
}

func (z *ZeinSecuritySystem) runDatabaseMaintenance() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Perform database backup
		if err := z.database.PerformBackup(); err != nil {
			log.Printf("❌ Database backup failed: %v", err)
		}

		// Cleanup old data (keep 90 days)
		if err := z.database.CleanupOldData(90); err != nil {
			log.Printf("❌ Data cleanup failed: %v", err)
		}
	}
}

func (z *ZeinSecuritySystem) updateThreatIntelligence() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("🔄 Updating threat intelligence...")

		// This would integrate with external threat feeds
		// For now, we'll simulate updates
		z.updateFromExternalFeeds()
	}
}

func (z *ZeinSecuritySystem) updateFromExternalFeeds() {
	// Simulate threat intelligence updates
	threats := []struct {
		ip          string
		threatType  string
		description string
	}{
		{"192.168.1.100", "MALWARE", "Known malware distribution node"},
		{"10.0.0.50", "BOTNET", "Botnet command and control server"},
		{"172.16.0.25", "SCANNER", "Aggressive port scanning activity"},
	}

	for _, threat := range threats {
		z.database.AddThreatIntelligence(
			threat.ip,
			threat.threatType,
			"external_feed",
			threat.description,
			0.85,
		)
	}
}

func (z *ZeinSecuritySystem) monitorSystemHealth() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Check database connection
		if err := z.database.Ping(); err != nil {
			log.Printf("❌ Database health check failed: %v", err)
			z.monitor.AddAlert(AdvancedAlert{
				Severity: "HIGH",
				Type:     "SYSTEM_HEALTH",
				Message:  "Database connection unstable",
			})
		}

		// Check Redis connection
		if err := z.redis.Health(); err != nil {
			log.Printf("❌ Redis health check failed: %v", err)
			z.monitor.AddAlert(AdvancedAlert{
				Severity: "HIGH",
				Type:     "SYSTEM_HEALTH",
				Message:  "Redis connection unstable",
			})
		}

		// Check AI service
		if _, err := z.aiPython.Health(); err != nil {
			log.Printf("❌ AI service health check failed: %v", err)
			z.monitor.AddAlert(AdvancedAlert{
				Severity: "MEDIUM",
				Type:     "SYSTEM_HEALTH",
				Message:  "AI service unavailable",
			})
		}
	}
}

func (z *ZeinSecuritySystem) waitForShutdown() error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down Zein Security System...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := z.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	// Close connections
	z.redis.Close()
	z.database.Close()

	log.Println("✅ Zein Security System stopped gracefully")
	return nil
}

// enhancedWAFMiddleware - WAF dengan semua fitur advanced terintegrasi
func (z *ZeinSecuritySystem) enhancedWAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		userAgent := r.UserAgent()
		path := r.URL.Path
		method := r.Method

		// WHITELIST: Skip WAF untuk internal/API endpoints yang aman
		internalPaths := []string{
			"/api/quantum/stats",
			"/api/quantum/logs",
			"/api/quantum/attackers",
			"/api/quantum/threats",
			"/api/quantum/performance",
			"/api/quantum/config",
			"/api/quantum/ai-chat",
			"/api/quantum/geolocation",
			"/api/geolocation",
			"/api/quantum/traffic-learning",
			"/api/quantum/asn-reputation",
			"/api/quantum/passive-learning",
			"/api/quantum/business",
			"/api/quantum/false-positive",
			"/ws/quantum",
			"/ws/",
			"/health",
			"/ready",
			"/metrics",
			"/install",
			"/api/install",
		}
		
		isInternalEndpoint := false
		for _, internalPath := range internalPaths {
			if path == internalPath || strings.HasPrefix(path, internalPath) {
				isInternalEndpoint = true
				break
			}
		}
		
		if isInternalEndpoint {
			log.Printf("✅ WAF SKIPPED (Internal): %s from IP %s", path, ip)
			next.ServeHTTP(w, r)
			return
		}
		
		// Skip advanced checks untuk AI endpoints (sudah di-whitelist, tapi double-check)
		isAIEndpoint := path == "/api/quantum/ai-chat"
		
		// 1. ADAPTIVE RATE LIMIT & LAYER-7 DDOS - Check adaptive rate limits
		if !isAIEndpoint && z.ddosMitigation != nil {
			ddosResponse := z.ddosMitigation.AnalyzeRequest(ip, r)
			if ddosResponse.Blocked {
				log.Printf("🚫 DDoS protection blocked: %s from %s - %s", path, ip, ddosResponse.Reason)
				z.monitor.IncrementBlocked()
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`<!DOCTYPE html><html><head><title>429 Too Many Requests</title></head><body><h1>429 Too Many Requests</h1><p>Rate limit exceeded. Please try again later.</p></body></html>`))
				return
			}
		}
		
		// 1.5. ASN Reputation Check (skip untuk AI endpoints)
		if !isAIEndpoint && z.asnReputation != nil {
			ipRep, isKnownThreat := z.asnReputation.GetIPReputation(ip)
			
			if isKnownThreat {
				log.Printf("🚫 Known threat IP: %s (Reputation: %.2f)", ip, ipRep)
				// Save to database
				z.saveSecurityEvent(r, ip, "KNOWN_THREAT", 0.9, "HIGH", true, map[string]interface{}{
					"reputation_score": ipRep,
					"reason": "IP flagged in reputation database",
				})
				z.monitor.IncrementBlocked()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "IP address flagged in reputation database",
					"reputation_score": ipRep,
				})
				return
			}
		}

		// 2. BOT MANAGEMENT - Advanced bot detection (Header fingerprint, Browser consistency, JS challenge, Non-human behavior)
		if !isAIEndpoint && z.botDetection != nil {
			sessionID := r.Header.Get("X-Session-ID")
			if sessionID == "" {
				sessionID = r.URL.Query().Get("session_id")
			}
			if sessionID == "" {
				// Generate session ID for tracking
				sessionID = generateSessionID()
			}
			
			behavioralData := map[string]interface{}{
				"headers": r.Header,
				"path":    path,
				"method":  method,
			}
			
			botAnalysis := z.botDetection.AnalyzeRequest(ip, userAgent, sessionID, time.Now(), behavioralData)
			if botAnalysis.IsBot && botAnalysis.Confidence > 0.7 {
				log.Printf("🤖 Bot detected: %s from %s (Confidence: %.2f, Type: %s)", path, ip, botAnalysis.Confidence, botAnalysis.BotType)
				z.monitor.IncrementBlocked()
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Bot detected. Access denied.</p></body></html>`))
				return
			}
		}
		
		// 2.5. Traffic Learning - Check learned patterns (skip untuk AI endpoints)
		patternThreatScore := 0.0
		if !isAIEndpoint && z.trafficLearning != nil {
			patternScore, hasPattern := z.trafficLearning.GetPatternScore(ip, userAgent, path, method)
			if hasPattern && patternScore > 0.7 {
				log.Printf("⚠️ Suspicious pattern detected: %s (Score: %.2f)", path, patternScore)
				patternThreatScore = patternScore
			}
		}

		// 3. Pre-analyze request untuk detect threats (sebelum WAF block)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		
		// Analyze request menggunakan WAF methods (akan dibuat public atau wrapper)
		var detectedThreats []DetectedThreat
		var finalThreatScore float64
		
		// Create temporary request copy for analysis
		rCopy := r
		if len(bodyBytes) > 0 {
			rCopy.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		
		// Analyze request menggunakan WAF public methods (skip untuk AI endpoints)
		if !isAIEndpoint {
			detectedThreats = z.waf.AnalyzeRequest(rCopy, bodyBytes)
			if len(detectedThreats) > 0 {
				finalThreatScore = z.waf.CalculateThreatScore(detectedThreats)
			}
			
			// Add pattern threat score
			if patternThreatScore > 0 {
				if patternThreatScore > finalThreatScore {
					finalThreatScore = patternThreatScore
				}
			}
			
			// FALSE POSITIVE CONTROL - Check if detection is false positive
			if z.falsePositiveCtrl != nil && len(detectedThreats) > 0 {
				context := map[string]interface{}{
					"ip":        ip,
					"path":      path,
					"method":    method,
					"user_agent": userAgent,
					"threats":   detectedThreats,
				}
				if z.falsePositiveCtrl.AnalyzeFalsePositive(detectedThreats[0].AttackType, detectedThreats[0].Pattern, context) {
					log.Printf("✅ False positive detected, allowing: %s", detectedThreats[0].AttackType)
					// Allow request but log for learning
					z.falsePositiveCtrl.UpdatePatternModel(detectedThreats[0].Pattern, false)
					detectedThreats = []DetectedThreat{} // Clear threats
					finalThreatScore = 0
				} else {
					z.falsePositiveCtrl.UpdatePatternModel(detectedThreats[0].Pattern, true)
				}
			}
		}
		
		// 4. Save security event to database SEBELUM WAF block (jika ada threats)
		// Skip untuk AI endpoints
		if !isAIEndpoint && len(detectedThreats) > 0 {
			attackType := detectedThreats[0].AttackType
			severity := detectedThreats[0].Severity
			if severity == "" {
				severity = "MEDIUM"
			}
			
			// Normalize attack type untuk mapping yang benar
			normalizedAttackType := z.normalizeAttackType(attackType)
			
			details := map[string]interface{}{
				"threats": detectedThreats,
				"threat_count": len(detectedThreats),
				"pattern_score": patternThreatScore,
				"asn_reputation": z.asnReputation != nil,
				"original_attack_type": attackType,
			}
			
			// Save event SEBELUM WAF block
			z.saveSecurityEvent(r, ip, normalizedAttackType, finalThreatScore, severity, false, details)
		} else if patternThreatScore > 0 {
			// Save pattern-based threat
			z.saveSecurityEvent(r, ip, "SUSPICIOUS_PATTERN", patternThreatScore, "MEDIUM", false, map[string]interface{}{
				"pattern_score": patternThreatScore,
				"source": "traffic_learning",
			})
		}
		
		// 5. WAF Analysis dengan enhanced logging (skip untuk AI endpoints)
		var wasBlocked bool
		
		// Skip WAF untuk AI endpoints
		if isAIEndpoint {
			log.Printf("✅ AI endpoint detected, skipping WAF for %s", path)
			z.monitor.IncrementRequest()
			next.ServeHTTP(w, r)
			return
		}
		
		// LEVEL DEWA: Block immediately jika ada threats terdeteksi (sebelum WAF middleware)
		if !isAIEndpoint && len(detectedThreats) > 0 {
			// Calculate final threat score
			calculatedScore := finalThreatScore
			if calculatedScore == 0 {
				calculatedScore = z.waf.CalculateThreatScore(detectedThreats)
			}
			
			// LEVEL DEWA: Block immediately untuk ANY threat (ZERO TOLERANCE)
			attackType := detectedThreats[0].AttackType
			severity := detectedThreats[0].Severity
			if severity == "" {
				severity = "CRITICAL" // Default ke CRITICAL untuk level dewa
			}
			
			normalizedAttackType := z.normalizeAttackType(attackType)
			
			// 🤖 AI ANALYSIS: Analisis serangan dengan AI untuk konfirmasi dan klasifikasi
			aiAttackType := normalizedAttackType
			aiConfidence := 0.9
			if z.aiPython != nil {
				// Prepare request data untuk AI analysis
				requestData := map[string]interface{}{
					"method":      method,
					"path":        path,
					"query":       r.URL.RawQuery,
					"headers":     r.Header,
					"body":        string(bodyBytes),
					"threats":     detectedThreats,
					"threat_score": calculatedScore,
				}
				
				// Analisis dengan AI
				aiAnalysis, err := z.aiPython.AnalyzeThreat(requestData, ip, userAgent)
				if err == nil && aiAnalysis != nil {
					// Gunakan hasil AI analysis jika lebih akurat
					if aiAnalysis.ThreatDetected {
						// AI mendeteksi attack types
						if len(aiAnalysis.DetectedAttacks) > 0 {
							// Gunakan attack type dari AI
							aiDetectedType := aiAnalysis.DetectedAttacks[0]
							// Normalize AI detected type
							switch {
							case contains(aiDetectedType, "XSS") || contains(aiDetectedType, "Cross-Site Scripting"):
								aiAttackType = "XSS"
							case contains(aiDetectedType, "SQL") || contains(aiDetectedType, "Injection"):
								aiAttackType = "SQL_INJECTION"
							case contains(aiDetectedType, "Path Traversal") || contains(aiDetectedType, "Directory"):
								aiAttackType = "PATH_TRAVERSAL"
							case contains(aiDetectedType, "Command") || contains(aiDetectedType, "RCE"):
								aiAttackType = "COMMAND_INJECTION"
							case contains(aiDetectedType, "XXE") || contains(aiDetectedType, "XML"):
								aiAttackType = "XXE"
							case contains(aiDetectedType, "Deserialization"):
								aiAttackType = "DESERIALIZATION"
							}
						}
						aiConfidence = aiAnalysis.Confidence
						log.Printf("🤖 AI Analysis: %s (Confidence: %.2f, Score: %.2f)", aiAttackType, aiConfidence, aiAnalysis.ThreatScore)
					}
				} else {
					log.Printf("⚠️ AI analysis failed: %v, using WAF detection", err)
				}
			}
			
			// Gunakan AI attack type jika lebih akurat, fallback ke WAF detection
			finalAttackType := aiAttackType
			if aiConfidence < 0.7 {
				finalAttackType = normalizedAttackType
			}
			
			// Block IP immediately (LEVEL DEWA - tidak peduli confidence)
			z.waf.ipBlockList.BlockIP(ip, detectedThreats[0].Description, finalAttackType, calculatedScore, z.waf.config.BlockDuration)
			
			// Save to database dengan blocked=true dan AI analysis
			details := map[string]interface{}{
				"threats": detectedThreats,
				"threat_count": len(detectedThreats),
				"pattern_score": patternThreatScore,
				"asn_reputation": z.asnReputation != nil,
				"original_attack_type": attackType,
				"ai_attack_type": aiAttackType,
				"ai_confidence": aiConfidence,
				"final_attack_type": finalAttackType,
				"blocked_reason": "LEVEL_DEWA_ZERO_TOLERANCE",
			}
			z.saveSecurityEvent(r, ip, finalAttackType, calculatedScore, severity, true, details)
			
			// Update monitor dengan attack type yang benar (dari AI atau WAF)
			z.updateMonitorWithAttackType(finalAttackType)
			
			// Update monitor
			z.monitor.IncrementBlocked()
			
			// Send block response (CLOUDFLARE-STYLE: Show IP and timestamp)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Zein-WAF-Blocked", "true")
			w.WriteHeader(http.StatusForbidden)
			
			// Cloudflare-style block page dengan IP dan timestamp
			blockPage := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden | Zein Security</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: #333;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%%;
            padding: 40px;
            text-align: center;
        }
        .logo {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 20px;
            letter-spacing: 2px;
        }
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 28px;
            color: #2d3748;
            margin-bottom: 16px;
        }
        .message {
            font-size: 16px;
            color: #4a5568;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        .info-box {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }
        .info-row:last-child {
            border-bottom: none;
        }
        .info-label {
            font-weight: 600;
            color: #2d3748;
        }
        .info-value {
            color: #4a5568;
            font-family: 'Courier New', monospace;
        }
        .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #718096;
        }
        .request-id {
            font-size: 12px;
            color: #a0aec0;
            margin-top: 20px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️ ZEIN SECURITY</div>
        <div class="icon">🚫</div>
        <h1>403 Forbidden</h1>
        <p class="message">Your request has been blocked by Zein Security WAF.<br>Access to this resource is denied.</p>
        
        <div class="info-box">
            <div class="info-row">
                <span class="info-label">Your IP Address:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Blocked At:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Request ID:</span>
                <span class="info-value">%s</span>
            </div>
        </div>
        
        <div class="footer">
            <p>If you believe this is an error, please contact the site administrator.</p>
            <p style="margin-top: 10px;"><strong>Zein Security WAF</strong> - Advanced Threat Protection</p>
        </div>
        
        <div class="request-id">Request ID: %s</div>
    </div>
</body>
</html>`, ip, time.Now().Format("2006-01-02 15:04:05 MST"), generateRequestID(r), generateRequestID(r))
			
			w.Write([]byte(blockPage))
			
			log.Printf("🚫 BLOCKED (LEVEL DEWA): %s from %s - %s (Score: %.2f, AI: %.2f)", path, ip, finalAttackType, calculatedScore, aiConfidence)
			return
		}
		
		// Capture response
		responseWriter := &responseCapture{ResponseWriter: w, statusCode: 200}
		
		// WAF middleware dengan callback
		wafHandler := z.waf.WAFMiddleware(http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
			// Request passed WAF
			z.monitor.IncrementRequest()
			responseWriter.statusCode = 200
			next.ServeHTTP(w2, r2)
		}))
		
		wafHandler.ServeHTTP(responseWriter, r)
		
		// Check if blocked
		if responseWriter.statusCode == 403 {
			wasBlocked = true
			z.monitor.IncrementBlocked()
			
			// Update event di database jika blocked (update blocked flag)
			if len(detectedThreats) > 0 {
				normalizedAttackType := z.normalizeAttackType(detectedThreats[0].AttackType)
				z.updateEventBlockedStatus(ip, normalizedAttackType, wasBlocked)
			}
		}

		// 6. Track geolocation for ALL requests (REAL DATA ONLY - NO FAKE DATA)
		if !isInternalEndpoint && !isAIEndpoint && z.geolocation != nil {
			// Track in background to avoid blocking request
			go func(currentIP string, currentThreats []DetectedThreat, currentScore float64, blocked bool) {
				// Always try to get/update REAL location for tracking
				location, err := z.geolocation.GetLocation(currentIP)
				if err != nil {
					// Retry once after short delay
					time.Sleep(2 * time.Second)
					location, err = z.geolocation.GetLocation(currentIP)
					if err != nil {
						log.Printf("⚠️ Geolocation fetch failed for %s after retry: %v (will retry on next request)", currentIP, err)
						return
					}
				}
				
				if location != nil {
					attackCount := int64(0)
					if blocked && len(currentThreats) > 0 {
						attackCount = 1
					}
					z.geolocation.UpdateLocation(currentIP, attackCount, currentScore)
					log.Printf("📍 REAL Geolocation tracked: %s -> %s, %s, %s (Lat: %.4f, Lon: %.4f, Attacks: %d, Requests: %d, ISP: %s)", 
						currentIP, location.City, location.Region, location.Country, 
						location.Latitude, location.Longitude, attackCount, location.RequestCount, location.ISP)
				}
			}(ip, detectedThreats, finalThreatScore, wasBlocked)
		}

		// 7. Learn from request (Traffic Learning & Passive Learning)
		if z.trafficLearning != nil {
			z.trafficLearning.LearnFromRequest(ip, userAgent, path, method, finalThreatScore, wasBlocked)
		}
		
		if z.passiveLearning != nil && z.passiveLearning.learningMode {
			z.passiveLearning.LearnFromRequest(ip, userAgent, path, method, finalThreatScore, wasBlocked)
		}

		// 7. Update ASN Reputation
		if z.asnReputation != nil {
			attackType := "request"
			if wasBlocked {
				if len(detectedThreats) > 0 {
					attackType = detectedThreats[0].AttackType
				} else {
					attackType = "BLOCKED"
				}
			}
			z.asnReputation.UpdateIPReputation(ip, finalThreatScore, attackType, wasBlocked)
		}
	})
}

// normalizeAttackType - Normalize attack type untuk mapping yang konsisten
func (z *ZeinSecuritySystem) normalizeAttackType(attackType string) string {
	// Normalize OWASP attack types ke format yang lebih sederhana untuk mapping
	switch attackType {
	case "A01:2021-Injection":
		return "SQL_INJECTION"
	case "A07:2021-Cross-Site Scripting":
		return "XSS"
	case "A05:2021-Broken Access Control":
		return "PATH_TRAVERSAL"
	case "A04:2021-XML External Entities":
		return "XXE"
	case "A08:2021-Insecure Deserialization":
		return "DESERIALIZATION"
	case "A02:2021-Broken Authentication":
		return "BRUTE_FORCE"
	default:
		return attackType
	}
}

// updateEventBlockedStatus - Update blocked status untuk event terbaru
func (z *ZeinSecuritySystem) updateEventBlockedStatus(ip, eventType string, blocked bool) {
	query := `
		UPDATE security_events 
		SET blocked = ?
		WHERE ip_address = ? 
		  AND event_type = ?
		  AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)
		ORDER BY timestamp DESC
		LIMIT 1
	`
	_, err := z.database.Exec(query, blocked, ip, eventType)
	if err != nil {
		log.Printf("⚠️ Failed to update event blocked status: %v", err)
	}
}

// saveSecurityEvent - Save security event to database
func (z *ZeinSecuritySystem) saveSecurityEvent(r *http.Request, ip, eventType string, threatScore float64, severity string, blocked bool, details map[string]interface{}) {
	detailsJSON, _ := json.Marshal(details)
	
	// Create SecurityEvent sesuai dengan struktur database
	event := &SecurityEvent{
		EventType:     eventType,
		IPAddress:     ip,
		UserAgent:     r.UserAgent(),
		RequestMethod: r.Method,
		RequestPath:   r.URL.Path,
		RequestQuery:  r.URL.RawQuery,
		ThreatScore:   threatScore,
		Severity:      severity,
		Blocked:       blocked,
		Details:       string(detailsJSON),
		Timestamp:     time.Now(),
	}

	if err := z.database.LogSecurityEvent(event); err != nil {
		log.Printf("❌ Failed to save security event: %v (EventType: %s, IP: %s)", err, eventType, ip)
	} else {
		log.Printf("✅ Security event saved: %s from %s (Score: %.2f, Blocked: %v, Path: %s)", eventType, ip, threatScore, blocked, r.URL.Path)
	}

	// Update monitor berdasarkan attack type (SELALU update, tidak hanya jika blocked)
	z.updateMonitorWithAttackType(eventType)
}

// updateMonitorWithAttackType - Update monitor dengan attack type yang benar
func (z *ZeinSecuritySystem) updateMonitorWithAttackType(attackType string) {
	log.Printf("🔄 Updating monitor for attack type: %s", attackType)
	switch attackType {
	case "SQL_INJECTION", "A01:2021-Injection":
		z.monitor.IncrementAttack("SQL_INJECTION")
		log.Printf("✅ Incremented SQL_INJECTION in monitor")
	case "XSS", "A07:2021-Cross-Site Scripting":
		z.monitor.IncrementAttack("XSS")
		log.Printf("✅ Incremented XSS in monitor")
	case "PATH_TRAVERSAL", "A05:2021-Broken Access Control":
		z.monitor.IncrementAttack("PATH_TRAVERSAL")
		log.Printf("✅ Incremented PATH_TRAVERSAL in monitor")
	case "COMMAND_INJECTION":
		z.monitor.IncrementAttack("COMMAND_INJECTION")
		log.Printf("✅ Incremented COMMAND_INJECTION in monitor")
	case "XXE", "A04:2021-XML External Entities":
		z.monitor.IncrementAttack("XXE")
		log.Printf("✅ Incremented XXE in monitor")
	case "DESERIALIZATION", "A08:2021-Insecure Deserialization":
		z.monitor.IncrementAttack("DESERIALIZATION")
		log.Printf("✅ Incremented DESERIALIZATION in monitor")
	default:
		log.Printf("⚠️ Unknown attack type for monitor: %s", attackType)
	}
}

// contains - Helper function untuk check string contains (case-insensitive)
func contains(s, substr string) bool {
	sLower := strings.ToLower(s)
	substrLower := strings.ToLower(substr)
	return strings.Contains(sLower, substrLower)
}

func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// generateSessionID - Generate session ID

// responseCapture - Capture response status code
type responseCapture struct {
	http.ResponseWriter
	statusCode int
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

// HTTP Handlers
func (z *ZeinSecuritySystem) loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	ipAddress := getClientIP(r)
	userAgent := r.UserAgent()

	response, err := z.auth.Login(loginReq, ipAddress, userAgent)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// getQuantumStats is defined in handlers.go

func (z *ZeinSecuritySystem) handleAIChat(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Message string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Get current security context for AI
	context := map[string]interface{}{
		"current_threats": z.monitor.GetStats().ThreatActors,
		"block_rate":      z.monitor.GetStats().BlockRate,
	}

	// Use AI Python service for advanced responses
	var response string
	var err error
	if z.aiPython != nil {
		// Test connection first
		_, healthErr := z.aiPython.Health()
		if healthErr != nil {
			log.Printf("⚠️ AI service health check failed: %v, using fallback", healthErr)
			response = generateAIResponse(request.Message)
		} else {
			response, err = z.aiPython.Chat(request.Message, context)
			if err != nil {
				log.Printf("⚠️ AI service chat error: %v, using fallback", err)
				// Fallback to local AI
				response = generateAIResponse(request.Message)
			}
		}
	} else {
		log.Printf("⚠️ AI Python client not initialized, using fallback")
		response = generateAIResponse(request.Message)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"response":  response,
		"timestamp": time.Now(),
	})
}

// Middleware
func (z *ZeinSecuritySystem) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response wrapper to capture status code
		wrapped := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Log the request
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, duration)

		// Update metrics
		z.metrics.requestsTotal.Inc()
		z.metrics.responseTime.Observe(duration.Seconds())
	})
}

func (z *ZeinSecuritySystem) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("🚨 PANIC recovered: %v", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (z *ZeinSecuritySystem) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigins := z.config.GetStringSlice("security.cors_allowed_origins")
		origin := r.Header.Get("Origin")

		// If no origin header (same-origin request), allow it
		if origin == "" {
			// Allow same-origin requests
			next.ServeHTTP(w, r)
			return
		}

		// Check if origin is allowed
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}

		// Set CORS headers (browser will enforce if origin not allowed)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Response writer wrapper
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func main() {
	system, err := NewZeinSecuritySystem()
	if err != nil {
		log.Fatalf("❌ Failed to initialize Zein Security System: %v", err)
	}

	if err := system.Start(); err != nil {
		log.Fatalf("❌ Zein Security System failed: %v", err)
	}
}
