package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ProxyMode represents the deployment mode
type ProxyMode string

const (
	ModeReverseProxy ProxyMode = "reverse_proxy"
	ModeInline       ProxyMode = "inline"
	ModeAPI          ProxyMode = "api"
	ModeSaaS         ProxyMode = "saas"
)

// ReverseProxyConfig holds configuration for reverse proxy
type ReverseProxyConfig struct {
	BackendURL      string            `json:"backend_url"`
	BackendHost     string            `json:"backend_host"`
	PreserveHost    bool              `json:"preserve_host"`
	FlushInterval   time.Duration     `json:"flush_interval"`
	Timeout         time.Duration     `json:"timeout"`
	MaxIdleConns    int               `json:"max_idle_conns"`
	MaxIdlePerHost  int               `json:"max_idle_per_host"`
	IdleConnTimeout time.Duration     `json:"idle_conn_timeout"`
	Headers         map[string]string `json:"headers"`
	SSLVerify       bool              `json:"ssl_verify"`
	RetryAttempts   int               `json:"retry_attempts"`
	HealthCheckURL  string            `json:"health_check_url"`
}

// ReverseProxy manages reverse proxy operations
type ReverseProxy struct {
	config      *ReverseProxyConfig
	proxy       *httputil.ReverseProxy
	transport   *http.Transport
	mu          sync.RWMutex
	backendURL  *url.URL
	healthCheck *HealthChecker
}

// HealthChecker monitors backend health
type HealthChecker struct {
	url        string
	interval   time.Duration
	healthy    bool
	lastCheck  time.Time
	mu         sync.RWMutex
	httpClient *http.Client
}

// NewReverseProxy creates a new reverse proxy instance
func NewReverseProxy(config *ReverseProxyConfig) (*ReverseProxy, error) {
	backendURL, err := url.Parse(config.BackendURL)
	if err != nil {
		return nil, err
	}

	// Create custom transport with connection pooling
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdlePerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   false,
	}

	// Configure TLS
	if !config.SSLVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	// Create reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Update scheme and host
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host

			// Preserve or set host header
			if config.PreserveHost {
				req.Host = req.Header.Get("Host")
			} else {
				req.Host = config.BackendHost
				req.Header.Set("Host", config.BackendHost)
			}

			// Add custom headers
			for key, value := range config.Headers {
				req.Header.Set(key, value)
			}

			// Add X-Forwarded-* headers
			req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-For", getClientIP(req))
			req.Header.Set("X-Real-IP", getClientIP(req))
			req.Header.Set("X-Forwarded-Port", getPort(req))

			// Add WAF identification
			req.Header.Set("X-Zein-WAF", "v5.0")
			req.Header.Set("X-Zein-WAF-Mode", "reverse_proxy")
		},
		Transport:     transport,
		FlushInterval: config.FlushInterval,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("❌ Reverse proxy error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error": "Backend server unavailable", "message": "The backend server is not responding"}`))
		},
		ModifyResponse: func(resp *http.Response) error {
			// Add WAF headers to response
			resp.Header.Set("X-Zein-WAF", "v5.0")
			resp.Header.Set("X-Zein-WAF-Protected", "true")
			return nil
		},
	}

	// Create health checker
	healthCheck := NewHealthChecker(config.HealthCheckURL, 30*time.Second)

	rp := &ReverseProxy{
		config:      config,
		proxy:       proxy,
		transport:   transport,
		backendURL:  backendURL,
		healthCheck: healthCheck,
	}

	// Start health checking
	go healthCheck.Start()

	return rp, nil
}

// ServeHTTP handles HTTP requests and forwards them to backend
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check backend health
	if !rp.healthCheck.IsHealthy() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error": "Backend unavailable", "message": "Backend server is currently unavailable"}`))
		return
	}

	// Forward request to backend
	rp.proxy.ServeHTTP(w, r)
}

// UpdateConfig updates proxy configuration
func (rp *ReverseProxy) UpdateConfig(config *ReverseProxyConfig) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	backendURL, err := url.Parse(config.BackendURL)
	if err != nil {
		return err
	}

	rp.config = config
	rp.backendURL = backendURL
	return nil
}

// GetBackendURL returns the backend URL
func (rp *ReverseProxy) GetBackendURL() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.config.BackendURL
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(url string, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		url:      url,
		interval: interval,
		healthy:  true,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start begins health checking
func (hc *HealthChecker) Start() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for range ticker.C {
		hc.check()
	}
}

// check performs a health check
func (hc *HealthChecker) check() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	resp, err := hc.httpClient.Get(hc.url)
	if err != nil {
		hc.healthy = false
		hc.lastCheck = time.Now()
		log.Printf("⚠️ Backend health check failed: %v", err)
		return
	}
	defer resp.Body.Close()

	hc.healthy = resp.StatusCode < 500
	hc.lastCheck = time.Now()

	if !hc.healthy {
		log.Printf("⚠️ Backend unhealthy: Status %d", resp.StatusCode)
	}
}

// IsHealthy returns the current health status
func (hc *HealthChecker) IsHealthy() bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.healthy
}

// GetStatus returns health check status
func (hc *HealthChecker) GetStatus() map[string]interface{} {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return map[string]interface{}{
		"healthy":    hc.healthy,
		"last_check": hc.lastCheck,
		"url":        hc.url,
	}
}

func getPort(r *http.Request) string {
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		return host[idx+1:]
	}
	if r.TLS != nil {
		return "443"
	}
	return "80"
}
