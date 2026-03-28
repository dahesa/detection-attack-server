package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// CDNEngine engine untuk CDN functionality
type CDNEngine struct {
	mu            sync.RWMutex
	cache         map[string]*CacheEntry
	edgeLocations []*EdgeLocation
	stats         *CDNStats
	config        *CDNConfig
}

// CacheEntry cache entry
type CacheEntry struct {
	Key          string
	Content      []byte
	ContentType  string
	ETag         string
	LastModified time.Time
	ExpiresAt    time.Time
	HitCount     int64
	Size         int64
}

// EdgeLocation edge location
type EdgeLocation struct {
	ID           string
	Name         string
	Region       string
	Latency      time.Duration
	IsActive     bool
	RequestCount int64
}

// CDNConfig CDN configuration
type CDNConfig struct {
	Enabled       bool
	CacheTTL      time.Duration
	MaxCacheSize  int64
	Compression   bool
	Minify        bool
	EdgeLocations []string
	PurgeOnUpdate bool
}

// CDNStats CDN statistics
type CDNStats struct {
	CacheHits     int64
	CacheMisses   int64
	TotalRequests int64
	CacheSize     int64
	HitRate       float64
}

// NewCDNEngine creates new CDN engine
func NewCDNEngine(config *CDNConfig) *CDNEngine {
	cdn := &CDNEngine{
		cache:         make(map[string]*CacheEntry),
		edgeLocations: make([]*EdgeLocation, 0),
		stats:         &CDNStats{},
		config:        config,
	}

	// Initialize edge locations
	cdn.initEdgeLocations()

	// Start cache cleanup
	go cdn.startCacheCleanup()

	return cdn
}

func (cdn *CDNEngine) initEdgeLocations() {
	locations := []struct {
		id     string
		name   string
		region string
	}{
		{"us-east", "US East", "us-east-1"},
		{"us-west", "US West", "us-west-1"},
		{"eu-west", "EU West", "eu-west-1"},
		{"asia-pac", "Asia Pacific", "ap-southeast-1"},
	}

	for _, loc := range locations {
		cdn.edgeLocations = append(cdn.edgeLocations, &EdgeLocation{
			ID:           loc.id,
			Name:         loc.name,
			Region:       loc.region,
			Latency:      10 * time.Millisecond,
			IsActive:     true,
			RequestCount: 0,
		})
	}
}

// ServeCached serves cached content
func (cdn *CDNEngine) ServeCached(w http.ResponseWriter, r *http.Request, key string) bool {
	if !cdn.config.Enabled {
		return false
	}

	cdn.mu.RLock()
	entry, exists := cdn.cache[key]
	cdn.mu.RUnlock()

	if !exists {
		cdn.stats.CacheMisses++
		return false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		cdn.mu.Lock()
		delete(cdn.cache, key)
		cdn.mu.Unlock()
		cdn.stats.CacheMisses++
		return false
	}

	// Check ETag
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if ifNoneMatch == entry.ETag {
			w.WriteHeader(http.StatusNotModified)
			cdn.stats.CacheHits++
			return true
		}
	}

	// Serve cached content
	w.Header().Set("Content-Type", entry.ContentType)
	w.Header().Set("ETag", entry.ETag)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(cdn.config.CacheTTL.Seconds())))
	w.Header().Set("X-Cache", "HIT")
	w.Header().Set("X-Cache-Key", key)

	w.Write(entry.Content)

	cdn.mu.Lock()
	entry.HitCount++
	cdn.stats.CacheHits++
	cdn.stats.TotalRequests++
	cdn.mu.Unlock()

	return true
}

// CacheResponse caches response
func (cdn *CDNEngine) CacheResponse(key string, content []byte, contentType string) {
	if !cdn.config.Enabled {
		return
	}

	cdn.mu.Lock()
	defer cdn.mu.Unlock()

	// Check cache size
	if cdn.stats.CacheSize+int64(len(content)) > cdn.config.MaxCacheSize {
		cdn.evictOldest()
	}

	// Create cache entry
	hash := md5.Sum(content)
	etag := hex.EncodeToString(hash[:])

	entry := &CacheEntry{
		Key:          key,
		Content:      content,
		ContentType:  contentType,
		ETag:         etag,
		LastModified: time.Now(),
		ExpiresAt:    time.Now().Add(cdn.config.CacheTTL),
		HitCount:     0,
		Size:         int64(len(content)),
	}

	cdn.cache[key] = entry
	cdn.stats.CacheSize += entry.Size
}

func (cdn *CDNEngine) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range cdn.cache {
		if oldestTime.IsZero() || entry.LastModified.Before(oldestTime) {
			oldestTime = entry.LastModified
			oldestKey = key
		}
	}

	if oldestKey != "" {
		entry := cdn.cache[oldestKey]
		cdn.stats.CacheSize -= entry.Size
		delete(cdn.cache, oldestKey)
	}
}

func (cdn *CDNEngine) startCacheCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cdn.cleanupExpired()
		cdn.updateStats()
	}
}

func (cdn *CDNEngine) cleanupExpired() {
	cdn.mu.Lock()
	defer cdn.mu.Unlock()

	now := time.Now()
	for key, entry := range cdn.cache {
		if now.After(entry.ExpiresAt) {
			cdn.stats.CacheSize -= entry.Size
			delete(cdn.cache, key)
		}
	}
}

func (cdn *CDNEngine) updateStats() {
	cdn.mu.RLock()
	defer cdn.mu.RUnlock()

	if cdn.stats.TotalRequests > 0 {
		cdn.stats.HitRate = float64(cdn.stats.CacheHits) / float64(cdn.stats.TotalRequests) * 100
	}
}

// PurgeCache purges cache
func (cdn *CDNEngine) PurgeCache(pattern string) int {
	cdn.mu.Lock()
	defer cdn.mu.Unlock()

	count := 0
	for key := range cdn.cache {
		if pattern == "" || key == pattern {
			entry := cdn.cache[key]
			cdn.stats.CacheSize -= entry.Size
			delete(cdn.cache, key)
			count++
		}
	}

	log.Printf("🗑️ Purged %d cache entries", count)
	return count
}

// GetStats returns CDN statistics
func (cdn *CDNEngine) GetStats() *CDNStats {
	cdn.mu.RLock()
	defer cdn.mu.RUnlock()

	return &CDNStats{
		CacheHits:     cdn.stats.CacheHits,
		CacheMisses:   cdn.stats.CacheMisses,
		TotalRequests: cdn.stats.TotalRequests,
		CacheSize:     cdn.stats.CacheSize,
		HitRate:       cdn.stats.HitRate,
	}
}

// Middleware untuk CDN
func (cdn *CDNEngine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cdn.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Generate cache key
		cacheKey := cdn.generateCacheKey(r)

		// Try to serve from cache
		if cdn.ServeCached(w, r, cacheKey) {
			return
		}

		// Cache response
		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     200,
			body:           make([]byte, 0),
		}

		next.ServeHTTP(recorder, r)

		// Cache if successful
		if recorder.statusCode == 200 {
			contentType := recorder.Header().Get("Content-Type")
			cdn.CacheResponse(cacheKey, recorder.body, contentType)
		}
	})
}

func (cdn *CDNEngine) generateCacheKey(r *http.Request) string {
	key := fmt.Sprintf("%s:%s", r.Method, r.URL.Path)
	hash := md5.Sum([]byte(key))
	return hex.EncodeToString(hash[:])
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       []byte
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	rr.body = append(rr.body, b...)
	return rr.ResponseWriter.Write(b)
}
