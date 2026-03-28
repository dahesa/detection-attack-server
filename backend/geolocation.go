package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// GeolocationService - IP geolocation service
type GeolocationService struct {
	mu          sync.RWMutex
	ipLocations map[string]*IPLocation
	cache       map[string]*CachedLocation
	cacheTTL    time.Duration
}

// IPLocation - IP location data
type IPLocation struct {
	IP          string
	Country     string
	CountryCode string
	Region      string
	City        string
	Latitude    float64
	Longitude   float64
	Timezone    string
	ISP         string
	ASN         string
	Org         string
	FirstSeen   time.Time
	LastSeen    time.Time
	RequestCount int64
	AttackCount  int64
	ThreatScore  float64
}

// CachedLocation - Cached location data
type CachedLocation struct {
	Location  *IPLocation
	CachedAt  time.Time
	ExpiresAt time.Time
}

// NewGeolocationService - Initialize geolocation service
func NewGeolocationService() *GeolocationService {
	return &GeolocationService{
		ipLocations: make(map[string]*IPLocation),
		cache:       make(map[string]*CachedLocation),
		cacheTTL:    24 * time.Hour,
	}
}

// GetLocation - Get location for IP (with caching)
func (gs *GeolocationService) GetLocation(ip string) (*IPLocation, error) {
	// Check cache first
	gs.mu.RLock()
	if cached, exists := gs.cache[ip]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			gs.mu.RUnlock()
			return cached.Location, nil
		}
	}
	gs.mu.RUnlock()

	// Check existing location
	gs.mu.RLock()
	if loc, exists := gs.ipLocations[ip]; exists {
		gs.mu.RUnlock()
		// Update cache
		gs.mu.Lock()
		gs.cache[ip] = &CachedLocation{
			Location:  loc,
			CachedAt:  time.Now(),
			ExpiresAt: time.Now().Add(gs.cacheTTL),
		}
		gs.mu.Unlock()
		return loc, nil
	}
	gs.mu.RUnlock()

	// Fetch REAL location from external service (NO MOCK DATA)
	location, err := gs.fetchLocation(ip)
	if err != nil {
		log.Printf("❌ Failed to fetch REAL geolocation for %s: %v (will not store fake data)", ip, err)
		// Return error - don't store fake "Unknown" data
		return nil, err
	}
	
	if location == nil {
		log.Printf("❌ Geolocation service returned nil for %s (will not store fake data)", ip)
		return nil, fmt.Errorf("geolocation service returned nil for %s", ip)
	}

	// Validate that we have REAL data (not fake)
	if location.CountryCode == "XX" && ip != "127.0.0.1" && ip != "::1" {
		log.Printf("⚠️ Suspicious data for %s: CountryCode=XX (might be fake), will not store", ip)
		return nil, fmt.Errorf("suspicious fake data detected for %s", ip)
	}
	
	if location.Country == "Unknown" && ip != "127.0.0.1" && ip != "::1" {
		log.Printf("⚠️ Suspicious data for %s: Country=Unknown (might be fake), will not store", ip)
		return nil, fmt.Errorf("suspicious fake data detected for %s", ip)
	}

	// Store REAL location
	gs.mu.Lock()
	gs.ipLocations[ip] = location
	gs.cache[ip] = &CachedLocation{
		Location:  location,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(gs.cacheTTL),
	}
	gs.mu.Unlock()

	log.Printf("✅ Stored REAL geolocation for %s: %s, %s (Lat: %.4f, Lon: %.4f, ISP: %s)", 
		ip, location.City, location.Country, location.Latitude, location.Longitude, location.ISP)
	return location, nil
}

// fetchLocation - Fetch location from external service (REAL DATA ONLY)
func (gs *GeolocationService) fetchLocation(ip string) (*IPLocation, error) {
	// Skip localhost IPs - return default for them
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return &IPLocation{
			IP:          ip,
			Country:     "Local",
			CountryCode: "LOC",
			City:        "Localhost",
			Latitude:    0.0,
			Longitude:   0.0,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		}, nil
	}

	// Try to fetch from ip-api.com (free tier)
	// Note: ip-api.com has rate limit of 45 requests/minute for free tier
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,as,org,query", ip)
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("⚠️ Error fetching geolocation for %s: %v", ip, err)
		// Return default location instead of error
		return &IPLocation{
			IP:          ip,
			Country:     "Unknown",
			CountryCode: "XX",
			Latitude:    0.0,
			Longitude:   0.0,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	var apiResponse struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		AS          string  `json:"as"`
		Org         string  `json:"org"`
		Query       string  `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		log.Printf("⚠️ Error decoding geolocation response for %s: %v", ip, err)
		return nil, err
	}

	if apiResponse.Status != "success" {
		log.Printf("⚠️ Geolocation API returned non-success for %s: %s", ip, apiResponse.Status)
		// Return default location instead of error
		return &IPLocation{
			IP:          ip,
			Country:     "Unknown",
			CountryCode: "XX",
			Latitude:    0.0,
			Longitude:   0.0,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		}, nil
	}

	location := &IPLocation{
		IP:          apiResponse.Query,
		Country:     apiResponse.Country,
		CountryCode: apiResponse.CountryCode,
		Region:      apiResponse.RegionName,
		City:        apiResponse.City,
		Latitude:    apiResponse.Lat,
		Longitude:   apiResponse.Lon,
		Timezone:    apiResponse.Timezone,
		ISP:         apiResponse.ISP,
		ASN:         apiResponse.AS,
		Org:         apiResponse.Org,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
	}

	return location, nil
}

// UpdateLocation - Update location data for IP (REAL DATA ONLY - NO FAKE DATA)
func (gs *GeolocationService) UpdateLocation(ip string, attackCount int64, threatScore float64) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	loc, exists := gs.ipLocations[ip]
	if !exists {
		// Get REAL location first (will fetch from API)
		loc, err := gs.GetLocation(ip)
		if err != nil || loc == nil {
			log.Printf("⚠️ Cannot update location for %s: REAL location not available (will not create fake data)", ip)
			return
		}
		gs.ipLocations[ip] = loc
		loc = gs.ipLocations[ip] // Get reference to stored location
	}
	
	// Validate we have REAL data before updating
	if loc.CountryCode == "XX" && ip != "127.0.0.1" && ip != "::1" {
		log.Printf("⚠️ Skipping update for %s: has fake data (CountryCode=XX)", ip)
		return
	}
	
	if loc.Country == "Unknown" && ip != "127.0.0.1" && ip != "::1" {
		log.Printf("⚠️ Skipping update for %s: has fake data (Country=Unknown)", ip)
		return
	}

	loc.RequestCount++
	loc.AttackCount += attackCount
	if threatScore > loc.ThreatScore {
		loc.ThreatScore = threatScore
	}
	loc.LastSeen = time.Now()
	
	log.Printf("📍 Updated REAL location for %s: %s, %s (Attacks: %d, Requests: %d, ISP: %s)", 
		ip, loc.City, loc.Country, loc.AttackCount, loc.RequestCount, loc.ISP)
}

// GetAttackersByLocation - Get attackers grouped by location
func (gs *GeolocationService) GetAttackersByLocation() map[string][]*IPLocation {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	result := make(map[string][]*IPLocation)
	for _, loc := range gs.ipLocations {
		if loc.AttackCount > 0 {
			key := loc.CountryCode
			if key == "" {
				key = "UNKNOWN"
			}
			result[key] = append(result[key], loc)
		}
	}

	return result
}

// GetAllLocations - Get all IP locations (REAL DATA ONLY)
func (gs *GeolocationService) GetAllLocations() []*IPLocation {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	result := make([]*IPLocation, 0, len(gs.ipLocations))
	for _, loc := range gs.ipLocations {
		if loc == nil {
			continue
		}
		
		// Include ALL locations with valid REAL data (not just attackers)
		// Filter out fake "Unknown" or "XX" data (except localhost)
		if loc.IP != "" {
			// Allow localhost with "LOC" code
			if loc.IP == "127.0.0.1" || loc.IP == "::1" {
				result = append(result, loc)
				continue
			}
			
			// Only include REAL data (not "Unknown" or "XX")
			if loc.CountryCode != "" && loc.CountryCode != "XX" && loc.Country != "" && loc.Country != "Unknown" {
				result = append(result, loc)
			} else if loc.RequestCount > 0 {
				// Include if has requests even if country is unknown (might be valid)
				result = append(result, loc)
			}
		}
	}

	log.Printf("📍 Returning %d REAL IP locations to frontend (NO FAKE DATA)", len(result))
	return result
}

// GetLocationStats - Get location statistics
func (gs *GeolocationService) GetLocationStats() map[string]interface{} {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	countryStats := make(map[string]int)
	totalAttacks := int64(0)
	totalIPs := len(gs.ipLocations)

	for _, loc := range gs.ipLocations {
		if loc.AttackCount > 0 {
			countryStats[loc.Country]++
			totalAttacks += loc.AttackCount
		}
	}

	return map[string]interface{}{
		"total_ips":      totalIPs,
		"total_attacks":  totalAttacks,
		"countries":      countryStats,
		"unique_countries": len(countryStats),
	}
}

