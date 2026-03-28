package main

import (
	"encoding/json"
	"net"
	"sync"
	"time"
)

// ASNReputationEngine - ASN dan IP reputation scoring
type ASNReputationEngine struct {
	asnScores     map[string]*ASNScore
	ipScores      map[string]*IPReputation
	asnMutex      sync.RWMutex
	ipMutex       sync.RWMutex
	updateInterval time.Duration
}

// ASNScore - Score untuk ASN
type ASNScore struct {
	ASN           string
	ASNName       string
	ReputationScore float64 // 0.0 (bad) to 1.0 (good)
	ThreatCount   int
	RequestCount  int
	FirstSeen     time.Time
	LastSeen      time.Time
	ThreatTypes   []string
	LastUpdated   time.Time
}

// IPReputation - Reputation untuk IP address
type IPReputation struct {
	IP            string
	ASN           string
	Country       string
	ReputationScore float64
	ThreatCount   int
	RequestCount  int
	FirstSeen     time.Time
	LastSeen      time.Time
	ThreatTypes   []string
	IsKnownThreat bool
	LastUpdated   time.Time
}

// KnownBadASNs - List ASN yang diketahui buruk
var KnownBadASNs = map[string]string{
	"AS24940": "Hetzner Online - Known for abuse",
	"AS16276": "OVH SAS - High abuse rate",
	"AS20473": "AS-CHOOPA - VPS provider, high abuse",
}

func NewASNReputationEngine() *ASNReputationEngine {
	engine := &ASNReputationEngine{
		asnScores:      make(map[string]*ASNScore),
		ipScores:       make(map[string]*IPReputation),
		updateInterval: 1 * time.Hour,
	}

	// Initialize known bad ASNs
	for asn, name := range KnownBadASNs {
		engine.asnScores[asn] = &ASNScore{
			ASN:            asn,
			ASNName:        name,
			ReputationScore: 0.3, // Low reputation
			ThreatCount:    0,
			RequestCount:   0,
			FirstSeen:      time.Now(),
			LastSeen:       time.Now(),
			ThreatTypes:    []string{},
			LastUpdated:    time.Now(),
		}
	}

	return engine
}

// GetASNFromIP - Get ASN dari IP (simplified - di production pakai MaxMind atau service lain)
func (are *ASNReputationEngine) GetASNFromIP(ip string) (string, string) {
	// Simplified ASN lookup
	// Di production, gunakan MaxMind GeoIP2 atau service lain
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "UNKNOWN", "Unknown ASN"
	}

	// Simple heuristic berdasarkan IP range
	// Di production, gunakan database ASN yang proper
	if parsedIP.IsPrivate() {
		return "AS0", "Private Network"
	}

	// Default ASN (ini harus diganti dengan lookup yang proper)
	return "AS0", "Unknown ASN"
}

// GetCountryFromIP - Get country dari IP (simplified)
func (are *ASNReputationEngine) GetCountryFromIP(ip string) string {
	// Simplified country lookup
	// Di production, gunakan MaxMind GeoIP2
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "UNKNOWN"
	}

	if parsedIP.IsPrivate() {
		return "LOCAL"
	}

	// Default country
	return "UNKNOWN"
}

// UpdateIPReputation - Update reputation untuk IP
func (are *ASNReputationEngine) UpdateIPReputation(ip string, threatScore float64, threatType string, blocked bool) {
	are.ipMutex.Lock()
	defer are.ipMutex.Unlock()

	reputation, exists := are.ipScores[ip]
	if !exists {
		asn, _ := are.GetASNFromIP(ip)
		country := are.GetCountryFromIP(ip)
		
		reputation = &IPReputation{
			IP:             ip,
			ASN:            asn,
			Country:        country,
			ReputationScore: 0.5, // Neutral
			ThreatCount:    0,
			RequestCount:  0,
			FirstSeen:      time.Now(),
			ThreatTypes:    []string{},
			IsKnownThreat:  false,
		}
		are.ipScores[ip] = reputation
	}

	reputation.RequestCount++
	reputation.LastSeen = time.Now()

	if blocked || threatScore > 0.5 {
		reputation.ThreatCount++
		reputation.ThreatTypes = append(reputation.ThreatTypes, threatType)
		
		// Update reputation score (lower is worse)
		threatRate := float64(reputation.ThreatCount) / float64(reputation.RequestCount)
		reputation.ReputationScore = 1.0 - threatRate
		
		if reputation.ReputationScore < 0.3 {
			reputation.IsKnownThreat = true
		}
	}

	reputation.LastUpdated = time.Now()

	// Update ASN score
	are.updateASNScore(reputation.ASN, threatScore, threatType, blocked)
}

// updateASNScore - Update ASN score
func (are *ASNReputationEngine) updateASNScore(asn string, threatScore float64, threatType string, blocked bool) {
	are.asnMutex.Lock()
	defer are.asnMutex.Unlock()

	score, exists := are.asnScores[asn]
	if !exists {
		asnName := "Unknown ASN"
		if name, ok := KnownBadASNs[asn]; ok {
			asnName = name
		}
		
		score = &ASNScore{
			ASN:            asn,
			ASNName:        asnName,
			ReputationScore: 0.5,
			ThreatCount:    0,
			RequestCount:   0,
			FirstSeen:      time.Now(),
			ThreatTypes:    []string{},
		}
		are.asnScores[asn] = score
	}

	score.RequestCount++
	score.LastSeen = time.Now()

	if blocked || threatScore > 0.5 {
		score.ThreatCount++
		score.ThreatTypes = append(score.ThreatTypes, threatType)
		
		// Update ASN reputation
		threatRate := float64(score.ThreatCount) / float64(score.RequestCount)
		score.ReputationScore = 1.0 - threatRate
	}

	score.LastUpdated = time.Now()
}

// GetIPReputation - Get reputation score untuk IP
func (are *ASNReputationEngine) GetIPReputation(ip string) (float64, bool) {
	are.ipMutex.RLock()
	defer are.ipMutex.RUnlock()

	reputation, exists := are.ipScores[ip]
	if !exists {
		return 0.5, false // Neutral jika tidak ada data
	}

	return reputation.ReputationScore, reputation.IsKnownThreat
}

// GetASNReputation - Get reputation score untuk ASN
func (are *ASNReputationEngine) GetASNReputation(asn string) float64 {
	are.asnMutex.RLock()
	defer are.asnMutex.RUnlock()

	score, exists := are.asnScores[asn]
	if !exists {
		return 0.5 // Neutral
	}

	return score.ReputationScore
}

// GetReputationBoost - Get boost untuk threat score berdasarkan reputation
func (are *ASNReputationEngine) GetReputationBoost(ip string) float64 {
	ipRep, isThreat := are.GetIPReputation(ip)
	asn, _ := are.GetASNFromIP(ip)
	asnRep := are.GetASNReputation(asn)

	// Combine IP dan ASN reputation
	combinedRep := (ipRep + asnRep) / 2.0

	// Jika known threat, boost threat score
	if isThreat {
		return 0.3 // Boost threat score by 0.3
	}

	// Jika reputation rendah, boost threat score
	if combinedRep < 0.3 {
		return 0.2
	}

	// Jika reputation tinggi, reduce threat score
	if combinedRep > 0.8 {
		return -0.1
	}

	return 0.0
}

// GetStats - Get reputation statistics
func (are *ASNReputationEngine) GetStats() map[string]interface{} {
	are.asnMutex.RLock()
	are.ipMutex.RLock()
	defer are.asnMutex.RUnlock()
	defer are.ipMutex.RUnlock()

	lowRepASNs := 0
	lowRepIPs := 0
	knownThreats := 0

	for _, score := range are.asnScores {
		if score.ReputationScore < 0.3 {
			lowRepASNs++
		}
	}

	for _, rep := range are.ipScores {
		if rep.ReputationScore < 0.3 {
			lowRepIPs++
		}
		if rep.IsKnownThreat {
			knownThreats++
		}
	}

	return map[string]interface{}{
		"total_asns":        len(are.asnScores),
		"total_ips":         len(are.ipScores),
		"low_reputation_asns": lowRepASNs,
		"low_reputation_ips":  lowRepIPs,
		"known_threats":     knownThreats,
	}
}

// ExportReputation - Export reputation data
func (are *ASNReputationEngine) ExportReputation() ([]byte, error) {
	are.asnMutex.RLock()
	are.ipMutex.RLock()
	defer are.asnMutex.RUnlock()
	defer are.ipMutex.RUnlock()

	data := map[string]interface{}{
		"asn_scores": are.asnScores,
		"ip_scores":  are.ipScores,
	}

	return json.Marshal(data)
}

