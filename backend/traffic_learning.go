package main

import (
	"encoding/json"
	"sync"
	"time"
)

// TrafficLearningEngine - Machine learning dari traffic patterns
type TrafficLearningEngine struct {
	patterns      map[string]*TrafficPattern
	patternMutex  sync.RWMutex
	learningRate  float64
	minSamples    int
	adaptiveRules map[string]*AdaptiveRule
	ruleMutex     sync.RWMutex
}

// TrafficPattern - Pattern yang dipelajari dari traffic
type TrafficPattern struct {
	PatternID      string
	PatternType    string // "normal", "suspicious", "attack"
	RequestCount   int
	FirstSeen      time.Time
	LastSeen       time.Time
	AvgThreatScore float64
	Features       map[string]float64 // Feature vector
	Confidence     float64
}

// AdaptiveRule - Rule yang beradaptasi berdasarkan traffic
type AdaptiveRule struct {
	RuleID         string
	RuleName       string
	BaseThreshold float64
	CurrentThreshold float64
	AdjustmentRate float64
	SuccessCount   int
	FailureCount   int
	LastUpdated    time.Time
}

func NewTrafficLearningEngine() *TrafficLearningEngine {
	return &TrafficLearningEngine{
		patterns:      make(map[string]*TrafficPattern),
		learningRate:  0.1, // Learning rate untuk update patterns
		minSamples:    10,  // Minimum samples sebelum pattern dianggap valid
		adaptiveRules: make(map[string]*AdaptiveRule),
	}
}

// LearnFromRequest - Belajar dari setiap request
func (tle *TrafficLearningEngine) LearnFromRequest(ip, userAgent, path, method string, threatScore float64, blocked bool) {
	tle.patternMutex.Lock()
	defer tle.patternMutex.Unlock()

	// Generate pattern key
	patternKey := tle.generatePatternKey(ip, userAgent, path, method)

	pattern, exists := tle.patterns[patternKey]
	if !exists {
		pattern = &TrafficPattern{
			PatternID:    patternKey,
			PatternType:  tle.classifyPattern(threatScore, blocked),
			RequestCount: 0,
			FirstSeen:    time.Now(),
			Features:     make(map[string]float64),
		}
		tle.patterns[patternKey] = pattern
	}

	// Update pattern
	pattern.RequestCount++
	pattern.LastSeen = time.Now()

	// Update average threat score (exponential moving average)
	if pattern.RequestCount == 1 {
		pattern.AvgThreatScore = threatScore
	} else {
		pattern.AvgThreatScore = pattern.AvgThreatScore*(1-tle.learningRate) + threatScore*tle.learningRate
	}

	// Update features
	tle.updateFeatures(pattern, ip, userAgent, path, method, threatScore, blocked)

	// Update confidence (semakin banyak samples, semakin confident)
	if pattern.RequestCount >= tle.minSamples {
		confidence := float64(pattern.RequestCount) / 100.0
		if confidence > 1.0 {
			confidence = 1.0
		}
		pattern.Confidence = confidence
	}

	// Reclassify jika sudah cukup samples
	if pattern.RequestCount >= tle.minSamples {
		pattern.PatternType = tle.classifyPattern(pattern.AvgThreatScore, blocked)
	}
}

// generatePatternKey - Generate unique key untuk pattern
func (tle *TrafficLearningEngine) generatePatternKey(ip, userAgent, path, method string) string {
	// Normalize path (remove query params, IDs, etc.)
	normalizedPath := tle.normalizePath(path)
	
	// Hash untuk pattern key
	return method + ":" + normalizedPath + ":" + tle.hashUserAgent(userAgent)
}

// normalizePath - Normalize path untuk pattern matching
func (tle *TrafficLearningEngine) normalizePath(path string) string {
	// Remove query params
	// Replace IDs dengan placeholder
	// Contoh: /api/users/123 -> /api/users/{id}
	// Ini bisa di-extend lebih lanjut
	return path
}

// hashUserAgent - Hash user agent untuk pattern
func (tle *TrafficLearningEngine) hashUserAgent(ua string) string {
	// Simple hash - bisa di-improve
	if len(ua) > 50 {
		return ua[:50] // Truncate
	}
	return ua
}

// classifyPattern - Classify pattern berdasarkan threat score
func (tle *TrafficLearningEngine) classifyPattern(threatScore float64, blocked bool) string {
	if blocked {
		return "attack"
	}
	if threatScore > 0.7 {
		return "suspicious"
	}
	if threatScore > 0.3 {
		return "suspicious"
	}
	return "normal"
}

// updateFeatures - Update feature vector
func (tle *TrafficLearningEngine) updateFeatures(pattern *TrafficPattern, ip, userAgent, path, method string, threatScore float64, blocked bool) {
	// Update berbagai features
	pattern.Features["threat_score_avg"] = pattern.AvgThreatScore
	pattern.Features["block_rate"] = tle.calculateBlockRate(pattern)
	pattern.Features["request_frequency"] = tle.calculateFrequency(pattern)
}

// calculateBlockRate - Calculate block rate untuk pattern
func (tle *TrafficLearningEngine) calculateBlockRate(pattern *TrafficPattern) float64 {
	// Ini akan di-update saat kita track blocked requests
	return pattern.AvgThreatScore
}

// calculateFrequency - Calculate request frequency
func (tle *TrafficLearningEngine) calculateFrequency(pattern *TrafficPattern) float64 {
	if pattern.RequestCount < 2 {
		return 0
	}
	duration := pattern.LastSeen.Sub(pattern.FirstSeen).Seconds()
	if duration == 0 {
		return 0
	}
	return float64(pattern.RequestCount) / duration
}

// GetPatternScore - Get threat score untuk pattern
func (tle *TrafficLearningEngine) GetPatternScore(ip, userAgent, path, method string) (float64, bool) {
	tle.patternMutex.RLock()
	defer tle.patternMutex.RUnlock()

	patternKey := tle.generatePatternKey(ip, userAgent, path, method)
	pattern, exists := tle.patterns[patternKey]

	if !exists || pattern.RequestCount < tle.minSamples {
		return 0, false
	}

	// Return threat score berdasarkan pattern
	if pattern.PatternType == "attack" {
		return 0.9, true
	}
	if pattern.PatternType == "suspicious" {
		return pattern.AvgThreatScore, true
	}

	return 0, false
}

// UpdateAdaptiveRule - Update adaptive rule berdasarkan hasil
func (tle *TrafficLearningEngine) UpdateAdaptiveRule(ruleID string, success bool) {
	tle.ruleMutex.Lock()
	defer tle.ruleMutex.Unlock()

	rule, exists := tle.adaptiveRules[ruleID]
	if !exists {
		rule = &AdaptiveRule{
			RuleID:         ruleID,
			BaseThreshold:  0.5,
			CurrentThreshold: 0.5,
			AdjustmentRate: 0.05,
			LastUpdated:    time.Now(),
		}
		tle.adaptiveRules[ruleID] = rule
	}

		if success {
		rule.SuccessCount++
		// Jika terlalu banyak success, kurangi threshold (lebih ketat)
		if rule.SuccessCount > rule.FailureCount*2 {
			newThreshold := rule.CurrentThreshold - rule.AdjustmentRate
			if newThreshold < 0.1 {
				newThreshold = 0.1
			}
			rule.CurrentThreshold = newThreshold
		}
	} else {
		rule.FailureCount++
		// Jika terlalu banyak failure, naikkan threshold (lebih longgar)
		if rule.FailureCount > rule.SuccessCount*2 {
			newThreshold := rule.CurrentThreshold + rule.AdjustmentRate
			if newThreshold > 0.9 {
				newThreshold = 0.9
			}
			rule.CurrentThreshold = newThreshold
		}
	}

	rule.LastUpdated = time.Now()
}

// GetAdaptiveThreshold - Get current threshold untuk rule
func (tle *TrafficLearningEngine) GetAdaptiveThreshold(ruleID string) float64 {
	tle.ruleMutex.RLock()
	defer tle.ruleMutex.RUnlock()

	rule, exists := tle.adaptiveRules[ruleID]
	if !exists {
		return 0.5 // Default threshold
	}

	return rule.CurrentThreshold
}

// GetStats - Get learning statistics
func (tle *TrafficLearningEngine) GetStats() map[string]interface{} {
	tle.patternMutex.RLock()
	defer tle.patternMutex.RUnlock()

	stats := map[string]interface{}{
		"total_patterns":    len(tle.patterns),
		"normal_patterns":   0,
		"suspicious_patterns": 0,
		"attack_patterns":   0,
		"adaptive_rules":    len(tle.adaptiveRules),
	}

	for _, pattern := range tle.patterns {
		switch pattern.PatternType {
		case "normal":
			stats["normal_patterns"] = stats["normal_patterns"].(int) + 1
		case "suspicious":
			stats["suspicious_patterns"] = stats["suspicious_patterns"].(int) + 1
		case "attack":
			stats["attack_patterns"] = stats["attack_patterns"].(int) + 1
		}
	}

	return stats
}

// ExportPatterns - Export patterns untuk analysis
func (tle *TrafficLearningEngine) ExportPatterns() ([]byte, error) {
	tle.patternMutex.RLock()
	defer tle.patternMutex.RUnlock()

	patterns := make([]*TrafficPattern, 0, len(tle.patterns))
	for _, pattern := range tle.patterns {
		patterns = append(patterns, pattern)
	}

	return json.Marshal(patterns)
}


