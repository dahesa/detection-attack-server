package main

import (
	"log"
	"sync"
	"time"
)

// PassiveLearningEngine - Belajar dari traffic tanpa blocking
type PassiveLearningEngine struct {
	learningMode   bool
	learnedPatterns map[string]*LearnedPattern
	patternMutex   sync.RWMutex
	learningWindow time.Duration
	minConfidence  float64
}

// LearnedPattern - Pattern yang dipelajari
type LearnedPattern struct {
	PatternID     string
	PatternType   string
	SampleCount   int
	ThreatScores  []float64
	BlockedCount  int
	AllowedCount  int
	FirstSeen     time.Time
	LastSeen      time.Time
	Confidence    float64
	Recommendation string
}

func NewPassiveLearningEngine() *PassiveLearningEngine {
	return &PassiveLearningEngine{
		learningMode:     true,
		learnedPatterns:  make(map[string]*LearnedPattern),
		learningWindow:   24 * time.Hour,
		minConfidence:    0.7,
	}
}

// EnableLearningMode - Enable passive learning
func (ple *PassiveLearningEngine) EnableLearningMode() {
	ple.learningMode = true
	log.Println("📚 Passive learning mode ENABLED")
}

// DisableLearningMode - Disable passive learning
func (ple *PassiveLearningEngine) DisableLearningMode() {
	ple.learningMode = false
	log.Println("📚 Passive learning mode DISABLED")
}

// LearnFromRequest - Belajar dari request tanpa block
func (ple *PassiveLearningEngine) LearnFromRequest(ip, userAgent, path, method string, threatScore float64, wouldBlock bool) {
	if !ple.learningMode {
		return
	}

	ple.patternMutex.Lock()
	defer ple.patternMutex.Unlock()

	patternKey := ple.generatePatternKey(ip, userAgent, path, method)
	pattern, exists := ple.learnedPatterns[patternKey]

	if !exists {
		pattern = &LearnedPattern{
			PatternID:    patternKey,
			PatternType:  ple.classifyPattern(threatScore),
			ThreatScores: []float64{},
			FirstSeen:    time.Now(),
		}
		ple.learnedPatterns[patternKey] = pattern
	}

	// Update pattern
	pattern.SampleCount++
	pattern.LastSeen = time.Now()
	pattern.ThreatScores = append(pattern.ThreatScores, threatScore)

	// Keep only last 100 scores
	if len(pattern.ThreatScores) > 100 {
		pattern.ThreatScores = pattern.ThreatScores[len(pattern.ThreatScores)-100:]
	}

	if wouldBlock {
		pattern.BlockedCount++
	} else {
		pattern.AllowedCount++
	}

	// Calculate confidence
	pattern.Confidence = ple.calculateConfidence(pattern)

	// Generate recommendation
	pattern.Recommendation = ple.generateRecommendation(pattern)
}

// generatePatternKey - Generate pattern key
func (ple *PassiveLearningEngine) generatePatternKey(ip, userAgent, path, method string) string {
	uaLen := len(userAgent)
	if uaLen > 50 {
		uaLen = 50
	}
	return method + ":" + path + ":" + userAgent[:uaLen]
}

// classifyPattern - Classify pattern
func (ple *PassiveLearningEngine) classifyPattern(threatScore float64) string {
	if threatScore > 0.7 {
		return "high_threat"
	}
	if threatScore > 0.4 {
		return "medium_threat"
	}
	return "low_threat"
}

// calculateConfidence - Calculate confidence untuk pattern
func (ple *PassiveLearningEngine) calculateConfidence(pattern *LearnedPattern) float64 {
	if pattern.SampleCount < 10 {
		return float64(pattern.SampleCount) / 10.0
	}
	return 1.0
}

// generateRecommendation - Generate recommendation
func (ple *PassiveLearningEngine) generateRecommendation(pattern *LearnedPattern) string {
	if pattern.SampleCount < 10 {
		return "Need more samples"
	}

	avgThreat := ple.calculateAvgThreat(pattern)
	blockRate := float64(pattern.BlockedCount) / float64(pattern.SampleCount)

	if avgThreat > 0.7 && blockRate > 0.5 {
		return "Should block - High threat pattern"
	}
	if avgThreat > 0.4 && blockRate > 0.3 {
		return "Consider blocking - Medium threat pattern"
	}
	if avgThreat < 0.2 && blockRate < 0.1 {
		return "Safe pattern - Low threat"
	}

	return "Monitor - Mixed signals"
}

// calculateAvgThreat - Calculate average threat score
func (ple *PassiveLearningEngine) calculateAvgThreat(pattern *LearnedPattern) float64 {
	if len(pattern.ThreatScores) == 0 {
		return 0
	}

	sum := 0.0
	for _, score := range pattern.ThreatScores {
		sum += score
	}
	return sum / float64(len(pattern.ThreatScores))
}

// GetRecommendations - Get recommendations untuk patterns
func (ple *PassiveLearningEngine) GetRecommendations() []map[string]interface{} {
	ple.patternMutex.RLock()
	defer ple.patternMutex.RUnlock()

	recommendations := []map[string]interface{}{}
	for _, pattern := range ple.learnedPatterns {
		if pattern.Confidence >= ple.minConfidence {
			recommendations = append(recommendations, map[string]interface{}{
				"pattern_id":    pattern.PatternID,
				"pattern_type":   pattern.PatternType,
				"sample_count":   pattern.SampleCount,
				"avg_threat":     ple.calculateAvgThreat(pattern),
				"block_rate":     float64(pattern.BlockedCount) / float64(pattern.SampleCount),
				"confidence":     pattern.Confidence,
				"recommendation": pattern.Recommendation,
				"first_seen":     pattern.FirstSeen,
				"last_seen":      pattern.LastSeen,
			})
		}
	}

	return recommendations
}

// GetStats - Get learning statistics
func (ple *PassiveLearningEngine) GetStats() map[string]interface{} {
	ple.patternMutex.RLock()
	defer ple.patternMutex.RUnlock()

	stats := map[string]interface{}{
		"learning_mode":    ple.learningMode,
		"total_patterns":   len(ple.learnedPatterns),
		"high_threat":      0,
		"medium_threat":    0,
		"low_threat":       0,
		"recommendations":  len(ple.GetRecommendations()),
	}

	for _, pattern := range ple.learnedPatterns {
		switch pattern.PatternType {
		case "high_threat":
			stats["high_threat"] = stats["high_threat"].(int) + 1
		case "medium_threat":
			stats["medium_threat"] = stats["medium_threat"].(int) + 1
		case "low_threat":
			stats["low_threat"] = stats["low_threat"].(int) + 1
		}
	}

	return stats
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

