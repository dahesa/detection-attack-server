package main

import (
	"log"
	"sync"
	"time"
)

// FalsePositiveControl - Smart false positive reduction system
type FalsePositiveControl struct {
	mu                sync.RWMutex
	whitelist         map[string]*WhitelistEntry
	falsePositives    map[string]*FalsePositive
	learningModel     *FPLearningModel
	confidenceScores map[string]float64
	lastUpdate        time.Time
}

// WhitelistEntry - Whitelist entry
type WhitelistEntry struct {
	Pattern     string
	Type        string // "ip", "path", "pattern", "user"
	Reason      string
	CreatedAt   time.Time
	LastUsed    time.Time
	UseCount    int64
	Confidence  float64
}

// FalsePositive - False positive record
type FalsePositive struct {
	Pattern     string
	AttackType  string
	Context     map[string]interface{}
	ReportedAt  time.Time
	ResolvedAt time.Time
	Resolution  string
	Confidence  float64
}

// FPLearningModel - False positive learning model
type FPLearningModel struct {
	mu              sync.RWMutex
	patterns        map[string]*PatternModel
	contextRules    []ContextRule
	confidenceRules []ConfidenceRule
	accuracy        float64
	lastTrained     time.Time
}

// PatternModel - Pattern model for FP reduction
type PatternModel struct {
	Pattern     string
	TruePositives int64
	FalsePositives int64
	Accuracy    float64
	LastSeen    time.Time
}

// ContextRule - Context-based rule
type ContextRule struct {
	Name        string
	Condition   func(map[string]interface{}) bool
	Action      string
	Confidence  float64
	Enabled     bool
}

// ConfidenceRule - Confidence-based rule
type ConfidenceRule struct {
	Name        string
	Threshold   float64
	Action      string
	Enabled     bool
}

// NewFalsePositiveControl - Initialize false positive control
func NewFalsePositiveControl() *FalsePositiveControl {
	fpc := &FalsePositiveControl{
		whitelist:         make(map[string]*WhitelistEntry),
		falsePositives:    make(map[string]*FalsePositive),
		learningModel:     NewFPLearningModel(),
		confidenceScores: make(map[string]float64),
	}

	// Initialize whitelist
	fpc.initializeWhitelist()

	log.Println("✅ False Positive Control initialized")
	return fpc
}

// NewFPLearningModel - Initialize FP learning model
func NewFPLearningModel() *FPLearningModel {
	return &FPLearningModel{
		patterns:        make(map[string]*PatternModel),
		contextRules:    []ContextRule{},
		confidenceRules: []ConfidenceRule{},
		accuracy:        0.95,
		lastTrained:     time.Now(),
	}
}

// initializeWhitelist - Initialize whitelist
func (fpc *FalsePositiveControl) initializeWhitelist() {
	// Common legitimate patterns
	whitelistPatterns := []WhitelistEntry{
		{Pattern: "/api/health", Type: "path", Reason: "Health check endpoint", Confidence: 1.0},
		{Pattern: "/api/metrics", Type: "path", Reason: "Metrics endpoint", Confidence: 1.0},
		{Pattern: "/favicon.ico", Type: "path", Reason: "Favicon request", Confidence: 1.0},
		{Pattern: "/robots.txt", Type: "path", Reason: "Robots.txt request", Confidence: 1.0},
	}

	for _, entry := range whitelistPatterns {
		entry.CreatedAt = time.Now()
		entry.LastUsed = time.Now()
		fpc.whitelist[entry.Pattern] = &entry
	}
}

// CheckWhitelist - Check if request matches whitelist
func (fpc *FalsePositiveControl) CheckWhitelist(ip, path, pattern string) bool {
	fpc.mu.RLock()
	defer fpc.mu.RUnlock()

	// Check path whitelist
	if entry, exists := fpc.whitelist[path]; exists {
		entry.LastUsed = time.Now()
		entry.UseCount++
		return true
	}

	// Check pattern whitelist
	if entry, exists := fpc.whitelist[pattern]; exists {
		entry.LastUsed = time.Now()
		entry.UseCount++
		return true
	}

	// Check IP whitelist
	if entry, exists := fpc.whitelist[ip]; exists {
		entry.LastUsed = time.Now()
		entry.UseCount++
		return true
	}

	return false
}

// AnalyzeFalsePositive - Analyze if detection is false positive
func (fpc *FalsePositiveControl) AnalyzeFalsePositive(attackType, pattern string, context map[string]interface{}) bool {
	fpc.mu.Lock()
	defer fpc.mu.Unlock()

	// Check learning model
	if fpc.learningModel.isFalsePositive(pattern, context) {
		// Record false positive
		fp := &FalsePositive{
			Pattern:    pattern,
			AttackType: attackType,
			Context:    context,
			ReportedAt: time.Now(),
			Confidence: 0.8,
		}
		fpc.falsePositives[pattern] = fp
		return true
	}

	return false
}

// isFalsePositive - Check if pattern is false positive
func (fpm *FPLearningModel) isFalsePositive(pattern string, context map[string]interface{}) bool {
	fpm.mu.RLock()
	defer fpm.mu.RUnlock()

	// Check pattern model
	if model, exists := fpm.patterns[pattern]; exists {
		if model.Accuracy < 0.3 { // Low accuracy = likely false positive
			return true
		}
	}

	// Check context rules
	for _, rule := range fpm.contextRules {
		if rule.Enabled && rule.Condition(context) {
			return true
		}
	}

	return false
}

// UpdatePatternModel - Update pattern model
func (fpc *FalsePositiveControl) UpdatePatternModel(pattern string, isTruePositive bool) {
	fpc.learningModel.mu.Lock()
	defer fpc.learningModel.mu.Unlock()

	model, exists := fpc.learningModel.patterns[pattern]
	if !exists {
		model = &PatternModel{
			Pattern: pattern,
		}
		fpc.learningModel.patterns[pattern] = model
	}

	if isTruePositive {
		model.TruePositives++
	} else {
		model.FalsePositives++
	}

	total := model.TruePositives + model.FalsePositives
	if total > 0 {
		model.Accuracy = float64(model.TruePositives) / float64(total)
	}

	model.LastSeen = time.Now()
}

// AddToWhitelist - Add entry to whitelist
func (fpc *FalsePositiveControl) AddToWhitelist(pattern, patternType, reason string) {
	fpc.mu.Lock()
	defer fpc.mu.Unlock()

	fpc.whitelist[pattern] = &WhitelistEntry{
		Pattern:    pattern,
		Type:       patternType,
		Reason:     reason,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		UseCount:   0,
		Confidence: 0.9,
	}
}

// GetFalsePositiveStats - Get false positive statistics
func (fpc *FalsePositiveControl) GetFalsePositiveStats() map[string]interface{} {
	fpc.mu.RLock()
	defer fpc.mu.RUnlock()

	return map[string]interface{}{
		"whitelist_count":    len(fpc.whitelist),
		"false_positive_count": len(fpc.falsePositives),
		"model_accuracy":     fpc.learningModel.accuracy,
		"patterns_learned":   len(fpc.learningModel.patterns),
	}
}



