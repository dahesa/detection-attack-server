package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// AdvancedThreatIntelligence dengan network effect learning
type AdvancedThreatIntelligence struct {
	mu             sync.RWMutex
	threatDatabase map[string]*ThreatProfile
	globalPatterns map[string]*PatternStats
	networkEffects *NetworkEffectEngine
	learningEngine *MLearningEngine
	lastUpdate     time.Time
	totalRequests  int64
	threatCount    int64
}

// ThreatProfile menyimpan profil ancaman untuk IP/pattern
type ThreatProfile struct {
	IP             string
	ThreatScore    float64
	AttackTypes    []string
	FirstSeen      time.Time
	LastSeen       time.Time
	RequestCount   int64
	BlockCount     int64
	Patterns       map[string]int
	BehavioralData *BehavioralProfile
	GlobalRank     int
	Confidence     float64
}

// PatternStats statistik global untuk pattern
type PatternStats struct {
	Pattern        string
	Occurrences    int64
	ThreatScore    float64
	FirstSeen      time.Time
	LastSeen       time.Time
	AffectedIPs    map[string]int
	GlobalImpact   float64
	LearningWeight float64
}

// NetworkEffectEngine engine untuk network effect learning
type NetworkEffectEngine struct {
	mu             sync.RWMutex
	globalThreats  map[string]*GlobalThreat
	correlationMap map[string][]string
	threatClusters map[string]*ThreatCluster
	updateInterval time.Duration
}

// GlobalThreat ancaman global dari network
type GlobalThreat struct {
	Signature       string
	Severity        string
	GlobalCount     int64
	AffectedDomains int64
	FirstDetected   time.Time
	LastDetected    time.Time
	Mitigation      string
	Confidence      float64
}

// ThreatCluster cluster ancaman terkait
type ThreatCluster struct {
	ID            string
	Threats       []string
	CommonPattern string
	Severity      string
	AffectedCount int64
	LastActivity  time.Time
}

// MLearningEngine machine learning engine untuk threat detection
type MLearningEngine struct {
	mu             sync.RWMutex
	models         map[string]*MLModel
	trainingData   []*TrainingSample
	featureWeights map[string]float64
	lastTraining   time.Time
}

// MLModel model machine learning
type MLModel struct {
	Name        string
	Version     string
	Accuracy    float64
	Precision   float64
	Recall      float64
	LastUpdated time.Time
	Features    []string
}

// TrainingSample sample untuk training
type TrainingSample struct {
	Features    map[string]float64
	Label       string
	Timestamp   time.Time
	ThreatScore float64
}

// BehavioralProfile profil perilaku
type BehavioralProfile struct {
	RequestPattern []float64
	TimingPattern  []float64
	UserAgentScore float64
	MouseMovement  []float64
	ClickPattern   []float64
	ScrollPattern  []float64
	IsHuman        bool
	Confidence     float64
}

// NewAdvancedThreatIntelligence creates new advanced threat intelligence
func NewAdvancedThreatIntelligence() *AdvancedThreatIntelligence {
	ati := &AdvancedThreatIntelligence{
		threatDatabase: make(map[string]*ThreatProfile),
		globalPatterns: make(map[string]*PatternStats),
		networkEffects: NewNetworkEffectEngine(),
		learningEngine: NewMLearningEngine(),
		lastUpdate:     time.Now(),
	}

	// Start background learning
	go ati.startLearningLoop()

	return ati
}

// AnalyzeRequest analyzes request dengan advanced threat intelligence
func (ati *AdvancedThreatIntelligence) AnalyzeRequest(ip, userAgent, path, method string, headers map[string]string) *ThreatAnalysis {
	ati.mu.Lock()
	defer ati.mu.Unlock()

	ati.totalRequests++

	// Get or create threat profile
	profile := ati.getOrCreateProfile(ip)

	// Analyze dengan network effect
	networkThreats := ati.networkEffects.Analyze(ip, path, method, headers)

	// Analyze dengan ML
	mlThreats := ati.learningEngine.Predict(ip, userAgent, path, method, headers)

	// Combine threats
	threatScore := ati.calculateThreatScore(profile, networkThreats, mlThreats)

	// Update profile
	profile.ThreatScore = threatScore
	profile.LastSeen = time.Now()
	profile.RequestCount++

	// Update global patterns
	ati.updateGlobalPatterns(path, method, threatScore)

	// Check network effect
	if networkThreats.GlobalThreat {
		ati.threatCount++
		profile.BlockCount++
	}

	return &ThreatAnalysis{
		ThreatScore:    threatScore,
		IsThreat:       threatScore > 0.7,
		ThreatTypes:    ati.identifyThreatTypes(profile, networkThreats, mlThreats),
		Confidence:     ati.calculateConfidence(profile, networkThreats, mlThreats),
		GlobalThreat:   networkThreats.GlobalThreat,
		Recommendation: ati.getRecommendation(threatScore, networkThreats),
	}
}

// ThreatAnalysis hasil analisis
type ThreatAnalysis struct {
	ThreatScore    float64
	IsThreat       bool
	ThreatTypes    []string
	Confidence     float64
	GlobalThreat   bool
	Recommendation string
}

// NetworkThreatAnalysis hasil analisis network
type NetworkThreatAnalysis struct {
	GlobalThreat  bool
	ThreatCluster string
	CorrelatedIPs []string
	Severity      string
	Mitigation    string
}

func (ati *AdvancedThreatIntelligence) getOrCreateProfile(ip string) *ThreatProfile {
	if profile, exists := ati.threatDatabase[ip]; exists {
		return profile
	}

	profile := &ThreatProfile{
		IP:             ip,
		ThreatScore:    0.0,
		AttackTypes:    []string{},
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
		RequestCount:   0,
		BlockCount:     0,
		Patterns:       make(map[string]int),
		BehavioralData: &BehavioralProfile{},
		Confidence:     0.0,
	}

	ati.threatDatabase[ip] = profile
	return profile
}

func (ati *AdvancedThreatIntelligence) calculateThreatScore(profile *ThreatProfile, network *NetworkThreatAnalysis, ml *MLThreatAnalysis) float64 {
	baseScore := 0.0

	// Base score dari profile
	if profile.RequestCount > 0 {
		baseScore = float64(profile.BlockCount) / float64(profile.RequestCount)
	}

	// Network effect boost
	if network.GlobalThreat {
		baseScore += 0.3
	}

	// ML prediction boost
	baseScore += ml.ThreatScore * 0.4

	// Behavioral analysis
	if profile.BehavioralData != nil && !profile.BehavioralData.IsHuman {
		baseScore += 0.2
	}

	// Normalize
	if baseScore > 1.0 {
		baseScore = 1.0
	}

	return baseScore
}

func (ati *AdvancedThreatIntelligence) identifyThreatTypes(profile *ThreatProfile, network *NetworkThreatAnalysis, ml *MLThreatAnalysis) []string {
	types := make(map[string]bool)

	// From profile
	for _, at := range profile.AttackTypes {
		types[at] = true
	}

	// From network
	if network.GlobalThreat {
		types["NETWORK_THREAT"] = true
	}

	// From ML
	for _, tt := range ml.ThreatTypes {
		types[tt] = true
	}

	result := make([]string, 0, len(types))
	for t := range types {
		result = append(result, t)
	}

	return result
}

func (ati *AdvancedThreatIntelligence) calculateConfidence(profile *ThreatProfile, network *NetworkThreatAnalysis, ml *MLThreatAnalysis) float64 {
	confidence := 0.5

	// More data = higher confidence
	if profile.RequestCount > 100 {
		confidence += 0.2
	}
	if profile.RequestCount > 1000 {
		confidence += 0.2
	}

	// Network effect = higher confidence
	if network.GlobalThreat {
		confidence += 0.1
	}

	// ML confidence
	confidence += ml.Confidence * 0.2

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (ati *AdvancedThreatIntelligence) getRecommendation(score float64, network *NetworkThreatAnalysis) string {
	if score > 0.9 {
		return "IMMEDIATE_BLOCK"
	}
	if score > 0.7 {
		return "BLOCK_AND_MONITOR"
	}
	if network.GlobalThreat {
		return "NETWORK_BLOCK"
	}
	if score > 0.5 {
		return "MONITOR_CLOSELY"
	}
	return "ALLOW"
}

func (ati *AdvancedThreatIntelligence) updateGlobalPatterns(path, method string, threatScore float64) {
	pattern := fmt.Sprintf("%s:%s", method, path)

	stats, exists := ati.globalPatterns[pattern]
	if !exists {
		stats = &PatternStats{
			Pattern:        pattern,
			Occurrences:    0,
			ThreatScore:    0.0,
			FirstSeen:      time.Now(),
			AffectedIPs:    make(map[string]int),
			GlobalImpact:   0.0,
			LearningWeight: 1.0,
		}
		ati.globalPatterns[pattern] = stats
	}

	stats.Occurrences++
	stats.LastSeen = time.Now()
	stats.ThreatScore = (stats.ThreatScore*float64(stats.Occurrences-1) + threatScore) / float64(stats.Occurrences)
}

func (ati *AdvancedThreatIntelligence) startLearningLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ati.learnFromData()
	}
}

func (ati *AdvancedThreatIntelligence) learnFromData() {
	ati.mu.Lock()
	defer ati.mu.Unlock()

	// Update ML models
	ati.learningEngine.UpdateModels(ati.learningEngine.trainingData)

	// Update network effects
	ati.networkEffects.UpdateFromGlobalData()

	// Update global rankings
	ati.updateGlobalRankings()

	log.Printf("🧠 Threat Intelligence: Learned from %d requests, %d threats detected", ati.totalRequests, ati.threatCount)
}

func (ati *AdvancedThreatIntelligence) updateGlobalRankings() {
	// Sort threats by score
	type threatRank struct {
		ip    string
		score float64
	}

	ranks := make([]threatRank, 0, len(ati.threatDatabase))
	for ip, profile := range ati.threatDatabase {
		ranks = append(ranks, threatRank{ip: ip, score: profile.ThreatScore})
	}

	// Simple ranking (in production, use proper sorting)
	for i, rank := range ranks {
		if profile, exists := ati.threatDatabase[rank.ip]; exists {
			profile.GlobalRank = i + 1
		}
	}
}

// NewNetworkEffectEngine creates network effect engine
func NewNetworkEffectEngine() *NetworkEffectEngine {
	return &NetworkEffectEngine{
		globalThreats:  make(map[string]*GlobalThreat),
		correlationMap: make(map[string][]string),
		threatClusters: make(map[string]*ThreatCluster),
		updateInterval: 1 * time.Minute,
	}
}

func (nee *NetworkEffectEngine) Analyze(ip, path, method string, headers map[string]string) *NetworkThreatAnalysis {
	nee.mu.RLock()
	defer nee.mu.RUnlock()

	signature := nee.createSignature(path, method, headers)

	// Check global threats
	if threat, exists := nee.globalThreats[signature]; exists {
		return &NetworkThreatAnalysis{
			GlobalThreat:  true,
			ThreatCluster: threat.Signature,
			Severity:      threat.Severity,
			Mitigation:    threat.Mitigation,
		}
	}

	// Check correlations
	if correlated, exists := nee.correlationMap[ip]; exists && len(correlated) > 5 {
		return &NetworkThreatAnalysis{
			GlobalThreat:  true,
			CorrelatedIPs: correlated,
			Severity:      "HIGH",
			Mitigation:    "BLOCK_CORRELATED",
		}
	}

	return &NetworkThreatAnalysis{
		GlobalThreat: false,
	}
}

func (nee *NetworkEffectEngine) createSignature(path, method string, headers map[string]string) string {
	// Create signature from request characteristics
	return fmt.Sprintf("%s:%s", method, path)
}

func (nee *NetworkEffectEngine) UpdateFromGlobalData() {
	nee.mu.Lock()
	defer nee.mu.Unlock()

	// Update global threat database
	// In production, this would sync with global threat intelligence feeds
}

// NewMLearningEngine creates ML engine
func NewMLearningEngine() *MLearningEngine {
	return &MLearningEngine{
		models:         make(map[string]*MLModel),
		trainingData:   make([]*TrainingSample, 0),
		featureWeights: make(map[string]float64),
		lastTraining:   time.Now(),
	}
}

// MLThreatAnalysis hasil analisis ML
type MLThreatAnalysis struct {
	ThreatScore  float64
	ThreatTypes  []string
	Confidence   float64
	ModelVersion string
}

func (mle *MLearningEngine) Predict(ip, userAgent, path, method string, headers map[string]string) *MLThreatAnalysis {
	mle.mu.RLock()
	defer mle.mu.RUnlock()

	// Extract features
	features := mle.extractFeatures(ip, userAgent, path, method, headers)

	// Simple ML prediction (in production, use real ML model)
	threatScore := mle.simplePredict(features)

	return &MLThreatAnalysis{
		ThreatScore:  threatScore,
		ThreatTypes:  mle.identifyThreatTypes(features),
		Confidence:   0.85,
		ModelVersion: "1.0.0",
	}
}

func (mle *MLearningEngine) extractFeatures(ip, userAgent, path, method string, headers map[string]string) map[string]float64 {
	features := make(map[string]float64)

	// Path length
	features["path_length"] = float64(len(path))

	// Query parameters count
	if idx := len(path); idx > 0 {
		features["has_query"] = 1.0
	}

	// User agent score
	features["ua_score"] = mle.scoreUserAgent(userAgent)

	// Method score
	features["method_score"] = mle.scoreMethod(method)

	return features
}

func (mle *MLearningEngine) simplePredict(features map[string]float64) float64 {
	score := 0.0

	// Weighted sum
	if pathLen, ok := features["path_length"]; ok && pathLen > 200 {
		score += 0.3
	}

	if uaScore, ok := features["ua_score"]; ok && uaScore < 0.5 {
		score += 0.4
	}

	if methodScore, ok := features["method_score"]; ok && methodScore < 0.3 {
		score += 0.3
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (mle *MLearningEngine) identifyThreatTypes(features map[string]float64) []string {
	types := []string{}

	if uaScore, ok := features["ua_score"]; ok && uaScore < 0.3 {
		types = append(types, "BOT_DETECTED")
	}

	if pathLen, ok := features["path_length"]; ok && pathLen > 500 {
		types = append(types, "SUSPICIOUS_PATH")
	}

	return types
}

func (mle *MLearningEngine) scoreUserAgent(ua string) float64 {
	// Simple scoring (in production, use ML model)
	if ua == "" {
		return 0.0
	}
	if len(ua) < 10 {
		return 0.2
	}
	return 0.8
}

func (mle *MLearningEngine) scoreMethod(method string) float64 {
	switch method {
	case "GET":
		return 0.9
	case "POST":
		return 0.8
	case "PUT", "DELETE":
		return 0.6
	default:
		return 0.3
	}
}

func (mle *MLearningEngine) UpdateModels(samples []*TrainingSample) {
	mle.mu.Lock()
	defer mle.mu.Unlock()

	// Update models based on training data
	// In production, this would retrain ML models
	mle.lastTraining = time.Now()
}

// GetGlobalStats returns global threat intelligence statistics
func (ati *AdvancedThreatIntelligence) GetGlobalStats() map[string]interface{} {
	ati.mu.RLock()
	defer ati.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":       ati.totalRequests,
		"threats_detected":     ati.threatCount,
		"threat_database_size": len(ati.threatDatabase),
		"global_patterns":      len(ati.globalPatterns),
		"network_effects":      ati.networkEffects.GetStats(),
		"ml_models":            ati.learningEngine.GetStats(),
		"last_update":          ati.lastUpdate,
	}
}

func (nee *NetworkEffectEngine) GetStats() map[string]interface{} {
	nee.mu.RLock()
	defer nee.mu.RUnlock()

	return map[string]interface{}{
		"global_threats":  len(nee.globalThreats),
		"threat_clusters": len(nee.threatClusters),
		"correlations":    len(nee.correlationMap),
	}
}

func (mle *MLearningEngine) GetStats() map[string]interface{} {
	mle.mu.RLock()
	defer mle.mu.RUnlock()

	return map[string]interface{}{
		"models":           len(mle.models),
		"training_samples": len(mle.trainingData),
		"last_training":    mle.lastTraining,
	}
}
