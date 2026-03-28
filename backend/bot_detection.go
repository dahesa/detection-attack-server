package main

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// BotDetectionEngine engine untuk deteksi bot dengan behavioral analysis
type BotDetectionEngine struct {
	mu               sync.RWMutex
	behaviorProfiles map[string]*BehaviorProfile
	botSignatures    map[string]*BotSignature
	mlModel          *BotMLModel
	lastUpdate       time.Time
}

// BehaviorProfile profil perilaku user
type BehaviorProfile struct {
	IP              string
	SessionID       string
	RequestTiming   []time.Duration
	MouseMovements  []MouseEvent
	ClickPatterns   []ClickEvent
	ScrollPatterns  []ScrollEvent
	KeystrokeTiming []KeystrokeEvent
	UserAgent       string
	ScreenSize      string
	Timezone        string
	Language        string
	IsHuman         bool
	Confidence      float64
	LastActivity    time.Time
	CreatedAt       time.Time
}

// MouseEvent event mouse movement
type MouseEvent struct {
	X            int
	Y            int
	Timestamp    time.Time
	Velocity     float64
	Acceleration float64
}

// ClickEvent event click
type ClickEvent struct {
	X         int
	Y         int
	Button    int
	Timestamp time.Time
	Duration  time.Duration
}

// ScrollEvent event scroll
type ScrollEvent struct {
	Delta     int
	Timestamp time.Time
	Direction string
}

// KeystrokeEvent event keystroke
type KeystrokeEvent struct {
	Key       string
	Timestamp time.Time
	Duration  time.Duration
}

// BotSignature signature bot yang diketahui
type BotSignature struct {
	Name        string
	Pattern     string
	UserAgents  []string
	Behavior    *BotBehavior
	ThreatLevel string
	Confidence  float64
}

// BotBehavior perilaku bot
type BotBehavior struct {
	RequestRate   float64
	TimingPattern []float64
	PathPattern   []string
	HeaderPattern map[string]string
	NoJavaScript  bool
	NoCookies     bool
	PerfectTiming bool
}

// BotMLModel model ML untuk bot detection
type BotMLModel struct {
	Version     string
	Accuracy    float64
	Features    []string
	Weights     map[string]float64
	LastTrained time.Time
}

// NewBotDetectionEngine creates new bot detection engine
func NewBotDetectionEngine() *BotDetectionEngine {
	bde := &BotDetectionEngine{
		behaviorProfiles: make(map[string]*BehaviorProfile),
		botSignatures:    make(map[string]*BotSignature),
		mlModel:          NewBotMLModel(),
		lastUpdate:       time.Now(),
	}

	// Load known bot signatures
	bde.loadKnownBots()

	// Start background analysis
	go bde.startAnalysisLoop()

	return bde
}

// AnalyzeRequest analyzes request untuk deteksi bot
func (bde *BotDetectionEngine) AnalyzeRequest(ip, userAgent, sessionID string, requestTime time.Time, behavioralData map[string]interface{}) *BotAnalysis {
	bde.mu.Lock()
	defer bde.mu.Unlock()

	// Get or create behavior profile
	profile := bde.getOrCreateProfile(ip, sessionID, userAgent)

	// Update profile dengan behavioral data
	bde.updateProfile(profile, behavioralData, requestTime)

	// Analyze dengan signature matching
	signatureMatch := bde.matchBotSignature(userAgent, profile)

	// Analyze dengan behavioral analysis
	behavioralScore := bde.analyzeBehavior(profile)

	// Analyze dengan ML
	mlScore := bde.mlModel.Predict(profile)

	// Combine scores
	finalScore := bde.combineScores(signatureMatch, behavioralScore, mlScore)

	// Determine if bot
	isBot := finalScore > 0.7

	profile.IsHuman = !isBot
	profile.Confidence = finalScore
	profile.LastActivity = requestTime

	return &BotAnalysis{
		IsBot:           isBot,
		Confidence:      finalScore,
		BotType:         signatureMatch.BotType,
		BehavioralScore: behavioralScore,
		MLScore:         mlScore,
		Recommendation:  bde.getRecommendation(isBot, finalScore),
	}
}

// BotAnalysis hasil analisis bot
type BotAnalysis struct {
	IsBot           bool
	Confidence      float64
	BotType         string
	BehavioralScore float64
	MLScore         float64
	Recommendation  string
}

// SignatureMatch hasil matching signature
type SignatureMatch struct {
	Matched    bool
	BotType    string
	Confidence float64
}

func (bde *BotDetectionEngine) getOrCreateProfile(ip, sessionID, userAgent string) *BehaviorProfile {
	key := fmt.Sprintf("%s:%s", ip, sessionID)

	if profile, exists := bde.behaviorProfiles[key]; exists {
		return profile
	}

	profile := &BehaviorProfile{
		IP:              ip,
		SessionID:       sessionID,
		UserAgent:       userAgent,
		RequestTiming:   make([]time.Duration, 0),
		MouseMovements:  make([]MouseEvent, 0),
		ClickPatterns:   make([]ClickEvent, 0),
		ScrollPatterns:  make([]ScrollEvent, 0),
		KeystrokeTiming: make([]KeystrokeEvent, 0),
		IsHuman:         true,
		Confidence:      0.5,
		CreatedAt:       time.Now(),
		LastActivity:    time.Now(),
	}

	bde.behaviorProfiles[key] = profile
	return profile
}

func (bde *BotDetectionEngine) updateProfile(profile *BehaviorProfile, behavioralData map[string]interface{}, requestTime time.Time) {
	// Update request timing
	if lastTime := profile.LastActivity; !lastTime.IsZero() {
		profile.RequestTiming = append(profile.RequestTiming, requestTime.Sub(lastTime))
		// Keep only last 100 timings
		if len(profile.RequestTiming) > 100 {
			profile.RequestTiming = profile.RequestTiming[len(profile.RequestTiming)-100:]
		}
	}

	// Update mouse movements
	if mouseData, ok := behavioralData["mouse"].([]interface{}); ok {
		for _, m := range mouseData {
			if mouse, ok := m.(map[string]interface{}); ok {
				profile.MouseMovements = append(profile.MouseMovements, MouseEvent{
					X:         int(mouse["x"].(float64)),
					Y:         int(mouse["y"].(float64)),
					Timestamp: requestTime,
				})
			}
		}
		// Keep only last 50 movements
		if len(profile.MouseMovements) > 50 {
			profile.MouseMovements = profile.MouseMovements[len(profile.MouseMovements)-50:]
		}
	}

	// Update click patterns
	if clickData, ok := behavioralData["clicks"].([]interface{}); ok {
		for _, c := range clickData {
			if click, ok := c.(map[string]interface{}); ok {
				profile.ClickPatterns = append(profile.ClickPatterns, ClickEvent{
					X:         int(click["x"].(float64)),
					Y:         int(click["y"].(float64)),
					Timestamp: requestTime,
				})
			}
		}
	}

	// Update scroll patterns
	if scrollData, ok := behavioralData["scrolls"].([]interface{}); ok {
		for _, s := range scrollData {
			if scroll, ok := s.(map[string]interface{}); ok {
				profile.ScrollPatterns = append(profile.ScrollPatterns, ScrollEvent{
					Delta:     int(scroll["delta"].(float64)),
					Timestamp: requestTime,
				})
			}
		}
	}
}

func (bde *BotDetectionEngine) matchBotSignature(userAgent string, profile *BehaviorProfile) *SignatureMatch {
	uaLower := strings.ToLower(userAgent)

	// Check known bot signatures
	for _, sig := range bde.botSignatures {
		for _, botUA := range sig.UserAgents {
			if strings.Contains(uaLower, strings.ToLower(botUA)) {
				return &SignatureMatch{
					Matched:    true,
					BotType:    sig.Name,
					Confidence: sig.Confidence,
				}
			}
		}
	}

	// Check common bot patterns
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "python-requests",
		"go-http-client", "java/", "apache",
	}

	for _, pattern := range botPatterns {
		if strings.Contains(uaLower, pattern) {
			return &SignatureMatch{
				Matched:    true,
				BotType:    "GENERIC_BOT",
				Confidence: 0.6,
			}
		}
	}

	return &SignatureMatch{
		Matched:    false,
		Confidence: 0.0,
	}
}

func (bde *BotDetectionEngine) analyzeBehavior(profile *BehaviorProfile) float64 {
	score := 0.0
	factors := 0

	// 1. Request timing analysis
	if len(profile.RequestTiming) > 10 {
		avgTiming := bde.calculateAverageTiming(profile.RequestTiming)
		stdDev := bde.calculateStdDev(profile.RequestTiming, avgTiming)

		// Perfect timing = bot
		if stdDev < 0.1 {
			score += 0.3
		}
		// Human timing has variation
		if stdDev > 0.5 {
			score -= 0.2
		}
		factors++
	}

	// 2. Mouse movement analysis
	if len(profile.MouseMovements) > 5 {
		// Calculate mouse velocity variance
		velocities := make([]float64, 0)
		for i := 1; i < len(profile.MouseMovements); i++ {
			prev := profile.MouseMovements[i-1]
			curr := profile.MouseMovements[i]
			dist := math.Sqrt(float64((curr.X-prev.X)*(curr.X-prev.X) + (curr.Y-prev.Y)*(curr.Y-prev.Y)))
			timeDiff := curr.Timestamp.Sub(prev.Timestamp).Seconds()
			if timeDiff > 0 {
				velocities = append(velocities, dist/timeDiff)
			}
		}

		if len(velocities) > 0 {
			velStdDev := bde.calculateStdDevFloat(velocities, bde.calculateAverageFloat(velocities))
			// Low variance = bot (linear movement)
			if velStdDev < 10 {
				score += 0.2
			}
		}
		factors++
	}

	// 3. Click pattern analysis
	if len(profile.ClickPatterns) > 5 {
		// Perfect click timing = bot
		clickIntervals := make([]float64, 0)
		for i := 1; i < len(profile.ClickPatterns); i++ {
			interval := profile.ClickPatterns[i].Timestamp.Sub(profile.ClickPatterns[i-1].Timestamp).Seconds()
			clickIntervals = append(clickIntervals, interval)
		}

		if len(clickIntervals) > 0 {
			clickStdDev := bde.calculateStdDevFloat(clickIntervals, bde.calculateAverageFloat(clickIntervals))
			if clickStdDev < 0.1 {
				score += 0.2
			}
		}
		factors++
	}

	// 4. No behavioral data = suspicious
	if len(profile.MouseMovements) == 0 && len(profile.ClickPatterns) == 0 {
		score += 0.3
		factors++
	}

	// Normalize
	if factors > 0 {
		score = score / float64(factors)
	}

	if score < 0 {
		score = 0
	}
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (bde *BotDetectionEngine) combineScores(signature *SignatureMatch, behavioral, ml float64) float64 {
	weights := map[string]float64{
		"signature":  0.3,
		"behavioral": 0.4,
		"ml":         0.3,
	}

	score := 0.0
	if signature.Matched {
		score += signature.Confidence * weights["signature"]
	}
	score += behavioral * weights["behavioral"]
	score += ml * weights["ml"]

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (bde *BotDetectionEngine) getRecommendation(isBot bool, confidence float64) string {
	if isBot && confidence > 0.9 {
		return "BLOCK_IMMEDIATELY"
	}
	if isBot && confidence > 0.7 {
		return "BLOCK_AND_CHALLENGE"
	}
	if confidence > 0.5 {
		return "CHALLENGE_CAPTCHA"
	}
	return "ALLOW"
}

func (bde *BotDetectionEngine) loadKnownBots() {
	// Load known bot signatures
	knownBots := []*BotSignature{
		{
			Name:        "Googlebot",
			UserAgents:  []string{"Googlebot", "Google-InspectionTool"},
			ThreatLevel: "LOW",
			Confidence:  0.9,
		},
		{
			Name:        "Bingbot",
			UserAgents:  []string{"bingbot", "BingPreview"},
			ThreatLevel: "LOW",
			Confidence:  0.9,
		},
		{
			Name:        "Scraper",
			UserAgents:  []string{"Scrapy", "scraper", "crawler"},
			ThreatLevel: "HIGH",
			Confidence:  0.8,
		},
	}

	for _, bot := range knownBots {
		bde.botSignatures[bot.Name] = bot
	}
}

func (bde *BotDetectionEngine) startAnalysisLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bde.cleanupOldProfiles()
	}
}

func (bde *BotDetectionEngine) cleanupOldProfiles() {
	bde.mu.Lock()
	defer bde.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for key, profile := range bde.behaviorProfiles {
		if profile.LastActivity.Before(cutoff) {
			delete(bde.behaviorProfiles, key)
		}
	}
}

// Helper functions
func (bde *BotDetectionEngine) calculateAverageTiming(timings []time.Duration) float64 {
	if len(timings) == 0 {
		return 0
	}
	sum := 0.0
	for _, t := range timings {
		sum += t.Seconds()
	}
	return sum / float64(len(timings))
}

func (bde *BotDetectionEngine) calculateStdDev(timings []time.Duration, mean float64) float64 {
	if len(timings) == 0 {
		return 0
	}
	sum := 0.0
	for _, t := range timings {
		diff := t.Seconds() - mean
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(timings)))
}

func (bde *BotDetectionEngine) calculateAverageFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (bde *BotDetectionEngine) calculateStdDevFloat(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		diff := v - mean
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(values)))
}

// NewBotMLModel creates new ML model
func NewBotMLModel() *BotMLModel {
	return &BotMLModel{
		Version:     "1.0.0",
		Accuracy:    0.92,
		Features:    []string{"timing", "mouse", "clicks", "scrolls", "keystrokes"},
		Weights:     make(map[string]float64),
		LastTrained: time.Now(),
	}
}

func (bml *BotMLModel) Predict(profile *BehaviorProfile) float64 {
	// Simple ML prediction (in production, use real ML model)
	score := 0.5

	// Feature-based scoring
	if len(profile.RequestTiming) > 0 {
		avg := calculateAverageTimingHelper(profile.RequestTiming)
		if avg < 0.1 {
			score += 0.2 // Too fast = bot
		}
	}

	if len(profile.MouseMovements) == 0 {
		score += 0.2 // No mouse = bot
	}

	if len(profile.ClickPatterns) == 0 {
		score += 0.1 // No clicks = suspicious
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func calculateAverageTimingHelper(timings []time.Duration) float64 {
	if len(timings) == 0 {
		return 0
	}
	sum := 0.0
	for _, t := range timings {
		sum += t.Seconds()
	}
	return sum / float64(len(timings))
}

// GetStats returns bot detection statistics
func (bde *BotDetectionEngine) GetStats() map[string]interface{} {
	bde.mu.RLock()
	defer bde.mu.RUnlock()

	botCount := 0
	humanCount := 0
	for _, profile := range bde.behaviorProfiles {
		if profile.IsHuman {
			humanCount++
		} else {
			botCount++
		}
	}

	return map[string]interface{}{
		"total_profiles": len(bde.behaviorProfiles),
		"bot_count":      botCount,
		"human_count":    humanCount,
		"known_bots":     len(bde.botSignatures),
		"ml_model":       bde.mlModel,
	}
}
