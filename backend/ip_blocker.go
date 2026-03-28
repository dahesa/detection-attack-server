package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type IPBlocker struct {
	database   *Database
	redis      *RedisClient
	blockedIPs map[string]*BlockRecord
	mutex      sync.RWMutex
	autoBlock  bool
	aiClient   *AIPythonClient
}

type BlockRecord struct {
	IP           string
	Reason       string
	BlockedAt    time.Time
	BlockedUntil time.Time
	ThreatScore  float64
	AttackType   string
	Source       string // "manual", "auto", "ai", "threat_intel"
	IsActive     bool
}

func NewIPBlocker(database *Database, redis *RedisClient, aiClient *AIPythonClient) *IPBlocker {
	blocker := &IPBlocker{
		database:   database,
		redis:      redis,
		blockedIPs: make(map[string]*BlockRecord),
		autoBlock:  true,
		aiClient:   aiClient,
	}

	// Load existing blocks from database
	go blocker.loadBlocksFromDatabase()

	// Start background tasks
	go blocker.startBackgroundTasks()

	return blocker
}

func (b *IPBlocker) BlockIP(ip, reason, attackType string, threatScore float64, duration time.Duration, source string) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	blockedUntil := time.Now().Add(duration)

	record := &BlockRecord{
		IP:           ip,
		Reason:       reason,
		BlockedAt:    time.Now(),
		BlockedUntil: blockedUntil,
		ThreatScore:  threatScore,
		AttackType:   attackType,
		Source:       source,
		IsActive:     true,
	}

	b.blockedIPs[ip] = record

	// Save to database
	if err := b.saveBlockToDatabase(record); err != nil {
		log.Printf("❌ Failed to save block to database: %v", err)
	}

	// Save to Redis for fast lookup
	if err := b.saveBlockToRedis(record); err != nil {
		log.Printf("❌ Failed to save block to Redis: %v", err)
	}

	// Add to threat intelligence
	if err := b.database.AddThreatIntelligence(
		ip,
		attackType,
		"auto_blocker",
		fmt.Sprintf("Auto-blocked: %s", reason),
		threatScore,
	); err != nil {
		log.Printf("❌ Failed to add threat intelligence: %v", err)
	}

	log.Printf("🚫 IP %s blocked: %s (Type: %s, Score: %.2f, Duration: %v)",
		ip, reason, attackType, threatScore, duration)

	return nil
}

func (b *IPBlocker) IsBlocked(ip string) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	record, exists := b.blockedIPs[ip]
	if !exists {
		// Check Redis cache
		if b.redis != nil {
			if blocked, _ := b.redis.Get(fmt.Sprintf("blocked:ip:%s", ip)); blocked != "" {
				return true
			}
		}
		return false
	}

	// Check if block has expired
	if time.Now().After(record.BlockedUntil) {
		b.mutex.RUnlock()
		b.mutex.Lock()
		delete(b.blockedIPs, ip)
		b.mutex.Unlock()
		b.mutex.RLock()
		return false
	}

	return record.IsActive
}

func (b *IPBlocker) UnblockIP(ip string) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	delete(b.blockedIPs, ip)

	// Remove from Redis
	if b.redis != nil {
		b.redis.Del(fmt.Sprintf("blocked:ip:%s", ip))
	}

	// Update database
	_, err := b.database.Exec(`
		UPDATE ip_blocks 
		SET is_active = false, unblocked_at = $1 
		WHERE ip_address = $2 AND is_active = true
	`, time.Now(), ip)

	if err != nil {
		return err
	}

	log.Printf("✅ IP %s unblocked", ip)
	return nil
}

func (b *IPBlocker) GetBlockedIPs() []BlockRecord {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	records := make([]BlockRecord, 0, len(b.blockedIPs))
	for _, record := range b.blockedIPs {
		if record.IsActive && time.Now().Before(record.BlockedUntil) {
			records = append(records, *record)
		}
	}

	return records
}

func (b *IPBlocker) AutoBlockSuspiciousIP(ip string, threatScore float64, attackType string) error {
	if !b.autoBlock {
		return nil
	}

	// Determine block duration based on threat score
	var duration time.Duration
	if threatScore >= 0.9 {
		duration = 30 * 24 * time.Hour // 30 days
	} else if threatScore >= 0.7 {
		duration = 7 * 24 * time.Hour // 7 days
	} else if threatScore >= 0.5 {
		duration = 24 * time.Hour // 1 day
	} else {
		duration = 1 * time.Hour // 1 hour
	}

	reason := fmt.Sprintf("Auto-blocked due to suspicious activity (Score: %.2f)", threatScore)

	return b.BlockIP(ip, reason, attackType, threatScore, duration, "auto")
}

func (b *IPBlocker) AnalyzeAndBlockFromLogs(logs []LogEntry) error {
	if b.aiClient == nil {
		return fmt.Errorf("AI client not available")
	}

	// Convert logs to format expected by AI
	logData := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		logData[i] = map[string]interface{}{
			"timestamp":      log.Timestamp,
			"ip_address":     log.IPAddress,
			"user_agent":     log.UserAgent,
			"request_method": log.RequestMethod,
			"request_path":   log.RequestPath,
			"request_query":  log.RequestQuery,
			"status_code":    0, // Default
			"threat_score":   log.ThreatScore,
			"details":        log.Details,
		}
	}

	// Analyze logs with AI
	analysis, err := b.aiClient.AnalyzeLogs(logs)
	if err != nil {
		return err
	}

	// Block suspicious IPs
	if analysis.ThreatDetected && len(analysis.SuspiciousIPs) > 0 {
		for _, suspiciousIP := range analysis.SuspiciousIPs {
			ip := suspiciousIP["ip"].(string)
			score := suspiciousIP["score"].(float64)
			reason := suspiciousIP["reason"].(string)

			if score > 0.6 {
				b.AutoBlockSuspiciousIP(ip, score, "LOG_ANALYSIS")
				log.Printf("🤖 AI recommended blocking IP %s (Score: %.2f, Reason: %s)", ip, score, reason)
			}
		}
	}

	return nil
}

func (b *IPBlocker) saveBlockToDatabase(record *BlockRecord) error {
	query := `
		INSERT INTO ip_blocks 
		(ip_address, reason, attack_type, threat_score, blocked_at, blocked_until, source, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (ip_address) 
		DO UPDATE SET 
			reason = EXCLUDED.reason,
			attack_type = EXCLUDED.attack_type,
			threat_score = EXCLUDED.threat_score,
			blocked_at = EXCLUDED.blocked_at,
			blocked_until = EXCLUDED.blocked_until,
			source = EXCLUDED.source,
			is_active = EXCLUDED.is_active
	`

	_, err := b.database.Exec(
		query,
		record.IP,
		record.Reason,
		record.AttackType,
		record.ThreatScore,
		record.BlockedAt,
		record.BlockedUntil,
		record.Source,
		record.IsActive,
	)

	return err
}

func (b *IPBlocker) saveBlockToRedis(record *BlockRecord) error {
	if b.redis == nil {
		return nil
	}

	key := fmt.Sprintf("blocked:ip:%s", record.IP)
	duration := record.BlockedUntil.Sub(time.Now())

	if duration > 0 {
		return b.redis.Set(key, "1", duration)
	}

	return nil
}

func (b *IPBlocker) loadBlocksFromDatabase() {
	query := `
		SELECT ip_address, reason, attack_type, threat_score, 
		       blocked_at, blocked_until, source, is_active
		FROM ip_blocks
		WHERE is_active = true AND blocked_until > NOW()
	`

	rows, err := b.database.Query(query)
	if err != nil {
		log.Printf("❌ Failed to load blocks from database: %v", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var record BlockRecord
		err := rows.Scan(
			&record.IP,
			&record.Reason,
			&record.AttackType,
			&record.ThreatScore,
			&record.BlockedAt,
			&record.BlockedUntil,
			&record.Source,
			&record.IsActive,
		)
		if err != nil {
			continue
		}

		b.mutex.Lock()
		b.blockedIPs[record.IP] = &record
		b.mutex.Unlock()

		// Load to Redis
		b.saveBlockToRedis(&record)

		count++
	}

	log.Printf("✅ Loaded %d blocked IPs from database", count)
}

func (b *IPBlocker) startBackgroundTasks() {
	// Cleanup expired blocks
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		b.cleanupExpiredBlocks()
	}
}

func (b *IPBlocker) cleanupExpiredBlocks() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	now := time.Now()
	expired := []string{}

	for ip, record := range b.blockedIPs {
		if now.After(record.BlockedUntil) {
			expired = append(expired, ip)
		}
	}

	for _, ip := range expired {
		delete(b.blockedIPs, ip)
		if b.redis != nil {
			b.redis.Del(fmt.Sprintf("blocked:ip:%s", ip))
		}
	}

	if len(expired) > 0 {
		log.Printf("🧹 Cleaned up %d expired IP blocks", len(expired))
	}
}
