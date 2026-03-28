package main

import (
	"log"
	"sync"
	"time"
)

type AdvancedMonitorEngine struct {
	stats      *MonitorStats
	statsMutex sync.RWMutex

	alerts      []AdvancedAlert
	alertsMutex sync.RWMutex

	events      []SecurityEvent
	eventsMutex sync.RWMutex
}

type MonitorStats struct {
	TotalRequests     int64
	BlockedRequests   int64
	SQLInjection      int64
	XSSAttempts       int64
	BruteForce        int64
	ZeroDayAttempts   int64
	DDoSAttempts      int64
	PathTraversal     int64
	CommandInjection  int64
	XXEAttempts       int64
	Deserialization   int64
	BlockRate         float64
	ThreatActors      int64
	RequestsPerSecond float64
	LastUpdated       time.Time
}

type AdvancedAlert struct {
	ID        string
	Severity  string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Type      string
	Message   string
	Timestamp time.Time
	IP        string
	Details   map[string]interface{}
}

type SecurityEvent struct {
	ID            int
	EventType     string
	IPAddress     string
	UserAgent     string
	RequestMethod string
	RequestPath   string
	RequestQuery  string
	ThreatScore   float64
	Severity      string
	Blocked       bool
	Details       string
	Timestamp     time.Time
}

type SystemMetric struct {
	Name      string
	Value     float64
	Timestamp time.Time
}

type MonitorThreatIntelligence struct {
	IPAddress       string
	ThreatType      string
	ConfidenceScore float64
	FirstSeen       time.Time
	LastSeen        time.Time
	Source          string
	Description     string
}

func NewAdvancedMonitorEngine() *AdvancedMonitorEngine {
	return &AdvancedMonitorEngine{
		stats: &MonitorStats{
			LastUpdated: time.Now(),
		},
		alerts: make([]AdvancedAlert, 0),
		events: make([]SecurityEvent, 0),
	}
}

func (m *AdvancedMonitorEngine) GetStats() MonitorStats {
	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()

	stats := *m.stats

	// Calculate block rate
	if stats.TotalRequests > 0 {
		stats.BlockRate = float64(stats.BlockedRequests) / float64(stats.TotalRequests) * 100
	}

	return stats
}

func (m *AdvancedMonitorEngine) IncrementRequest() {
	m.statsMutex.Lock()
	defer m.statsMutex.Unlock()
	m.stats.TotalRequests++
	m.stats.LastUpdated = time.Now()
}

func (m *AdvancedMonitorEngine) IncrementBlocked() {
	m.statsMutex.Lock()
	defer m.statsMutex.Unlock()
	m.stats.BlockedRequests++
}

func (m *AdvancedMonitorEngine) IncrementAttack(attackType string) {
	m.statsMutex.Lock()
	defer m.statsMutex.Unlock()

	switch attackType {
	case "SQL_INJECTION":
		m.stats.SQLInjection++
	case "XSS":
		m.stats.XSSAttempts++
	case "BRUTE_FORCE":
		m.stats.BruteForce++
	case "ZERO_DAY":
		m.stats.ZeroDayAttempts++
	case "DDOS":
		m.stats.DDoSAttempts++
	case "PATH_TRAVERSAL":
		m.stats.PathTraversal++
	case "COMMAND_INJECTION":
		m.stats.CommandInjection++
	case "XXE":
		m.stats.XXEAttempts++
	case "DESERIALIZATION":
		m.stats.Deserialization++
	}
}

func (m *AdvancedMonitorEngine) AddAlert(alert AdvancedAlert) {
	m.alertsMutex.Lock()
	defer m.alertsMutex.Unlock()

	alert.ID = generateAlertID()
	alert.Timestamp = time.Now()

	m.alerts = append(m.alerts, alert)

	// Keep only last 1000 alerts
	if len(m.alerts) > 1000 {
		m.alerts = m.alerts[len(m.alerts)-1000:]
	}

	log.Printf("🚨 Alert [%s] %s: %s", alert.Severity, alert.Type, alert.Message)
}

func (m *AdvancedMonitorEngine) GetAlerts(limit int) []AdvancedAlert {
	m.alertsMutex.RLock()
	defer m.alertsMutex.RUnlock()

	if limit > len(m.alerts) {
		limit = len(m.alerts)
	}

	start := len(m.alerts) - limit
	if start < 0 {
		start = 0
	}

	alerts := make([]AdvancedAlert, limit)
	copy(alerts, m.alerts[start:])

	return alerts
}

func (m *AdvancedMonitorEngine) AddEvent(event SecurityEvent) {
	m.eventsMutex.Lock()
	defer m.eventsMutex.Unlock()

	event.Timestamp = time.Now()
	m.events = append(m.events, event)

	// Keep only last 10000 events
	if len(m.events) > 10000 {
		m.events = m.events[len(m.events)-10000:]
	}
}

func (m *AdvancedMonitorEngine) GetEvents(limit int) []SecurityEvent {
	m.eventsMutex.RLock()
	defer m.eventsMutex.RUnlock()

	if limit > len(m.events) {
		limit = len(m.events)
	}

	start := len(m.events) - limit
	if start < 0 {
		start = 0
	}

	events := make([]SecurityEvent, limit)
	copy(events, m.events[start:])

	return events
}

func generateAlertID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
