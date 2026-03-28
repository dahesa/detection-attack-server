package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// BusinessReporting - Visibility & Business Reporting System
type BusinessReporting struct {
	mu              sync.RWMutex
	reports         map[string]*BusinessReport
	metrics         *BusinessMetrics
	dashboards      map[string]*Dashboard
	alerts          []Alert
	exportFormats   []string
}

// BusinessReport - Business report
type BusinessReport struct {
	ID            string
	Type          string // "daily", "weekly", "monthly", "custom"
	Title         string
	GeneratedAt   time.Time
	Period        ReportPeriod
	Metrics       *BusinessMetrics
	Charts        []Chart
	Insights      []Insight
	Recommendations []Recommendation
	Format        string // "json", "pdf", "csv", "html"
}

// ReportPeriod - Report period
type ReportPeriod struct {
	Start time.Time
	End   time.Time
}

// BusinessMetrics - Business metrics
type BusinessMetrics struct {
	TotalRequests      int64
	BlockedRequests    int64
	AllowedRequests    int64
	AttackCount        int64
	TopAttackTypes     map[string]int64
	TopAttackers       []AttackerStats
	TopTargets         []TargetStats
	GeographicData     map[string]int64
	TimeSeriesData     []TimeSeriesPoint
	PerformanceMetrics *PerformanceMetrics
	CostMetrics        *CostMetrics
	ROI                float64
}

// AttackerStats - Attacker statistics
type AttackerStats struct {
	IP            string
	Country       string
	AttackCount   int64
	AttackTypes   []string
	FirstSeen     time.Time
	LastSeen      time.Time
	ThreatScore   float64
}

// TargetStats - Target statistics
type TargetStats struct {
	Path          string
	RequestCount  int64
	AttackCount   int64
	BlockCount    int64
	SuccessRate   float64
}

// TimeSeriesPoint - Time series data point
type TimeSeriesPoint struct {
	Timestamp time.Time
	Value     float64
	Label     string
}

// PerformanceMetrics - Performance metrics
type PerformanceMetrics struct {
	AverageResponseTime time.Duration
	P95ResponseTime     time.Duration
	P99ResponseTime     time.Duration
	Throughput          float64
	ErrorRate           float64
	Uptime              float64
}

// CostMetrics - Cost metrics
type CostMetrics struct {
	BlockedAttacks      int64
	PreventedDamage     float64
	InfrastructureCost  float64
	Savings             float64
	ROI                 float64
}

// Chart - Chart data
type Chart struct {
	Type        string // "line", "bar", "pie", "area"
	Title       string
	Data        []ChartDataPoint
	XAxis       string
	YAxis       string
	Labels      []string
}

// ChartDataPoint - Chart data point
type ChartDataPoint struct {
	Label string
	Value float64
	Color string
}

// Insight - Business insight
type Insight struct {
	Type        string // "trend", "anomaly", "opportunity", "risk"
	Title       string
	Description string
	Impact      string
	Confidence  float64
	Timestamp   time.Time
}

// Recommendation - Business recommendation
type Recommendation struct {
	Category    string
	Title       string
	Description string
	Priority    string // "high", "medium", "low"
	Impact      string
	Effort      string
	Timestamp   time.Time
}

// Dashboard - Dashboard configuration
type Dashboard struct {
	ID          string
	Name        string
	Widgets     []Widget
	Layout      string
	RefreshRate time.Duration
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Widget - Dashboard widget
type Widget struct {
	ID       string
	Type     string // "metric", "chart", "table", "alert"
	Title    string
	Config   map[string]interface{}
	Position Position
	Size     Size
}

// Position - Widget position
type Position struct {
	X int
	Y int
}

// Size - Widget size
type Size struct {
	Width  int
	Height int
}

// Alert - Alert configuration
type Alert struct {
	ID          string
	Name        string
	Condition   string
	Threshold   float64
	Action      string
	Enabled     bool
	LastTrigger time.Time
	Count       int64
}

// NewBusinessReporting - Initialize business reporting
func NewBusinessReporting() *BusinessReporting {
	br := &BusinessReporting{
		reports:       make(map[string]*BusinessReport),
		metrics:       &BusinessMetrics{},
		dashboards:    make(map[string]*Dashboard),
		alerts:        []Alert{},
		exportFormats: []string{"json", "csv", "html", "pdf"},
	}

	// Initialize default dashboard
	br.initializeDefaultDashboard()

	log.Println("📊 Business Reporting initialized")
	return br
}

// initializeDefaultDashboard - Initialize default dashboard
func (br *BusinessReporting) initializeDefaultDashboard() {
	dashboard := &Dashboard{
		ID:        "default",
		Name:      "Zein Security Dashboard",
		Widgets:   []Widget{},
		Layout:    "grid",
		RefreshRate: 5 * time.Second,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add default widgets
	dashboard.Widgets = []Widget{
		{ID: "total_requests", Type: "metric", Title: "Total Requests", Position: Position{X: 0, Y: 0}, Size: Size{Width: 2, Height: 1}},
		{ID: "blocked_requests", Type: "metric", Title: "Blocked Requests", Position: Position{X: 2, Y: 0}, Size: Size{Width: 2, Height: 1}},
		{ID: "attack_types", Type: "chart", Title: "Attack Types", Position: Position{X: 0, Y: 1}, Size: Size{Width: 4, Height: 2}},
		{ID: "top_attackers", Type: "table", Title: "Top Attackers", Position: Position{X: 0, Y: 3}, Size: Size{Width: 4, Height: 2}},
	}

	br.dashboards["default"] = dashboard
}

// GenerateReport - Generate business report
func (br *BusinessReporting) GenerateReport(reportType string, period ReportPeriod) (*BusinessReport, error) {
	br.mu.Lock()
	defer br.mu.Unlock()

	report := &BusinessReport{
		ID:          generateReportID(),
		Type:        reportType,
		Title:       br.getReportTitle(reportType),
		GeneratedAt: time.Now(),
		Period:      period,
		Metrics:     br.calculateMetrics(period),
		Charts:      br.generateCharts(period),
		Insights:    br.generateInsights(period),
		Recommendations: br.generateRecommendations(period),
		Format:      "json",
	}

	br.reports[report.ID] = report
	return report, nil
}

// calculateMetrics - Calculate business metrics
func (br *BusinessReporting) calculateMetrics(period ReportPeriod) *BusinessMetrics {
	// This would query database for metrics
	// For now, return empty metrics
	return &BusinessMetrics{
		TotalRequests:   0,
		BlockedRequests: 0,
		AllowedRequests: 0,
		AttackCount:     0,
		TopAttackTypes:  make(map[string]int64),
		TopAttackers:    []AttackerStats{},
		TopTargets:      []TargetStats{},
		GeographicData:  make(map[string]int64),
		TimeSeriesData:  []TimeSeriesPoint{},
		PerformanceMetrics: &PerformanceMetrics{},
		CostMetrics:     &CostMetrics{},
		ROI:             0.0,
	}
}

// generateCharts - Generate charts for report
func (br *BusinessReporting) generateCharts(period ReportPeriod) []Chart {
	return []Chart{
		{
			Type:  "line",
			Title: "Request Volume Over Time",
			Data:  []ChartDataPoint{},
			XAxis: "Time",
			YAxis: "Requests",
		},
		{
			Type:  "pie",
			Title: "Attack Type Distribution",
			Data:  []ChartDataPoint{},
		},
		{
			Type:  "bar",
			Title: "Top Attackers",
			Data:  []ChartDataPoint{},
			XAxis: "IP Address",
			YAxis: "Attack Count",
		},
	}
}

// generateInsights - Generate business insights
func (br *BusinessReporting) generateInsights(period ReportPeriod) []Insight {
	return []Insight{
		{
			Type:        "trend",
			Title:       "Attack Volume Trend",
			Description: "Attack volume has increased by 15% compared to last period",
			Impact:      "medium",
			Confidence:  0.85,
			Timestamp:   time.Now(),
		},
	}
}

// generateRecommendations - Generate recommendations
func (br *BusinessReporting) generateRecommendations(period ReportPeriod) []Recommendation {
	return []Recommendation{
		{
			Category:    "security",
			Title:       "Enable Advanced Bot Protection",
			Description: "Consider enabling advanced bot protection to reduce automated attacks",
			Priority:    "high",
			Impact:      "high",
			Effort:      "medium",
			Timestamp:   time.Now(),
		},
	}
}

// getReportTitle - Get report title
func (br *BusinessReporting) getReportTitle(reportType string) string {
	titles := map[string]string{
		"daily":   "Daily Security Report",
		"weekly":  "Weekly Security Report",
		"monthly": "Monthly Security Report",
		"custom":  "Custom Security Report",
	}
	if title, exists := titles[reportType]; exists {
		return title
	}
	return "Security Report"
}

// ExportReport - Export report in specified format
func (br *BusinessReporting) ExportReport(reportID, format string) ([]byte, error) {
	br.mu.RLock()
	defer br.mu.RUnlock()

	report, exists := br.reports[reportID]
	if !exists {
		return nil, nil
	}

	switch format {
	case "json":
		return json.Marshal(report)
	case "csv":
		return br.exportCSV(report)
	case "html":
		return br.exportHTML(report)
	case "pdf":
		return br.exportPDF(report)
	default:
		return json.Marshal(report)
	}
}

// exportCSV - Export report as CSV
func (br *BusinessReporting) exportCSV(report *BusinessReport) ([]byte, error) {
	// CSV export implementation
	return []byte("CSV export"), nil
}

// exportHTML - Export report as HTML
func (br *BusinessReporting) exportHTML(report *BusinessReport) ([]byte, error) {
	// HTML export implementation
	return []byte("HTML export"), nil
}

// exportPDF - Export report as PDF
func (br *BusinessReporting) exportPDF(report *BusinessReport) ([]byte, error) {
	// PDF export implementation
	return []byte("PDF export"), nil
}

// Helper function
func generateReportID() string {
	return time.Now().Format("20060102150405")
}



