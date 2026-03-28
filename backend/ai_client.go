package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AIPythonClient struct {
	endpoint string
	client   *http.Client
}

type AIThreatAnalysisRequest struct {
	RequestData map[string]interface{} `json:"request_data"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	LogData     []LogEntry             `json:"log_data,omitempty"`
}

type AIThreatAnalysisResponse struct {
	ThreatDetected  bool                     `json:"threat_detected"`
	ThreatScore     float64                  `json:"threat_score"`
	RiskLevel       string                   `json:"risk_level"`
	Confidence      float64                  `json:"confidence"`
	DetectedAttacks []string                 `json:"detected_attacks"`
	Recommendation  string                   `json:"recommendation"`
	QuantumAnalysis string                   `json:"quantum_analysis"`
	SuspiciousIPs   []map[string]interface{} `json:"suspicious_ips,omitempty"`
}

type AIChatRequest struct {
	Message string                 `json:"message"`
	Context map[string]interface{} `json:"context,omitempty"`
}

type AIChatResponse struct {
	Response       string `json:"response"`
	Timestamp      string `json:"timestamp"`
	ContextUsed    bool   `json:"context_used"`
	ConversationID string `json:"conversation_id"`
}

type LogEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	RequestMethod string                 `json:"request_method"`
	RequestPath   string                 `json:"request_path"`
	RequestQuery  string                 `json:"request_query"`
	StatusCode    int                    `json:"status_code"`
	ThreatScore   float64                `json:"threat_score"`
	Details       map[string]interface{} `json:"details"`
}

func NewAIPythonClient(endpoint string) *AIPythonClient {
	return &AIPythonClient{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *AIPythonClient) AnalyzeThreat(requestData map[string]interface{}, ip, userAgent string) (*AIThreatAnalysisResponse, error) {
	req := AIThreatAnalysisRequest{
		RequestData: requestData,
		IPAddress:   ip,
		UserAgent:   userAgent,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(
		c.endpoint+"/analyze-threat",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AI service error: %s", string(body))
	}

	var analysis AIThreatAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}

func (c *AIPythonClient) AnalyzeLogs(logs []LogEntry) (*AIThreatAnalysisResponse, error) {
	if len(logs) == 0 {
		return &AIThreatAnalysisResponse{
			ThreatDetected:  false,
			ThreatScore:     0.0,
			RiskLevel:       "LOW",
			Confidence:      0.0,
			DetectedAttacks: []string{},
			Recommendation:  "No threats detected",
			QuantumAnalysis: "QUANTUM_AI_CLEAN",
		}, nil
	}

	// Convert logs to format expected by Python service
	logData := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		logData[i] = map[string]interface{}{
			"timestamp":      log.Timestamp.Format(time.RFC3339),
			"ip_address":     log.IPAddress,
			"user_agent":     log.UserAgent,
			"request_method": log.RequestMethod,
			"request_path":   log.RequestPath,
			"request_query":  log.RequestQuery,
			"status_code":    log.StatusCode,
			"threat_score":   log.ThreatScore,
			"details":        log.Details,
		}
	}

	req := map[string]interface{}{
		"log_data": logData,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(
		c.endpoint+"/analyze-logs",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AI service error: %s", string(body))
	}

	var analysis map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, err
	}

	// Convert response to AIThreatAnalysisResponse
	result := &AIThreatAnalysisResponse{
		ThreatDetected:  getBoolFromMap(analysis, "threat_detected", false),
		ThreatScore:     getFloatFromMap(analysis, "threat_score", 0.0),
		RiskLevel:       getStringFromMap(analysis, "risk_level", "LOW"),
		Confidence:      getFloatFromMap(analysis, "threat_score", 0.0),
		DetectedAttacks: []string{},
		Recommendation:  getStringFromMap(analysis, "recommendations", ""),
		QuantumAnalysis: "QUANTUM_AI_ANALYSIS",
	}

	return result, nil
}

func getBoolFromMap(m map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return defaultValue
}

func getFloatFromMap(m map[string]interface{}, key string, defaultValue float64) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	return defaultValue
}

func getStringFromMap(m map[string]interface{}, key string, defaultValue string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return defaultValue
}

func (c *AIPythonClient) Chat(message string, context map[string]interface{}) (string, error) {
	req := AIChatRequest{
		Message: message,
		Context: context,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := c.client.Post(
		c.endpoint+"/chat",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to connect to AI service at %s: %v", c.endpoint+"/chat", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("AI service returned status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp AIChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("failed to decode AI response: %v (body: %s)", err, string(body))
	}

	if chatResp.Response == "" {
		return "", fmt.Errorf("AI service returned empty response")
	}

	return chatResp.Response, nil
}

func (c *AIPythonClient) Health() (map[string]interface{}, error) {
	resp, err := c.client.Get(c.endpoint + "/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, err
	}

	return health, nil
}
