package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Advanced features handlers

func (z *ZeinSecuritySystem) getThreatIntelStats(w http.ResponseWriter, r *http.Request) {
	if z.threatIntel == nil {
		http.Error(w, `{"error": "Threat intelligence not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	stats := z.threatIntel.GetGlobalStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getBotDetectionStats(w http.ResponseWriter, r *http.Request) {
	if z.botDetection == nil {
		http.Error(w, `{"error": "Bot detection not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	stats := z.botDetection.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getDDoSStats(w http.ResponseWriter, r *http.Request) {
	if z.ddosMitigation == nil {
		http.Error(w, `{"error": "DDoS mitigation not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	stats := z.ddosMitigation.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getDNSDomains(w http.ResponseWriter, r *http.Request) {
	if z.dnsMode == nil {
		http.Error(w, `{"error": "DNS mode not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	z.dnsMode.mu.RLock()
	domains := make([]*DomainConfig, 0, len(z.dnsMode.domains))
	for _, domain := range z.dnsMode.domains {
		domains = append(domains, domain)
	}
	z.dnsMode.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

func (z *ZeinSecuritySystem) addDNSDomain(w http.ResponseWriter, r *http.Request) {
	if z.dnsMode == nil {
		http.Error(w, `{"error": "DNS mode not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	var domain DomainConfig
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	if err := z.dnsMode.AddDomain(&domain); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domain)
}

func (z *ZeinSecuritySystem) getCDNStats(w http.ResponseWriter, r *http.Request) {
	if z.cdn == nil {
		http.Error(w, `{"error": "CDN not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	stats := z.cdn.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) purgeCDN(w http.ResponseWriter, r *http.Request) {
	if z.cdn == nil {
		http.Error(w, `{"error": "CDN not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	var data map[string]interface{}
	json.NewDecoder(r.Body).Decode(&data)

	pattern := ""
	if p, ok := data["pattern"].(string); ok {
		pattern = p
	}

	count := z.cdn.PurgeCache(pattern)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"purged": count,
	})
}

func (z *ZeinSecuritySystem) getZeroTrustStats(w http.ResponseWriter, r *http.Request) {
	if z.zeroTrust == nil {
		http.Error(w, `{"error": "Zero Trust not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	stats := z.zeroTrust.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (z *ZeinSecuritySystem) getWorkers(w http.ResponseWriter, r *http.Request) {
	if z.workers == nil {
		http.Error(w, `{"error": "Workers not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	z.workers.mu.RLock()
	workers := make([]*Worker, 0, len(z.workers.workers))
	for _, worker := range z.workers.workers {
		workers = append(workers, worker)
	}
	z.workers.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(workers)
}

func (z *ZeinSecuritySystem) createWorker(w http.ResponseWriter, r *http.Request) {
	if z.workers == nil {
		http.Error(w, `{"error": "Workers not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	name := getString(data, "name", "")
	script := getString(data, "script", "")
	runtime := getString(data, "runtime", "javascript")
	triggers := getStringSlice(data, "triggers")

	if name == "" || script == "" {
		http.Error(w, `{"error": "name and script required"}`, http.StatusBadRequest)
		return
	}

	worker, err := z.workers.CreateWorker(name, script, runtime, triggers)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(worker)
}
