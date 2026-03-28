package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OWASP Top 10 Attack Types
const (
	OWASP_INJECTION          = "A01:2021-Injection"
	OWASP_BROKEN_AUTH        = "A02:2021-Broken Authentication"
	OWASP_SENSITIVE_DATA     = "A03:2021-Sensitive Data Exposure"
	OWASP_XXE                = "A04:2021-XML External Entities"
	OWASP_BROKEN_ACCESS      = "A05:2021-Broken Access Control"
	OWASP_SECURITY_MISCONFIG = "A06:2021-Security Misconfiguration"
	OWASP_XSS                = "A07:2021-Cross-Site Scripting"
	OWASP_INsecure_DESERIAL  = "A08:2021-Insecure Deserialization"
	OWASP_KNOWN_VULN         = "A09:2021-Known Vulnerabilities"
	OWASP_LOGGING            = "A10:2021-Insufficient Logging"
)

type ZeinSecurityUltimate struct {
	// Pattern matching
	sqlInjectionPatterns     []*regexp.Regexp
	xssPatterns              []*regexp.Regexp
	pathTraversalPatterns    []*regexp.Regexp
	commandInjectionPatterns []*regexp.Regexp
	xxePatterns              []*regexp.Regexp
	deserializationPatterns  []*regexp.Regexp

	// Rate limiting
	rateLimiter *RateLimiter
	ipBlockList *IPBlockList

	// Behavioral analysis
	ipBehaviorMap map[string]*IPBehavior
	behaviorMutex sync.RWMutex

	// Threat intelligence
	threatIntelligence *ThreatIntelligence

	// Configuration
	config *WAFConfig
}

type WAFConfig struct {
	Enabled                  bool
	ProtectionLevel          string // "low", "medium", "high", "paranoid"
	MaxRequestSize           int64
	RateLimitRequests        int
	RateLimitWindow          time.Duration
	BlockDuration            time.Duration
	EnableAI                 bool
	EnableBehavioralAnalysis bool
}

type IPBehavior struct {
	IP             string
	RequestCount   int
	ThreatScore    float64
	LastRequest    time.Time
	AttackPatterns []string
	BlockedUntil   *time.Time
	FirstSeen      time.Time
}

type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

type IPBlockList struct {
	blockedIPs map[string]*BlockEntry
	mutex      sync.RWMutex
}

type BlockEntry struct {
	IP           string
	Reason       string
	BlockedAt    time.Time
	BlockedUntil time.Time
	ThreatScore  float64
	AttackType   string
}

type ThreatIntelligence struct {
	knownThreats map[string]*ThreatInfo
	mutex        sync.RWMutex
}

type ThreatInfo struct {
	IP          string
	ThreatTypes []string
	Confidence  float64
	LastSeen    time.Time
	Source      string
}

func InitZeinSecurityUltimate() *ZeinSecurityUltimate {
	waf := &ZeinSecurityUltimate{
		sqlInjectionPatterns:     loadSQLInjectionPatterns(),
		xssPatterns:              loadXSSPatterns(),
		pathTraversalPatterns:    loadPathTraversalPatterns(),
		commandInjectionPatterns: loadCommandInjectionPatterns(),
		xxePatterns:              loadXXEPatterns(),
		deserializationPatterns:  loadDeserializationPatterns(),
		rateLimiter:              NewRateLimiter(10, time.Minute), // CLOUDFLARE ENTERPRISE+: 10 requests per minute
		ipBlockList:              NewIPBlockList(),
		ipBehaviorMap:            make(map[string]*IPBehavior),
		threatIntelligence:       NewThreatIntelligence(),
		config: &WAFConfig{
			Enabled:                  true,
			ProtectionLevel:          "paranoid", // LEVEL DEWA: Super ketat
			MaxRequestSize:           5 * 1024 * 1024, // 5MB (lebih ketat)
			RateLimitRequests:        20, // LEVEL DEWA: 20 requests per minute (sangat ketat)
			RateLimitWindow:          time.Minute,
			BlockDuration:            48 * time.Hour, // Block 48 jam (lebih lama)
			EnableAI:                 true,
			EnableBehavioralAnalysis: true,
		},
	}

	log.Println("🛡️ Zein Security Ultimate WAF initialized")
	log.Printf("📊 Protection Level: %s", waf.config.ProtectionLevel)
	log.Printf("🔒 OWASP Top 10 Protection: ENABLED")

	return waf
}

// OWASP Top 10 Pattern Loaders
func loadSQLInjectionPatterns() []*regexp.Regexp {
	patterns := []string{
		// Basic SQL injection
		`(?i)(union\s+(all\s+)?select|select\s+.*\s+from)`,
		`(?i)(insert\s+into|update\s+.*\s+set|delete\s+from)`,
		`(?i)(drop\s+(table|database|schema|view|index|trigger|procedure|function)|alter\s+table|truncate\s+table)`,
		`(?i)(--|\#|\/\*|\*\/|waitfor\s+delay|sleep\s*\(|benchmark\s*\()`,
		`(?i)(exec\s*\(|execute\s*\(|sp_|xp_|dbo\.|sys\.)`,
		`(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+"1"\s*=\s*"1"|or\s+true|or\s+1=1)`,
		`(?i)(and\s+1\s*=\s*1|and\s+'1'\s*=\s*'1'|and\s+true|and\s+1=1)`,
		`(?i)(';?\s*(or|and)\s+.*\s*=\s*.*|';?\s*(or|and)\s+.*\s*like\s*|';?\s*(or|and)\s+.*\s*in\s*\()`,
		`(?i)(benchmark\s*\(|pg_sleep\s*\(|sleep\s*\(|waitfor\s+delay|dbms_pipe\.receive_message)`,
		// MySQL-specific time-based SQLi patterns
		`(?i)(SELECT\s+IF\s*\(|IF\s*\(\s*\d+\s*=\s*\d+)`,
		`(?i)(benchmark\s*\(\s*\d+\s*,\s*md5\s*\()`,
		`(?i)(\|\|\s*\(SELECT|%27\|\|\(SELECT)`, // URL encoded: '||(SELECT
		`(?i)(%27%7C%7C%28SELECT)`, // Double URL encoded: '||(SELECT
		`(?i)(information_schema|sys\.|mysql\.|pg_|sys\.|master\.|msdb\.)`,
		
		// Advanced SQL injection
		`(?i)(union\s+select\s+null|union\s+select\s+1|union\s+select\s+@@version)`,
		`(?i)(';?\s*drop\s+table|';?\s*delete\s+from|';?\s*truncate\s+table)`,
		`(?i)(';?\s*exec\s*\(|';?\s*execute\s*\(|';?\s*sp_executesql)`,
		`(?i)(';?\s*insert\s+into|';?\s*update\s+.*\s+set|';?\s*delete\s+from)`,
		`(?i)(';?\s*create\s+table|';?\s*alter\s+table|';?\s*create\s+database)`,
		`(?i)(';?\s*grant\s+|';?\s*revoke\s+|';?\s*deny\s+)`,
		
		// Time-based SQL injection
		`(?i)(sleep\s*\(\s*\d+|waitfor\s+delay\s+['"]\d+|benchmark\s*\(\s*\d+)`,
		`(?i)(pg_sleep\s*\(|dbms_pipe\.receive_message|dbms_lock\.sleep)`,
		
		// Boolean-based SQL injection
		`(?i)(and\s+.*\s*=\s*.*|or\s+.*\s*=\s*.*|and\s+.*\s*like\s*.*|or\s+.*\s*like\s*.*)`,
		`(?i)(and\s+.*\s*>\s*.*|or\s+.*\s*>\s*.*|and\s+.*\s*<\s*.*|or\s+.*\s*<\s*.*)`,
		
		// Error-based SQL injection
		`(?i)(extractvalue\s*\(|updatexml\s*\(|exp\s*\(|floor\s*\(|rand\s*\()`,
		`(?i)(cast\s*\(|convert\s*\(|@@version|@@datadir|@@basedir)`,
		
		// NoSQL injection
		`(?i)(\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex)`,
		`(?i)(\{\s*"\$where|"\$ne"|"\$gt"|"\$lt")`,
		
		// LDAP injection
		`(?i)(\(|\)|&|\||!|~|\(.*=.*\)|\(.*\*.*\))`,
		
		// URL encoded SQL injection
		`(?i)(%27|%22|%5c|%2f|%2a|%2d%2d)`, // ', ", \, /, *, --
		`(?i)(%55%4e%49%4f%4e|%53%45%4c%45%43%54)`, // UNION, SELECT in hex
		
		// Double encoding
		`(?i)(%2527|%2522|%255c|%252f)`, // Double encoded ', ", \, /
		
		// Comment variations
		`(?i)(/\*.*\*/|--\s|#\s|;--|;/\*|\*/)`,
	}

	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	return compiled
}

func loadXSSPatterns() []*regexp.Regexp {
	patterns := []string{
		// Basic XSS patterns
		`(?i)(<script[^>]*>|</script>)`,
		`(?i)(javascript:|on\w+\s*=)`,
		`(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()`,
		`(?i)(document\.(cookie|write|location|domain|referrer)|window\.(location|document|parent|top|self))`,
		`(?i)(eval\s*\(|setTimeout\s*\(|setInterval\s*\(|Function\s*\(|new\s+Function)`,
		`(?i)(<iframe|<embed|<object|<svg\s+on|<link\s+on)`,
		`(?i)(expression\s*\(|@import|url\s*\()`,
		`(?i)(<img[^>]+src\s*=\s*["']?\s*javascript:|<img[^>]+onerror)`,
		`(?i)(<body[^>]*onload|<body[^>]*onerror|<body[^>]*onfocus)`,
		`(?i)(data:text/html|vbscript:|livescript:|mocha:|charset=)`,
		
		// URL encoded XSS patterns
		`(?i)(%3cscript|%3Cscript|%3c%2fscript|%3C%2Fscript)`,
		`(?i)(%3c%73%63%72%69%70%74|%3C%53%43%52%49%50%54)`, // Hex encoded <script
		`(?i)(javascript%3a|javascript%3A|%6a%61%76%61%73%63%72%69%70%74%3a)`, // URL encoded javascript:
		`(?i)(%61%6c%65%72%74|%41%4c%45%52%54)`, // Hex encoded alert
		`(?i)(onclick%3d|onerror%3d|onload%3d|%6f%6e%63%6c%69%63%6b)`, // URL encoded event handlers
		
		// Double encoding
		`(?i)(%253cscript|%253Cscript|%25253cscript)`,
		`(?i)(%2561%256c%2565%2572%2574)`, // Double encoded alert
		
		// HTML entity encoding
		`(?i)(&lt;script|&#60;script|&#x3c;script|&#X3C;script)`,
		`(?i)(&amp;#60;script|&amp;lt;script)`, // Double entity encoding
		
		// Event handler variations
		`(?i)(on\w+\s*=\s*["']?\s*[^"'\s>]*\s*[\(\)])`, // on*="...(" or "...)"
		`(?i)(onabort|onblur|onchange|onclick|ondblclick|onerror|onfocus|onkeydown|onkeypress|onkeyup|onload|onmousedown|onmouseenter|onmouseleave|onmousemove|onmouseout|onmouseover|onmouseup|onreset|onresize|onselect|onsubmit|onunload)`,
		
		// Script injection variations
		`(?i)(<script|</script|script\s*>|script\s*/>)`,
		`(?i)(<style[^>]*>.*expression|style\s*=\s*["'].*expression)`,
		`(?i)(<link[^>]*href\s*=\s*["']?\s*javascript:)`,
		`(?i)(<meta[^>]*http-equiv\s*=\s*["']?\s*refresh)`,
		
		// DOM manipulation
		`(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)`,
		`(?i)(createElement|appendChild|insertBefore|replaceChild)`,
		
		// Base64 encoded scripts
		`(?i)(data:text/html;base64|data:image/svg\+xml;base64)`,
		
		// Unicode and obfuscation (Go regex doesn't support \u or \x directly)
		`(?i)(%u003cscript|%u003Cscript|%u003c%u002fscript)`, // URL encoded Unicode <script
		`(?i)(%5cx3cscript|%5cx3Cscript)`, // URL encoded \x3cscript
		
		// Filter bypass attempts
		`(?i)(<scr<script>ipt>|<<script>script>|<scri<script>pt>)`, // Nested tags
		`(?i)(<script%00>|<script%20>|<script%09>)`, // URL encoded null bytes and whitespace
		`(?i)(<script/|script/>|script//>|script/>)`, // Self-closing variations
		
		// SVG and MathML XSS
		`(?i)(<svg[^>]*on|<math[^>]*on|<details[^>]*on)`,
		`(?i)(<animate[^>]*on|<set[^>]*on)`,
		
		// CSS injection
		`(?i)(expression\s*\(|@import|url\s*\(\s*["']?\s*javascript:)`,
		`(?i)(behavior\s*:\s*url|binding\s*:\s*url)`,
		
		// Template injection
		`(?i)(\{\{.*\}\}|<%.*%>|\$\{.*\})`, // Template syntax that could be XSS
	}

	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	return compiled
}

func loadPathTraversalPatterns() []*regexp.Regexp {
	patterns := []string{
		`\.\./|\.\.\\`,
		`\.\.%2f|\.\.%5c|%2e%2e%2f`,
		`\.\.%c0%af|\.\.%c1%9c`,
		`etc/passwd|etc/shadow|boot\.ini`,
		`/bin/sh|/bin/bash|cmd\.exe`,
		`\.\./\.\./\.\./`,
		`%2e%2e%2f%2e%2e%2f`,
	}

	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	return compiled
}

func loadCommandInjectionPatterns() []*regexp.Regexp {
	patterns := []string{
		// Command separators
		`(?i)(\||\||&|;|\$\(|` + "`" + `|&&|\|\|)`,
		`(?i)(\n|\r\n|\r)`, // Newline injection
		
		// Command execution
		`(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell|pwsh|sh|bash|zsh|fish)`,
		`(?i)(system\s*\(|exec\s*\(|shell_exec|passthru|proc_open|popen|shell_exec)`,
		`(?i)(eval\s*\(|assert\s*\(|call_user_func|create_function)`,
		`(?i)(os\.system|subprocess|commands\.getoutput|os\.popen)`,
		
		// System commands
		`(?i)(whoami|id|uname|hostname|ifconfig|ipconfig|ip\s+addr|netstat)`,
		`(?i)(cat\s+|ls\s+|dir\s+|type\s+|more\s+|less\s+|head\s+|tail\s+)`,
		`(?i)(ps\s+|top\s+|kill\s+|killall\s+|pkill\s+)`,
		`(?i)(rm\s+|del\s+|delete\s+|rmdir\s+|rd\s+)`,
		`(?i)(wget|curl|nc\s+|netcat|telnet|ssh|scp)`,
		
		// File operations
		`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/proc/|/sys/)`,
		`(?i)(C:\\Windows\\System32|C:\\Windows\\SysWOW64)`,
		
		// URL encoded command injection
		`(?i)(%7c|%26|%3b|%24%28|%60)`, // |, &, ;, $(, `
		`(?i)(%0a|%0d|%0a%0d)`, // Newline encoded
		
		// Double encoding
		`(?i)(%257c|%2526|%253b)`, // Double encoded |, &, ;
		
		// Command chaining
		`(?i)(\|\s*\w+|\&\s*\w+|\;\s*\w+)`,
		`(?i)(\|\|\s*\w+|\&\&\s*\w+)`,
		
		// Process substitution
		`(?i)(<\(|>\(|\$\(\(|` + "`" + `.*` + "`" + `)`,
		
		// Environment variable injection
		`(?i)(\$[A-Z_]+|\$\{[A-Z_]+\}|%[A-Z_]+%)`,
	}

	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	return compiled
}

func loadXXEPatterns() []*regexp.Regexp {
	patterns := []string{
		`<!ENTITY.*SYSTEM`,
		`<!DOCTYPE.*\[.*ENTITY`,
		`file://|http://|ftp://`,
		`&[a-zA-Z]+;`,
	}

	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	return compiled
}

func loadDeserializationPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)(ObjectInputStream|readObject|unserialize)`,
		`(?i)(pickle|marshal|yaml\.load)`,
		`(?i)(__reduce__|__getstate__|__setstate__)`,
	}

	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	return compiled
}

// Rate Limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) IsAllowed(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old requests
	if times, exists := rl.requests[ip]; exists {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rl.requests[ip] = valid

		if len(valid) >= rl.limit {
			return false
		}
	}

	// Add current request
	rl.requests[ip] = append(rl.requests[ip], now)
	return true
}

// IP Block List
func NewIPBlockList() *IPBlockList {
	return &IPBlockList{
		blockedIPs: make(map[string]*BlockEntry),
	}
}

func (bl *IPBlockList) IsBlocked(ip string) bool {
	bl.mutex.RLock()
	defer bl.mutex.RUnlock()

	entry, exists := bl.blockedIPs[ip]
	if !exists {
		return false
	}

	// Check if block has expired
	if time.Now().After(entry.BlockedUntil) {
		bl.mutex.RUnlock()
		bl.mutex.Lock()
		delete(bl.blockedIPs, ip)
		bl.mutex.Unlock()
		bl.mutex.RLock()
		return false
	}

	return true
}

func (bl *IPBlockList) BlockIP(ip, reason, attackType string, threatScore float64, duration time.Duration) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()

	bl.blockedIPs[ip] = &BlockEntry{
		IP:           ip,
		Reason:       reason,
		BlockedAt:    time.Now(),
		BlockedUntil: time.Now().Add(duration),
		ThreatScore:  threatScore,
		AttackType:   attackType,
	}

	log.Printf("🚫 IP %s blocked: %s (Attack: %s, Score: %.2f)", ip, reason, attackType, threatScore)
}

func (bl *IPBlockList) UnblockIP(ip string) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()
	delete(bl.blockedIPs, ip)
	log.Printf("✅ IP %s unblocked", ip)
}

func (bl *IPBlockList) ClearAllBlocks() {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()
	count := len(bl.blockedIPs)
	bl.blockedIPs = make(map[string]*BlockEntry)
	log.Printf("🧹 Cleared all IP blocks (%d IPs unblocked)", count)
}

// Threat Intelligence
func NewThreatIntelligence() *ThreatIntelligence {
	return &ThreatIntelligence{
		knownThreats: make(map[string]*ThreatInfo),
	}
}

func (ti *ThreatIntelligence) IsKnownThreat(ip string) bool {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	_, exists := ti.knownThreats[ip]
	return exists
}

func (ti *ThreatIntelligence) AddThreat(ip, threatType, source string, confidence float64) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()

	if existing, exists := ti.knownThreats[ip]; exists {
		existing.ThreatTypes = append(existing.ThreatTypes, threatType)
		existing.LastSeen = time.Now()
		if confidence > existing.Confidence {
			existing.Confidence = confidence
		}
	} else {
		ti.knownThreats[ip] = &ThreatInfo{
			IP:          ip,
			ThreatTypes: []string{threatType},
			Confidence:  confidence,
			LastSeen:    time.Now(),
			Source:      source,
		}
	}
}

// WAF Middleware - Main Entry Point
func (waf *ZeinSecurityUltimate) WAFMiddleware(next http.Handler) http.Handler {
	return waf.WAFMiddlewareWithMode(next, false)
}

// WAF Middleware with relaxed mode (for auth endpoints)
func (waf *ZeinSecurityUltimate) WAFMiddlewareWithRelaxedMode(next http.Handler) http.Handler {
	return waf.WAFMiddlewareWithMode(next, true)
}

// WAF Middleware with mode control
func (waf *ZeinSecurityUltimate) WAFMiddlewareWithMode(next http.Handler, relaxedMode bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !waf.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := getClientIP(r)

		// Check if IP is blocked
		if waf.ipBlockList.IsBlocked(ip) {
			waf.sendBlockResponse(w, r, "IP_BLOCKED", "Your IP address has been blocked due to suspicious activity")
			return
		}

		// Check rate limiting (lebih longgar untuk relaxed mode)
		if !relaxedMode {
			if !waf.rateLimiter.IsAllowed(ip) {
				waf.handleRateLimitExceeded(w, r, ip)
				return
			}
		}

		// Check request size
		if r.ContentLength > waf.config.MaxRequestSize {
			waf.sendBlockResponse(w, r, "REQUEST_TOO_LARGE", "Request body exceeds maximum allowed size")
			return
		}

		// Read request body for analysis
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Analyze request for OWASP Top 10 threats
		threats := waf.analyzeRequest(r, bodyBytes)

		if len(threats) > 0 {
			threatScore := waf.calculateThreatScore(threats)

			// Update behavioral tracking
			waf.updateIPBehavior(ip, threats, threatScore)

			// In relaxed mode, hanya block serangan yang sangat jelas (CRITICAL severity)
			if relaxedMode {
				// Filter: hanya block CRITICAL threats atau HIGH dengan score sangat tinggi
				var criticalThreats []DetectedThreat
				for _, threat := range threats {
					if threat.Severity == "CRITICAL" || (threat.Severity == "HIGH" && threatScore > 0.8) {
						criticalThreats = append(criticalThreats, threat)
					}
				}
				
				// Jika ada critical threats, block
				if len(criticalThreats) > 0 {
					attackType := criticalThreats[0].AttackType
					waf.ipBlockList.BlockIP(ip, criticalThreats[0].Description, attackType, threatScore, waf.config.BlockDuration)
					waf.logSecurityEvent(r, ip, criticalThreats, threatScore, true)
					waf.sendBlockResponse(w, r, attackType, criticalThreats[0].Description)
					return
				}
				
				// Untuk threats lainnya, hanya log (tidak block)
				waf.logSecurityEvent(r, ip, threats, threatScore, false)
			} else {
				// Normal mode: block sesuai threshold
				if waf.shouldBlock(threatScore, threats) {
					// Block IP
					attackType := threats[0].AttackType
					waf.ipBlockList.BlockIP(ip, threats[0].Description, attackType, threatScore, waf.config.BlockDuration)

					// Log security event
					waf.logSecurityEvent(r, ip, threats, threatScore, true)

					waf.sendBlockResponse(w, r, attackType, threats[0].Description)
					return
				}

				// Log suspicious activity
				waf.logSecurityEvent(r, ip, threats, threatScore, false)
			}
		}

		// Check threat intelligence (skip untuk relaxed mode)
		if !relaxedMode && waf.threatIntelligence.IsKnownThreat(ip) {
			waf.sendBlockResponse(w, r, "KNOWN_THREAT", "IP address flagged in threat intelligence database")
			return
		}

		// Request passed all checks
		next.ServeHTTP(w, r)
	})
}

type DetectedThreat struct {
	AttackType  string
	Description string
	Severity    string
	Pattern     string
}

// decodeURL decodes URL-encoded strings multiple times to catch double/triple encoding
func decodeURL(s string) string {
	decoded := s
	maxDecodes := 5 // Prevent infinite loops
	
	for i := 0; i < maxDecodes; i++ {
		if decodedURL, err := url.QueryUnescape(decoded); err == nil && decodedURL != decoded {
			decoded = decodedURL
		} else {
			break
		}
	}
	
	return decoded
}

// decodeHex decodes hex-encoded strings
func decodeHex(s string) string {
	// Try to decode hex patterns like %3c, %3C, \x3c, etc.
	decoded := s
	
	// Decode %XX patterns
	if strings.Contains(decoded, "%") {
		if decodedURL, err := url.QueryUnescape(decoded); err == nil {
			decoded = decodedURL
		}
	}
	
	// Decode \xXX patterns
	hexPattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	decoded = hexPattern.ReplaceAllStringFunc(decoded, func(match string) string {
		hexStr := match[2:]
		if val, err := hex.DecodeString(hexStr); err == nil {
			return string(val)
		}
		return match
	})
	
	return decoded
}

// AnalyzeRequest - Public method untuk analyze request
func (waf *ZeinSecurityUltimate) AnalyzeRequest(r *http.Request, body []byte) []DetectedThreat {
	return waf.analyzeRequest(r, body)
}

func (waf *ZeinSecurityUltimate) analyzeRequest(r *http.Request, body []byte) []DetectedThreat {
	var threats []DetectedThreat

	// Decode URL parameters
	decodedURL, _ := url.QueryUnescape(r.URL.String())
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
	decodedPath, _ := url.QueryUnescape(r.URL.Path)
	
	// Multiple decoding passes for double/triple encoding
	decodedURL = decodeURL(decodedURL)
	decodedQuery = decodeURL(decodedQuery)
	decodedPath = decodeURL(decodedPath)
	
	// Decode hex encoding
	decodedURL = decodeHex(decodedURL)
	decodedQuery = decodeHex(decodedQuery)
	decodedPath = decodeHex(decodedPath)
	
	// Decode body if it's URL-encoded
	decodedBody := string(body)
	if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		decodedBody = decodeURL(decodedBody)
		decodedBody = decodeHex(decodedBody)
	}

	// Combine all request data for analysis (both original and decoded)
	requestData := strings.ToLower(decodedBody)
	requestData += " " + strings.ToLower(r.URL.String()) // Original
	requestData += " " + strings.ToLower(decodedURL) // Decoded
	requestData += " " + strings.ToLower(r.URL.RawQuery) // Original query
	requestData += " " + strings.ToLower(decodedQuery) // Decoded query
	requestData += " " + strings.ToLower(decodedPath) // Decoded path

	// Check headers (also decode them)
	for key, values := range r.Header {
		headerValue := strings.ToLower(strings.Join(values, " "))
		decodedHeader := decodeURL(headerValue)
		decodedHeader = decodeHex(decodedHeader)
		requestData += " " + strings.ToLower(key) + ":" + headerValue + " " + decodedHeader
	}

	// PRIORITAS: Check XSS FIRST (lebih spesifik dari SQL injection)
	// OWASP A07:2021 - Cross-Site Scripting (XSS) - CHECK FIRST!
	xssThreats := waf.detectXSS(requestData)
	threats = append(threats, xssThreats...)
	
	// OWASP A01:2021 - Injection (SQL, NoSQL, Command, LDAP, etc.)
	// Only check SQL injection if XSS not detected (avoid false positive)
	if len(xssThreats) == 0 {
		threats = append(threats, waf.detectSQLInjection(requestData)...)
	}
	threats = append(threats, waf.detectCommandInjection(requestData)...)

	// OWASP A05:2021 - Broken Access Control (Path Traversal)
	threats = append(threats, waf.detectPathTraversal(requestData)...)

	// OWASP A04:2021 - XML External Entities (XXE)
	threats = append(threats, waf.detectXXE(requestData, r.Header.Get("Content-Type"))...)

	// OWASP A08:2021 - Insecure Deserialization
	threats = append(threats, waf.detectInsecureDeserialization(requestData, r.Header.Get("Content-Type"))...)

	// OWASP A02:2021 - Broken Authentication (Brute Force, Session Fixation)
	threats = append(threats, waf.detectBrokenAuth(r)...)

	// OWASP A03:2021 - Sensitive Data Exposure
	threats = append(threats, waf.detectSensitiveDataExposure(requestData)...)

	return threats
}

func (waf *ZeinSecurityUltimate) detectSQLInjection(data string) []DetectedThreat {
	var threats []DetectedThreat
	for _, pattern := range waf.sqlInjectionPatterns {
		if pattern.MatchString(data) {
			threats = append(threats, DetectedThreat{
				AttackType:  OWASP_INJECTION,
				Description: "SQL Injection attempt detected",
				Severity:    "HIGH",
				Pattern:     pattern.String(),
			})
		}
	}
	return threats
}

func (waf *ZeinSecurityUltimate) detectXSS(data string) []DetectedThreat {
	var threats []DetectedThreat
	for _, pattern := range waf.xssPatterns {
		if pattern.MatchString(data) {
			threats = append(threats, DetectedThreat{
				AttackType:  OWASP_XSS,
				Description: "Cross-Site Scripting (XSS) attempt detected",
				Severity:    "HIGH",
				Pattern:     pattern.String(),
			})
		}
	}
	return threats
}

func (waf *ZeinSecurityUltimate) detectPathTraversal(data string) []DetectedThreat {
	var threats []DetectedThreat
	for _, pattern := range waf.pathTraversalPatterns {
		if pattern.MatchString(data) {
			threats = append(threats, DetectedThreat{
				AttackType:  OWASP_BROKEN_ACCESS,
				Description: "Path Traversal attempt detected",
				Severity:    "HIGH",
				Pattern:     pattern.String(),
			})
		}
	}
	return threats
}

func (waf *ZeinSecurityUltimate) detectCommandInjection(data string) []DetectedThreat {
	var threats []DetectedThreat
	for _, pattern := range waf.commandInjectionPatterns {
		if pattern.MatchString(data) {
			threats = append(threats, DetectedThreat{
				AttackType:  OWASP_INJECTION,
				Description: "Command Injection attempt detected",
				Severity:    "CRITICAL",
				Pattern:     pattern.String(),
			})
		}
	}
	return threats
}

func (waf *ZeinSecurityUltimate) detectXXE(data string, contentType string) []DetectedThreat {
	var threats []DetectedThreat
	if strings.Contains(strings.ToLower(contentType), "xml") {
		for _, pattern := range waf.xxePatterns {
			if pattern.MatchString(data) {
				threats = append(threats, DetectedThreat{
					AttackType:  OWASP_XXE,
					Description: "XML External Entity (XXE) attack detected",
					Severity:    "HIGH",
					Pattern:     pattern.String(),
				})
			}
		}
	}
	return threats
}

func (waf *ZeinSecurityUltimate) detectInsecureDeserialization(data string, contentType string) []DetectedThreat {
	var threats []DetectedThreat
	for _, pattern := range waf.deserializationPatterns {
		if pattern.MatchString(data) {
			threats = append(threats, DetectedThreat{
				AttackType:  OWASP_INsecure_DESERIAL,
				Description: "Insecure Deserialization attempt detected",
				Severity:    "HIGH",
				Pattern:     pattern.String(),
			})
		}
	}
	return threats
}

func (waf *ZeinSecurityUltimate) detectBrokenAuth(r *http.Request) []DetectedThreat {
	var threats []DetectedThreat

	// Check for session fixation
	if r.URL.Query().Get("PHPSESSID") != "" || r.URL.Query().Get("JSESSIONID") != "" {
		threats = append(threats, DetectedThreat{
			AttackType:  OWASP_BROKEN_AUTH,
			Description: "Session ID in URL detected (Session Fixation risk)",
			Severity:    "MEDIUM",
		})
	}

	// Check for weak authentication headers
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && len(authHeader) < 20 {
		threats = append(threats, DetectedThreat{
			AttackType:  OWASP_BROKEN_AUTH,
			Description: "Weak authentication token detected",
			Severity:    "MEDIUM",
		})
	}

	return threats
}

func (waf *ZeinSecurityUltimate) detectSensitiveDataExposure(data string) []DetectedThreat {
	var threats []DetectedThreat

	sensitivePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?[^'"]+['"]?`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[^'"]+['"]?`),
		regexp.MustCompile(`(?i)(secret|token|bearer)\s*[:=]\s*['"]?[^'"]+['"]?`),
		regexp.MustCompile(`(?i)(credit[_-]?card|cc[_-]?number|card[_-]?number)\s*[:=]\s*['"]?[^'"]+['"]?`),
		regexp.MustCompile(`(?i)(ssn|social[_-]?security)\s*[:=]\s*['"]?[^'"]+['"]?`),
	}

	for _, pattern := range sensitivePatterns {
		if pattern.MatchString(data) {
			threats = append(threats, DetectedThreat{
				AttackType:  OWASP_SENSITIVE_DATA,
				Description: "Potential sensitive data exposure detected",
				Severity:    "MEDIUM",
			})
		}
	}

	return threats
}

// CalculateThreatScore - Public method untuk calculate threat score
func (waf *ZeinSecurityUltimate) CalculateThreatScore(threats []DetectedThreat) float64 {
	return waf.calculateThreatScore(threats)
}

func (waf *ZeinSecurityUltimate) calculateThreatScore(threats []DetectedThreat) float64 {
	score := 0.0
	for _, threat := range threats {
		switch threat.Severity {
		case "CRITICAL":
			score += 0.4
		case "HIGH":
			score += 0.3
		case "MEDIUM":
			score += 0.15
		case "LOW":
			score += 0.05
		}
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

func (waf *ZeinSecurityUltimate) shouldBlock(threatScore float64, threats []DetectedThreat) bool {
	thresholds := map[string]float64{
		"low":      0.9,
		"medium":   0.7,
		"high":     0.5,
		"paranoid": 0.001, // CLOUDFLARE ENTERPRISE+: block bahkan untuk threat score sangat sangat sangat rendah (near zero)
	}
	
	// CLOUDFLARE ENTERPRISE+ LEVEL: Block immediately if ANY threat detected (ABSOLUTE ZERO TOLERANCE)
	if waf.config.ProtectionLevel == "paranoid" && len(threats) > 0 {
		// Block immediately for ANY threat (absolute zero tolerance policy)
		// Tidak peduli severity, tidak peduli score, jika terdeteksi = BLOCK
		// Bahkan untuk LOW severity pun tetap di-block
		log.Printf("🚫 CLOUDFLARE ENTERPRISE+ LEVEL: Blocking request with %d threat(s), score: %.2f (ABSOLUTE ZERO TOLERANCE)", len(threats), threatScore)
		return true
	}
	
	// Extra protection: Block if threat score is above near-zero threshold
	if threatScore > 0.001 && len(threats) > 0 {
		// Block for ANY threat, regardless of severity
		return true
	}

	threshold, exists := thresholds[waf.config.ProtectionLevel]
	if !exists {
		threshold = 0.7
	}

	return threatScore >= threshold
}

func (waf *ZeinSecurityUltimate) updateIPBehavior(ip string, threats []DetectedThreat, threatScore float64) {
	waf.behaviorMutex.Lock()
	defer waf.behaviorMutex.Unlock()

	behavior, exists := waf.ipBehaviorMap[ip]
	if !exists {
		behavior = &IPBehavior{
			IP:             ip,
			FirstSeen:      time.Now(),
			AttackPatterns: []string{},
		}
		waf.ipBehaviorMap[ip] = behavior
	}

	behavior.RequestCount++
	behavior.LastRequest = time.Now()
	behavior.ThreatScore = (behavior.ThreatScore + threatScore) / 2

	for _, threat := range threats {
		behavior.AttackPatterns = append(behavior.AttackPatterns, threat.AttackType)
	}

	// Auto-block if behavior is too suspicious
	if behavior.ThreatScore > 0.8 && behavior.RequestCount > 5 {
		waf.ipBlockList.BlockIP(ip, "Suspicious behavioral pattern", "BEHAVIORAL", behavior.ThreatScore, waf.config.BlockDuration)
	}
}

// logSecurityEvent - Log security event to database and monitor
func (waf *ZeinSecurityUltimate) logSecurityEvent(r *http.Request, ip string, threats []DetectedThreat, threatScore float64, blocked bool) {
	threatTypes := make([]string, len(threats))
	if len(threats) > 0 {
		for i, t := range threats {
			threatTypes[i] = t.AttackType
		}
	}

	log.Printf("🔒 Security Event - IP: %s, Threats: %v, Score: %.2f, Blocked: %v",
		ip, threatTypes, threatScore, blocked)

	// This will be called from WAF middleware with database reference
	// For now, just log - database integration will be added in main.go
}

func (waf *ZeinSecurityUltimate) handleRateLimitExceeded(w http.ResponseWriter, r *http.Request, ip string) {
	// Increase block duration for rate limit violations
	waf.ipBlockList.BlockIP(ip, "Rate limit exceeded", "RATE_LIMIT", 0.6, 1*time.Hour)

	waf.sendBlockResponse(w, r, "RATE_LIMIT", "Too many requests. Please try again later.")
}

func (waf *ZeinSecurityUltimate) sendBlockResponse(w http.ResponseWriter, r *http.Request, attackType, message string) {
	// CLOUDFLARE-STYLE: Show IP and timestamp
	ip := getClientIP(r)
	requestID := generateRequestID(r)
	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Zein-WAF-Blocked", "true")
	w.WriteHeader(http.StatusForbidden)
	
	// Cloudflare-style block page dengan IP dan timestamp
	blockPage := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden | Zein Security</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: #333;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%%;
            padding: 40px;
            text-align: center;
        }
        .logo {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 20px;
            letter-spacing: 2px;
        }
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 28px;
            color: #2d3748;
            margin-bottom: 16px;
        }
        .message {
            font-size: 16px;
            color: #4a5568;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        .info-box {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }
        .info-row:last-child {
            border-bottom: none;
        }
        .info-label {
            font-weight: 600;
            color: #2d3748;
        }
        .info-value {
            color: #4a5568;
            font-family: 'Courier New', monospace;
        }
        .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #718096;
        }
        .request-id {
            font-size: 12px;
            color: #a0aec0;
            margin-top: 20px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️ ZEIN SECURITY</div>
        <div class="icon">🚫</div>
        <h1>403 Forbidden</h1>
        <p class="message">Your request has been blocked by Zein Security WAF.<br>Access to this resource is denied.</p>
        
        <div class="info-box">
            <div class="info-row">
                <span class="info-label">Your IP Address:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Blocked At:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Request ID:</span>
                <span class="info-value">%s</span>
            </div>
        </div>
        
        <div class="footer">
            <p>If you believe this is an error, please contact the site administrator.</p>
            <p style="margin-top: 10px;"><strong>Zein Security WAF</strong> - Advanced Threat Protection</p>
        </div>
        
        <div class="request-id">Request ID: %s</div>
    </div>
</body>
</html>`, ip, timestamp, requestID, requestID)
	
	w.Write([]byte(blockPage))
}

func generateRequestID(r *http.Request) string {
	data := fmt.Sprintf("%s%s%s%s", r.RemoteAddr, r.URL.String(), r.Method, time.Now().String())
	hash := hmac.New(sha256.New, []byte("zein-secret-key"))
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))[:16]
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}




