package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// TLSFingerprinting - Advanced TLS / Network Fingerprinting
type TLSFingerprinting struct {
	mu                sync.RWMutex
	tlsFingerprints   map[string]*TLSFingerprint
	ja3Fingerprints   map[string]*JA3Fingerprint
	networkProfiles   map[string]*NetworkProfile
	knownThreats      map[string]*TLSThreat
	lastUpdate        time.Time
}

// TLSFingerprint - TLS fingerprint data
type TLSFingerprint struct {
	IP              string
	CipherSuites    []uint16
	Extensions      []uint16
	Curves          []tls.CurveID
	Points          []uint8
	Versions        []uint16
	SignatureAlgs   []tls.SignatureScheme
	Fingerprint     string
	JA3Hash         string
	IsSuspicious    bool
	Confidence      float64
	LastSeen        time.Time
}

// JA3Fingerprint - JA3 fingerprint
type JA3Fingerprint struct {
	Hash        string
	Description string
	IsBot       bool
	IsMalware   bool
	IsVPN       bool
	IsProxy     bool
	Confidence  float64
	LastSeen    time.Time
}

// NetworkProfile - Network profile
type NetworkProfile struct {
	IP              string
	TCPOptions      *TCPOptions
	TLSVersion      uint16
	CipherSuite     uint16
	SNI             string
	ALPN            []string
	IsSuspicious    bool
	ThreatScore     float64
	LastSeen        time.Time
}

// TCPOptions - TCP options
type TCPOptions struct {
	MSS           int
	WindowScale   int
	SACKPermitted bool
	Timestamp     bool
	NOP           bool
	Options       []byte
}

// TLSThreat - TLS-based threat
type TLSThreat struct {
	Fingerprint string
	ThreatType  string
	Severity    string
	Description string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int64
	Confidence  float64
}

// NewTLSFingerprinting - Initialize TLS fingerprinting
func NewTLSFingerprinting() *TLSFingerprinting {
	tf := &TLSFingerprinting{
		tlsFingerprints: make(map[string]*TLSFingerprint),
		ja3Fingerprints: make(map[string]*JA3Fingerprint),
		networkProfiles: make(map[string]*NetworkProfile),
		knownThreats:    make(map[string]*TLSThreat),
	}

	// Load known JA3 fingerprints
	tf.loadKnownJA3Fingerprints()

	log.Println("🔐 TLS / Network Fingerprinting initialized")
	return tf
}

// loadKnownJA3Fingerprints - Load known JA3 fingerprints
func (tf *TLSFingerprinting) loadKnownJA3Fingerprints() {
	knownJA3 := []JA3Fingerprint{
		{Hash: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0", Description: "Chrome", IsBot: false, Confidence: 0.9},
		{Hash: "772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-17513,29-23-24-25,0", Description: "Firefox", IsBot: false, Confidence: 0.9},
		{Hash: "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-51-43-45-28-17513,29-23-24-25,0", Description: "Safari", IsBot: false, Confidence: 0.9},
		{Hash: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0", Description: "Bot/Scraper", IsBot: true, Confidence: 0.8},
	}

	for _, ja3 := range knownJA3 {
		tf.ja3Fingerprints[ja3.Hash] = &ja3
	}
}

// AnalyzeTLS - Analyze TLS handshake
func (tf *TLSFingerprinting) AnalyzeTLS(conn net.Conn, clientHello *tls.ClientHelloInfo) *TLSFingerprint {
	fingerprint := &TLSFingerprint{
		IP:            getIPFromConn(conn),
		CipherSuites:  clientHello.CipherSuites,
		Extensions:    extractExtensions(clientHello),
		Curves:        clientHello.SupportedCurves,
		Points:        clientHello.SupportedPoints,
		Versions:      []uint16{clientHello.SupportedVersions[0]},
		SignatureAlgs: clientHello.SignatureSchemes,
		LastSeen:      time.Now(),
	}

	// Generate JA3 fingerprint
	fingerprint.JA3Hash = tf.generateJA3Hash(fingerprint)
	fingerprint.Fingerprint = tf.generateFingerprint(fingerprint)

	// Check against known fingerprints
	tf.checkFingerprint(fingerprint)

	tf.mu.Lock()
	tf.tlsFingerprints[fingerprint.IP] = fingerprint
	tf.mu.Unlock()

	return fingerprint
}

// generateJA3Hash - Generate JA3 hash
func (tf *TLSFingerprinting) generateJA3Hash(fp *TLSFingerprint) string {
	// JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
	cipherStr := ""
	for i, cs := range fp.CipherSuites {
		if i > 0 {
			cipherStr += "-"
		}
		cipherStr += fmt.Sprintf("%d", cs)
	}

	extStr := ""
	for i, ext := range fp.Extensions {
		if i > 0 {
			extStr += "-"
		}
		extStr += fmt.Sprintf("%d", ext)
	}

	curveStr := ""
	for i, curve := range fp.Curves {
		if i > 0 {
			curveStr += "-"
		}
		curveStr += fmt.Sprintf("%d", curve)
	}

	pointStr := ""
	for i, point := range fp.Points {
		if i > 0 {
			pointStr += "-"
		}
		pointStr += fmt.Sprintf("%d", point)
	}

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s", fp.Versions[0], cipherStr, extStr, curveStr, pointStr)
	return ja3String
}

// generateFingerprint - Generate TLS fingerprint
func (tf *TLSFingerprinting) generateFingerprint(fp *TLSFingerprint) string {
	data := fmt.Sprintf("%v-%v-%v-%v", fp.CipherSuites, fp.Extensions, fp.Curves, fp.Versions)
	hash := md5Hash(data)
	return hex.EncodeToString(hash)
}

// checkFingerprint - Check fingerprint against known threats
func (tf *TLSFingerprinting) checkFingerprint(fp *TLSFingerprint) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	// Check JA3 hash
	if ja3, exists := tf.ja3Fingerprints[fp.JA3Hash]; exists {
		if ja3.IsBot || ja3.IsMalware {
			fp.IsSuspicious = true
			fp.Confidence = ja3.Confidence
		}
	}

	// Check known threats
	if threat, exists := tf.knownThreats[fp.Fingerprint]; exists {
		fp.IsSuspicious = true
		fp.Confidence = threat.Confidence
	}
}

// AnalyzeNetwork - Analyze network characteristics
func (tf *TLSFingerprinting) AnalyzeNetwork(conn net.Conn) *NetworkProfile {
	ip := getIPFromConn(conn)

	profile := &NetworkProfile{
		IP:          ip,
		TCPOptions:  &TCPOptions{},
		IsSuspicious: false,
		ThreatScore: 0.0,
		LastSeen:    time.Now(),
	}

	// Analyze TCP options (would need raw socket access)
	// For now, create basic profile

	tf.mu.Lock()
	tf.networkProfiles[ip] = profile
	tf.mu.Unlock()

	return profile
}

// GetTLSFingerprint - Get TLS fingerprint for IP
func (tf *TLSFingerprinting) GetTLSFingerprint(ip string) (*TLSFingerprint, bool) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	fp, exists := tf.tlsFingerprints[ip]
	return fp, exists
}

// Helper functions
func getIPFromConn(conn net.Conn) string {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if addr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP.String()
		}
	}
	return ""
}

func extractExtensions(hello *tls.ClientHelloInfo) []uint16 {
	// Extract extension IDs from ClientHello
	// This is simplified - real implementation would parse TLS handshake
	return []uint16{0, 10, 11, 13, 16, 23, 27, 35, 43, 45, 51}
}

func md5Hash(data string) []byte {
	hash := md5.Sum([]byte(data))
	return hash[:]
}

