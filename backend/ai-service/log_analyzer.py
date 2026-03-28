#!/usr/bin/env python3
"""
ZEIN SECURITY WAF - AI LOG ANALYSIS SYSTEM
Advanced log analysis with machine learning for threat detection
"""

import asyncio
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
from dataclasses import dataclass

logger = logging.getLogger("ZeinLogAnalyzer")

@dataclass
class LogEntry:
    timestamp: datetime
    ip_address: str
    user_agent: str
    request_method: str
    request_path: str
    request_query: str
    status_code: int
    threat_score: float
    details: Dict[str, Any]

class AILogAnalyzer:
    """Advanced AI-powered log analysis system"""
    
    def __init__(self):
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.ip_behavior_profiles = {}
        self.attack_signatures = self._load_attack_signatures()
        logger.info("🤖 AI Log Analyzer initialized")
    
    def _load_suspicious_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load patterns for detecting suspicious behavior"""
        return {
            "rapid_requests": [
                re.compile(r"requests_per_minute > 100"),
            ],
            "error_spikes": [
                re.compile(r"status_code: (4\d{2}|5\d{2})"),
            ],
            "unusual_paths": [
                re.compile(r"(/admin|/wp-admin|/phpmyadmin|/\.env|/config)"),
            ],
            "suspicious_agents": [
                re.compile(r"(sqlmap|nikto|nmap|masscan|zap|burp|w3af)"),
            ],
        }
    
    def _load_attack_signatures(self) -> Dict[str, List[str]]:
        """Load known attack signatures"""
        return {
            "sql_injection": [
                "union select", "drop table", "exec(", "information_schema"
            ],
            "xss": [
                "<script>", "javascript:", "onerror=", "alert("
            ],
            "path_traversal": [
                "../", "..\\", "etc/passwd", "/bin/sh"
            ],
            "command_injection": [
                "|", "&", ";", "$(", "`"
            ],
            "brute_force": [
                "login", "password", "auth", "failed"
            ],
        }
    
    async def analyze_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs and detect suspicious patterns
        
        Returns:
            Analysis results with threat scores, suspicious IPs, and recommendations
        """
        if not logs:
            return {
                "threat_detected": False,
                "threat_score": 0.0,
                "suspicious_ips": [],
                "recommendations": []
            }
        
        # Convert to LogEntry objects
        log_entries = [self._parse_log_entry(log) for log in logs]
        
        # Analyze patterns
        ip_analysis = self._analyze_ip_patterns(log_entries)
        temporal_analysis = self._analyze_temporal_patterns(log_entries)
        behavioral_analysis = self._analyze_behavioral_patterns(log_entries)
        attack_detection = self._detect_attack_patterns(log_entries)
        
        # Calculate overall threat score
        threat_score = self._calculate_threat_score(
            ip_analysis, temporal_analysis, behavioral_analysis, attack_detection
        )
        
        # Identify suspicious IPs
        suspicious_ips = self._identify_suspicious_ips(
            ip_analysis, behavioral_analysis, attack_detection
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            threat_score, suspicious_ips, attack_detection
        )
        
        return {
            "threat_detected": threat_score > 0.6,
            "threat_score": threat_score,
            "risk_level": self._determine_risk_level(threat_score),
            "suspicious_ips": suspicious_ips,
            "ip_analysis": ip_analysis,
            "temporal_analysis": temporal_analysis,
            "behavioral_analysis": behavioral_analysis,
            "attack_detection": attack_detection,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }
    
    def _parse_log_entry(self, log: Dict[str, Any]) -> LogEntry:
        """Parse log entry from dictionary"""
        timestamp = datetime.fromisoformat(log.get("timestamp", datetime.now().isoformat()))
        return LogEntry(
            timestamp=timestamp,
            ip_address=log.get("ip_address", ""),
            user_agent=log.get("user_agent", ""),
            request_method=log.get("request_method", ""),
            request_path=log.get("request_path", ""),
            request_query=log.get("request_query", ""),
            status_code=log.get("status_code", 200),
            threat_score=log.get("threat_score", 0.0),
            details=log.get("details", {})
        )
    
    def _analyze_ip_patterns(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze patterns by IP address"""
        ip_stats = defaultdict(lambda: {
            "count": 0,
            "unique_paths": set(),
            "error_count": 0,
            "threat_scores": [],
            "user_agents": set(),
            "time_range": None
        })
        
        for log in logs:
            ip = log.ip_address
            stats = ip_stats[ip]
            
            stats["count"] += 1
            stats["unique_paths"].add(log.request_path)
            stats["user_agents"].add(log.user_agent)
            stats["threat_scores"].append(log.threat_score)
            
            if log.status_code >= 400:
                stats["error_count"] += 1
            
            if stats["time_range"] is None:
                stats["time_range"] = (log.timestamp, log.timestamp)
            else:
                start, end = stats["time_range"]
                if log.timestamp < start:
                    start = log.timestamp
                if log.timestamp > end:
                    end = log.timestamp
                stats["time_range"] = (start, end)
        
        # Calculate metrics
        analysis = {}
        for ip, stats in ip_stats.items():
            time_range = stats["time_range"]
            duration = (time_range[1] - time_range[0]).total_seconds() if time_range else 1
            requests_per_second = stats["count"] / max(duration, 1)
            avg_threat_score = np.mean(stats["threat_scores"]) if stats["threat_scores"] else 0.0
            error_rate = stats["error_count"] / max(stats["count"], 1)
            
            analysis[ip] = {
                "request_count": stats["count"],
                "unique_paths": len(stats["unique_paths"]),
                "requests_per_second": requests_per_second,
                "error_rate": error_rate,
                "avg_threat_score": avg_threat_score,
                "unique_user_agents": len(stats["user_agents"]),
                "suspicious_score": self._calculate_ip_suspicious_score(
                    requests_per_second, error_rate, avg_threat_score, stats["count"]
                )
            }
        
        return analysis
    
    def _analyze_temporal_patterns(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze temporal patterns (time-based attacks)"""
        if not logs:
            return {}
        
        # Group by time windows
        time_windows = defaultdict(int)
        error_windows = defaultdict(int)
        
        for log in logs:
            # Round to minute
            window = log.timestamp.replace(second=0, microsecond=0)
            time_windows[window] += 1
            
            if log.status_code >= 400:
                error_windows[window] += 1
        
        # Detect spikes
        if time_windows:
            avg_requests = np.mean(list(time_windows.values()))
            max_requests = max(time_windows.values())
            
            # Detect error spikes
            error_spikes = []
            for window, errors in error_windows.items():
                if errors > avg_requests * 0.5:
                    error_spikes.append({
                        "timestamp": window.isoformat(),
                        "error_count": errors
                    })
            
            return {
                "avg_requests_per_minute": avg_requests,
                "max_requests_per_minute": max_requests,
                "request_spike_detected": max_requests > avg_requests * 3,
                "error_spikes": error_spikes,
                "total_time_windows": len(time_windows)
            }
        
        return {}
    
    def _analyze_behavioral_patterns(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze behavioral patterns"""
        behaviors = {
            "suspicious_user_agents": [],
            "unusual_paths": [],
            "repeated_failures": [],
            "scanning_patterns": []
        }
        
        # Check user agents
        user_agents = Counter([log.user_agent for log in logs])
        for agent, count in user_agents.items():
            if any(pattern.search(agent.lower()) for pattern in self.suspicious_patterns["suspicious_agents"]):
                behaviors["suspicious_user_agents"].append({
                    "user_agent": agent,
                    "count": count
                })
        
        # Check paths
        paths = Counter([log.request_path for log in logs])
        for path, count in paths.items():
            if any(pattern.search(path.lower()) for pattern in self.suspicious_patterns["unusual_paths"]):
                behaviors["unusual_paths"].append({
                    "path": path,
                    "count": count
                })
        
        # Check for scanning patterns (many different paths from same IP)
        ip_paths = defaultdict(set)
        for log in logs:
            ip_paths[log.ip_address].add(log.request_path)
        
        for ip, paths_set in ip_paths.items():
            if len(paths_set) > 20:  # Likely scanning
                behaviors["scanning_patterns"].append({
                    "ip": ip,
                    "unique_paths": len(paths_set)
                })
        
        return behaviors
    
    def _detect_attack_patterns(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Detect specific attack patterns"""
        attacks = defaultdict(lambda: {
            "count": 0,
            "ips": set(),
            "paths": set()
        })
        
        for log in logs:
            request_data = f"{log.request_path} {log.request_query}".lower()
            
            for attack_type, signatures in self.attack_signatures.items():
                for signature in signatures:
                    if signature.lower() in request_data:
                        attacks[attack_type]["count"] += 1
                        attacks[attack_type]["ips"].add(log.ip_address)
                        attacks[attack_type]["paths"].add(log.request_path)
        
        # Format results
        results = {}
        for attack_type, data in attacks.items():
            results[attack_type] = {
                "count": data["count"],
                "unique_ips": len(data["ips"]),
                "affected_paths": len(data["paths"]),
                "ips": list(data["ips"])[:10]  # Limit to 10 IPs
            }
        
        return results
    
    def _calculate_ip_suspicious_score(
        self, 
        requests_per_second: float,
        error_rate: float,
        avg_threat_score: float,
        request_count: int
    ) -> float:
        """Calculate suspicious score for an IP"""
        score = 0.0
        
        # High request rate
        if requests_per_second > 10:
            score += 0.3
        elif requests_per_second > 5:
            score += 0.15
        
        # High error rate
        if error_rate > 0.5:
            score += 0.3
        elif error_rate > 0.3:
            score += 0.15
        
        # High threat score
        if avg_threat_score > 0.7:
            score += 0.3
        elif avg_threat_score > 0.5:
            score += 0.15
        
        # Many requests
        if request_count > 1000:
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_threat_score(
        self,
        ip_analysis: Dict[str, Any],
        temporal_analysis: Dict[str, Any],
        behavioral_analysis: Dict[str, Any],
        attack_detection: Dict[str, Any]
    ) -> float:
        """Calculate overall threat score"""
        score = 0.0
        
        # IP analysis
        if ip_analysis:
            max_suspicious = max(
                (ip_data.get("suspicious_score", 0.0) for ip_data in ip_analysis.values()),
                default=0.0
            )
            score += max_suspicious * 0.3
        
        # Temporal analysis
        if temporal_analysis.get("request_spike_detected"):
            score += 0.2
        
        if temporal_analysis.get("error_spikes"):
            score += 0.15
        
        # Behavioral analysis
        if behavioral_analysis.get("suspicious_user_agents"):
            score += 0.15
        
        if behavioral_analysis.get("scanning_patterns"):
            score += 0.2
        
        # Attack detection
        if attack_detection:
            total_attacks = sum(data.get("count", 0) for data in attack_detection.values())
            if total_attacks > 0:
                score += min(total_attacks * 0.05, 0.3)
        
        return min(score, 1.0)
    
    def _identify_suspicious_ips(
        self,
        ip_analysis: Dict[str, Any],
        behavioral_analysis: Dict[str, Any],
        attack_detection: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Identify suspicious IPs that should be blocked"""
        suspicious_ips = []
        
        # From IP analysis
        for ip, data in ip_analysis.items():
            if data.get("suspicious_score", 0.0) > 0.6:
                suspicious_ips.append({
                    "ip": ip,
                    "reason": "High suspicious score",
                    "score": data.get("suspicious_score", 0.0),
                    "details": {
                        "request_count": data.get("request_count", 0),
                        "requests_per_second": data.get("requests_per_second", 0.0),
                        "error_rate": data.get("error_rate", 0.0)
                    }
                })
        
        # From attack detection
        for attack_type, data in attack_detection.items():
            for ip in data.get("ips", [])[:5]:  # Top 5 IPs per attack type
                suspicious_ips.append({
                    "ip": ip,
                    "reason": f"Detected {attack_type} attacks",
                    "score": 0.8,
                    "details": {
                        "attack_type": attack_type,
                        "attack_count": data.get("count", 0)
                    }
                })
        
        # From scanning patterns
        for pattern in behavioral_analysis.get("scanning_patterns", []):
            suspicious_ips.append({
                "ip": pattern.get("ip"),
                "reason": "Port/path scanning detected",
                "score": 0.7,
                "details": {
                    "unique_paths": pattern.get("unique_paths", 0)
                }
            })
        
        # Deduplicate and sort by score
        ip_map = {}
        for entry in suspicious_ips:
            ip = entry["ip"]
            if ip not in ip_map or entry["score"] > ip_map[ip]["score"]:
                ip_map[ip] = entry
        
        return sorted(ip_map.values(), key=lambda x: x["score"], reverse=True)
    
    def _generate_recommendations(
        self,
        threat_score: float,
        suspicious_ips: List[Dict[str, Any]],
        attack_detection: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if threat_score > 0.7:
            recommendations.append("🚨 CRITICAL: High threat score detected. Immediate action required.")
        
        if suspicious_ips:
            top_ip = suspicious_ips[0]
            recommendations.append(
                f"🔒 Block IP {top_ip['ip']}: {top_ip['reason']} (Score: {top_ip['score']:.2f})"
            )
        
        if attack_detection:
            attack_types = list(attack_detection.keys())
            recommendations.append(
                f"⚠️ Detected attack types: {', '.join(attack_types)}"
            )
        
        if threat_score > 0.5:
            recommendations.append("📊 Review security logs and increase monitoring")
            recommendations.append("🛡️ Consider enabling stricter WAF rules")
        
        return recommendations
    
    def _determine_risk_level(self, threat_score: float) -> str:
        """Determine risk level from threat score"""
        if threat_score >= 0.9:
            return "CRITICAL"
        elif threat_score >= 0.7:
            return "HIGH"
        elif threat_score >= 0.5:
            return "MEDIUM"
        elif threat_score >= 0.3:
            return "LOW"
        else:
            return "INFO"

