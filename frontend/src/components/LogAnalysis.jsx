import React, { useState, useEffect } from 'react';
import './LogAnalysis.css';

const LogAnalysis = ({ apiCall }) => {
  const [logs, setLogs] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [timeRange, setTimeRange] = useState('1h');

  useEffect(() => {
    loadLogs();
    const interval = setInterval(loadLogs, 5000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const loadLogs = async () => {
    try {
      const data = await apiCall(`/quantum/logs?limit=100&time_range=${timeRange}`);
      setLogs(data || []);
    } catch (error) {
      console.error('Error loading logs:', error);
    }
  };

  const runAIAnalysis = async () => {
    setAnalyzing(true);
    try {
      const response = await apiCall('/quantum/analyze-logs', {
        method: 'POST',
        body: JSON.stringify({
          log_data: logs.slice(0, 1000) // Analyze last 1000 logs
        })
      });
      setAnalysis(response);
    } catch (error) {
      alert(`Analysis failed: ${error.message}`);
    } finally {
      setAnalyzing(false);
    }
  };

  const getSeverityClass = (severity) => {
    return severity?.toLowerCase() || 'low';
  };

  return (
    <div className="log-analysis-container">
      <div className="analysis-header">
        <h2>📊 AI Log Analysis</h2>
        <p>Advanced AI-powered log analysis and threat detection</p>
      </div>

      <div className="analysis-controls">
        <div className="control-group">
          <label>Time Range:</label>
          <select value={timeRange} onChange={(e) => setTimeRange(e.target.value)}>
            <option value="15m">Last 15 Minutes</option>
            <option value="1h">Last Hour</option>
            <option value="6h">Last 6 Hours</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>
        </div>
        <button
          className="analyze-btn"
          onClick={runAIAnalysis}
          disabled={analyzing || logs.length === 0}
        >
          {analyzing ? '🤖 Analyzing...' : '🤖 Run AI Analysis'}
        </button>
      </div>

      {/* Analysis Results */}
      {analysis && (
        <div className="analysis-results">
          <div className={`threat-alert ${analysis.threat_detected ? 'threat-detected' : 'no-threat'}`}>
            <h3>
              {analysis.threat_detected ? '🚨 THREAT DETECTED' : '✅ NO THREATS DETECTED'}
            </h3>
            <div className="threat-score">
              Threat Score: {(analysis.threat_score * 100).toFixed(1)}%
              <span className={`risk-level ${analysis.risk_level?.toLowerCase()}`}>
                ({analysis.risk_level})
              </span>
            </div>
          </div>

          {analysis.suspicious_ips && analysis.suspicious_ips.length > 0 && (
            <div className="suspicious-ips-section">
              <h4>🚫 Suspicious IPs Detected</h4>
              <div className="suspicious-ips-list">
                {analysis.suspicious_ips.map((ip, index) => (
                  <div key={index} className="suspicious-ip-card">
                    <div className="ip-header">
                      <span className="ip-address">{ip.ip}</span>
                      <span className={`threat-badge score-${Math.floor(ip.score * 10)}`}>
                        Score: {(ip.score * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="ip-reason">{ip.reason}</div>
                    {ip.details && (
                      <div className="ip-details">
                        {Object.entries(ip.details).map(([key, value]) => (
                          <div key={key}>
                            <strong>{key}:</strong> {String(value)}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {analysis.recommendations && analysis.recommendations.length > 0 && (
            <div className="recommendations-section">
              <h4>💡 Recommendations</h4>
              <ul className="recommendations-list">
                {analysis.recommendations.map((rec, index) => (
                  <li key={index}>{rec}</li>
                ))}
              </ul>
            </div>
          )}

          {analysis.attack_detection && Object.keys(analysis.attack_detection).length > 0 && (
            <div className="attack-detection-section">
              <h4>🎯 Attack Detection Summary</h4>
              <div className="attack-grid">
                {Object.entries(analysis.attack_detection).map(([type, data]) => (
                  <div key={type} className="attack-card">
                    <div className="attack-type">{type.replace(/_/g, ' ')}</div>
                    <div className="attack-count">{data.count} detections</div>
                    <div className="attack-ips">{data.unique_ips} unique IPs</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Logs List */}
      <div className="logs-section">
        <h3>Recent Security Logs ({logs.length})</h3>
        <div className="logs-table">
          <div className="table-header">
            <div>Time</div>
            <div>IP Address</div>
            <div>Attack Type</div>
            <div>Severity</div>
            <div>Threat Score</div>
            <div>Status</div>
            <div>Details</div>
          </div>
          {logs.length === 0 ? (
            <div className="empty-state">No logs found</div>
          ) : (
            logs.slice(0, 50).map((log, index) => (
              <div key={index} className={`table-row severity-${getSeverityClass(log.severity)}`}>
                <div className="time-cell">
                  {new Date(log.timestamp).toLocaleString()}
                </div>
                <div className="ip-cell">{log.ip_address}</div>
                <div className="type-cell">
                  <span className={`attack-badge ${log.event_type?.toLowerCase()}`}>
                    {log.event_type || 'N/A'}
                  </span>
                </div>
                <div className="severity-cell">
                  <span className={`severity-badge ${getSeverityClass(log.severity)}`}>
                    {log.severity || 'LOW'}
                  </span>
                </div>
                <div className="score-cell">
                  {(log.threat_score * 100).toFixed(1)}%
                </div>
                <div className="status-cell">
                  {log.blocked ? (
                    <span className="blocked-badge">🚫 BLOCKED</span>
                  ) : (
                    <span className="allowed-badge">✓ ALLOWED</span>
                  )}
                </div>
                <div className="details-cell">
                  {log.request_path && (
                    <div className="request-info">
                      {log.request_method} {log.request_path}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default LogAnalysis;




