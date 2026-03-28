import React, { useState, useEffect } from 'react';
import './IPBlockManager.css';

const IPBlockManager = ({ apiCall }) => {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [newBlock, setNewBlock] = useState({
    ip: '',
    reason: '',
    duration: '24h',
    attack_type: 'MANUAL'
  });

  useEffect(() => {
    loadBlockedIPs();
    const interval = setInterval(loadBlockedIPs, 10000);
    return () => clearInterval(interval);
  }, []);

  const loadBlockedIPs = async () => {
    try {
      const data = await apiCall('/admin/ip-blocks');
      setBlockedIPs(data || []);
    } catch (error) {
      console.error('Error loading blocked IPs:', error);
    }
  };

  const handleBlockIP = async (e) => {
    e.preventDefault();
    if (!newBlock.ip.trim()) return;

    setLoading(true);
    try {
      await apiCall('/admin/ip-blocks', {
        method: 'POST',
        body: JSON.stringify(newBlock)
      });
      setNewBlock({ ip: '', reason: '', duration: '24h', attack_type: 'MANUAL' });
      loadBlockedIPs();
    } catch (error) {
      alert(`Error blocking IP: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleUnblockIP = async (ip) => {
    if (!confirm(`Unblock IP ${ip}?`)) return;

    try {
      await apiCall(`/admin/ip-blocks/${ip}`, {
        method: 'DELETE'
      });
      loadBlockedIPs();
    } catch (error) {
      alert(`Error unblocking IP: ${error.message}`);
    }
  };

  const formatDuration = (blockedUntil) => {
    const now = new Date();
    const until = new Date(blockedUntil);
    const diff = until - now;
    
    if (diff <= 0) return 'Expired';
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} day(s)`;
    if (hours > 0) return `${hours} hour(s)`;
    return 'Less than 1 hour';
  };

  return (
    <div className="ip-block-manager">
      <div className="block-header">
        <h2>🚫 IP Blocking Management</h2>
        <p>Manage blocked IP addresses and auto-blocking rules</p>
      </div>

      {/* Block New IP Form */}
      <div className="block-form-section">
        <h3>Block New IP Address</h3>
        <form onSubmit={handleBlockIP} className="block-form">
          <div className="form-row">
            <div className="form-group">
              <label>IP Address *</label>
              <input
                type="text"
                value={newBlock.ip}
                onChange={(e) => setNewBlock(prev => ({ ...prev, ip: e.target.value }))}
                placeholder="192.168.1.100"
                required
              />
            </div>
            <div className="form-group">
              <label>Block Duration</label>
              <select
                value={newBlock.duration}
                onChange={(e) => setNewBlock(prev => ({ ...prev, duration: e.target.value }))}
              >
                <option value="1h">1 Hour</option>
                <option value="6h">6 Hours</option>
                <option value="24h">24 Hours</option>
                <option value="7d">7 Days</option>
                <option value="30d">30 Days</option>
                <option value="permanent">Permanent</option>
              </select>
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Attack Type</label>
              <select
                value={newBlock.attack_type}
                onChange={(e) => setNewBlock(prev => ({ ...prev, attack_type: e.target.value }))}
              >
                <option value="MANUAL">Manual Block</option>
                <option value="SQL_INJECTION">SQL Injection</option>
                <option value="XSS">XSS Attack</option>
                <option value="BRUTE_FORCE">Brute Force</option>
                <option value="DDOS">DDoS</option>
                <option value="SCANNING">Port Scanning</option>
                <option value="BEHAVIORAL">Suspicious Behavior</option>
              </select>
            </div>
            <div className="form-group full-width">
              <label>Reason</label>
              <input
                type="text"
                value={newBlock.reason}
                onChange={(e) => setNewBlock(prev => ({ ...prev, reason: e.target.value }))}
                placeholder="Reason for blocking this IP"
              />
            </div>
          </div>
          <button type="submit" className="block-btn" disabled={loading}>
            {loading ? 'Blocking...' : '🚫 Block IP'}
          </button>
        </form>
      </div>

      {/* Blocked IPs List */}
      <div className="blocked-list-section">
        <h3>Currently Blocked IPs ({blockedIPs.length})</h3>
        <div className="blocked-ips-table">
          <div className="table-header">
            <div>IP Address</div>
            <div>Reason</div>
            <div>Attack Type</div>
            <div>Threat Score</div>
            <div>Blocked At</div>
            <div>Expires In</div>
            <div>Source</div>
            <div>Actions</div>
          </div>
          {blockedIPs.length === 0 ? (
            <div className="empty-state">No IPs currently blocked</div>
          ) : (
            blockedIPs.map((block, index) => (
              <div key={index} className="table-row">
                <div className="ip-cell">{block.ip}</div>
                <div className="reason-cell">{block.reason || 'N/A'}</div>
                <div className="type-cell">
                  <span className={`attack-badge ${block.attack_type?.toLowerCase()}`}>
                    {block.attack_type}
                  </span>
                </div>
                <div className="score-cell">
                  {(block.threat_score * 100).toFixed(1)}%
                </div>
                <div className="time-cell">
                  {new Date(block.blocked_at).toLocaleString()}
                </div>
                <div className="expires-cell">
                  {formatDuration(block.blocked_until)}
                </div>
                <div className="source-cell">
                  <span className={`source-badge ${block.source}`}>
                    {block.source}
                  </span>
                </div>
                <div className="actions-cell">
                  <button
                    className="unblock-btn"
                    onClick={() => handleUnblockIP(block.ip)}
                  >
                    Unblock
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Statistics */}
      <div className="block-stats">
        <div className="stat-card">
          <div className="stat-value">{blockedIPs.length}</div>
          <div className="stat-label">Total Blocked</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {blockedIPs.filter(b => b.source === 'auto').length}
          </div>
          <div className="stat-label">Auto-Blocked</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {blockedIPs.filter(b => b.source === 'ai').length}
          </div>
          <div className="stat-label">AI-Blocked</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {blockedIPs.filter(b => b.source === 'manual').length}
          </div>
          <div className="stat-label">Manual Blocks</div>
        </div>
      </div>
    </div>
  );
};

export default IPBlockManager;







