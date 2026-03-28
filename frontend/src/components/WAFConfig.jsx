import React, { useState, useEffect } from 'react';
import './WAFConfig.css';

const WAFConfig = ({ apiCall, onConfigUpdate }) => {
  const [config, setConfig] = useState({
    domain: '',
    ssl_enabled: true,
    protection_level: 'high',
    rate_limiting: true,
    rate_limit_requests: 100,
    rate_limit_window: '1m',
    bot_protection: true,
    custom_rules: '',
    max_upload_size: 10485760,
    blocked_countries: '',
    allowed_ips: '',
    blocked_ips: '',
    enable_ai: true,
    enable_behavioral_analysis: true,
    block_duration: '24h',
    threat_score_threshold: 0.7
  });

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const data = await apiCall('/quantum/config');
      if (data) {
        setConfig(prev => ({ ...prev, ...data }));
      }
    } catch (error) {
      console.error('Error loading config:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: '', text: '' });

    try {
      const response = await apiCall('/quantum/config', {
        method: 'POST',
        body: JSON.stringify(config)
      });

      if (response.status === 'success' || response.success) {
        setMessage({ type: 'success', text: 'Configuration saved successfully!' });
        if (onConfigUpdate) onConfigUpdate(config);
      } else {
        setMessage({ type: 'error', text: 'Failed to save configuration' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: `Error: ${error.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (field, value) => {
    setConfig(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div className="waf-config-container">
      <div className="config-header">
        <h2>🛡️ WAF Configuration</h2>
        <p>Configure your Web Application Firewall settings</p>
      </div>

      {message.text && (
        <div className={`config-message ${message.type}`}>
          {message.text}
        </div>
      )}

      <form onSubmit={handleSubmit} className="waf-config-form">
        {/* Domain Configuration */}
        <div className="config-section">
          <h3>🌐 Domain Configuration</h3>
          <div className="form-group">
            <label>Domain Name *</label>
            <input
              type="text"
              value={config.domain}
              onChange={(e) => handleChange('domain', e.target.value)}
              placeholder="example.com"
              required
            />
          </div>
        </div>

        {/* Security Settings */}
        <div className="config-section">
          <h3>🔒 Security Settings</h3>
          
          <div className="form-group checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={config.ssl_enabled}
                onChange={(e) => handleChange('ssl_enabled', e.target.checked)}
              />
              Enable SSL/TLS
            </label>
          </div>

          <div className="form-group">
            <label>Protection Level *</label>
            <select
              value={config.protection_level}
              onChange={(e) => handleChange('protection_level', e.target.value)}
            >
              <option value="low">Low (Threshold: 0.9)</option>
              <option value="medium">Medium (Threshold: 0.7)</option>
              <option value="high">High (Threshold: 0.5)</option>
              <option value="paranoid">Paranoid (Threshold: 0.3) - Maximum Security</option>
            </select>
            <small>Lower threshold = stricter protection (like Cloudflare)</small>
          </div>

          <div className="form-group">
            <label>Threat Score Threshold</label>
            <input
              type="number"
              step="0.1"
              min="0"
              max="1"
              value={config.threat_score_threshold}
              onChange={(e) => handleChange('threat_score_threshold', parseFloat(e.target.value))}
            />
            <small>IPs with threat score above this will be auto-blocked</small>
          </div>

          <div className="form-group checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={config.enable_ai}
                onChange={(e) => handleChange('enable_ai', e.target.checked)}
              />
              Enable AI Threat Detection
            </label>
          </div>

          <div className="form-group checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={config.enable_behavioral_analysis}
                onChange={(e) => handleChange('enable_behavioral_analysis', e.target.checked)}
              />
              Enable Behavioral Analysis
            </label>
          </div>
        </div>

        {/* Rate Limiting */}
        <div className="config-section">
          <h3>⚡ Rate Limiting</h3>
          
          <div className="form-group checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={config.rate_limiting}
                onChange={(e) => handleChange('rate_limiting', e.target.checked)}
              />
              Enable Rate Limiting
            </label>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Max Requests</label>
              <input
                type="number"
                value={config.rate_limit_requests}
                onChange={(e) => handleChange('rate_limit_requests', parseInt(e.target.value))}
                min="1"
              />
            </div>
            <div className="form-group">
              <label>Time Window</label>
              <select
                value={config.rate_limit_window}
                onChange={(e) => handleChange('rate_limit_window', e.target.value)}
              >
                <option value="1m">1 Minute</option>
                <option value="5m">5 Minutes</option>
                <option value="15m">15 Minutes</option>
                <option value="1h">1 Hour</option>
              </select>
            </div>
          </div>
        </div>

        {/* Bot Protection */}
        <div className="config-section">
          <h3>🤖 Bot Protection</h3>
          
          <div className="form-group checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={config.bot_protection}
                onChange={(e) => handleChange('bot_protection', e.target.checked)}
              />
              Enable Bot Protection
            </label>
          </div>
        </div>

        {/* Access Control */}
        <div className="config-section">
          <h3>🚫 Access Control</h3>
          
          <div className="form-group">
            <label>Blocked Countries (ISO codes, comma-separated)</label>
            <input
              type="text"
              value={config.blocked_countries}
              onChange={(e) => handleChange('blocked_countries', e.target.value)}
              placeholder="CN,RU,KP,IR"
            />
            <small>Example: CN,RU,KP,IR</small>
          </div>

          <div className="form-group">
            <label>Allowed IPs (one per line or comma-separated)</label>
            <textarea
              value={config.allowed_ips}
              onChange={(e) => handleChange('allowed_ips', e.target.value)}
              placeholder="192.168.1.0/24&#10;10.0.0.1"
              rows="4"
            />
            <small>IPs or CIDR ranges that bypass WAF</small>
          </div>

          <div className="form-group">
            <label>Blocked IPs (one per line or comma-separated)</label>
            <textarea
              value={config.blocked_ips}
              onChange={(e) => handleChange('blocked_ips', e.target.value)}
              placeholder="192.168.1.100&#10;10.0.0.50"
              rows="4"
            />
            <small>IPs that will be permanently blocked</small>
          </div>
        </div>

        {/* Advanced Settings */}
        <div className="config-section">
          <h3>⚙️ Advanced Settings</h3>
          
          <div className="form-group">
            <label>Max Upload Size (bytes)</label>
            <input
              type="number"
              value={config.max_upload_size}
              onChange={(e) => handleChange('max_upload_size', parseInt(e.target.value))}
              min="0"
            />
            <small>Default: 10485760 (10MB)</small>
          </div>

          <div className="form-group">
            <label>Auto-Block Duration</label>
            <select
              value={config.block_duration}
              onChange={(e) => handleChange('block_duration', e.target.value)}
            >
              <option value="1h">1 Hour</option>
              <option value="6h">6 Hours</option>
              <option value="24h">24 Hours</option>
              <option value="7d">7 Days</option>
              <option value="30d">30 Days</option>
            </select>
          </div>

          <div className="form-group">
            <label>Custom WAF Rules (JSON format)</label>
            <textarea
              value={config.custom_rules}
              onChange={(e) => handleChange('custom_rules', e.target.value)}
              placeholder='{"rules": [{"pattern": ".*", "action": "block"}]}'
              rows="8"
            />
            <small>Advanced: Custom security rules in JSON format</small>
          </div>
        </div>

        <div className="form-actions">
          <button type="submit" className="save-btn" disabled={loading}>
            {loading ? 'Saving...' : '💾 Save Configuration'}
          </button>
          <button type="button" className="reset-btn" onClick={loadConfig}>
            🔄 Reset to Saved
          </button>
        </div>
      </form>
    </div>
  );
};

export default WAFConfig;







