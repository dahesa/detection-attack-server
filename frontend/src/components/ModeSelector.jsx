import React, { useState, useEffect } from 'react';
import './ModeSelector.css';

const ModeSelector = ({ token }) => {
  const [currentMode, setCurrentMode] = useState('reverse_proxy');
  const [config, setConfig] = useState({
    reverse_proxy: { enabled: false, backend_url: '' },
    inline: { enabled: false, internal_networks: [] },
    api: { enabled: false, api_key_required: true },
    saas: { enabled: false, total_tenants: 0 }
  });
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('reverse_proxy');

  useEffect(() => {
    fetchModeConfig();
  }, []);

  const fetchModeConfig = async () => {
    try {
      const response = await fetch('/api/mode/config', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      setCurrentMode(data.current_mode || 'reverse_proxy');
      setConfig({
        reverse_proxy: data.reverse_proxy || { enabled: false },
        inline: data.inline || { enabled: false },
        api: data.api || { enabled: false },
        saas: data.saas || { enabled: false }
      });
    } catch (error) {
      console.error('Failed to fetch mode config:', error);
    }
  };

  const updateReverseProxy = async (e) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData(e.target);
    const data = {
      backend_url: formData.get('backend_url'),
      backend_host: formData.get('backend_host'),
      preserve_host: formData.get('preserve_host') === 'on',
      ssl_verify: formData.get('ssl_verify') === 'on'
    };

    try {
      const response = await fetch('/api/mode/reverse-proxy', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      if (response.ok) {
        alert('Reverse proxy configured successfully!');
        fetchModeConfig();
      }
    } catch (error) {
      alert('Failed to configure reverse proxy');
    } finally {
      setLoading(false);
    }
  };

  const updateInline = async (e) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData(e.target);
    const networks = formData.get('internal_networks').split(',').map(s => s.trim()).filter(s => s);
    const data = {
      enabled: formData.get('enabled') === 'on',
      internal_networks: networks,
      bypass_ips: formData.get('bypass_ips').split(',').map(s => s.trim()).filter(s => s),
      log_only: formData.get('log_only') === 'on',
      strict_mode: formData.get('strict_mode') === 'on'
    };

    try {
      const response = await fetch('/api/mode/inline', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      if (response.ok) {
        alert('Inline mode configured successfully!');
        fetchModeConfig();
      }
    } catch (error) {
      alert('Failed to configure inline mode');
    } finally {
      setLoading(false);
    }
  };

  const updateAPI = async (e) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData(e.target);
    const data = {
      enabled: formData.get('enabled') === 'on',
      api_key_required: formData.get('api_key_required') === 'on',
      allowed_origins: formData.get('allowed_origins').split(',').map(s => s.trim()).filter(s => s)
    };

    try {
      const response = await fetch('/api/mode/api', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      if (response.ok) {
        alert('API mode configured successfully!');
        fetchModeConfig();
      }
    } catch (error) {
      alert('Failed to configure API mode');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mode-selector">
      <div className="mode-header">
        <h2>🔄 Deployment Mode Configuration</h2>
        <div className="current-mode-badge">
          Current Mode: <strong>{currentMode.replace('_', ' ').toUpperCase()}</strong>
        </div>
      </div>

      <div className="mode-tabs">
        <button 
          className={activeTab === 'reverse_proxy' ? 'active' : ''}
          onClick={() => setActiveTab('reverse_proxy')}
        >
          🔄 Reverse Proxy
        </button>
        <button 
          className={activeTab === 'inline' ? 'active' : ''}
          onClick={() => setActiveTab('inline')}
        >
          🔗 Inline Mode
        </button>
        <button 
          className={activeTab === 'api' ? 'active' : ''}
          onClick={() => setActiveTab('api')}
        >
          🔌 API/SDK Mode
        </button>
        <button 
          className={activeTab === 'saas' ? 'active' : ''}
          onClick={() => setActiveTab('saas')}
        >
          ☁️ SaaS Mode
        </button>
      </div>

      <div className="mode-content">
        {activeTab === 'reverse_proxy' && (
          <div className="mode-panel">
            <h3>Reverse Proxy Mode (REALISTIS & WAJIB)</h3>
            <p className="mode-description">
              Mode reverse proxy yang realistis untuk meneruskan request ke backend server.
              Semua request akan melalui WAF sebelum diteruskan ke backend.
            </p>
            <form onSubmit={updateReverseProxy}>
              <div className="form-group">
                <label>Backend URL *</label>
                <input 
                  type="url" 
                  name="backend_url" 
                  placeholder="http://backend:8080"
                  defaultValue={config.reverse_proxy.backend_url}
                  required
                />
              </div>
              <div className="form-group">
                <label>Backend Host</label>
                <input 
                  type="text" 
                  name="backend_host" 
                  placeholder="backend.example.com"
                />
              </div>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="preserve_host" />
                  Preserve Host Header
                </label>
              </div>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="ssl_verify" defaultChecked />
                  Verify SSL Certificate
                </label>
              </div>
              <button type="submit" disabled={loading}>
                {loading ? 'Configuring...' : 'Configure Reverse Proxy'}
              </button>
            </form>
            {config.reverse_proxy.health && (
              <div className="health-status">
                <h4>Backend Health</h4>
                <div className={config.reverse_proxy.health.healthy ? 'healthy' : 'unhealthy'}>
                  {config.reverse_proxy.health.healthy ? '✅ Healthy' : '❌ Unhealthy'}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'inline' && (
          <div className="mode-panel">
            <h3>Inline Mode (Internal Network)</h3>
            <p className="mode-description">
              Mode untuk melindungi jaringan internal. WAF berjalan inline di jaringan internal.
            </p>
            <form onSubmit={updateInline}>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="enabled" defaultChecked={config.inline.enabled} />
                  Enable Inline Mode
                </label>
              </div>
              <div className="form-group">
                <label>Internal Networks (CIDR)</label>
                <input 
                  type="text" 
                  name="internal_networks" 
                  placeholder="192.168.1.0/24,10.0.0.0/8"
                  defaultValue={config.inline.internal_networks?.join(',')}
                />
              </div>
              <div className="form-group">
                <label>Bypass IPs</label>
                <input 
                  type="text" 
                  name="bypass_ips" 
                  placeholder="192.168.1.100,10.0.0.1"
                />
              </div>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="log_only" />
                  Log Only (Don't Block)
                </label>
              </div>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="strict_mode" />
                  Strict Mode (Apply to All Traffic)
                </label>
              </div>
              <button type="submit" disabled={loading}>
                {loading ? 'Configuring...' : 'Configure Inline Mode'}
              </button>
            </form>
          </div>
        )}

        {activeTab === 'api' && (
          <div className="mode-panel">
            <h3>API/SDK Mode (ADVANCED)</h3>
            <p className="mode-description">
              Mode API/SDK untuk integrasi dengan aplikasi lain. Mendukung API key authentication dan webhooks.
            </p>
            <form onSubmit={updateAPI}>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="enabled" defaultChecked={config.api.enabled} />
                  Enable API Mode
                </label>
              </div>
              <div className="form-group">
                <label>
                  <input type="checkbox" name="api_key_required" defaultChecked={config.api.api_key_required} />
                  Require API Key
                </label>
              </div>
              <div className="form-group">
                <label>Allowed Origins (CORS)</label>
                <input 
                  type="text" 
                  name="allowed_origins" 
                  placeholder="https://app1.com,https://app2.com"
                />
              </div>
              <button type="submit" disabled={loading}>
                {loading ? 'Configuring...' : 'Configure API Mode'}
              </button>
            </form>
            <div className="api-info">
              <h4>API Usage</h4>
              <pre>
{`curl -H "X-API-Key: your-api-key" \\
     -H "X-Signature: signature" \\
     https://your-waf.com/api/endpoint`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === 'saas' && (
          <div className="mode-panel">
            <h3>SaaS Mode (Cloudflare-style)</h3>
            <p className="mode-description">
              Mode multi-tenant seperti Cloudflare. Setiap tenant memiliki domain dan konfigurasi sendiri.
            </p>
            <div className="saas-stats">
              <div className="stat">
                <div className="stat-value">{config.saas.total_tenants || 0}</div>
                <div className="stat-label">Total Tenants</div>
              </div>
              <div className="stat">
                <div className="stat-value">{config.saas.active_tenants || 0}</div>
                <div className="stat-label">Active</div>
              </div>
              <div className="stat">
                <div className="stat-value">{config.saas.trial_tenants || 0}</div>
                <div className="stat-label">Trial</div>
              </div>
            </div>
            <div className="saas-info">
              <h4>Features</h4>
              <ul>
                <li>✅ Multi-tenant support</li>
                <li>✅ Custom domains per tenant</li>
                <li>✅ Per-tenant rate limiting</li>
                <li>✅ Per-tenant WAF rules</li>
                <li>✅ Tenant isolation</li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ModeSelector;




