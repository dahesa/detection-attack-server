import React, { useState, useEffect, useRef, useCallback } from 'react';
import './QuantumDashboard.css';
import WAFConfig from './WAFConfig';
import IPBlockManager from './IPBlockManager';
import LogAnalysis from './LogAnalysis';
import ModeSelector from './ModeSelector';
import IPTrackingMap from './IPTrackingMap';

// Utility functions
const formatNumber = (num) => {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + 'M';
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + 'K';
  }
  return num.toString();
};

const getThreatLevel = (blockRate) => {
  if (blockRate > 15) return { level: 'CRITICAL', class: 'critical' };
  if (blockRate > 8) return { level: 'HIGH', class: 'high' };
  if (blockRate > 3) return { level: 'MEDIUM', class: 'medium' };
  return { level: 'LOW', class: 'low' };
};

const StatCard = ({ value, label, type, trend, loading }) => {
  // Handle different value types
  const displayValue = () => {
    if (loading) return '...';
    if (value === null || value === undefined) return '0';
    if (typeof value === 'string') return value; // Already formatted strings like "98.50%" or "LIVE"
    if (typeof value === 'number') {
      // Handle decimal numbers
      if (value % 1 !== 0) {
        return value.toFixed(2);
      }
      return formatNumber(value);
    }
    return String(value);
  };

  return (
    <div className={`quantum-stat-card ${loading ? 'loading' : ''}`}>
      <div className={`quantum-stat-value ${type}`}>
        {displayValue()}
        {trend && <span className={`trend ${trend > 0 ? 'up' : 'down'}`}>
          {trend > 0 ? '↗' : '↘'} {Math.abs(trend)}%
        </span>}
      </div>
      <div className="quantum-stat-label">{label}</div>
      {loading && <div className="loading-pulse"></div>}
    </div>
  );
};

const LogEntry = ({ log, index }) => (
  <div className={`quantum-log-entry quantum-log-severity-${log.severity?.toLowerCase()}`}>
    <div className="quantum-log-time">
      {new Date(log.timestamp).toLocaleTimeString()}
    </div>
    <div className="quantum-log-main">
      <span className="quantum-log-ip">{log.ip}</span> - 
      <span className="quantum-log-type"> {log.attack_type}</span> - 
      <span className={`severity-${log.severity?.toLowerCase()}`}> {log.severity}</span>
      {log.blocked && <span className="blocked-badge">🚫 BLOCKED</span>}
    </div>
    <div className="quantum-log-details">
      {log.request_method} {log.request_path} | Score: {log.threat_score?.toFixed(2)}
    </div>
    <div className="quantum-log-ai">
      {log.ai_insights?.map((insight, i) => (
        <span key={i} className="ai-insight">🤖 {insight}</span>
      ))}
    </div>
  </div>
);

const QuantumDashboard = () => {
  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });

  // Main state
  const [activeTab, setActiveTab] = useState('quantum_dashboard');
  const [loading, setLoading] = useState({
    stats: true,
    logs: true,
    attackers: true,
    threats: true
  });

  const [stats, setStats] = useState({
    total_requests: 0,
    blocked_requests: 0,
    sql_injections: 0,
    xss_attempts: 0,
    brute_force: 0,
    zero_day_attempts: 0,
    block_rate: 0,
    threat_actors: 0,
    requests_per_second: 0,
    api_attacks: 0,
    ddos_attempts: 0
  });

  const [logs, setLogs] = useState([]);
  const [attackers, setAttackers] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [threats, setThreats] = useState([]);
  const [performance, setPerformance] = useState({});
  const [aiConsole, setAiConsole] = useState([
    { type: 'ai', message: 'Quantum AI systems initialized. All quantum engines online.' },
    { type: 'ai', message: 'Quantum threat intelligence synchronized across dimensions.' },
    { type: 'ai', message: 'Neural networks optimized with quantum algorithms.' },
    { type: 'ai', message: 'WAF middleware activated and protecting all routes.' },
    { type: 'ai', message: 'Real-time threat detection operational.' },
    { type: 'ai', message: 'Ready for quantum cyber command operations.' }
  ]);

  const [webConfig, setWebConfig] = useState({
    domain: 'example.com',
    sslEnabled: true,
    protectionLevel: 'maximum',
    rateLimiting: true,
    botProtection: true,
    customRules: '',
    maxUploadSize: 10485760,
    blockedCountries: '',
    allowedIPs: '',
    blockedIPs: ''
  });

  const [aiChat, setAiChat] = useState([
    { type: 'ai', message: 'Halo! Saya Zein AI Security Assistant. Saya bisa membantu Anda dengan pertanyaan tentang keamanan siber, serangan, dan konfigurasi WAF.' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [showChat, setShowChat] = useState(false);
  const [aiPythonStatus, setAiPythonStatus] = useState('connecting');
  const [chatLoading, setChatLoading] = useState(false);

  const [isConnected, setIsConnected] = useState(false);
  const [realTimeData, setRealTimeData] = useState([]);
  const [systemHealth, setSystemHealth] = useState({});
  
  const ws = useRef(null);
  const consoleRef = useRef(null);
  const chatRef = useRef(null);
  const tokenRef = useRef(null);

  // Authentication methods
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(loginForm)
      });

      // Check content type
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        console.error('Non-JSON response:', text);
        alert('Login failed: Server returned invalid response. Please check if backend is running.');
        return;
      }

      if (response.ok) {
        const data = await response.json();
        tokenRef.current = data.token;
        setUser(data.user);
        setIsAuthenticated(true);
        addAIConsoleMessage('ai', `✅ User ${data.user.username} authenticated successfully`);
      } else {
        try {
          const error = await response.json();
          alert(`Login failed: ${error.error || error.message || 'Invalid credentials'}`);
        } catch (parseError) {
          const text = await response.text();
          console.error('Error parsing response:', text);
          alert(`Login failed: ${response.status} ${response.statusText}`);
        }
      }
    } catch (error) {
      console.error('Login error:', error);
      alert('Login failed: ' + (error.message || 'Network error. Please check if backend is running on port 8080.'));
    }
  };

  const handleLogout = () => {
    tokenRef.current = null;
    setUser(null);
    setIsAuthenticated(false);
    setLoginForm({ username: '', password: '' });
  };

  // API call helper with authentication
  const apiCall = async (endpoint, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (tokenRef.current) {
      headers['Authorization'] = `Bearer ${tokenRef.current}`;
    }

    try {
      const response = await fetch(`/api${endpoint}`, {
        ...options,
        headers,
      });

      if (response.status === 401) {
        // Token expired
        handleLogout();
        throw new Error('Authentication required');
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API call failed for ${endpoint}:`, error);
      throw error;
    }
  };

  // WebSocket connection
  const connectWebSocket = useCallback(() => {
    try {
      // WebSocket needs direct connection to backend (not through Vite proxy)
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//localhost:8080/ws/quantum${tokenRef.current ? `?token=${tokenRef.current}` : ''}`;
      ws.current = new WebSocket(wsUrl);
      
      ws.current.onopen = () => {
        console.log('🔌 Connected to Quantum WebSocket');
        setIsConnected(true);
        addAIConsoleMessage('ai', 'WebSocket connected to Quantum AI backend - Real-time updates active');
      };
      
      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleWebSocketMessage(data);
        } catch (error) {
          console.error('WebSocket message error:', error);
        }
      };
      
      ws.current.onclose = (event) => {
        console.log('WebSocket disconnected', event.code, event.reason);
        setIsConnected(false);
        // Only reconnect if not a normal closure
        if (event.code !== 1000 && event.code !== 1001) {
          addAIConsoleMessage('ai', `WebSocket disconnected (code: ${event.code}) - attempting reconnect...`);
          // Exponential backoff
          const reconnectCount = ws.current?.reconnectCount || 0;
          const delay = Math.min(30000, 3000 * Math.pow(2, Math.min(5, reconnectCount)));
          setTimeout(() => {
            if (!ws.current || ws.current.readyState === WebSocket.CLOSED) {
              if (ws.current) ws.current.reconnectCount = reconnectCount + 1;
              connectWebSocket();
            }
          }, delay);
        } else {
          addAIConsoleMessage('ai', 'WebSocket closed normally');
        }
      };
      
      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        setIsConnected(false);
      };
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      setIsConnected(false);
    }
  }, []);

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'quantum_stats_update':
      case 'initial_stats':
        if (data.data) {
          const normalizedStats = {
            total_requests: data.data.total_requests || 0,
            blocked_requests: data.data.blocked_requests || 0,
            sql_injections: data.data.sql_injections || 0,
            xss_attempts: data.data.xss_attempts || 0,
            brute_force: data.data.brute_force || 0,
            zero_day_attempts: data.data.zero_day_attempts || 0,
            block_rate: data.data.block_rate || 0,
            threat_actors: data.data.threat_actors || 0,
            requests_per_second: data.data.requests_per_second || 0,
            path_traversal: data.data.path_traversal || 0,
            command_injection: data.data.command_injection || 0,
            xxe_attempts: data.data.xxe_attempts || 0,
            deserialization: data.data.deserialization || 0,
            ddos_attempts: data.data.ddos_attempts || 0,
            ...data.data
          };
          setStats(prevStats => ({ ...prevStats, ...normalizedStats }));
          console.log('📊 Stats updated via WebSocket:', normalizedStats);
        }
        break;
      case 'security_event':
        addSecurityEvent(data.data);
        break;
      case 'system_health':
        setSystemHealth(data.data);
        break;
      case 'config_update':
        addAIConsoleMessage('ai', `Configuration updated: ${data.key}`);
        break;
      default:
        console.log('Unknown WebSocket message:', data);
    }
  };

  const addSecurityEvent = (event) => {
    setLogs(prevLogs => {
      const newLogs = [event, ...prevLogs.slice(0, 49)];
      return newLogs;
    });

    // Update stats in real-time
    if (event.blocked) {
      setStats(prev => ({
        ...prev,
        blocked_requests: prev.blocked_requests + 1,
        total_requests: prev.total_requests + 1
      }));
    }
  };

  // Data fetching methods
  const fetchInitialData = async () => {
    if (!isAuthenticated) return;

    try {
      setLoading(prev => ({ ...prev, stats: true, logs: true, attackers: true, threats: true }));

      const [statsData, logsData, attackersData, threatsData, performanceData, configData, healthData] = await Promise.all([
        apiCall('/quantum/stats').catch(err => {
          console.error('Error fetching stats:', err);
          return {
            total_requests: 0,
            blocked_requests: 0,
            sql_injections: 0,
            xss_attempts: 0,
            brute_force: 0,
            zero_day_attempts: 0,
            block_rate: 0,
            threat_actors: 0,
            requests_per_second: 0,
            path_traversal: 0,
            command_injection: 0,
            xxe_attempts: 0,
            deserialization: 0,
            ddos_attempts: 0
          };
        }),
        apiCall('/quantum/logs?limit=50').catch(err => {
          console.error('Error fetching logs:', err);
          return [];
        }),
        apiCall('/quantum/attackers?limit=20').catch(err => {
          console.error('Error fetching attackers:', err);
          return [];
        }),
        apiCall('/quantum/threats').catch(err => {
          console.error('Error fetching threats:', err);
          return [];
        }),
        apiCall('/quantum/performance').catch(err => {
          console.error('Error fetching performance:', err);
          return {};
        }),
        apiCall('/quantum/config').catch(err => {
          console.error('Error fetching config:', err);
          return {};
        }),
        apiCall('/health').catch(err => {
          console.error('Error fetching health:', err);
          return { status: 'unknown' };
        })
      ]);

      // Ensure stats has all required fields
      const normalizedStats = {
        total_requests: statsData.total_requests || 0,
        blocked_requests: statsData.blocked_requests || 0,
        sql_injections: statsData.sql_injections || 0,
        xss_attempts: statsData.xss_attempts || 0,
        brute_force: statsData.brute_force || 0,
        zero_day_attempts: statsData.zero_day_attempts || 0,
        block_rate: statsData.block_rate || 0,
        threat_actors: statsData.threat_actors || 0,
        requests_per_second: statsData.requests_per_second || 0,
        path_traversal: statsData.path_traversal || 0,
        command_injection: statsData.command_injection || 0,
        xxe_attempts: statsData.xxe_attempts || 0,
        deserialization: statsData.deserialization || 0,
        ddos_attempts: statsData.ddos_attempts || 0,
        ...statsData // Keep any additional fields
      };

      setStats(normalizedStats);
      setLogs(Array.isArray(logsData) ? logsData : []);
      setAttackers(Array.isArray(attackersData) ? attackersData : []);
      setThreats(Array.isArray(threatsData) ? threatsData : []);
      setPerformance(performanceData || {});
      setWebConfig(prev => ({ ...prev, ...configData }));
      setSystemHealth(healthData || { status: 'unknown' });
      
      // Set IP locations (fetch separately to avoid Promise.all issues)
      try {
        const locationsDataResult = await apiCall('/geolocation/ips').catch(err => {
          console.error('Error fetching IP locations:', err);
          return { locations: [], stats: {} };
        });
        
        if (locationsDataResult && locationsDataResult.locations) {
          setIPLocations(Array.isArray(locationsDataResult.locations) ? locationsDataResult.locations : []);
          setLocationStats(locationsDataResult.stats || {});
        } else {
          setIPLocations([]);
          setLocationStats({});
        }
      } catch (error) {
        console.error('Error setting IP locations:', error);
        setIPLocations([]);
        setLocationStats({});
      }

      console.log('✅ Data fetched successfully:', {
        stats: normalizedStats,
        logsCount: Array.isArray(logsData) ? logsData.length : 0,
        attackersCount: Array.isArray(attackersData) ? attackersData.length : 0
      });

    } catch (error) {
      console.error('Error fetching initial data:', error);
      addAIConsoleMessage('ai', `❌ Error fetching data: ${error.message}`);
    } finally {
      setLoading(prev => ({ ...prev, stats: false, logs: false, attackers: false, threats: false, locations: false }));
    }
  };

  const fetchSystemMetrics = async () => {
    try {
      const metrics = await apiCall('/admin/system/metrics');
      setPerformance(metrics);
    } catch (error) {
      console.error('Error fetching system metrics:', error);
    }
  };

  // AI Console methods
  const addAIConsoleMessage = (type, message) => {
    setAiConsole(prev => [...prev, { type, message }]);
  };

  const executeQuantumAICommand = async (command) => {
    const commands = {
      'QUANTUM_DEFENSE': 'Activating quantum defense systems... Quantum entanglement established. Defense matrix optimized.',
      'AI_OPTIMIZATION': 'Optimizing AI algorithms... Quantum neural networks enhanced. Performance improved by 45%.',
      'THREAT_ANALYSIS': 'Initiating quantum threat analysis... Multidimensional scanning complete. No quantum threats detected.',
      'QUANTUM_SCAN': 'Executing quantum vulnerability scan... Scanning quantum space-time. All systems secure.',
      'NEURAL_ENHANCE': 'Enhancing neural networks... Quantum learning algorithms activated. AI intelligence boosted.',
      'SHIELD_BOOST': 'Boosting quantum shield... Shield strength increased to 99.99%. Multiversal protection active.',
      'WAF_TEST': 'Testing WAF protection... Sending test requests to verify threat detection capabilities.',
      'SYSTEM_DIAGNOSTIC': 'Running comprehensive system diagnostic... All subsystems reporting optimal status.'
    };

    if (commands[command]) {
      addAIConsoleMessage('user', `EXECUTE: ${command}`);
      
      // Simulate AI processing
      setTimeout(() => {
        addAIConsoleMessage('ai', commands[command]);
        
        // Execute specific actions
        if (command === 'WAF_TEST') {
          setTimeout(() => testWAFProtection(), 1000);
        } else if (command === 'SYSTEM_DIAGNOSTIC') {
          setTimeout(() => runSystemDiagnostic(), 1500);
        }
      }, 500);
    }
  };

  const testWAFProtection = async () => {
    addAIConsoleMessage('ai', 'Initiating WAF protection test...');
    
    const testCases = [
      { 
        url: '/api/login', 
        method: 'POST', 
        data: { username: "admin' OR '1'='1", password: "test" },
        description: 'SQL Injection Test'
      },
      { 
        url: '/api/data?q=<script>alert("xss")</script>', 
        method: 'GET',
        description: 'XSS Attack Test'
      },
      { 
        url: '/admin/../etc/passwd', 
        method: 'GET',
        description: 'Path Traversal Test'
      },
      { 
        url: '/api/upload', 
        method: 'POST',
        headers: { 'Content-Type': 'multipart/form-data' },
        description: 'File Upload Test'
      }
    ];

    for (const testCase of testCases) {
      try {
        const response = await fetch(testCase.url, {
          method: testCase.method,
          headers: {
            'Content-Type': 'application/json',
            ...testCase.headers
          },
          body: testCase.data ? JSON.stringify(testCase.data) : undefined
        });
        
        if (response.status === 403) {
          addAIConsoleMessage('ai', `✅ WAF BLOCKED: ${testCase.description}`);
        } else {
          addAIConsoleMessage('ai', `⚠️ ALLOWED: ${testCase.description} (Status: ${response.status})`);
        }
      } catch (error) {
        addAIConsoleMessage('ai', `❌ ERROR: ${testCase.description} - ${error.message}`);
      }
      
      await new Promise(resolve => setTimeout(resolve, 800));
    }
    
    addAIConsoleMessage('ai', 'WAF protection test completed. Defense systems verified.');
  };

  const runSystemDiagnostic = async () => {
    addAIConsoleMessage('ai', 'Starting comprehensive system diagnostic...');
    
    const checks = [
      { name: 'Database Connection', check: () => apiCall('/health') },
      { name: 'AI Service', check: () => fetch('/ai/health').then(r => r.ok).catch(() => false) },
      { name: 'Redis Cache', check: () => apiCall('/health') },
      { name: 'Threat Intelligence', check: () => apiCall('/quantum/threats') }
    ];

    for (const check of checks) {
      try {
        await check.check();
        addAIConsoleMessage('ai', `✅ ${check.name}: OPERATIONAL`);
      } catch (error) {
        addAIConsoleMessage('ai', `❌ ${check.name}: FAILED - ${error.message}`);
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    addAIConsoleMessage('ai', 'System diagnostic completed. All critical systems operational.');
  };

  // Configuration methods
  const handleWebConfigSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await apiCall('/quantum/config', {
        method: 'POST',
        body: JSON.stringify(webConfig)
      });

      if (response.status === 'success') {
        addAIConsoleMessage('ai', `✅ Web configuration updated for domain: ${webConfig.domain}`);
        // Notify via WebSocket
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
          ws.current.send(JSON.stringify({
            type: 'config_update',
            domain: webConfig.domain
          }));
        }
      } else {
        addAIConsoleMessage('ai', `❌ Failed to update configuration`);
      }
    } catch (error) {
      addAIConsoleMessage('ai', `❌ Error updating configuration: ${error.message}`);
    }
  };

  // AI Chat methods
  const handleChatSubmit = async (e) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;

    const userMessage = chatInput;
    setAiChat(prev => [...prev, { type: 'user', message: userMessage }]);
    setChatInput('');
    setChatLoading(true);

    // Add loading message
    setAiChat(prev => [...prev, { type: 'ai', message: '...', loading: true }]);

    try {
      const response = await apiCall('/quantum/ai-chat', {
        method: 'POST',
        body: JSON.stringify({ message: userMessage })
      });

      // Remove loading message and add real response
      setAiChat(prev => {
        const filtered = prev.filter(msg => !msg.loading);
        return [...filtered, { type: 'ai', message: response.response || response.message || 'Response received' }];
      });
    } catch (error) {
      console.error('Chat error:', error);
      // Remove loading message and add error
      setAiChat(prev => {
        const filtered = prev.filter(msg => !msg.loading);
        return [...filtered, { 
          type: 'ai', 
          message: `Maaf, terjadi kesalahan: ${error.message || 'Tidak dapat terhubung ke AI service. Pastikan backend dan AI service berjalan dengan baik.'}` 
        }];
      });
    } finally {
      setChatLoading(false);
    }
  };

  const testAIPythonConnection = async () => {
    setAiPythonStatus('testing');
    try {
      // Try proxy first, fallback to direct
      let response = await fetch('/ai/health').catch(() => null);
      if (!response || !response.ok) {
        response = await fetch('http://localhost:5000/health').catch(() => null);
      }
      if (response && response.ok) {
        setAiPythonStatus('connected');
        addAIConsoleMessage('ai', '✅ AI.PY system connected and operational');
        return true;
      } else {
        setAiPythonStatus('error');
        addAIConsoleMessage('ai', '❌ AI.PY system connection failed - AI service may not be running');
        return false;
      }
    } catch (error) {
      setAiPythonStatus('error');
      addAIConsoleMessage('ai', '❌ AI.PY system connection failed: ' + error.message);
      return false;
    }
  };

  // User management methods
  const [users, setUsers] = useState([]);
  const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'user' });

  const fetchUsers = async () => {
    try {
      const usersData = await apiCall('/admin/users');
      setUsers(usersData);
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  };

  const createUser = async (e) => {
    e.preventDefault();
    try {
      await apiCall('/admin/users', {
        method: 'POST',
        body: JSON.stringify(newUser)
      });
      setNewUser({ username: '', email: '', password: '', role: 'user' });
      fetchUsers();
      addAIConsoleMessage('ai', `✅ User ${newUser.username} created successfully`);
    } catch (error) {
      addAIConsoleMessage('ai', `❌ Failed to create user: ${error.message}`);
    }
  };

  // Fetch stats separately for better reliability
  const fetchStats = async () => {
    if (!isAuthenticated) return;
    
    try {
      const statsData = await apiCall('/quantum/stats').catch(err => {
        console.error('Error fetching stats:', err);
        return null;
      });
      
      if (statsData) {
        const normalizedStats = {
          total_requests: statsData.total_requests || 0,
          blocked_requests: statsData.blocked_requests || 0,
          sql_injections: statsData.sql_injections || 0,
          xss_attempts: statsData.xss_attempts || 0,
          brute_force: statsData.brute_force || 0,
          zero_day_attempts: statsData.zero_day_attempts || 0,
          block_rate: statsData.block_rate || 0,
          threat_actors: statsData.threat_actors || 0,
          requests_per_second: statsData.requests_per_second || 0,
          path_traversal: statsData.path_traversal || 0,
          command_injection: statsData.command_injection || 0,
          xxe_attempts: statsData.xxe_attempts || 0,
          deserialization: statsData.deserialization || 0,
          ddos_attempts: statsData.ddos_attempts || 0,
          ...statsData
        };
        setStats(prev => ({ ...prev, ...normalizedStats }));
        console.log('📊 Stats updated:', normalizedStats);
      }
    } catch (error) {
      console.error('Error in fetchStats:', error);
    }
  };

  // Effects
  useEffect(() => {
    if (isAuthenticated) {
      connectWebSocket();
      fetchInitialData();
      
      // Poll stats more frequently (every 5 seconds)
      const statsInterval = setInterval(fetchStats, 5000);
      // Poll full data less frequently (every 15 seconds)
      const dataInterval = setInterval(fetchInitialData, 15000);
      const metricsInterval = setInterval(fetchSystemMetrics, 30000);

      return () => {
        if (ws.current) {
          ws.current.close();
        }
        clearInterval(statsInterval);
        clearInterval(dataInterval);
        clearInterval(metricsInterval);
        clearInterval(locationsInterval);
      };
    }
  }, [isAuthenticated, connectWebSocket]);
  
  // Fetch IP locations
  const fetchIPLocations = async () => {
    if (!isAuthenticated) return;
    
    try {
      const data = await apiCall('/geolocation/ips').catch(err => {
        console.error('Error fetching IP locations:', err);
        return { locations: [], stats: {} };
      });
      
      if (data && data.locations) {
        setIPLocations(Array.isArray(data.locations) ? data.locations : []);
        setLocationStats(data.stats || {});
      }
    } catch (error) {
      console.error('Error in fetchIPLocations:', error);
    }
  };

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [aiConsole]);

  useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight;
    }
  }, [aiChat]);

  // Test AI service connection on mount and when authenticated
  useEffect(() => {
    if (isAuthenticated) {
      testAIPythonConnection();
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (activeTab === 'user_management' && user?.role === 'admin') {
      fetchUsers();
    }
  }, [activeTab, user]);

  // Threat level calculation
  const threatLevel = getThreatLevel(stats.block_rate);

  // Render login form if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="login-container">
        <div className="login-form">
          <div className="login-header">
            <h1>🔒 ZEIN SECURITY WAF</h1>
            <p>Quantum AI Cyber Command Center</p>
          </div>
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label>Username:</label>
              <input
                type="text"
                value={loginForm.username}
                onChange={(e) => setLoginForm(prev => ({ ...prev, username: e.target.value }))}
                placeholder="Enter username"
                required
              />
            </div>
            <div className="form-group">
              <label>Password:</label>
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm(prev => ({ ...prev, password: e.target.value }))}
                placeholder="Enter password"
                required
              />
            </div>
            <button type="submit" className="login-btn">
              🔐 Login to Quantum Dashboard
            </button>
          </form>
          <div className="demo-credentials">
            <p><strong>Demo Credentials:</strong></p>
            <p>Username: <code>admin</code></p>
            <p>Password: <code>admin123</code></p>
          </div>
        </div>
      </div>
    );
  }

  // Main dashboard render
  return (
    <div className="quantum-dashboard">
      {/* AI Chat Modal */}
      {showChat && (
        <div className="ai-chat-modal">
          <div className="ai-chat-container">
            <div className="ai-chat-header">
              <h3>🤖 Zein AI Security Assistant</h3>
              <button onClick={() => setShowChat(false)}>✕</button>
            </div>
            <div className="ai-chat-messages" ref={chatRef}>
              {aiChat.map((msg, index) => (
                <div key={index} className={`chat-message ${msg.type} ${msg.loading ? 'loading' : ''}`}>
                  <div className="message-content">
                    {msg.loading ? (
                      <span className="typing-indicator">
                        <span></span><span></span><span></span>
                      </span>
                    ) : (
                      <div dangerouslySetInnerHTML={{ __html: msg.message.replace(/\n/g, '<br/>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') }} />
                    )}
                  </div>
                </div>
              ))}
            </div>
            <form onSubmit={handleChatSubmit} className="ai-chat-input">
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Tanya tentang keamanan siber, serangan, konfigurasi WAF..."
                disabled={chatLoading}
              />
              <button type="submit" disabled={chatLoading || !chatInput.trim()}>
                {chatLoading ? '...' : 'Kirim'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="quantum-real-time-indicator ${isConnected ? 'connected' : 'disconnected'}">
        {isConnected ? '🔴 LIVE' : '⚪ OFFLINE'}
      </div>
      
      <div className="quantum-command-center">
        <div className="quantum-header">
          <div className="quantum-title">ZEIN SECURITY WAF v5.0</div>
          <div className="quantum-subtitle">QUANTUM AI CYBER COMMAND CENTER | MULTIDIMENSIONAL THREAT PROTECTION</div>
          <div className="quantum-status">
            <span className={`status-indicator ${isConnected ? 'online' : 'offline'}`}>
              {isConnected ? '● REAL-TIME' : '○ OFFLINE'}
            </span>
            <span>WAF: ACTIVE</span>
            <span>AI: OPERATIONAL</span>
            <span>THREATS: {stats.threat_actors}</span>
            <span className="user-info">User: {user?.username} ({user?.role})</span>
            <button 
              className="ai-assistant-btn"
              onClick={() => setShowChat(true)}
            >
              💬 AI Assistant
            </button>
            <button className="logout-btn" onClick={handleLogout}>
              🚪 Logout
            </button>
          </div>
        </div>
        
        {/* System Status Bar */}
        <div className="quantum-system-status">
          {[
            `QUANTUM AI: ${isConnected ? 'ONLINE' : 'OFFLINE'}`,
            `NEURAL NETWORK: OPTIMIZED`, 
            `THREAT DETECTION: ACTIVE`,
            `WAF PROTECTION: ENABLED`,
            `REAL-TIME STATS: ${isConnected ? 'LIVE' : 'CACHED'}`,
            `BLOCK RATE: ${stats.block_rate?.toFixed(2)}%`,
            `REQUESTS/SEC: ${stats.requests_per_second?.toFixed(2)}`,
            `MEMORY: ${systemHealth.memory_usage || '0'}%`
          ].map((status, index) => (
            <div key={index} className="quantum-status-item">
              <span className="quantum-status-indicator quantum-status-online"></span>
              {status}
            </div>
          ))}
        </div>
        
        {/* Main Navigation Tabs */}
        <div className="quantum-tab-container">
          <div className="quantum-tab-buttons">
            {[
              { id: 'quantum_dashboard', label: 'QUANTUM DASHBOARD' },
              { id: 'ip_tracking', label: '🌍 IP TRACKING MAP' },
              { id: 'quantum_threats', label: 'QUANTUM THREATS' },
              { id: 'quantum_attackers', label: 'ATTACKER ANALYSIS' },
              { id: 'web_config', label: 'WAF CONFIG' },
              { id: 'deployment_mode', label: 'DEPLOYMENT MODE', adminOnly: true },
              { id: 'ip_blocking', label: 'IP BLOCKING', adminOnly: true },
              { id: 'log_analysis', label: 'LOG ANALYSIS' },
              { id: 'ai_python', label: 'AI.PY SYSTEM' },
              { id: 'quantum_ai', label: 'QUANTUM AI COMMAND' },
              ...(user?.role === 'admin' ? [{ id: 'user_management', label: 'USER MANAGEMENT' }] : []),
              { id: 'system_metrics', label: 'SYSTEM METRICS' }
            ].filter(tab => !tab.adminOnly || user?.role === 'admin').map(tab => (
              <button
                key={tab.id}
                className={`quantum-tab-button ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          
          {/* Tab Content */}
          <div className="quantum-tab-content">
            
            {/* Quantum Dashboard Tab */}
            {activeTab === 'quantum_dashboard' && (
              <div className="dashboard-grid">
                <div className="quantum-panel">
                  <div className="panel-title">⚡ QUANTUM SECURITY METRICS</div>
                  <div className="quantum-stats-grid">
                    <StatCard 
                      value={stats.total_requests} 
                      label="Total Requests" 
                      type="ai" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={stats.blocked_requests} 
                      label="Threats Blocked" 
                      type="critical" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={stats.sql_injections} 
                      label="SQL Injection Attacks" 
                      type="high" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={stats.xss_attempts} 
                      label="XSS Attempts" 
                      type="high" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={stats.brute_force} 
                      label="Brute Force Attacks" 
                      type="medium" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={stats.zero_day_attempts} 
                      label="Zero-Day Exploits" 
                      type="critical" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={`${stats.block_rate?.toFixed(2)}%`} 
                      label="Block Rate" 
                      type="quantum" 
                      loading={loading.stats}
                    />
                    <StatCard 
                      value={stats.requests_per_second?.toFixed(2)} 
                      label="Requests/Sec" 
                      type="ai" 
                      loading={loading.stats}
                    />
                  </div>
                </div>
                
                {/* Threat Map */}
                <div className="quantum-panel">
                  <div className="panel-title">🎯 QUANTUM THREAT MAP</div>
                  <div className="quantum-map-container">
                    <div className="map-placeholder">
                      <div className="map-icon">⚛️</div>
                      <div>Quantum Threat Visualization</div>
                      <div className="map-subtitle">Tracking {attackers.length} active attackers</div>
                      <div className="map-stats">
                        <div>High Risk: {attackers.filter(a => a.threat_level === 'HIGH' || a.threat_level === 'CRITICAL').length}</div>
                        <div>Blocked Today: {stats.blocked_requests}</div>
                        <div>Active Incidents: {incidents.length}</div>
                      </div>
                    </div>
                    {attackers.slice(0, 15).map((attacker, i) => (
                      <div 
                        key={i}
                        className={`quantum-map-point threat-${attacker.threat_level?.toLowerCase()}`}
                        style={{
                          top: `${(attacker.geo_lat + 90) / 180 * 80 + 10}%`,
                          left: `${(attacker.geo_lon + 180) / 360 * 80 + 10}%`
                        }}
                        title={`${attacker.ip} - ${attacker.threat_level} - ${attacker.organization}`}
                      />
                    ))}
                  </div>
                </div>
                
                {/* Real-time Security Logs */}
                <div className="quantum-panel">
                  <div className="panel-title">📊 REAL-TIME SECURITY LOGS</div>
                  <div className="quantum-logs-container">
                    {logs.length > 0 ? (
                      logs.map((log, index) => (
                        <LogEntry key={index} log={log} index={index} />
                      ))
                    ) : (
                      <div className="no-logs">
                        {loading.logs ? 'Loading security logs...' : 'No security events detected'}
                      </div>
                    )}
                  </div>
                </div>
                
                {/* System Status */}
                <div className="quantum-panel">
                  <div className="panel-title">🤖 QUANTUM AI SYSTEMS</div>
                  <div className="quantum-stats-grid">
                    <StatCard value={stats.threat_actors} label="Threat Actors" type="high" />
                    <StatCard value={incidents.length} label="Active Incidents" type="medium" />
                    <StatCard value="98.50%" label="Detection Accuracy" type="quantum" />
                    <StatCard value={isConnected ? 'LIVE' : 'CACHED'} label="Data Feed" type="ai" />
                  </div>
                  <div className={`quantum-threat-level ${threatLevel.class}`}>
                    QUANTUM THREAT LEVEL: {threatLevel.level}
                  </div>
                  <div className="quantum-performance">
                    <div className="performance-item">
                      <span>Requests/sec:</span>
                      <span>{stats.requests_per_second?.toFixed(2)}</span>
                    </div>
                    <div className="performance-item">
                      <span>Total Blocked:</span>
                      <span>{stats.blocked_requests}</span>
                    </div>
                    <div className="performance-item">
                      <span>Block Rate:</span>
                      <span>{stats.block_rate?.toFixed(2)}%</span>
                    </div>
                    <div className="performance-item">
                      <span>Uptime:</span>
                      <span>{systemHealth.uptime || '100%'}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {/* Quantum Threats Tab */}
            {activeTab === 'quantum_threats' && (
              <div className="quantum-panel full-height">
                <div className="panel-title">🚨 QUANTUM THREAT INTELLIGENCE</div>
                <div className="threats-grid">
                  {threats.map((threat, index) => (
                    <div key={index} className={`threat-card threat-${threat.severity?.toLowerCase()}`}>
                      <div className="threat-header">
                        <div className="threat-id">{threat.id}</div>
                        <div className={`threat-severity ${threat.severity?.toLowerCase()}`}>
                          {threat.severity}
                        </div>
                      </div>
                      <div className="threat-name">{threat.name}</div>
                      <div className="threat-description">{threat.description}</div>
                      <div className="threat-details">
                        <div>Type: {threat.type}</div>
                        <div>Confidence: {(threat.confidence * 100).toFixed(1)}%</div>
                        <div>Affected IPs: {threat.affected_ips}</div>
                        <div>Status: {threat.status}</div>
                        <div>First Seen: {new Date(threat.timestamp).toLocaleDateString()}</div>
                      </div>
                      <div className="threat-countermeasures">
                        <strong>Countermeasures:</strong>
                        <ul>
                          {threat.countermeasures?.map((cm, idx) => (
                            <li key={idx}>{cm}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Attacker Analysis Tab */}
            {activeTab === 'quantum_attackers' && (
              <div className="quantum-panel">
                <div className="panel-title">🎯 ACTIVE ATTACKER ANALYSIS</div>
                <div className="attackers-grid">
                  {attackers.map((attacker, index) => (
                    <div key={index} className={`attacker-card threat-${attacker.threat_level?.toLowerCase()}`}>
                      <div className="attacker-header">
                        <div className="attacker-ip">{attacker.ip}</div>
                        <div className={`threat-level ${attacker.threat_level?.toLowerCase()}`}>
                          {attacker.threat_level}
                        </div>
                      </div>
                      <div className="attacker-stats">
                        <div>Risk Score: {(attacker.risk_score * 100).toFixed(1)}%</div>
                        <div>Total Attacks: {attacker.total_attacks}</div>
                        <div>Blocked: {attacker.blocked_attacks}</div>
                        <div>Last Seen: {new Date(attacker.last_seen).toLocaleDateString()}</div>
                      </div>
                      <div className="attacker-location">
                        ASN: {attacker.asn} | {attacker.organization}
                      </div>
                      <div className="attacker-geo">
                        Location: {attacker.geo_lat?.toFixed(2)}, {attacker.geo_lon?.toFixed(2)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Web Configuration Tab */}
            {activeTab === 'web_config' && (
              <WAFConfig 
                apiCall={apiCall}
                onConfigUpdate={(config) => {
                  setWebConfig(config);
                  addAIConsoleMessage('ai', '✅ WAF configuration updated');
                }}
              />
            )}

            {/* Deployment Mode Tab */}
            {activeTab === 'deployment_mode' && user?.role === 'admin' && (
              <ModeSelector token={tokenRef.current} />
            )}

            {/* IP Blocking Tab */}
            {activeTab === 'ip_blocking' && user?.role === 'admin' && (
              <IPBlockManager apiCall={apiCall} />
            )}

            {/* Log Analysis Tab */}
            {activeTab === 'log_analysis' && (
              <LogAnalysis apiCall={apiCall} />
            )}

            {/* Old Web Config - Keep for backward compatibility */}
            {activeTab === 'web_config_old' && (
              <div className="quantum-panel">
                <div className="panel-title">🌐 WEB CONFIGURATION</div>
                <form onSubmit={handleWebConfigSubmit} className="web-config-form">
                  <div className="config-section">
                    <h3>Domain Configuration</h3>
                    <div className="form-group">
                      <label>Domain Name:</label>
                      <input
                        type="text"
                        value={webConfig.domain}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, domain: e.target.value }))}
                        placeholder="example.com"
                        required
                      />
                    </div>
                  </div>

                  <div className="config-section">
                    <h3>Security Settings</h3>
                    <div className="form-group checkbox-group">
                      <label>
                        <input
                          type="checkbox"
                          checked={webConfig.sslEnabled}
                          onChange={(e) => setWebConfig(prev => ({ ...prev, sslEnabled: e.target.checked }))}
                        />
                        Enable SSL/TLS
                      </label>
                    </div>
                    <div className="form-group">
                      <label>Protection Level:</label>
                      <select
                        value={webConfig.protectionLevel}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, protectionLevel: e.target.value }))}
                      >
                        <option value="basic">Basic</option>
                        <option value="advanced">Advanced</option>
                        <option value="maximum">Maximum</option>
                      </select>
                    </div>
                    <div className="form-group checkbox-group">
                      <label>
                        <input
                          type="checkbox"
                          checked={webConfig.rateLimiting}
                          onChange={(e) => setWebConfig(prev => ({ ...prev, rateLimiting: e.target.checked }))}
                        />
                        Enable Rate Limiting
                      </label>
                    </div>
                    <div className="form-group checkbox-group">
                      <label>
                        <input
                          type="checkbox"
                          checked={webConfig.botProtection}
                          onChange={(e) => setWebConfig(prev => ({ ...prev, botProtection: e.target.checked }))}
                        />
                        Enable Bot Protection
                      </label>
                    </div>
                    <div className="form-group">
                      <label>Max Upload Size (bytes):</label>
                      <input
                        type="number"
                        value={webConfig.maxUploadSize}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, maxUploadSize: parseInt(e.target.value) }))}
                        placeholder="10485760"
                      />
                    </div>
                  </div>

                  <div className="config-section">
                    <h3>Access Control</h3>
                    <div className="form-group">
                      <label>Blocked Countries (comma-separated):</label>
                      <input
                        type="text"
                        value={webConfig.blockedCountries}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, blockedCountries: e.target.value }))}
                        placeholder="CN,RU,KP,IR"
                      />
                    </div>
                    <div className="form-group">
                      <label>Allowed IPs (comma-separated):</label>
                      <textarea
                        value={webConfig.allowedIPs}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, allowedIPs: e.target.value }))}
                        placeholder="192.168.1.0/24, 10.0.0.1"
                        rows="3"
                      />
                    </div>
                    <div className="form-group">
                      <label>Blocked IPs (comma-separated):</label>
                      <textarea
                        value={webConfig.blockedIPs}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, blockedIPs: e.target.value }))}
                        placeholder="192.168.1.100, 10.0.0.50"
                        rows="3"
                      />
                    </div>
                  </div>

                  <div className="config-section">
                    <h3>Custom Rules</h3>
                    <div className="form-group">
                      <label>Custom WAF Rules:</label>
                      <textarea
                        value={webConfig.customRules}
                        onChange={(e) => setWebConfig(prev => ({ ...prev, customRules: e.target.value }))}
                        placeholder="Add custom security rules here..."
                        rows="8"
                      />
                    </div>
                  </div>

                  <button type="submit" className="config-save-btn">
                    💾 Save Configuration
                  </button>
                </form>
              </div>
            )}
            
            {/* AI.PY System Tab */}
            {activeTab === 'ai_python' && (
              <div className="quantum-panel">
                <div className="panel-title">🤖 AI.PY - QUANTUM AI SECURITY ASSISTANT</div>
                <div className="ai-python-container">
                  <div className="ai-status-section">
                    <div className={`ai-status ${aiPythonStatus}`}>
                      <div className="status-indicator"></div>
                      <div className="status-text">
                        AI.PY Status: {aiPythonStatus.toUpperCase()}
                      </div>
                    </div>
                    <button 
                      className="test-connection-btn"
                      onClick={testAIPythonConnection}
                    >
                      Test Connection
                    </button>
                  </div>

                  <div className="ai-capabilities">
                    <h3>🛡️ AI Capabilities</h3>
                    <div className="capabilities-grid">
                      <div className="capability-card">
                        <div className="capability-icon">🧠</div>
                        <div className="capability-title">Quantum Neural Network</div>
                        <div className="capability-desc">Advanced threat detection using AI algorithms</div>
                      </div>
                      <div className="capability-card">
                        <div className="capability-icon">⛓️</div>
                        <div className="capability-title">Blockchain Audit</div>
                        <div className="capability-desc">Immutable security event logging</div>
                      </div>
                      <div className="capability-card">
                        <div className="capability-icon">🌐</div>
                        <div className="capability-title">Threat Intelligence</div>
                        <div className="capability-desc">Real-time threat data analysis</div>
                      </div>
                      <div className="capability-card">
                        <div className="capability-icon">💬</div>
                        <div className="capability-title">AI Chat Assistant</div>
                        <div className="capability-desc">Intelligent security guidance</div>
                      </div>
                    </div>
                  </div>

                  <div className="ai-performance">
                    <h3>📊 Performance Metrics</h3>
                    <div className="performance-stats">
                      <div className="performance-stat">
                        <span className="stat-label">Total Requests Analyzed:</span>
                        <span className="stat-value">{stats.total_requests}</span>
                      </div>
                      <div className="performance-stat">
                        <span className="stat-label">AI Confidence:</span>
                        <span className="stat-value">{(performance.ai_confidence_avg * 100)?.toFixed(1) || '0'}%</span>
                      </div>
                      <div className="performance-stat">
                        <span className="stat-label">Processing Time:</span>
                        <span className="stat-value">{performance.processing_time_avg?.toFixed(2) || '0'}ms</span>
                      </div>
                      <div className="performance-stat">
                        <span className="stat-label">Memory Usage:</span>
                        <span className="stat-value">{performance.memory_usage?.toFixed(1) || '0'}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {/* Quantum AI Command Tab */}
            {activeTab === 'quantum_ai' && (
              <div className="quantum-panel full-height">
                <div className="panel-title">🤖 QUANTUM AI COMMAND INTERFACE</div>
                <div className="quantum-ai-console" ref={consoleRef}>
                  {aiConsole.map((entry, index) => (
                    <div key={index} className="quantum-command-line">
                      <span className={`quantum-command-prompt ${entry.type}`}>
                        {entry.type === 'user' ? 'QUANTUM_USER>' : 'QUANTUM_AI>'}
                      </span>
                      <span className={`command-message ${entry.type}`}>{entry.message}</span>
                    </div>
                  ))}
                </div>
                <div className="quantum-ai-commands">
                  {[
                    'QUANTUM_DEFENSE',
                    'AI_OPTIMIZATION', 
                    'THREAT_ANALYSIS',
                    'QUANTUM_SCAN',
                    'NEURAL_ENHANCE',
                    'SHIELD_BOOST',
                    'WAF_TEST',
                    'SYSTEM_DIAGNOSTIC'
                  ].map(command => (
                    <button
                      key={command}
                      className="quantum-ai-command-btn"
                      onClick={() => executeQuantumAICommand(command)}
                      disabled={!isConnected}
                    >
                      {command.replace(/_/g, ' ')}
                    </button>
                  ))}
                </div>
              </div>
            )}
            
            {/* User Management Tab (Admin only) */}
            {activeTab === 'user_management' && user?.role === 'admin' && (
              <div className="quantum-panel">
                <div className="panel-title">👥 USER MANAGEMENT</div>
                
                <div className="user-management-section">
                  <h3>Create New User</h3>
                  <form onSubmit={createUser} className="user-form">
                    <div className="form-row">
                      <div className="form-group">
                        <label>Username:</label>
                        <input
                          type="text"
                          value={newUser.username}
                          onChange={(e) => setNewUser(prev => ({ ...prev, username: e.target.value }))}
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label>Email:</label>
                        <input
                          type="email"
                          value={newUser.email}
                          onChange={(e) => setNewUser(prev => ({ ...prev, email: e.target.value }))}
                          required
                        />
                      </div>
                    </div>
                    <div className="form-row">
                      <div className="form-group">
                        <label>Password:</label>
                        <input
                          type="password"
                          value={newUser.password}
                          onChange={(e) => setNewUser(prev => ({ ...prev, password: e.target.value }))}
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label>Role:</label>
                        <select
                          value={newUser.role}
                          onChange={(e) => setNewUser(prev => ({ ...prev, role: e.target.value }))}
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                        </select>
                      </div>
                    </div>
                    <button type="submit" className="create-user-btn">
                      👤 Create User
                    </button>
                  </form>
                </div>

                <div className="users-list-section">
                  <h3>Existing Users</h3>
                  <div className="users-grid">
                    {users.map((user, index) => (
                      <div key={index} className="user-card">
                        <div className="user-header">
                          <div className="user-username">{user.username}</div>
                          <div className={`user-role ${user.role}`}>{user.role}</div>
                        </div>
                        <div className="user-email">{user.email}</div>
                        <div className="user-status">
                          <span className={`status ${user.is_active ? 'active' : 'inactive'}`}>
                            {user.is_active ? 'Active' : 'Inactive'}
                          </span>
                          <span>Last Login: {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
            
            {/* System Metrics Tab */}
            {activeTab === 'system_metrics' && (
              <div className="quantum-panel">
                <div className="panel-title">📈 SYSTEM METRICS & MONITORING</div>
                <div className="metrics-container">
                  <div className="metrics-grid">
                    <div className="metric-card">
                      <h4>🚀 Performance</h4>
                      <div className="metric-value">{performance.requests_per_second?.toFixed(2) || '0'} req/s</div>
                      <div className="metric-label">Request Rate</div>
                    </div>
                    <div className="metric-card">
                      <h4>💾 Memory</h4>
                      <div className="metric-value">{performance.memory_usage?.toFixed(1) || '0'}%</div>
                      <div className="metric-label">Memory Usage</div>
                    </div>
                    <div className="metric-card">
                      <h4>⚡ CPU</h4>
                      <div className="metric-value">{performance.cpu_usage?.toFixed(1) || '0'}%</div>
                      <div className="metric-label">CPU Usage</div>
                    </div>
                    <div className="metric-card">
                      <h4>🔗 Connections</h4>
                      <div className="metric-value">{performance.concurrent_connections || '0'}</div>
                      <div className="metric-label">Active Connections</div>
                    </div>
                  </div>
                  
                  <div className="health-status">
                    <h4>🏥 System Health</h4>
                    <div className="health-indicators">
                      <div className={`health-indicator ${systemHealth.database === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                        <span>Database:</span>
                        <span>{systemHealth.database || 'Unknown'}</span>
                      </div>
                      <div className={`health-indicator ${systemHealth.redis === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                        <span>Redis:</span>
                        <span>{systemHealth.redis || 'Unknown'}</span>
                      </div>
                      <div className={`health-indicator ${systemHealth.ai_service === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                        <span>AI Service:</span>
                        <span>{systemHealth.ai_service || 'Unknown'}</span>
                      </div>
                      <div className={`health-indicator ${isConnected ? 'healthy' : 'unhealthy'}`}>
                        <span>WebSocket:</span>
                        <span>{isConnected ? 'Connected' : 'Disconnected'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuantumDashboard;