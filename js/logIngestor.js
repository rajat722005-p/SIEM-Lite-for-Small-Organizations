/**
 * SIEM-Lite Enterprise Log Ingestor & Real-Time Sync Module
 * Synchronizes with Python SQLite Backend via Server-Sent Events (SSE) & REST API (/api/logs).
 */

class LogIngestor {
  constructor() {
    this.logs = [];
    this.maxLogs = 1000;
    this.subscribers = [];
    this.alertSubscribers = [];
    this.eventSource = null;
    this.isConnected = false;
    this.statusSubscribers = [];

    this.init();
  }

  init() {
    // 1. Initial Load of recent logs from backend SQLite
    this.fetchInitialLogs();

    // 2. Connect to Real-Time Server-Sent Events (SSE)
    this.connectSSE();
  }

  onConnectionChange(callback) {
    this.statusSubscribers.push(callback);
  }

  notifyConnection(status) {
    this.isConnected = status;
    this.statusSubscribers.forEach(cb => cb(status));
  }

  fetchInitialLogs() {
    fetch('/api/logs?limit=300')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          this.logs = data.map(item => this.normalizeObject(item));
          this.notifyAll();
        }
      })
      .catch(err => {
        console.warn('[SIEM Ingestor] Could not load initial logs from backend:', err);
      });
  }

  connectSSE() {
    try {
      this.eventSource = new EventSource('/api/stream');

      this.eventSource.addEventListener('connected', (e) => {
        this.notifyConnection(true);
      });

      this.eventSource.addEventListener('log', (e) => {
        try {
          const logData = JSON.parse(e.data);
          this.handleIncomingLog(logData, false);
        } catch (err) {
          console.error('[SSE Log Parse Error]', err);
        }
      });

      this.eventSource.addEventListener('alert', (e) => {
        try {
          const alertData = JSON.parse(e.data);
          this.notifyAlertSubscribers(alertData);
        } catch (err) {
          console.error('[SSE Alert Parse Error]', err);
        }
      });

      this.eventSource.onopen = () => {
        this.notifyConnection(true);
      };

      this.eventSource.onerror = () => {
        this.notifyConnection(false);
        // EventSource automatically retries connection
      };
    } catch (e) {
      console.warn('[SSE Init Notice] SSE not available, falling back to polling.', e);
      this.startPollingFallback();
    }
  }

  startPollingFallback() {
    setInterval(() => {
      fetch('/api/logs?limit=50')
        .then(res => res.json())
        .then(data => {
          if (Array.isArray(data) && data.length > 0) {
            const existingIds = new Set(this.logs.map(l => l.id));
            const newLogs = data.filter(l => !existingIds.has(l.id || l.log_id));
            if (newLogs.length > 0) {
              newLogs.reverse().forEach(l => this.handleIncomingLog(l, false));
            }
          }
        })
        .catch(() => {});
    }, 3000);
  }

  subscribe(callback) {
    this.subscribers.push(callback);
  }

  subscribeAlerts(callback) {
    this.alertSubscribers.push(callback);
  }

  notify(log) {
    this.subscribers.forEach(cb => cb(log));
  }

  notifyAll() {
    this.subscribers.forEach(cb => cb(null));
  }

  notifyAlertSubscribers(alert) {
    this.alertSubscribers.forEach(cb => cb(alert));
  }

  handleIncomingLog(rawLog, pushToBackend = false) {
    const normalized = typeof rawLog === 'object' ? this.normalizeObject(rawLog) : this.parseStringLog(rawLog);

    // Check duplicate
    if (!this.logs.some(l => l.id === normalized.id)) {
      this.logs.unshift(normalized);
      if (this.logs.length > this.maxLogs) {
        this.logs.pop();
      }
      this.notify(normalized);
    }

    if (pushToBackend) {
      fetch('/api/logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(normalized)
      }).catch(e => console.warn('[Log Push Error]', e));
    }

    return normalized;
  }

  /**
   * Ingests a raw log and pushes to backend REST API
   */
  ingest(rawLog) {
    return this.handleIncomingLog(rawLog, true);
  }

  normalizeObject(obj) {
    return {
      id: obj.id || obj.log_id || 'LOG-' + Math.random().toString(36).substr(2, 9),
      timestamp: obj.timestamp || new Date().toISOString(),
      source: obj.source || 'endpoint',
      ip: obj.ip || obj.source_ip || '192.168.1.1',
      user: obj.user || 'system',
      severity: (obj.severity || 'INFO').toUpperCase(),
      message: obj.message || obj.raw || JSON.stringify(obj),
      raw: obj.raw || obj.message || JSON.stringify(obj)
    };
  }

  parseStringLog(str) {
    const timestamp = new Date().toISOString();
    
    // Check for Syslog / SSH format
    if (str.includes('sshd') || str.includes('Failed password') || str.includes('authentication failure')) {
      const ipMatch = str.match(/from\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
      const userMatch = str.match(/for\s+([a-zA-Z0-9_-]+)/);
      return {
        id: 'LOG-' + Math.random().toString(36).substr(2, 9),
        timestamp,
        source: 'linux-server',
        ip: ipMatch ? ipMatch[1] : '192.168.1.50',
        user: userMatch ? userMatch[1] : 'root',
        severity: str.includes('Failed password') || str.includes('failure') ? 'WARN' : 'INFO',
        message: str,
        raw: str
      };
    }

    // Check for Nginx / Apache HTTP format
    if (str.includes('GET') || str.includes('POST') || str.match(/HTTP\/[12]\.[01]/)) {
      const ipMatch = str.match(/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
      const isSqlInjection = str.includes("' OR '1'='1") || str.includes('UNION SELECT') || str.includes('%27') || str.includes("' or 1=1");
      return {
        id: 'LOG-' + Math.random().toString(36).substr(2, 9),
        timestamp,
        source: 'web-application',
        ip: ipMatch ? ipMatch[1] : '10.0.0.45',
        user: 'web-user',
        severity: isSqlInjection ? 'HIGH' : 'INFO',
        message: str,
        raw: str
      };
    }

    // Default
    return {
      id: 'LOG-' + Math.random().toString(36).substr(2, 9),
      timestamp,
      source: 'endpoint',
      ip: '192.168.1.15',
      user: 'localuser',
      severity: 'INFO',
      message: str,
      raw: str
    };
  }

  getLogs() {
    return this.logs;
  }
}

window.LogIngestor = LogIngestor;
