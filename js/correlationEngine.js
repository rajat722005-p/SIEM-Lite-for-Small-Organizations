/**
 * SIEM-Lite Correlation & Threat Intelligence Client Engine
 * Coordinates stateful rules, active alerts, and MITRE ATT&CK categorization with SQLite Backend.
 */

class CorrelationEngine {
  constructor(logIngestor) {
    this.logIngestor = logIngestor;
    this.alerts = [];
    this.rules = [];
    this.subscribers = [];

    // Memory sliding windows for client-side fallback
    this.failedAuthWindow = new Map();
    this.portScanWindow = new Map();

    this.init();
  }

  init() {
    this.fetchRules();
    this.fetchAlerts();

    // Listen to real-time backend alerts via LogIngestor SSE
    this.logIngestor.subscribeAlerts(alert => {
      this.handleIncomingAlert(alert);
    });

    // Client-side rule evaluation for local events
    this.logIngestor.subscribe(log => {
      if (log) this.evaluateLocalRules(log);
    });
  }

  fetchRules() {
    fetch('/api/rules')
      .then(res => res.json())
      .then(rules => {
        if (Array.isArray(rules) && rules.length > 0) {
          this.rules = rules;
        }
      })
      .catch(e => console.warn('[Correlation Engine] Could not fetch rules:', e));
  }

  fetchAlerts() {
    fetch('/api/alerts')
      .then(res => res.json())
      .then(alerts => {
        if (Array.isArray(alerts)) {
          this.alerts = alerts;
          this.notifyAlert(null);
        }
      })
      .catch(e => console.warn('[Correlation Engine] Could not fetch alerts:', e));
  }

  subscribe(callback) {
    this.subscribers.push(callback);
  }

  notifyAlert(alert) {
    this.subscribers.forEach(cb => cb(alert));
  }

  handleIncomingAlert(alert) {
    if (!this.alerts.some(a => a.id === alert.id || a.alert_id === alert.id)) {
      this.alerts.unshift(alert);
      if (this.alerts.length > 200) this.alerts.pop();
      this.notifyAlert(alert);
    }
  }

  evaluateLocalRules(log) {
    const now = Date.now();
    const message = ((log.message || '') + ' ' + (log.raw || '')).toLowerCase();

    // Rule 1: SSH / Auth Brute Force
    const rule1 = this.rules.find(r => r.id === 'RULE-01');
    if (rule1 && rule1.enabled) {
      if (message.includes('failed password') || message.includes('authentication failure') || message.includes('invalid user') || message.includes('4625')) {
        let attempts = this.failedAuthWindow.get(log.ip) || [];
        attempts = attempts.filter(ts => now - ts < (rule1.timeWindowSec || 60) * 1000);
        attempts.push(now);
        this.failedAuthWindow.set(log.ip, attempts);

        if (attempts.length >= (rule1.threshold || 5)) {
          this.failedAuthWindow.set(log.ip, []);
          this.triggerLocalAlert({
            ruleId: rule1.id,
            title: rule1.name,
            severity: rule1.severity,
            category: rule1.category,
            attackerIp: log.ip,
            targetHost: log.source,
            count: attempts.length,
            details: `Detected ${attempts.length} failed login attempts from ${log.ip} within ${rule1.timeWindowSec} seconds.`,
            mitigation: rule1.mitigation,
            log
          });
        }
      }
    }

    // Rule 2: SQL Injection
    const rule2 = this.rules.find(r => r.id === 'RULE-02');
    if (rule2 && rule2.enabled) {
      const patterns = ["' or 1=1", "union select", "select * from", "drop table", "sleep(", "benchmark(", "or '1'='1", "admin'--"];
      if (patterns.some(p => message.includes(p))) {
        this.triggerLocalAlert({
          ruleId: rule2.id,
          title: rule2.name,
          severity: rule2.severity,
          category: rule2.category,
          attackerIp: log.ip,
          targetHost: log.source,
          count: 1,
          details: `SQL Injection payload detected from IP ${log.ip} targeting ${log.source}. Payload: ${log.message}`,
          mitigation: rule2.mitigation,
          log
        });
      }
    }
  }

  triggerLocalAlert(alertData) {
    const newAlert = {
      id: 'ALT-' + Math.random().toString(36).substr(2, 8).toUpperCase(),
      alert_id: 'ALT-' + Math.random().toString(36).substr(2, 8).toUpperCase(),
      timestamp: new Date().toISOString(),
      status: 'OPEN',
      ...alertData
    };

    if (!this.alerts.some(a => a.attackerIp === newAlert.attackerIp && a.ruleId === newAlert.ruleId && Date.now() - new Date(a.timestamp).getTime() < 3000)) {
      this.alerts.unshift(newAlert);
      if (this.alerts.length > 200) this.alerts.pop();
      this.notifyAlert(newAlert);
    }
  }

  updateAlertStatus(alertId, newStatus) {
    const alert = this.alerts.find(a => a.id === alertId || a.alert_id === alertId);
    if (alert) {
      alert.status = newStatus;
      this.notifyAlert(null);
    }

    fetch(`/api/alerts/${alertId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    }).catch(e => console.warn('[Alert Status Update Error]', e));
  }

  toggleRule(ruleId) {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = !rule.enabled;
      fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule)
      }).catch(e => console.warn('[Rule Toggle Error]', e));
    }
  }

  getAlerts() {
    return this.alerts;
  }

  getRules() {
    return this.rules;
  }
}

window.CorrelationEngine = CorrelationEngine;
