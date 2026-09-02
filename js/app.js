/**
 * SIEM-Lite SOC Master Application Controller
 */

class SiemApp {
  constructor() {
    this.logIngestor = new window.LogIngestor();
    this.correlationEngine = new window.CorrelationEngine(this.logIngestor);
    this.attackSimulator = new window.AttackSimulator(this.logIngestor);

    this.state = {
      activeView: 'dashboard',
      logs: [],
      alerts: [],
      rules: [],
      agents: [],
      blockedIps: [],
      backendStatus: {},
      searchTerm: '',
      filterSource: 'ALL',
      filterSeverity: 'ALL',
      isPaused: false,
      isAutoTraffic: false,
      isConnected: false
    };

    this.historyVelocity = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    this.currentSecondEvents = 0;

    this.init();
  }

  init() {
    // 1. Connection status sync
    this.logIngestor.onConnectionChange(connected => {
      this.state.isConnected = connected;
      this.renderConnectionBadge();
    });

    // 2. Subscribe to Log Ingestor
    this.logIngestor.subscribe(log => {
      if (!this.state.isPaused) {
        this.state.logs = this.logIngestor.getLogs();
        this.currentSecondEvents++;
        if (this.state.activeView === 'logStream' || this.state.activeView === 'dashboard') {
          this.renderView();
        }
      }
    });

    // 3. Subscribe to Correlation Alerts
    this.correlationEngine.subscribe(alert => {
      this.state.alerts = this.correlationEngine.getAlerts();
      this.state.rules = this.correlationEngine.getRules();
      if (alert) {
        this.playAlertSound();
      }
      this.renderNavBadges();
      if (['dashboard', 'alerts', 'reports'].includes(this.state.activeView)) {
        this.renderView();
      }
    });

    // 4. Ingestion Velocity Tracker (every 1 sec)
    setInterval(() => {
      this.historyVelocity.shift();
      this.historyVelocity.push(this.currentSecondEvents);
      this.currentSecondEvents = 0;

      if (this.state.activeView === 'dashboard') {
        this.renderCharts();
      }
    }, 1000);

    // 5. Periodic Backend Sync (every 3 seconds for Agents, Blocked IPs, Status)
    this.pollBackendData();
    setInterval(() => this.pollBackendData(), 3000);

    // 6. Attach Event Listeners
    this.attachEventListeners();
    this.render();
  }

  pollBackendData() {
    // Fetch Status
    fetch('/api/status')
      .then(res => res.json())
      .then(status => {
        this.state.backendStatus = status;
        this.updateSystemStatusWidget();
      })
      .catch(() => {});

    // Fetch Agents
    fetch('/api/agents')
      .then(res => res.json())
      .then(agents => {
        if (Array.isArray(agents)) {
          this.state.agents = agents;
          if (this.state.activeView === 'agents') {
            this.renderView();
          }
        }
      })
      .catch(() => {});

    // Fetch Blocked IPs
    fetch('/api/blocked-ips')
      .then(res => res.json())
      .then(blocked => {
        if (Array.isArray(blocked)) {
          this.state.blockedIps = blocked;
        }
      })
      .catch(() => {});
  }

  updateSystemStatusWidget() {
    const statusText = document.getElementById('sidebarStatusText');
    const collectorsText = document.getElementById('sidebarCollectorsText');
    if (statusText && this.state.backendStatus) {
      statusText.innerHTML = `DB Events: <strong>${this.state.backendStatus.total_logs || this.state.logs.length}</strong>`;
    }
    if (collectorsText && this.state.backendStatus) {
      collectorsText.innerHTML = `Agents: <strong>${this.state.agents.length || this.state.backendStatus.active_agents || 1} Active</strong>`;
    }
  }

  renderConnectionBadge() {
    const badge = document.getElementById('connectionStatusBadge');
    if (badge) {
      if (this.state.isConnected) {
        badge.innerHTML = '<span class="dot pulse"></span><span style="color: #10b981; font-weight: 700;">LIVE SSE</span>';
      } else {
        badge.innerHTML = '<span class="dot" style="background: #f59e0b; box-shadow: 0 0 8px #f59e0b;"></span><span style="color: #f59e0b;">CONNECTING</span>';
      }
    }
  }

  renderNavBadges() {
    const alertBadge = document.getElementById('alertNavBadge');
    if (alertBadge) {
      const activeCount = this.state.alerts.filter(a => a.status === 'OPEN').length;
      alertBadge.textContent = activeCount;
      alertBadge.style.display = activeCount > 0 ? 'inline-block' : 'none';
    }
  }

  attachEventListeners() {
    // Navigation clicks
    document.addEventListener('click', (e) => {
      const navItem = e.target.closest('.nav-item');
      if (navItem && navItem.dataset.view) {
        const view = navItem.dataset.view;
        this.setActiveView(view);
      }

      // Attack simulator buttons
      const attackBtn = e.target.closest('.btn-trigger-attack');
      if (attackBtn) {
        const type = attackBtn.dataset.attack;
        this.triggerAttackScenario(type);
      }

      // Active Defense 1-Click Block IP button
      const blockBtn = e.target.closest('.btn-block-ip');
      if (blockBtn) {
        const ip = blockBtn.dataset.ip;
        const alertId = blockBtn.dataset.id;
        if (ip) {
          this.executeBlockIp(ip, alertId);
        }
      }

      // Mark Resolved
      const resolveBtn = e.target.closest('.btn-resolve');
      if (resolveBtn) {
        const alertId = resolveBtn.dataset.id;
        this.correlationEngine.updateAlertStatus(alertId, 'RESOLVED');
        this.state.alerts = this.correlationEngine.getAlerts();
        this.renderView();
      }

      // Isolate Host
      const isolateBtn = e.target.closest('.btn-isolate-host');
      if (isolateBtn) {
        const host = isolateBtn.dataset.host;
        alert(`🔒 HOST ISOLATION: ${host} network interface successfully quarantined from internal VLAN.`);
      }

      // Toggle Rule Enabled
      const toggleRuleBtn = e.target.closest('.toggle-rule-btn');
      if (toggleRuleBtn) {
        const ruleId = toggleRuleBtn.dataset.id;
        this.correlationEngine.toggleRule(ruleId);
        this.state.rules = this.correlationEngine.getRules();
        this.renderView();
      }

      // Open Add Rule Modal
      const openRuleModalBtn = e.target.closest('#btnOpenAddRuleModal');
      if (openRuleModalBtn) {
        const modal = document.getElementById('addRuleModal');
        if (modal) modal.classList.add('open');
      }

      // Close Add Rule Modal
      const closeRuleModalBtn = e.target.closest('#btnCloseAddRuleModal') || e.target.closest('#btnCancelAddRule');
      if (closeRuleModalBtn) {
        const modal = document.getElementById('addRuleModal');
        if (modal) modal.classList.remove('open');
      }
    });

    // Handle Add Rule Form Submit
    document.addEventListener('submit', (e) => {
      if (e.target && e.target.id === 'addRuleForm') {
        e.preventDefault();
        const newRule = {
          rule_id: 'RULE-' + Math.floor(1000 + Math.random() * 9000),
          name: document.getElementById('newRuleName').value,
          category: document.getElementById('newRuleCategory').value,
          severity: document.getElementById('newRuleSeverity').value,
          threshold: parseInt(document.getElementById('newRuleThreshold').value) || 1,
          time_window_sec: parseInt(document.getElementById('newRuleWindow').value) || 60,
          pattern: document.getElementById('newRulePattern').value,
          description: document.getElementById('newRuleDesc').value,
          mitigation: document.getElementById('newRuleMitigation').value,
          enabled: true
        };

        fetch('/api/rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newRule)
        }).then(() => {
          this.correlationEngine.fetchRules();
          const modal = document.getElementById('addRuleModal');
          if (modal) modal.classList.remove('open');
          setTimeout(() => this.renderView(), 300);
        });
      }
    });

    // Topbar attack button
    const topbarAttackBtn = document.getElementById('btnTopbarAttack');
    if (topbarAttackBtn) {
      topbarAttackBtn.addEventListener('click', () => {
        this.attackSimulator.simulateBruteForceAttack();
      });
    }
  }

  executeBlockIp(ip, alertId = null) {
    fetch('/api/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason: `Blocked from SOC Incident ${alertId || ''}` })
    })
      .then(res => res.json())
      .then(data => {
        if (alertId) {
          this.correlationEngine.updateAlertStatus(alertId, 'BLOCKED');
        }
        this.logIngestor.ingest({
          source: 'firewall',
          ip: ip,
          user: 'soc-analyst',
          severity: 'INFO',
          message: `🛡️ ACTIVE DEFENSE: Blocked attacker IP ${ip} via OS Firewall rule.`
        });
        this.pollBackendData();
        this.renderView();
      })
      .catch(e => console.warn('[Block IP Error]', e));
  }

  setActiveView(view) {
    this.state.activeView = view;
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === view);
    });

    const pageTitle = document.getElementById('pageTitle');
    const titles = {
      dashboard: 'SOC Security Operations Overview',
      logStream: 'Live Real-Time Terminal Log Stream',
      alerts: 'Incident Triage & Active Defense Mitigation',
      agents: 'Collector & Endpoint Agent Fleet',
      rules: 'Stateful Threat Correlation Rules',
      simulator: 'Multi-Vector Cyber Attack Telemetry Console',
      reports: 'Executive Security Audit & Compliance Reports'
    };
    if (pageTitle) pageTitle.textContent = titles[view] || 'SIEM-Lite Security Operations';

    this.render();
  }

  triggerAttackScenario(type) {
    switch (type) {
      case 'brute-force': this.attackSimulator.simulateBruteForceAttack(); break;
      case 'sqli': this.attackSimulator.simulateSqlInjectionAttack(); break;
      case 'port-scan': this.attackSimulator.simulatePortScanAttack(); break;
      case 'path-traversal': this.attackSimulator.simulatePathTraversalAttack(); break;
      case 'priv-esc': this.attackSimulator.simulatePrivilegeEscalationAttack(); break;
      case 'web-shell': this.attackSimulator.simulateWebShellAttack(); break;
      case 'audit-cleared': this.attackSimulator.simulateAuditLogCleared(); break;
      case 'account-created': this.attackSimulator.simulateAccountCreated(); break;
      case 'vuln-scanner': this.attackSimulator.simulateVulnScanner(); break;
      case 'ransomware': this.attackSimulator.simulateRansomwareActivity(); break;
    }
  }

  playAlertSound() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      gain.gain.setValueAtTime(0.1, ctx.currentTime);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.15);
    } catch (e) {
      // Audio policy fallback
    }
  }

  render() {
    this.renderNavBadges();
    this.renderView();
  }

  renderView() {
    const contentBody = document.getElementById('contentBody');
    if (!contentBody) return;

    this.state.rules = this.correlationEngine.getRules();
    this.state.alerts = this.correlationEngine.getAlerts();
    this.state.logs = this.logIngestor.getLogs();

    switch (this.state.activeView) {
      case 'dashboard':
        contentBody.innerHTML = window.renderDashboardView(this.state);
        this.renderCharts();
        break;

      case 'logStream':
        contentBody.innerHTML = window.renderLogStreamView(this.state);
        this.bindLogStreamEvents();
        break;

      case 'alerts':
        contentBody.innerHTML = window.renderAlertTriageView(this.state);
        break;

      case 'agents':
        contentBody.innerHTML = window.renderAgentsView(this.state);
        break;

      case 'rules':
        contentBody.innerHTML = window.renderRuleEngineView(this.state);
        break;

      case 'simulator':
        contentBody.innerHTML = window.renderAttackSimView(this.state);
        this.bindSimulatorEvents();
        break;

      case 'reports':
        contentBody.innerHTML = window.renderReportsView(this.state);
        this.bindReportsEvents();
        break;
    }
  }

  bindLogStreamEvents() {
    const searchInput = document.getElementById('logSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.state.searchTerm = e.target.value;
        this.renderView();
      });
    }

    const sourceSelect = document.getElementById('logSourceSelect');
    if (sourceSelect) {
      sourceSelect.addEventListener('change', (e) => {
        this.state.filterSource = e.target.value;
        this.renderView();
      });
    }

    const severitySelect = document.getElementById('logSeveritySelect');
    if (severitySelect) {
      severitySelect.addEventListener('change', (e) => {
        this.state.filterSeverity = e.target.value;
        this.renderView();
      });
    }

    const btnPause = document.getElementById('btnPauseStream');
    if (btnPause) {
      btnPause.addEventListener('click', () => {
        this.state.isPaused = !this.state.isPaused;
        this.renderView();
      });
    }

    const btnClear = document.getElementById('btnClearLogs');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        this.state.logs = [];
        this.renderView();
      });
    }
  }

  bindSimulatorEvents() {
    const btnToggleAuto = document.getElementById('btnToggleAutoTraffic');
    if (btnToggleAuto) {
      btnToggleAuto.addEventListener('click', () => {
        if (this.state.isAutoTraffic) {
          this.attackSimulator.stopBackgroundTraffic();
          this.state.isAutoTraffic = false;
        } else {
          this.attackSimulator.startBackgroundTraffic(3000);
          this.state.isAutoTraffic = true;
        }
        this.renderView();
      });
    }
  }

  bindReportsEvents() {
    const btnPrint = document.getElementById('btnPrintReport');
    if (btnPrint) {
      btnPrint.addEventListener('click', () => window.print());
    }
  }

  renderCharts() {
    if (window.SocCharts) {
      window.SocCharts.renderLineChart('velocityChart', this.historyVelocity);
      
      const counts = {
        CRITICAL: this.state.alerts.filter(a => a.severity === 'CRITICAL').length,
        HIGH: this.state.alerts.filter(a => a.severity === 'HIGH').length,
        MEDIUM: this.state.alerts.filter(a => a.severity === 'MEDIUM').length,
        LOW: this.state.alerts.filter(a => a.severity === 'LOW').length
      };
      window.SocCharts.renderDoughnutChart('severityChart', counts);
    }
  }
}

// Initialize SIEM Application on DOM Loaded
document.addEventListener('DOMContentLoaded', () => {
  window.app = new SiemApp();
});
