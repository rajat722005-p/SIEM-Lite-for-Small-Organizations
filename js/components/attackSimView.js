/**
 * SIEM-Lite Cyber Attack Simulator View Component
 */

window.renderAttackSimView = function (appState) {
  const { isAutoTraffic } = appState;

  return `
    <div style="margin-bottom: 20px;">
      <h2 style="font-size: 20px; font-weight: 700;">Multi-Vector Cyber Attack Telemetry Console</h2>
      <p style="font-size: 13px; color: #94a3b8; margin-top: 2px;">
        Trigger live cyber attack scenarios against the SIEM ingestion engine to test sliding-window correlation, SQLite logging, and 1-Click mitigation.
      </p>
    </div>

    <!-- Auto Background Traffic Controls -->
    <div class="card" style="margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
      <div>
        <h3 style="font-size: 15px; font-weight: 700;">Benign Background Log Streamer</h3>
        <p style="font-size: 12px; color: #94a3b8; margin-top: 2px;">Generates realistic normal traffic (HTTP 200, Firewall allow, SSH login, VLAN health checks).</p>
      </div>

      <button id="btnToggleAutoTraffic" class="${isAutoTraffic ? 'btn-outline' : 'btn-primary'}">
        ${isAutoTraffic ? '⏹️ Stop Background Traffic' : '▶️ Start Background Traffic'}
      </button>
    </div>

    <!-- Attack Vector Trigger Cards Grid -->
    <div class="grid-2">
      <!-- Attack 1: SSH Brute Force -->
      <div class="card" style="border-left: 4px solid var(--severity-critical);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-critical">CRITICAL</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">SSH Password Brute Force</h3>
          </div>
          <span style="font-size: 22px;">🔑</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Fires 6 rapid SSH authentication failures from IP <code style="color: #a855f7;">185.220.101.4</code> targeting Linux Server within 2 seconds.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="brute-force">
          ⚡ Trigger SSH Brute Force
        </button>
      </div>

      <!-- Attack 2: Web SQL Injection -->
      <div class="card" style="border-left: 4px solid var(--severity-high);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-high">HIGH</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Web SQL Injection (SQLi)</h3>
          </div>
          <span style="font-size: 22px;">💉</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Sends malicious HTTP GET payload containing <code style="color: #f43f5e;">' UNION SELECT username, password FROM users--</code> to Web Server.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="sqli">
          ⚡ Trigger SQL Injection
        </button>
      </div>

      <!-- Attack 3: Firewall Port Scan -->
      <div class="card" style="border-left: 4px solid var(--severity-high);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-high">HIGH</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Firewall Reconnaissance Port Scan</h3>
          </div>
          <span style="font-size: 22px;">🛰️</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Probes 12 distinct TCP ports (21, 22, 23, 80, 135, 445, 3389) on perimeter firewall from IP <code style="color: #a855f7;">198.51.100.42</code>.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="port-scan">
          ⚡ Trigger Port Scan
        </button>
      </div>

      <!-- Attack 4: Path Traversal / LFI -->
      <div class="card" style="border-left: 4px solid var(--severity-med);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-med">MEDIUM</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Path Traversal & File Access</h3>
          </div>
          <span style="font-size: 22px;">📁</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Attempts URI directory traversal <code style="color: #f59e0b;">/download?file=../../../../etc/passwd</code> on web application.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="path-traversal">
          ⚡ Trigger Path Traversal
        </button>
      </div>

      <!-- Attack 5: Privilege Escalation -->
      <div class="card" style="border-left: 4px solid var(--severity-high);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-high">HIGH</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Unauthorized Privilege Escalation</h3>
          </div>
          <span style="font-size: 22px;">🔓</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Triggers unauthorized root <code style="color: #f43f5e;">sudo</code> escalation attempt by low-privilege user account.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="priv-esc">
          ⚡ Trigger Privilege Escalation
        </button>
      </div>

      <!-- Attack 6: Web Shell / Command Execution -->
      <div class="card" style="border-left: 4px solid var(--severity-critical);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-critical">CRITICAL</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Web Shell / Remote Command Execution</h3>
          </div>
          <span style="font-size: 22px;">⚡</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Executes encoded PowerShell command via uploaded web shell <code style="color: #f43f5e;">powershell -enc ...</code>
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="web-shell">
          ⚡ Trigger Web Shell
        </button>
      </div>

      <!-- Attack 7: Windows Audit Log Cleared -->
      <div class="card" style="border-left: 4px solid var(--severity-critical);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-critical">CRITICAL</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Windows Audit Log Cleared (Event 1102)</h3>
          </div>
          <span style="font-size: 22px;">🧹</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Simulates attacker clearing Windows Security Audit logs to evade SOC detection.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="audit-cleared">
          ⚡ Trigger Audit Log Tampering
        </button>
      </div>

      <!-- Attack 8: Windows Backdoor Account Creation -->
      <div class="card" style="border-left: 4px solid var(--severity-high);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-high">HIGH</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Rogue User Account Created (Event 4720)</h3>
          </div>
          <span style="font-size: 22px;">👤</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Detects unauthorized user persistence account creation on Windows Domain Controller.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="account-created">
          ⚡ Trigger Rogue Account Creation
        </button>
      </div>

      <!-- Attack 9: Vulnerability Scanner -->
      <div class="card" style="border-left: 4px solid var(--severity-med);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-med">MEDIUM</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Nikto / SQLmap Scanner Bot</h3>
          </div>
          <span style="font-size: 22px;">🤖</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Fires automated web vulnerability scanner probing sensitive administrative paths.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="vuln-scanner">
          ⚡ Trigger Scanner Bot Traffic
        </button>
      </div>

      <!-- Attack 10: Ransomware File Extension -->
      <div class="card" style="border-left: 4px solid var(--severity-critical);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
          <div>
            <span class="badge badge-critical">CRITICAL</span>
            <h3 style="font-weight: 700; font-size: 15px; margin-top: 6px; color: #f8fafc;">Ransomware Mass File Encryption</h3>
          </div>
          <span style="font-size: 22px;">☣️</span>
        </div>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 14px;">
          Simulates endpoint EDR alert for bulk file modification to <code style="color: #f43f5e;">.locked</code> extension.
        </p>
        <button class="btn-sim-attack btn-trigger-attack" data-attack="ransomware">
          ⚡ Trigger Ransomware Alert
        </button>
      </div>
    </div>
  `;
};
