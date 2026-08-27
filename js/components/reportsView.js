/**
 * SIEM-Lite Security Audit Report Generator Component
 */

window.renderReportsView = function (appState) {
  const { logs, alerts, backendStatus } = appState;

  const totalLogs = backendStatus.total_logs || logs.length;
  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;

  return `
    <div style="margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
      <div>
        <h2 style="font-size: 20px; font-weight: 700;">Executive Security Audit & Compliance Report</h2>
        <p style="font-size: 13px; color: #94a3b8; margin-top: 2px;">
          Comprehensive incident and security audit report for management, CISO, and compliance audits (ISO 27001, SOC 2, HIPAA).
        </p>
      </div>

      <div style="display: flex; gap: 10px; align-items: center;">
        <a href="/api/export?type=alerts&format=json" target="_blank" class="btn-outline" style="text-decoration: none; font-size: 12px;">
          📥 Export JSON
        </a>
        <a href="/api/export?type=alerts&format=csv" target="_blank" class="btn-outline" style="text-decoration: none; font-size: 12px;">
          📊 Export CSV
        </a>
        <button id="btnPrintReport" class="btn-primary" style="font-size: 12px;">🖨️ Print Security Report</button>
      </div>
    </div>

    <!-- Executive Summary Card -->
    <div class="card" style="margin-bottom: 24px;">
      <h3 style="font-size: 16px; font-weight: 700; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 16px;">
        🛡️ Executive Security Operations Summary
      </h3>

      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px;">
        <div style="background: rgba(15, 23, 42, 0.7); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Audit Generation Timestamp</div>
          <div style="font-size: 13px; font-weight: 700; color: #f8fafc; margin-top: 4px;">${new Date().toLocaleString()}</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.7); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Total Logs Ingested</div>
          <div style="font-size: 14px; font-weight: 700; color: var(--accent-cyan); margin-top: 4px;">${totalLogs} Events (DB)</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.7); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Correlated Threat Incidents</div>
          <div style="font-size: 14px; font-weight: 700; color: var(--severity-critical); margin-top: 4px;">${totalAlerts} Incidents</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.7); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Critical / High Severity</div>
          <div style="font-size: 14px; font-weight: 700; color: var(--severity-high); margin-top: 4px;">${criticalCount + highCount} Threats</div>
        </div>
      </div>

      <div style="font-size: 13px; color: #cbd5e1; line-height: 1.6;">
        <p>
          SIEM-Lite actively collects, standardizes, and evaluates real-time security events across Windows workstations, Linux servers, edge firewalls, and public web applications.
          During the current continuous monitoring session, <strong>${totalAlerts} security incidents</strong> were detected via stateful correlation rules.
        </p>
      </div>
    </div>

    <!-- Detailed Incidents Table -->
    <div class="card">
      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px;">Audited Threat Incidents & Mitigation Log</h3>

      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid var(--border-color); color: #94a3b8; text-transform: uppercase;">
              <th style="padding: 10px;">ID</th>
              <th style="padding: 10px;">Timestamp</th>
              <th style="padding: 10px;">Rule Name</th>
              <th style="padding: 10px;">Attacker IP</th>
              <th style="padding: 10px;">Target</th>
              <th style="padding: 10px;">MITRE Category</th>
              <th style="padding: 10px;">Severity</th>
              <th style="padding: 10px;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${alerts.length === 0 ? '<tr><td colspan="8" style="padding: 20px; text-align: center; color: #64748b;">No incidents recorded in audit log.</td></tr>' : ''}
            ${alerts.map(alert => `
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.03); font-family: var(--font-mono);">
                <td style="padding: 10px; color: var(--accent-cyan); font-weight: 700;">${alert.id || alert.alert_id}</td>
                <td style="padding: 10px; color: #94a3b8;">${new Date(alert.timestamp).toLocaleTimeString()}</td>
                <td style="padding: 10px; font-weight: 600; color: #f8fafc;">${alert.title}</td>
                <td style="padding: 10px; color: #a855f7;">${alert.attackerIp}</td>
                <td style="padding: 10px;">${alert.targetHost}</td>
                <td style="padding: 10px; color: #cbd5e1;">${alert.category || 'Threat Activity'}</td>
                <td style="padding: 10px;"><span class="badge badge-${(alert.severity || 'high').toLowerCase()}">${alert.severity}</span></td>
                <td style="padding: 10px; color: ${alert.status === 'RESOLVED' ? '#10b981' : (alert.status === 'BLOCKED' ? '#3b82f6' : '#f59e0b')}; font-weight: 700;">${alert.status}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
};
