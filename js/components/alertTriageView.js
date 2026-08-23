/**
 * SIEM-Lite Incident Triage & Active Defense Mitigation Center
 */

window.renderAlertTriageView = function (appState) {
  const { alerts, blockedIps } = appState;

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const medCount = alerts.filter(a => a.severity === 'MEDIUM').length;

  return `
    <div style="margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
      <div>
        <h2 style="font-size: 20px; font-weight: 700;">Incident Triage & Active Defense Center</h2>
        <p style="font-size: 13px; color: #94a3b8; margin-top: 2px;">
          Continuous stateful threat correlation engine with real-time incident triage and 1-Click OS Firewall Blocking.
        </p>
      </div>

      <div style="display: flex; gap: 10px; align-items: center;">
        <span class="badge badge-critical">${criticalCount} Critical</span>
        <span class="badge badge-high">${highCount} High</span>
        <span class="badge badge-med">${medCount} Medium</span>
        <a href="/api/export?type=alerts&format=csv" target="_blank" class="btn-outline" style="text-decoration: none; font-size: 12px;">
          📥 Export Incidents CSV
        </a>
      </div>
    </div>

    <!-- Active Incident List -->
    <div class="incident-list">
      ${alerts.length === 0 ? `
        <div class="card" style="text-align: center; padding: 48px;">
          <div style="font-size: 36px; margin-bottom: 12px;">🛡️</div>
          <h3 style="font-weight: 700; font-size: 17px;">Zero Active Security Incidents</h3>
          <p style="font-size: 13px; color: #64748b; margin-top: 4px;">
            All system logs are currently compliant with correlation rules. Host defense posture is nominal.
          </p>
        </div>
      ` : ''}

      ${alerts.map(alert => {
        const timeAgo = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Just now';
        const isResolved = alert.status === 'RESOLVED';
        const isBlocked = alert.status === 'BLOCKED' || (blockedIps && blockedIps.some(b => b.ip === alert.attackerIp));

        return `
          <div class="incident-item ${(alert.severity || 'high').toLowerCase()}" style="${isResolved ? 'opacity: 0.55;' : ''}">
            <div class="incident-header">
              <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                <span class="badge badge-${(alert.severity || 'high').toLowerCase()}">${alert.severity}</span>
                <span class="incident-title">${alert.title}</span>
                <span style="font-size: 11px; font-family: var(--font-mono); color: #64748b;">[${alert.id || alert.alert_id}]</span>
              </div>
              <span style="font-size: 12px; color: #94a3b8;">Triggered: ${timeAgo}</span>
            </div>

            <p style="font-size: 13px; color: #cbd5e1; line-height: 1.5;">${alert.details}</p>

            <div class="incident-meta">
              <span>🎯 <strong>Attacker IP:</strong> <code style="color: #a855f7; font-weight: 700;">${alert.attackerIp}</code></span>
              <span>💻 <strong>Target System:</strong> <code style="color: var(--accent-cyan); font-weight: 700;">${alert.targetHost}</code></span>
              <span>🏷️ <strong>MITRE ATT&CK:</strong> <span style="color: #e2e8f0;">${alert.category || 'Threat Activity'}</span></span>
              ${alert.eventCount > 1 ? `<span>⚡ <strong>Occurrences:</strong> ${alert.eventCount}</span>` : ''}
            </div>

            <div style="background: rgba(6, 182, 212, 0.05); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 6px; padding: 8px 12px; font-size: 12px; color: var(--accent-cyan); display: flex; align-items: center; justify-content: space-between;">
              <div>💡 <strong>Recommended Mitigation:</strong> ${alert.mitigation}</div>
            </div>

            <div class="incident-actions">
              ${isBlocked ? '<span class="badge badge-low" style="padding: 6px 12px;">🛡️ Attacker IP Blocked at Perimeter Firewall</span>' : ''}
              ${isResolved ? '<span class="badge badge-info" style="padding: 6px 12px;">✓ Incident Marked Resolved</span>' : ''}

              ${!isBlocked && !isResolved ? `
                <button class="btn-sim-attack btn-block-ip" data-id="${alert.id}" data-ip="${alert.attackerIp}" style="padding: 6px 14px; font-size: 12px;">
                  🚫 1-Click Firewall Block
                </button>
                <button class="btn-outline btn-isolate-host" data-id="${alert.id}" data-host="${alert.targetHost}" style="padding: 6px 14px; font-size: 12px;">
                  🔒 Isolate Host
                </button>
                <button class="btn-primary btn-resolve" data-id="${alert.id}" style="padding: 6px 14px; font-size: 12px;">
                  ✓ Mark Resolved
                </button>
              ` : ''}

              ${isBlocked && !isResolved ? `
                <button class="btn-primary btn-resolve" data-id="${alert.id}" style="padding: 6px 14px; font-size: 12px;">
                  ✓ Mark Incident Resolved
                </button>
              ` : ''}
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;
};
