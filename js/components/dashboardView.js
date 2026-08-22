/**
 * SIEM-Lite Enterprise SOC Dashboard View Component
 */

window.renderDashboardView = function (appState) {
  const { logs, alerts, backendStatus, blockedIps, agents } = appState;
  
  const totalLogs = backendStatus.total_logs || logs.length;
  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const medCount = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowCount = alerts.filter(a => a.severity === 'LOW').length;
  const activeAgentCount = (agents && agents.length > 0) ? agents.length : (backendStatus.active_agents || 1);
  const blockedIpCount = (blockedIps && blockedIps.length > 0) ? blockedIps.length : (backendStatus.blocked_ips || 0);

  // Calculate Threat Level
  let threatLevel = 'LOW';
  let threatColor = 'var(--severity-low)';
  if (criticalCount > 0) {
    threatLevel = 'CRITICAL';
    threatColor = 'var(--severity-critical)';
  } else if (highCount > 0) {
    threatLevel = 'HIGH';
    threatColor = 'var(--severity-high)';
  } else if (medCount > 0) {
    threatLevel = 'MEDIUM';
    threatColor = 'var(--severity-med)';
  }

  // Top Attacker IPs
  const ipCounts = {};
  alerts.forEach(a => {
    if (a.attackerIp) {
      ipCounts[a.attackerIp] = (ipCounts[a.attackerIp] || 0) + 1;
    }
  });

  const sortedAttackers = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return `
    <!-- Top Row Stat Cards -->
    <div class="grid-4">
      <div class="card">
        <div class="card-title">
          <span>Global Threat Level</span>
          <span class="icon">🛡️</span>
        </div>
        <div class="threat-gauge">
          <div class="threat-level-text" style="color: ${threatColor}">${threatLevel}</div>
          <div class="card-subtext">Real-Time Threat Intelligence & Active Rules</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Active Incidents</span>
          <span class="icon">🚨</span>
        </div>
        <div class="card-value" style="color: var(--severity-critical)">${totalAlerts}</div>
        <div class="card-subtext">
          <span style="color: var(--severity-critical); font-weight: 700;">${criticalCount} Critical</span> • 
          <span style="color: var(--severity-high); font-weight: 700;">${highCount} High</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Logs Ingested (DB)</span>
          <span class="icon">📡</span>
        </div>
        <div class="card-value" style="color: var(--accent-cyan)">${totalLogs}</div>
        <div class="card-subtext">Persistent SQLite Engine • Syslog + REST</div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Active Defenses</span>
          <span class="icon">💻</span>
        </div>
        <div class="card-value" style="color: var(--accent-blue)">${activeAgentCount} Agents</div>
        <div class="card-subtext">
          <span style="color: var(--severity-critical); font-weight: 600;">🚫 ${blockedIpCount} Blocked IPs</span>
        </div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="grid-3-1">
      <div class="card">
        <div class="card-title">
          <span>Real-Time Ingestion Velocity (Events / sec)</span>
          <span style="font-size: 11px; color: var(--accent-cyan);">Live Telemetry</span>
        </div>
        <canvas id="velocityChart"></canvas>
      </div>

      <div class="card">
        <div class="card-title">Threat Breakdown</div>
        <canvas id="severityChart"></canvas>
      </div>
    </div>

    <!-- Attacker Ranking & Recent Alerts -->
    <div class="grid-2">
      <div class="card">
        <div class="card-title">
          <span>Top Hostile Attacking IPs</span>
          <span style="font-size: 11px; color: #a855f7;">Threat Geolocation</span>
        </div>
        <div style="margin-top: 12px;">
          ${sortedAttackers.length === 0 ? '<p style="color: #64748b; font-size: 13px; padding: 20px 0; text-align: center;">No hostile attacker IPs identified yet. System baseline clean.</p>' : ''}
          ${sortedAttackers.map(([ip, count]) => {
            const isBlocked = blockedIps && blockedIps.some(b => b.ip === ip);
            return `
              <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-family: var(--font-mono); font-size: 13px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span style="color: #a855f7; font-weight: 700;">🎯 ${ip}</span>
                  ${isBlocked ? '<span class="badge badge-low" style="font-size: 9px; padding: 1px 6px;">BLOCKED</span>' : ''}
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span class="badge badge-critical">${count} Incident${count > 1 ? 's' : ''}</span>
                  ${!isBlocked ? `
                    <button class="btn-sim-attack btn-block-ip" data-ip="${ip}" style="padding: 2px 8px; font-size: 11px;">
                      🚫 Block
                    </button>
                  ` : ''}
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Recent Critical Security Alerts</span>
          <span style="font-size: 11px; color: var(--severity-critical);">Requires Action</span>
        </div>
        <div style="margin-top: 12px; display: flex; flex-direction: column; gap: 10px;">
          ${alerts.length === 0 ? '<p style="color: #64748b; font-size: 13px; padding: 20px 0; text-align: center;">No active security alerts triggered. Monitoring 24/7.</p>' : ''}
          ${alerts.slice(0, 4).map(alert => `
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: rgba(15, 23, 42, 0.7); border-radius: 8px; border-left: 4px solid var(--severity-${alert.severity.toLowerCase()}); border: 1px solid var(--border-color); border-left-width: 4px;">
              <div style="flex: 1; margin-right: 12px;">
                <div style="font-weight: 700; font-size: 13px; color: #f8fafc;">${alert.title}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">Attacker: <span style="color: #a855f7; font-family: var(--font-mono);">${alert.attackerIp}</span> | Target: <span style="color: var(--accent-cyan); font-family: var(--font-mono);">${alert.targetHost}</span></div>
              </div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
                <button class="btn-outline btn-block-ip" data-id="${alert.id}" data-ip="${alert.attackerIp}" style="padding: 3px 8px; font-size: 11px; border-color: rgba(244, 63, 94, 0.4); color: #f43f5e;">
                  🚫 Block
                </button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
};
