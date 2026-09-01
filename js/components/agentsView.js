/**
 * SIEM-Lite Agent & Collector Fleet Management Component
 */

window.renderAgentsView = function (appState) {
  const { agents = [] } = appState;

  return `
    <div style="margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
      <div>
        <h2 style="font-size: 20px; font-weight: 700;">Collector & Endpoint Agent Fleet</h2>
        <p style="font-size: 13px; color: #94a3b8; margin-top: 2px;">
          Monitors connected Windows endpoints, Linux servers, Syslog forwarders, and log file tailers in real-time.
        </p>
      </div>

      <div style="display: flex; gap: 10px;">
        <span class="badge badge-low">● Ingestion Port: 8000</span>
        <span class="badge badge-info">● Syslog UDP: 1514</span>
      </div>
    </div>

    <!-- Active Collectors List -->
    <div class="card" style="margin-bottom: 24px;">
      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 16px;">
        📡 Registered Agents & Forwarders (${agents.length})
      </h3>

      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid var(--border-color); color: #94a3b8; text-transform: uppercase; font-size: 11px;">
              <th style="padding: 12px 10px;">Agent ID</th>
              <th style="padding: 12px 10px;">Agent Name / Host</th>
              <th style="padding: 12px 10px;">Type</th>
              <th style="padding: 12px 10px;">IP Address</th>
              <th style="padding: 12px 10px;">Operating System</th>
              <th style="padding: 12px 10px;">Events Shipped</th>
              <th style="padding: 12px 10px;">Last Heartbeat</th>
              <th style="padding: 12px 10px;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${agents.length === 0 ? `
              <tr>
                <td colspan="8" style="padding: 30px; text-align: center; color: #64748b;">
                  No external agents registered yet. Use the deployment commands below to connect Windows/Linux hosts.
                </td>
              </tr>
            ` : ''}
            ${agents.map(ag => `
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.03); font-family: var(--font-mono);">
                <td style="padding: 12px 10px; color: var(--accent-cyan); font-weight: 600;">${ag.agent_id}</td>
                <td style="padding: 12px 10px; color: #f8fafc; font-weight: 600;">${ag.name}</td>
                <td style="padding: 12px 10px; color: #cbd5e1;">${ag.type}</td>
                <td style="padding: 12px 10px; color: #a855f7;">${ag.ip_address}</td>
                <td style="padding: 12px 10px; color: #94a3b8;">${ag.os || 'Unknown'}</td>
                <td style="padding: 12px 10px; color: var(--severity-low); font-weight: 700;">${ag.total_logs || 0}</td>
                <td style="padding: 12px 10px; color: #64748b; font-size: 11px;">${new Date(ag.last_heartbeat).toLocaleTimeString()}</td>
                <td style="padding: 12px 10px;">
                  <span class="badge badge-low">ONLINE</span>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Deployment & Installation Guide -->
    <div class="grid-2">
      <div class="card">
        <h3 style="font-size: 15px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">
          🪟 1. Deploy Windows Security Event Collector
        </h3>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 12px;">
          Reads native Windows Event Logs (4625 Brute force, 4720 User creation, 1102 Audit log cleared) and forwards to SIEM.
        </p>
        <div style="background: #040711; border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 12px; color: #a855f7; overflow-x: auto;">
          <code>python collectors/windows_event_collector.py</code>
        </div>
        <p style="font-size: 11px; color: #64748b; margin-top: 6px;">Or run native PowerShell script: <code>.\collectors\windows_agent.ps1</code></p>
      </div>

      <div class="card">
        <h3 style="font-size: 15px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">
          🐧 2. Configure Syslog on Routers / Linux (UDP:1514)
        </h3>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 12px;">
          Point Cisco/pfSense/Mikrotik routers or Linux <code>/etc/rsyslog.conf</code> to SIEM-Lite:
        </p>
        <div style="background: #040711; border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 12px; color: #10b981; overflow-x: auto;">
          <code>*.* @127.0.0.1:1514</code>
        </div>
        <p style="font-size: 11px; color: #64748b; margin-top: 6px;">Test with test shipper: <code>python collectors/syslog_forwarder.py</code></p>
      </div>

      <div class="card">
        <h3 style="font-size: 15px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">
          📄 3. Universal Web / App Log File Tailer
        </h3>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 12px;">
          Stream Nginx <code>access.log</code>, Apache, or custom application logs in real-time:
        </p>
        <div style="background: #040711; border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 12px; color: #e2e8f0; overflow-x: auto;">
          <code>python collectors/file_tail_agent.py --file /var/log/nginx/access.log</code>
        </div>
      </div>

      <div class="card">
        <h3 style="font-size: 15px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">
          🌐 4. Direct REST Ingestion API
        </h3>
        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 12px;">
          Submit JSON logs from custom webapps, microservices, or cloud webhooks:
        </p>
        <div style="background: #040711; border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 12px; color: #f59e0b; overflow-x: auto;">
          <code>POST http://localhost:8000/api/logs</code>
        </div>
      </div>
    </div>
  `;
};
