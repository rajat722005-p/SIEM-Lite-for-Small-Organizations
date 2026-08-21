/**
 * SIEM-Lite Live Terminal Log Viewer Component
 */

window.renderLogStreamView = function (appState) {
  const { logs, searchTerm, filterSource, filterSeverity, isPaused, isConnected } = appState;

  // Filter logs based on user controls
  let filteredLogs = logs.filter(log => {
    const msg = (log.message || '') + ' ' + (log.raw || '') + ' ' + (log.user || '');
    const matchSearch = !searchTerm || msg.toLowerCase().includes(searchTerm.toLowerCase()) || (log.ip && log.ip.includes(searchTerm));
    const matchSource = filterSource === 'ALL' || log.source === filterSource;
    const matchSeverity = filterSeverity === 'ALL' || log.severity === filterSeverity;
    return matchSearch && matchSource && matchSeverity;
  });

  return `
    <div class="card" style="padding: 16px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;">
      <div style="display: flex; gap: 12px; align-items: center; flex: 1; min-width: 320px;">
        <input 
          type="text" 
          id="logSearchInput" 
          class="search-input" 
          placeholder="🔍 Search live logs by keyword, IP address, user, or event payload..." 
          value="${searchTerm || ''}"
          style="flex: 1; padding: 8px 12px; font-size: 13px;"
        />
        
        <select id="logSourceSelect" class="select-input" style="padding: 8px 12px; font-size: 13px;">
          <option value="ALL" ${filterSource === 'ALL' ? 'selected' : ''}>All Log Sources</option>
          <option value="web-application" ${filterSource === 'web-application' ? 'selected' : ''}>Web Application</option>
          <option value="linux-server" ${filterSource === 'linux-server' ? 'selected' : ''}>Linux Server</option>
          <option value="firewall" ${filterSource === 'firewall' ? 'selected' : ''}>Firewall / Router</option>
          <option value="windows-server" ${filterSource === 'windows-server' ? 'selected' : ''}>Windows Server</option>
          <option value="syslog-network" ${filterSource === 'syslog-network' ? 'selected' : ''}>Syslog Network</option>
          <option value="endpoint" ${filterSource === 'endpoint' ? 'selected' : ''}>Endpoint</option>
        </select>

        <select id="logSeveritySelect" class="select-input" style="padding: 8px 12px; font-size: 13px;">
          <option value="ALL" ${filterSeverity === 'ALL' ? 'selected' : ''}>All Severities</option>
          <option value="INFO" ${filterSeverity === 'INFO' ? 'selected' : ''}>INFO</option>
          <option value="WARN" ${filterSeverity === 'WARN' ? 'selected' : ''}>WARN</option>
          <option value="HIGH" ${filterSeverity === 'HIGH' ? 'selected' : ''}>HIGH</option>
          <option value="CRITICAL" ${filterSeverity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
        </select>
      </div>

      <div style="display: flex; gap: 10px; align-items: center;">
        <button id="btnPauseStream" class="btn-outline" style="display: flex; align-items: center; gap: 6px;">
          <span>${isPaused ? '▶️ Resume Live Feed' : '⏸️ Pause Feed'}</span>
        </button>
        <a href="/api/export?type=logs&format=csv" target="_blank" class="btn-outline" style="text-decoration: none; display: flex; align-items: center; gap: 6px;">
          <span>📥 Export CSV</span>
        </a>
        <button id="btnClearLogs" class="btn-outline">Clear View</button>
      </div>
    </div>

    <!-- Terminal Window -->
    <div class="terminal-window">
      <div class="terminal-header">
        <div class="terminal-controls">
          <span class="t-dot t-red"></span>
          <span class="t-dot t-yellow"></span>
          <span class="t-dot t-green"></span>
        </div>
        <div style="font-size: 12px; color: #94a3b8; font-family: var(--font-mono);">
          RAW INGESTION STREAM (${filteredLogs.length} Events Displayed • SQLite Persisted)
        </div>
        <div style="font-size: 11px; color: ${isPaused ? '#f59e0b' : '#10b981'}; font-weight: 600;">
          ${isPaused ? '● PAUSED' : (isConnected ? '● STREAMING LIVE (SSE)' : '● CONNECTING...')}
        </div>
      </div>

      <div class="terminal-body" id="terminalLogBody">
        ${filteredLogs.length === 0 ? '<div style="color: #64748b; padding: 40px; text-align: center;">No log events matching current filters. Ingest logs via REST / Syslog / Windows Agent.</div>' : ''}
        ${filteredLogs.map(log => {
          const isThreat = (log.message && (log.message.includes('🚨') || log.message.includes('[TRIGGER]'))) || log.severity === 'HIGH' || log.severity === 'CRITICAL';
          const timeStr = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
          return `
            <div class="log-line">
              <span class="log-time">[${timeStr}]</span>
              <span class="log-source">[${log.source}]</span>
              <span class="log-ip">${log.ip || '127.0.0.1'}</span>
              <span class="log-user" style="color: #64748b; width: 70px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${log.user || 'system'}</span>
              <span class="badge badge-${(log.severity || 'info').toLowerCase()}" style="font-size: 9px; padding: 1px 6px; height: 18px; margin-right: 6px;">${log.severity || 'INFO'}</span>
              <span class="log-msg ${isThreat ? 'highlight-threat' : ''}">${log.message || log.raw}</span>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
};
