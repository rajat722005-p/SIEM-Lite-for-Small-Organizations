/**
 * SIEM-Lite Rule Engine Configuration Component
 */

window.renderRuleEngineView = function (appState) {
  const { rules } = appState;

  return `
    <div style="margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
      <div>
        <h2 style="font-size: 20px; font-weight: 700;">Stateful Threat Correlation Rules</h2>
        <p style="font-size: 13px; color: #94a3b8; margin-top: 2px;">
          Production detection rules evaluated 24/7 on continuous sliding-window log streams on the backend server.
        </p>
      </div>

      <button id="btnOpenAddRuleModal" class="btn-primary">+ Add Custom Detection Rule</button>
    </div>

    <!-- Rule List -->
    <div style="display: flex; flex-direction: column; gap: 16px;">
      ${rules.map(rule => `
        <div class="card" style="display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; border-left: 4px solid var(--severity-${(rule.severity || 'high').toLowerCase()});">
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 6px; flex-wrap: wrap;">
              <span class="badge badge-${(rule.severity || 'high').toLowerCase()}">${rule.severity}</span>
              <h3 style="font-weight: 700; font-size: 16px; color: #f8fafc;">${rule.name}</h3>
              <span style="font-size: 12px; font-family: var(--font-mono); color: #64748b;">[${rule.id || rule.rule_id}]</span>
            </div>

            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 10px;">${rule.description}</p>

            <div style="display: flex; gap: 20px; font-size: 12px; color: #94a3b8; font-family: var(--font-mono); flex-wrap: wrap;">
              <span>🏷️ <strong>Category:</strong> ${rule.category}</span>
              ${rule.threshold && rule.threshold > 1 ? `<span>⚡ <strong>Threshold:</strong> ${rule.threshold} events / ${rule.timeWindowSec}s</span>` : '<span>⚡ <strong>Mode:</strong> Real-Time Signature Match</span>'}
              <span>🛡️ <strong>Mitigation:</strong> ${rule.mitigation}</span>
            </div>

            ${rule.pattern ? `
              <div style="margin-top: 8px; font-size: 11px; font-family: var(--font-mono); color: #64748b;">
                <strong>Signatures:</strong> <code style="color: var(--accent-cyan);">${rule.pattern}</code>
              </div>
            ` : ''}
          </div>

          <div style="display: flex; align-items: center; gap: 12px;">
            <span style="font-size: 12px; font-weight: 600; color: ${rule.enabled ? '#10b981' : '#64748b'};">
              ${rule.enabled ? 'ACTIVE' : 'DISABLED'}
            </span>
            <button 
              class="btn-outline toggle-rule-btn" 
              data-id="${rule.id || rule.rule_id}"
              style="padding: 6px 14px; border-color: ${rule.enabled ? 'rgba(16, 185, 129, 0.4)' : 'var(--border-color)'};"
            >
              ${rule.enabled ? 'Disable' : 'Enable'}
            </button>
          </div>
        </div>
      `).join('')}
    </div>

    <!-- Add Custom Rule Modal -->
    <div class="modal-overlay" id="addRuleModal">
      <div class="modal-content">
        <div class="modal-header">
          <h3 style="font-size: 16px; font-weight: 700;">+ Create Custom Threat Detection Rule</h3>
          <button class="modal-close" id="btnCloseAddRuleModal">&times;</button>
        </div>
        <form id="addRuleForm" style="display: flex; flex-direction: column; gap: 14px;">
          <div>
            <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Rule Name</label>
            <input type="text" id="newRuleName" class="search-input" style="width: 100%;" placeholder="e.g. Excessive 404 Scanning" required />
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <div>
              <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Category (MITRE)</label>
              <input type="text" id="newRuleCategory" class="search-input" style="width: 100%;" placeholder="e.g. Discovery" value="Discovery" required />
            </div>
            <div>
              <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Severity</label>
              <select id="newRuleSeverity" class="select-input" style="width: 100%;">
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH" selected>HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <div>
              <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Threshold (Event Count)</label>
              <input type="number" id="newRuleThreshold" class="search-input" style="width: 100%;" value="5" min="1" required />
            </div>
            <div>
              <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Time Window (Seconds)</label>
              <input type="number" id="newRuleWindow" class="search-input" style="width: 100%;" value="60" min="0" required />
            </div>
          </div>

          <div>
            <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Signatures / Keywords (Comma Separated)</label>
            <input type="text" id="newRulePattern" class="search-input" style="width: 100%;" placeholder="404 not found, forbidden, invalid path" required />
          </div>

          <div>
            <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Description</label>
            <textarea id="newRuleDesc" class="search-input" style="width: 100%; height: 60px; resize: none;" placeholder="Rule description and detection rationale..."></textarea>
          </div>

          <div>
            <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Recommended Mitigation</label>
            <input type="text" id="newRuleMitigation" class="search-input" style="width: 100%;" placeholder="e.g. Block Client IP & Inspect WAF logs" />
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
            <button type="button" class="btn-outline" id="btnCancelAddRule">Cancel</button>
            <button type="submit" class="btn-primary">Save Detection Rule</button>
          </div>
        </form>
      </div>
    </div>
  `;
};
