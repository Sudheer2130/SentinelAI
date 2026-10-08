// SentinelAI - SOC Command Center Frontend Application Logic

let activeIncidents = [];
let selectedIncidentId = null;
let currentFilter = 'all';
let chatHistory = [];

document.addEventListener('DOMContentLoaded', () => {
    initApp();
    setupEventListeners();
    // Auto-refresh stats & incidents periodically
    setInterval(fetchStats, 10000);
});

async function initApp() {
    await fetchStats();
    await fetchIncidents();
}

function setupEventListeners() {
    // Filter tabs
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
            e.target.classList.add('active');
            currentFilter = e.target.dataset.filter;
            renderAlertsList();
        });
    });

    // Console tabs
    document.querySelectorAll('.console-tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tabId = e.currentTarget.dataset.tab;
            document.querySelectorAll('.console-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            
            e.currentTarget.classList.add('active');
            const targetPane = document.getElementById(tabId);
            if (targetPane) targetPane.classList.add('active');
        });
    });

    // Chat submit
    const chatForm = document.getElementById('chatForm');
    if (chatForm) {
        chatForm.addEventListener('submit', handleChatSubmit);
    }
}

// Fetch Metrics & Stats
async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        if (!res.ok) return;
        const data = await res.json();
        
        document.getElementById('metricTotalAlerts').innerText = data.total_alerts_analyzed;
        document.getElementById('metricCritical').innerText = data.critical_incidents;
        document.getElementById('metricFpRate').innerText = data.false_positive_rate;
        document.getElementById('metricHoursSaved').innerText = `${data.estimated_hours_saved}h`;
        
        if (data.llm_engine_status) {
            document.getElementById('engineStatusText').innerText = data.llm_engine_status;
        }
    } catch (err) {
        console.error('Error fetching stats:', err);
    }
}

// Fetch Incidents
async function fetchIncidents() {
    try {
        const res = await fetch('/api/incidents');
        if (!res.ok) return;
        activeIncidents = await res.json();
        renderAlertsList();

        // Auto select first incident if none selected
        if (!selectedIncidentId && activeIncidents.length > 0) {
            selectIncident(activeIncidents[0].incident_id);
        } else if (selectedIncidentId) {
            selectIncident(selectedIncidentId);
        }
    } catch (err) {
        console.error('Error loading incidents:', err);
    }
}

// Render Alerts Stream
function renderAlertsList() {
    const container = document.getElementById('alertsListContainer');
    if (!container) return;

    let filtered = [...activeIncidents];
    if (currentFilter === 'critical') {
        filtered = filtered.filter(i => i.severity === 'CRITICAL');
    } else if (currentFilter === 'high') {
        filtered = filtered.filter(i => i.severity === 'HIGH' || i.severity === 'CRITICAL');
    } else if (currentFilter === 'fp') {
        filtered = filtered.filter(i => i.verdict === 'FALSE_POSITIVE');
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.85rem;">
                No incidents matching current filter.
            </div>`;
        return;
    }

    container.innerHTML = filtered.map(inc => {
        const isSelected = inc.incident_id === selectedIncidentId;
        const sevClass = `badge-${inc.severity.toLowerCase()}`;
        const sourceLabel = inc.log_source === 'WINDOWS_SYSMON' ? 'SYS-EVENT' : 'SURICATA';
        const hostOrIp = inc.normalized_alert.hostname || inc.normalized_alert.dest_ip || 'Internal Asset';
        
        return `
            <div class="alert-item ${isSelected ? 'selected' : ''}" onclick="selectIncident('${inc.incident_id}')">
                <div class="alert-item-header">
                    <span class="badge ${sevClass}">${inc.severity}</span>
                    <span class="alert-time">${formatTime(inc.timestamp)}</span>
                </div>
                <div class="alert-item-title">${escapeHtml(inc.title)}</div>
                <div class="alert-item-footer">
                    <span class="source-tag">${sourceLabel}</span>
                    <span>${escapeHtml(hostOrIp)}</span>
                </div>
            </div>
        `;
    }).join('');
}

// Select and Display Incident Details
function selectIncident(incidentId) {
    selectedIncidentId = incidentId;
    const inc = activeIncidents.find(i => i.incident_id === incidentId);
    if (!inc) return;

    // Highlight selected item in list
    document.querySelectorAll('.alert-item').forEach(el => el.classList.remove('selected'));
    renderAlertsList();

    // Reset Chat history for new incident
    chatHistory = [];
    renderChatHistory();

    // Populate Console Header
    document.getElementById('activeIncidentTitle').innerText = inc.title;
    document.getElementById('activeIncidentId').innerText = inc.incident_id;
    document.getElementById('activeIncidentTime').innerText = inc.timestamp;
    document.getElementById('activeIncidentHost').innerText = inc.normalized_alert.hostname || inc.normalized_alert.src_ip || 'N/A';
    
    // Status selector
    const statusSelect = document.getElementById('incidentStatusSelect');
    if (statusSelect) statusSelect.value = inc.status;

    // Severity & Verdict Badge
    const sevBadge = document.getElementById('activeSeverityBadge');
    sevBadge.className = `badge badge-${inc.severity.toLowerCase()}`;
    sevBadge.innerText = inc.severity;

    // Verdict Hero Card
    const verdictHero = document.getElementById('activeVerdictBadge');
    const vClass = inc.verdict.toLowerCase().replace('_', '-');
    verdictHero.className = `badge badge-${vClass}`;
    verdictHero.innerText = inc.verdict.replace('_', ' ');

    const confPercent = Math.round(inc.confidence_score * 100);
    document.getElementById('confidenceScoreText').innerText = `${confPercent}% Confidence`;
    document.getElementById('confidenceBarFill').style.width = `${confPercent}%`;

    document.getElementById('heroKillchainPhase').innerText = inc.attack_killchain_phase || 'Active Execution';
    document.getElementById('heroAiProvider').innerText = inc.ai_provider_used || 'SentinelAI Engine';

    // Summaries & Analysis
    document.getElementById('executiveSummaryContent').innerText = inc.executive_summary;
    document.getElementById('rootCauseContent').innerText = inc.root_cause_analysis;
    document.getElementById('blastRadiusContent').innerText = inc.blast_radius;

    // Render Timeline
    renderTimeline(inc.timeline);

    // Render IOCs
    renderIOCs(inc.extracted_iocs);

    // Render MITRE TTPs
    renderMitre(inc.mitre_ttps);

    // Render Playbooks & Rules
    renderPlaybooks(inc);
}

function renderTimeline(timeline) {
    const container = document.getElementById('timelineContainer');
    if (!container) return;

    if (!timeline || timeline.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No correlated events logged.</div>';
        return;
    }

    container.innerHTML = timeline.map(ev => `
        <div class="timeline-event">
            <div class="timeline-event-header">
                <span class="timeline-event-stage">${escapeHtml(ev.stage)}</span>
                <span style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-muted);">${formatTime(ev.timestamp)}</span>
            </div>
            <div class="timeline-event-desc">${escapeHtml(ev.description)}</div>
            <div style="margin-top: 0.25rem; font-size: 0.7rem; color: var(--text-secondary);">Source: <code>${escapeHtml(ev.source)}</code></div>
        </div>
    `).join('');
}

function renderIOCs(iocs) {
    const tbody = document.getElementById('iocsTableBody');
    if (!tbody) return;

    if (!iocs || iocs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No external IOCs identified.</td></tr>';
        return;
    }

    tbody.innerHTML = iocs.map(ioc => {
        const isMal = ioc.is_malicious || ioc.reputation_score >= 50;
        const repColor = isMal ? 'var(--accent-red)' : (ioc.reputation_score > 20 ? 'var(--accent-orange)' : 'var(--accent-green)');
        const tags = (ioc.tags || []).map(t => `<span class="badge" style="background: rgba(255,255,255,0.06); font-size: 0.65rem;">${escapeHtml(t)}</span>`).join(' ');

        return `
            <tr>
                <td><span class="badge" style="background: rgba(0,242,254,0.1); color: var(--accent-cyan);">${ioc.ioc_type.toUpperCase()}</span></td>
                <td><span class="code-pill">${escapeHtml(ioc.value)}</span></td>
                <td><strong style="color: ${repColor};">${ioc.reputation_score}/100</strong></td>
                <td><span class="badge ${isMal ? 'badge-critical' : 'badge-low'}">${isMal ? 'MALICIOUS' : 'CLEAN'}</span></td>
                <td>${tags || '<span style="color: var(--text-muted); font-size: 0.75rem;">None</span>'}</td>
            </tr>
        `;
    }).join('');
}

function renderMitre(ttps) {
    const tbody = document.getElementById('mitreTableBody');
    if (!tbody) return;

    if (!ttps || ttps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No MITRE techniques mapped for this alert.</td></tr>';
        return;
    }

    tbody.innerHTML = ttps.map(ttp => `
        <tr>
            <td><strong style="color: var(--accent-cyan);">${escapeHtml(ttp.tactic_name)}</strong> <span style="font-size: 0.7rem; color: var(--text-muted);">(${ttp.tactic_id})</span></td>
            <td><span class="code-pill" style="color: var(--accent-orange);">${escapeHtml(ttp.technique_id)}</span></td>
            <td><strong>${escapeHtml(ttp.technique_name)}</strong><br><span style="font-size: 0.74rem; color: var(--text-secondary);">${escapeHtml(ttp.description)}</span></td>
            <td><span class="badge badge-high">${Math.round(ttp.confidence * 100)}%</span></td>
        </tr>
    `).join('');
}

function renderPlaybooks(inc) {
    // Actions
    const actionsBox = document.getElementById('playbookActionsContainer');
    if (actionsBox) {
        if (!inc.playbook_actions || inc.playbook_actions.length === 0) {
            actionsBox.innerHTML = '<p style="color: var(--text-muted);">No automated playbook actions required.</p>';
        } else {
            actionsBox.innerHTML = inc.playbook_actions.map(act => `
                <div class="code-container">
                    <div class="code-header">
                        <span><strong>${escapeHtml(act.title)}</strong> &mdash; Target: <code>${escapeHtml(act.target)}</code></span>
                        <button class="btn btn-outline btn-sm" onclick="copyText('${escapeAttr(act.command)}')">Copy Command</button>
                    </div>
                    <div class="code-body">${escapeHtml(act.command)}</div>
                    <div style="padding: 0.5rem 1rem; font-size: 0.75rem; color: var(--text-muted); background: rgba(0,0,0,0.2);">
                        ${escapeHtml(act.explanation)}
                    </div>
                </div>
            `).join('');
        }
    }

    // Sigma Rule
    const sigmaBox = document.getElementById('sigmaRuleContent');
    if (sigmaBox) sigmaBox.innerText = inc.sigma_rule || '# No Sigma rule available';

    // YARA Rule
    const yaraBox = document.getElementById('yaraRuleContent');
    if (yaraBox) yaraBox.innerText = inc.yara_rule || '// No YARA signature available';

    // Firewall Script
    const fwBox = document.getElementById('firewallScriptContent');
    if (fwBox) fwBox.innerText = inc.firewall_script || '# No firewall rules generated';
}

// Preset Scenario Execution
async function runScenario(scenarioId) {
    const btn = event.currentTarget;
    const originalText = btn.innerText;
    btn.innerText = '⚡ Running...';
    btn.disabled = true;

    try {
        const res = await fetch(`/api/scenarios/${scenarioId}/run`, { method: 'POST' });
        if (res.ok) {
            const report = await res.json();
            await fetchStats();
            await fetchIncidents();
            selectIncident(report.incident_id);
        } else {
            alert('Failed to trigger scenario.');
        }
    } catch (err) {
        console.error(err);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

// Custom Ingestion
function openIngestModal() {
    document.getElementById('ingestModal').classList.add('active');
}

function closeIngestModal() {
    document.getElementById('ingestModal').classList.remove('active');
}

async function submitCustomLog() {
    const rawVal = document.getElementById('customLogTextarea').value.trim();
    if (!rawVal) return;

    let payload;
    try {
        payload = JSON.parse(rawVal);
    } catch (e) {
        // Wrap plain text as generic log
        payload = {
            message: rawVal,
            log_source: "GENERIC_SYSLOG",
            timestamp: new Date().toISOString()
        };
    }

    try {
        const res = await fetch('/api/investigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            const report = await res.json();
            closeIngestModal();
            await fetchStats();
            await fetchIncidents();
            selectIncident(report.incident_id);
        } else {
            alert('Investigation failed. Check payload.');
        }
    } catch (err) {
        alert(`Error: ${err.message}`);
    }
}

// Interactive SOC Copilot Chat
async function handleChatSubmit(e) {
    e.preventDefault();
    const input = document.getElementById('chatInput');
    const msg = input.value.trim();
    if (!msg || !selectedIncidentId) return;

    input.value = '';
    
    // Add user message
    chatHistory.push({ role: 'user', content: msg });
    renderChatHistory();

    try {
        const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                incident_id: selectedIncidentId,
                message: msg,
                history: chatHistory
            })
        });

        if (res.ok) {
            const data = await res.json();
            chatHistory.push({ role: 'assistant', content: data.response });
            renderChatHistory();
        }
    } catch (err) {
        chatHistory.push({ role: 'assistant', content: 'Connection to SOC copilot interrupted.' });
        renderChatHistory();
    }
}

function sendPresetQuestion(text) {
    const input = document.getElementById('chatInput');
    input.value = text;
    document.getElementById('chatForm').dispatchEvent(new Event('submit'));
}

function renderChatHistory() {
    const box = document.getElementById('chatMessagesBox');
    if (!box) return;

    if (chatHistory.length === 0) {
        box.innerHTML = `
            <div class="chat-msg assistant">
                <div class="chat-avatar">AI</div>
                <div class="chat-bubble">
                    Greetings Analyst. I have completed autonomous triage for Incident <code>${selectedIncidentId || ''}</code>.
                    Ask me about the attack lineage, IOCs, containment commands, or detection queries.
                </div>
            </div>
        `;
        return;
    }

    box.innerHTML = chatHistory.map(m => `
        <div class="chat-msg ${m.role}">
            <div class="chat-avatar">${m.role === 'user' ? 'YOU' : 'AI'}</div>
            <div class="chat-bubble">${escapeHtml(m.content).replace(/\n/g, '<br>')}</div>
        </div>
    `).join('');

    box.scrollTop = box.scrollHeight;
}

// Status update
async function onStatusChange(newStatus) {
    if (!selectedIncidentId) return;
    try {
        await fetch(`/api/incidents/${selectedIncidentId}/status`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        const inc = activeIncidents.find(i => i.incident_id === selectedIncidentId);
        if (inc) inc.status = newStatus;
    } catch (err) {
        console.error('Failed to update status', err);
    }
}

// Export Markdown Report
function exportReport() {
    if (!selectedIncidentId) return;
    window.open(`/api/incidents/${selectedIncidentId}/export/markdown`, '_blank');
}

// Helpers
function formatTime(isoStr) {
    if (!isoStr) return '';
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return isoStr;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeAttr(str) {
    if (!str) return '';
    return String(str).replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

function copyText(text) {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
}
