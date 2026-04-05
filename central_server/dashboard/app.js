const COLORS = {
    green: '#10b981',
    red: '#f43f5e',
    yellow: '#f59e0b',
    blue: '#06b6d4',
    purple: '#8b5cf6',
    bgLight: 'rgba(255,255,255,0.05)'
};

Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Outfit', sans-serif";
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';

// Initialize Charts
const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');
const attackTypeChart = new Chart(attackTypeCtx, {
    type: 'doughnut',
    data: {
        labels: [],
        datasets: [{
            data: [],
            backgroundColor: [COLORS.red, COLORS.purple, COLORS.blue, COLORS.yellow],
            borderWidth: 0,
            hoverOffset: 10
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { 
            legend: { position: 'right', labels: { color: '#f8fafc', font: { size: 13 }, padding: 20 } } 
        },
        cutout: '75%',
        layout: { padding: 20 }
    }
});

const subtypeCtx = document.getElementById('subtypeChart').getContext('2d');
const subtypeChart = new Chart(subtypeCtx, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [{
            label: 'Matches',
            data: [],
            backgroundColor: 'rgba(6, 182, 212, 0.8)',
            borderColor: COLORS.blue,
            borderWidth: 1,
            borderRadius: 6,
            hoverBackgroundColor: COLORS.blue
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { stepSize: 1, font: { size: 12 } } },
            x: { grid: { display: false }, ticks: { font: { size: 11 } } }
        }
    }
});

const timelineCtx = document.getElementById('timelineChart').getContext('2d');
const timelineChart = new Chart(timelineCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Alerts',
            data: [],
            borderColor: COLORS.red,
            backgroundColor: 'rgba(244, 63, 94, 0.15)',
            borderWidth: 3,
            fill: true,
            pointRadius: 0,
            pointHoverRadius: 6,
            tension: 0.4
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
        scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { stepSize: 1 } },
            x: { grid: { display: false }, ticks: { maxTicksLimit: 8, color: '#94a3b8' } }
        },
        interaction: { mode: 'nearest', axis: 'x', intersect: false }
    }
});

let currentEvents = [];
let currentTimeline = [];

async function fetchData() {
    try {
        const [eventsRes, overviewRes, typesRes, subtypesRes, timelineRes, connRes, attackersRes, enginesRes] = await Promise.all([
            fetch('/events?limit=100'),
            fetch('/stats/overview'),
            fetch('/stats/types'),
            fetch('/stats/subtypes'),
            fetch('/stats/timeline'),
            fetch('/stats/connections'),
            fetch('/stats/top_attackers'),
            fetch('/stats/engines')
        ]);

        if (!eventsRes.ok) throw new Error("API Offline");

        const events = await eventsRes.json();
        const overview = await overviewRes.json();
        const types = await typesRes.json();
        const subtypes = await subtypesRes.json();
        const timeline = await timelineRes.json();
        const connections = await connRes.json();
        const attackers = await attackersRes.json();
        const engines = await enginesRes.json();
        
        currentEvents = events;
        currentTimeline = timeline;
        updateUI(overview, types, subtypes, connections, attackers, engines);
        
        const statusEl = document.getElementById('connectionStatus');
        statusEl.innerHTML = "● SECURE CONNECTION";
        statusEl.style.color = COLORS.green;
    } catch (e) {
        const statusEl = document.getElementById('connectionStatus');
        statusEl.innerHTML = "● CONNECTION LOST";
        statusEl.style.color = COLORS.red;
    }
}

function updateUI(overview, types, subtypes, connections, attackers, engines) {
    // 1. Overview
    document.getElementById('totalAlerts').innerText = overview.total_alerts.toLocaleString();
    document.getElementById('alertsPerSec').innerText = overview.alerts_per_sec;
    document.getElementById('activeTypes').innerText = overview.active_types;
    document.getElementById('sidsCount').innerText = engines.SIDS || 0;
    document.getElementById('aidsCount').innerText = engines.AIDS || 0;
    document.getElementById('hybridCount').innerText = engines.HYBRID || 0;
    
    const threatElem = document.getElementById('threatLevel');
    threatElem.innerText = overview.threat_level;
    threatElem.className = 'threat-level-badge ' + (
        overview.threat_level === 'HIGH' ? 'level-high' : 
        overview.threat_level === 'MEDIUM' ? 'level-med' : 'level-low'
    );

    // 2. Charts
    attackTypeChart.data.labels = Object.keys(types);
    attackTypeChart.data.datasets[0].data = Object.values(types);
    attackTypeChart.update();

    subtypeChart.data.labels = Object.keys(subtypes).map(s => s.length > 15 ? s.substring(0, 15) + '...' : s);
    subtypeChart.data.datasets[0].data = Object.values(subtypes);
    subtypeChart.update();

    renderTimeline(currentTimeline);
    renderHeat(types, overview.total_alerts);

    // 3. Tables
    document.getElementById('connectionsTableBody').innerHTML = connections.slice(0, 10).map(c => `
        <tr><td><code>${c.src_ip}</code></td><td><code>${c.dest_ip}</code></td>
        <td><span class="tag" style="border:1px solid rgba(255,255,255,0.2);">${c.type}</span></td><td>${c.count}</td></tr>
    `).join('');

    document.getElementById('attackersTableBody').innerHTML = attackers.slice(0, 10).map(a => `
        <tr><td><code>${a.src_ip}</code></td><td style="font-weight:600; color:var(--text-main);">${a.count}</td></tr>
    `).join('');

    renderTable();
}

function renderTable() {
    const tableBody = document.getElementById('alertsTableBody');
    const fType = document.getElementById('filterType').value;
    const fSev = document.getElementById('filterSeverity').value;

    let filtered = currentEvents.filter(ev => {
        if (fType !== 'ALL' && ev.type !== fType) return false;
        if (fSev !== 'ALL') {
            const evSevStr = ev.severity ? ev.severity.toString() : 'NONE';
            if (fSev !== evSevStr) return false;
        }
        return true;
    });

    tableBody.innerHTML = '';
    filtered.slice(0, 50).forEach(ev => {
        const row = document.createElement('tr');
        row.className = 'alert-row';
        row.onclick = () => showModal(ev);
        
        const date = new Date(ev.timestamp).toLocaleTimeString();
        let sevClass = 'sev-none'; let sevText = '---';
        if (ev.severity === 1) { sevClass = 'sev-1'; sevText = 'HIGH'; }
        else if (ev.severity === 2) { sevClass = 'sev-2'; sevText = 'MED'; }
        else if (ev.severity === 3) { sevClass = 'sev-3'; sevText = 'LOW'; }
        
        const subtypeText = ev.subtype ? ev.subtype : '<span style="color:var(--text-muted)">N/A</span>';
        const sources = ev.detected_by.map(s => `<span class="tag ${s.toLowerCase()}">${s}</span>`).join(' ');
        
        row.innerHTML = `
            <td style="color:var(--text-muted); font-size:0.8rem;">${date}</td>
            <td><code>${ev.src_ip}</code></td>
            <td><code>${ev.dest_ip}</code></td>
            <td style="font-weight:600;">${ev.type}</td>
            <td>${subtypeText}</td>
            <td>${sources}</td>
            <td class="${sevClass}">${sevText}</td>
            <td style="color:var(--text-muted);">${ev.confidence ? (ev.confidence * 100).toFixed(0) + '%' : '---'}</td>
        `;
        tableBody.appendChild(row);
    });
}

function renderTimeline(timelineData) {
    if (!timelineData || timelineData.length === 0) return;
    const filter = document.getElementById('timelineFilter').value.toLowerCase();
    
    // Dynamic color based on filter
    const clr = filter === 'dos' ? COLORS.blue : filter === 'sqli' ? COLORS.purple : filter === 'recon' ? COLORS.yellow : COLORS.red;
    timelineChart.data.datasets[0].borderColor = clr;
    timelineChart.data.datasets[0].backgroundColor = clr + '22'; // 22 is hex alpha for ~15%

    timelineChart.data.labels = timelineData.map(t => t.time);
    timelineChart.data.datasets[0].data = timelineData.map(t => t[filter] || 0);
    timelineChart.update();
}

function renderHeat(types, total) {
    const container = document.getElementById('heatIndicatorContainer');
    if (total === 0) { container.innerHTML = "<span class='text-muted'>System nominal. No attacks recorded.</span>"; return; }
    let html = '';
    for (const [t, count] of Object.entries(types)) {
        const ratio = count / total;
        const pct = (ratio * 100).toFixed(1);
        html += `
            <div class="heat-row">
                <div class="heat-label">${t}</div>
                <div class="heat-bar-container">
                    <div class="heat-bar-fill" style="width: ${pct}%"></div>
                </div>
                <div class="heat-value">${pct}%</div>
            </div>
        `;
    }
    container.innerHTML = html;
}

function showModal(ev) {
    const modal = document.getElementById('signatureModal');
    const details = document.getElementById('modalDetails');
    const sources = ev.detected_by.map(s => `<span class="tag ${s.toLowerCase()}">${s}</span>`).join(' ');
    
    details.innerHTML = `
        <div class="info-grid">
            <div class="info-box">
                <span class="info-label">Source Node</span>
                <code style="font-size:1.1rem; padding:0; background:none;">${ev.src_ip}</code>${ev.src_port ? `<span class="text-muted">:${ev.src_port}</span>` : ''}
            </div>
            <div class="info-box">
                <span class="info-label">Target Node</span>
                <code style="font-size:1.1rem; padding:0; background:none;">${ev.dest_ip}</code>${ev.dest_port ? `<span class="text-muted">:${ev.dest_port}</span>` : ''}
            </div>
        </div>
        
        <div style="margin-bottom:1.5rem;">
            <span class="info-label">Detection Engines</span>
            <div style="margin-top:0.5rem;">${sources}</div>
        </div>
        
        <div class="info-box" style="margin-bottom:1.5rem;">
            <span class="info-label">Attack Categorization</span>
            <div style="font-size:1.1rem; color:var(--accent-purple); font-weight:600;">${ev.category || 'Unclassified Anomaly'}</div>
        </div>

        <div class="info-box" style="margin-bottom:1.5rem;">
            <span class="info-label">Signature Alias</span>
            <div style="font-size:1.1rem; color:var(--accent-cyan); font-family:var(--font-mono);">${ev.signature || 'N/A'}</div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid var(--border-light); padding-top:1.5rem;">
            <span class="info-label" style="margin:0;">AI Confidence Score</span>
            <span style="font-size:1.2rem; color:var(--accent-amber); font-weight:700;">${ev.confidence ? (ev.confidence * 100).toFixed(0) + '%' : 'N/A'}</span>
        </div>
    `;
    modal.classList.add('active');
}

// Navigation Logic
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Remove active class
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        document.querySelectorAll('.page').forEach(page => {
            page.classList.remove('active');
            page.classList.remove('fade-enter');
        });
        
        // Set active class
        item.classList.add('active');
        
        // Show target page with animation
        const targetId = item.getAttribute('data-target');
        const targetPage = document.getElementById(targetId);
        targetPage.classList.add('active');
        
        // Trigger reflow to restart animation
        void targetPage.offsetWidth; 
        targetPage.classList.add('fade-enter');
        
        // Update Title
        document.getElementById('pageTitle').innerText = item.innerText.toUpperCase();
    });
});

// Filter Listeners
document.getElementById('filterType').addEventListener('change', renderTable);
document.getElementById('filterSeverity').addEventListener('change', renderTable);
document.getElementById('timelineFilter').addEventListener('change', () => renderTimeline(currentTimeline));

// Init
fetchData();
setInterval(fetchData, 2000);
