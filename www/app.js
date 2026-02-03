const API_BASE = "http://localhost:8082";

// Session management
let sessionToken = localStorage.getItem("session_token");
let currentUser = localStorage.getItem("username");
let metricsInterval;
let alertsHistory = [];
const MAX_ALERTS = 50;

// Alert thresholds (configurable)
const THRESHOLDS = {
    BANDWIDTH_SPIKE_MBPS: 100,      // Alert if > 100 MB/s
    DROP_RATE_WARNING: 1,           // Warning if > 1% drops
    DROP_RATE_CRITICAL: 5,          // Critical if > 5% drops
    FLOW_COUNT_WARNING: 500,        // Warning if > 500 flows
    SUSPICIOUS_PORTS: [23, 445, 3389, 4444, 5900, 6666, 31337]
};

// =====================================================
// BANDWIDTH CHART (D3.js)
// =====================================================
let bandwidthData = [];
const MAX_DATA_POINTS = 60;

const margin = { top: 10, right: 20, bottom: 20, left: 45 };
const width = 400 - margin.left - margin.right;
const height = 120 - margin.top - margin.bottom;

const svg = d3.select("#bandwidth-chart")
    .append("svg")
    .attr("viewBox", `0 0 ${width + margin.left + margin.right} ${height + margin.top + margin.bottom}`)
    .attr("preserveAspectRatio", "xMidYMid meet")
    .append("g")
    .attr("transform", `translate(${margin.left},${margin.top})`);

const x = d3.scaleTime().range([0, width]);
const y = d3.scaleLinear().range([height, 0]);

const line = d3.line()
    .curve(d3.curveMonotoneX)
    .x(d => x(d.timestamp))
    .y(d => y(d.bytes_per_second));

const area = d3.area()
    .curve(d3.curveMonotoneX)
    .x(d => x(d.timestamp))
    .y0(height)
    .y1(d => y(d.bytes_per_second));

svg.append("path")
    .attr("class", "area-fill")
    .attr("fill", "rgba(34, 197, 94, 0.1)");

const path = svg.append("path")
    .attr("class", "line")
    .attr("fill", "none")
    .attr("stroke", "#22c55e")
    .attr("stroke-width", 2);

const xAxis = svg.append("g")
    .attr("class", "axis")
    .attr("transform", `translate(0,${height})`);

const yAxis = svg.append("g")
    .attr("class", "axis");

function updateBandwidthChart(data) {
    const now = Date.now();
    const bps = data.bytes_per_second || 0;
    
    bandwidthData.push({ timestamp: now, bytes_per_second: bps });
    
    if (bandwidthData.length > MAX_DATA_POINTS) {
        bandwidthData.shift();
    }
    
    x.domain(d3.extent(bandwidthData, d => d.timestamp));
    y.domain([0, d3.max(bandwidthData, d => d.bytes_per_second) * 1.1 || 1000]);
    
    path.datum(bandwidthData)
        .transition()
        .duration(300)
        .attr("d", line);
    
    svg.select(".area-fill")
        .datum(bandwidthData)
        .transition()
        .duration(300)
        .attr("d", area);
    
    xAxis.transition().duration(300).call(
        d3.axisBottom(x).ticks(5).tickFormat(d3.timeFormat("%H:%M:%S"))
    );
    yAxis.transition().duration(300).call(
        d3.axisLeft(y).ticks(4).tickFormat(d => formatBytesShort(d))
    );
    
    // Check for bandwidth spike alert
    const mbps = bps / (1024 * 1024);
    if (mbps > THRESHOLDS.BANDWIDTH_SPIKE_MBPS) {
        addAlert('warning', `Bandwidth spike: ${formatBytes(bps)}/s`);
    }
}

// =====================================================
// PROTOCOL CHART (Chart.js)
// =====================================================
let protocolChart = null;

function updateProtocolChart(protocolData) {
    const ctx = document.getElementById('protocol-chart').getContext('2d');
    
    const data = {
        labels: Object.keys(protocolData),
        datasets: [{
            data: Object.values(protocolData),
            backgroundColor: ['#22c55e', '#4ade80', '#86efac', '#bbf7d0'],
            borderColor: '#000',
            borderWidth: 1
        }]
    };
    
    if (protocolChart) {
        protocolChart.data = data;
        protocolChart.update('none');
    } else {
        protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: { size: 10, family: 'inherit' },
                            padding: 8
                        }
                    }
                },
                cutout: '60%'
            }
        });
    }
}

// =====================================================
// PACKET SIZE CHART (Chart.js)
// =====================================================
let packetSizeChart = null;

function updatePacketSizeChart(sizeData) {
    const ctx = document.getElementById('packet-size-chart').getContext('2d');
    
    const labels = ['Tiny (≤64)', 'Small (65-128)', 'Medium (129-512)', 'Large (513-1024)', 'Jumbo (1025+)'];
    const values = [sizeData.tiny || 0, sizeData.small || 0, sizeData.medium || 0, sizeData.large || 0, sizeData.jumbo || 0];
    
    const data = {
        labels: labels,
        datasets: [{
            data: values,
            backgroundColor: ['#14532d', '#166534', '#15803d', '#16a34a', '#22c55e'],
            borderColor: '#000',
            borderWidth: 1
        }]
    };
    
    if (packetSizeChart) {
        packetSizeChart.data = data;
        packetSizeChart.update('none');
    } else {
        packetSizeChart = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: '#64748b', font: { size: 9 } },
                        grid: { color: '#1a1a1a' }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { size: 9 } },
                        grid: { display: false }
                    }
                }
            }
        });
    }
}

// =====================================================
// ALERTS PANEL
// =====================================================
function addAlert(level, message) {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
    
    // Prevent duplicate alerts within 10 seconds
    const recentDuplicate = alertsHistory.find(a => 
        a.message === message && (now - new Date(a.timestamp)) < 10000
    );
    if (recentDuplicate) return;
    
    const alert = {
        id: Date.now(),
        level: level, // 'critical', 'warning', 'info'
        message: message,
        timestamp: now.toISOString(),
        timeStr: timeStr
    };
    
    alertsHistory.unshift(alert);
    if (alertsHistory.length > MAX_ALERTS) {
        alertsHistory.pop();
    }
    
    renderAlerts();
}

function renderAlerts() {
    const container = document.getElementById('alerts-container');
    
    if (alertsHistory.length === 0) {
        container.innerHTML = '<div class="alert-empty">No alerts</div>';
        return;
    }
    
    container.innerHTML = alertsHistory.slice(0, 10).map(alert => `
        <div class="alert-item ${alert.level}">
            <span class="alert-time">${alert.timeStr}</span>
            <span class="alert-message">${alert.message}</span>
        </div>
    `).join('');
}

function checkAlerts(metrics, health) {
    // Check drop rate
    if (health && health.drop_rate > THRESHOLDS.DROP_RATE_CRITICAL) {
        addAlert('critical', `High packet drop rate: ${health.drop_rate.toFixed(2)}%`);
    } else if (health && health.drop_rate > THRESHOLDS.DROP_RATE_WARNING) {
        addAlert('warning', `Elevated packet drop rate: ${health.drop_rate.toFixed(2)}%`);
    }
    
    // Check flow count
    if (metrics && metrics.active_flows && metrics.active_flows.length > THRESHOLDS.FLOW_COUNT_WARNING) {
        addAlert('warning', `High connection count: ${metrics.active_flows.length} active flows`);
    }
    
    // Check for suspicious ports
    if (metrics && metrics.active_flows) {
        for (const flow of metrics.active_flows) {
            if (THRESHOLDS.SUSPICIOUS_PORTS.includes(flow.dst_port)) {
                addAlert('critical', `Suspicious port activity: ${flow.src_ip} → port ${flow.dst_port}`);
            }
        }
    }
}

// =====================================================
// TOP TALKERS
// =====================================================
function updateTopTalkers(data) {
    const maxBytes = Math.max(
        ...data.top_sources.map(s => s.bytes),
        ...data.top_destinations.map(d => d.bytes),
        1
    );
    
    document.getElementById('top-sources-list').innerHTML = data.top_sources.slice(0, 5).map((item, i) => `
        <div class="top-item">
            <span class="top-rank">${i + 1}</span>
            <span class="top-ip">${item.ip}</span>
            <span class="top-bytes">${formatBytes(item.bytes)}</span>
        </div>
        <div class="top-bar"><div class="top-bar-fill" style="width: ${(item.bytes / maxBytes * 100)}%"></div></div>
    `).join('') || '<div class="alert-empty">No data</div>';
    
    document.getElementById('top-destinations-list').innerHTML = data.top_destinations.slice(0, 5).map((item, i) => `
        <div class="top-item">
            <span class="top-rank">${i + 1}</span>
            <span class="top-ip">${item.ip}</span>
            <span class="top-bytes">${formatBytes(item.bytes)}</span>
        </div>
        <div class="top-bar"><div class="top-bar-fill" style="width: ${(item.bytes / maxBytes * 100)}%"></div></div>
    `).join('') || '<div class="alert-empty">No data</div>';
}

// =====================================================
// PORT ACTIVITY
// =====================================================
function updatePortActivity(ports) {
    document.getElementById('port-list').innerHTML = ports.slice(0, 10).map(port => `
        <div class="port-item">
            <span class="port-number">${port.port}</span>
            <span class="port-service">${port.service || '—'}</span>
            <span class="port-stats">${formatBytes(port.bytes)} · ${port.connections} conn</span>
        </div>
    `).join('') || '<div class="alert-empty">No data</div>';
}

// =====================================================
// SYSTEM HEALTH
// =====================================================
function updateSystemHealth(health) {
    document.getElementById('uptime').textContent = formatUptime(health.uptime_seconds);
    document.getElementById('packets-received').textContent = formatNumber(health.packets_received);
    document.getElementById('packets-dropped').textContent = formatNumber(health.packets_dropped);
    
    const dropRateEl = document.getElementById('drop-rate');
    dropRateEl.textContent = health.drop_rate.toFixed(2) + '%';
    dropRateEl.className = 'health-value' + 
        (health.drop_rate > THRESHOLDS.DROP_RATE_CRITICAL ? ' danger' : 
         health.drop_rate > THRESHOLDS.DROP_RATE_WARNING ? ' warning' : '');
    
    document.getElementById('interface-name').textContent = health.interface || '--';
    
    const statusEl = document.getElementById('capture-status');
    statusEl.textContent = health.capture_running ? 'Running' : 'Stopped';
    statusEl.className = 'health-value' + (health.capture_running ? '' : ' danger');
}

// =====================================================
// CONNECTIONS TABLE
// =====================================================
function updateConnectionsTable(flows) {
    const tbody = document.getElementById('connections-tbody');
    
    if (!flows || flows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7">No active connections</td></tr>';
        return;
    }
    
    tbody.innerHTML = flows.slice(0, 50).map(flow => `
        <tr>
            <td>${flow.src_ip}</td>
            <td>${flow.src_port}</td>
            <td>${flow.dst_ip}</td>
            <td>${flow.dst_port}</td>
            <td>${flow.protocol}</td>
            <td>${formatBytes(flow.bytes)}</td>
            <td>${flow.packets}</td>
        </tr>
    `).join('');
}

// =====================================================
// DATA FETCHING
// =====================================================
async function fetchWithAuth(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: { 'X-Session-Token': sessionToken }
    });
    
    if (response.status === 401) {
        handleSessionExpired();
        throw new Error('Session expired');
    }
    
    return response.json();
}

async function fetchMetrics() {
    try {
        const metrics = await fetchWithAuth('/metrics');
        
        document.getElementById('total-bytes').textContent = formatBytes(metrics.total_bytes);
        document.getElementById('total-packets').textContent = formatNumber(metrics.total_packets);
        document.getElementById('active-flows').textContent = metrics.active_flows?.length || 0;
        
        updateBandwidthChart(metrics);
        updateProtocolChart(metrics.protocol_breakdown || {});
        updateConnectionsTable(metrics.active_flows);
        
        document.getElementById('status-text').textContent = 'Connected';
        
        return metrics;
    } catch (error) {
        console.error('Error fetching metrics:', error);
        document.getElementById('status-text').textContent = 'Error';
    }
}

async function fetchTopTalkers() {
    try {
        const data = await fetchWithAuth('/api/top-talkers');
        updateTopTalkers(data);
    } catch (error) {
        console.error('Error fetching top talkers:', error);
    }
}

async function fetchPortStats() {
    try {
        const data = await fetchWithAuth('/api/port-stats');
        updatePortActivity(data);
    } catch (error) {
        console.error('Error fetching port stats:', error);
    }
}

async function fetchSystemHealth() {
    try {
        const data = await fetchWithAuth('/api/system-health');
        updateSystemHealth(data);
        return data;
    } catch (error) {
        console.error('Error fetching system health:', error);
    }
}

async function fetchPacketSizes() {
    try {
        const data = await fetchWithAuth('/api/packet-sizes');
        updatePacketSizeChart(data);
    } catch (error) {
        console.error('Error fetching packet sizes:', error);
    }
}

async function fetchAllData() {
    const [metrics, health] = await Promise.all([
        fetchMetrics(),
        fetchSystemHealth()
    ]);
    
    // Run these in parallel but don't block
    fetchTopTalkers();
    fetchPortStats();
    fetchPacketSizes();
    
    // Check for alerts based on current data
    checkAlerts(metrics, health);
}

function startMetricsPolling() {
    fetchAllData();
    metricsInterval = setInterval(fetchAllData, 2000);
}

function stopMetricsPolling() {
    if (metricsInterval) {
        clearInterval(metricsInterval);
        metricsInterval = null;
    }
}

// =====================================================
// AUTHENTICATION
// =====================================================
async function login(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('login-error');
    
    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        if (!response.ok) {
            throw new Error('Invalid credentials');
        }
        
        const data = await response.json();
        sessionToken = data.token;
        currentUser = data.username;
        
        localStorage.setItem('session_token', sessionToken);
        localStorage.setItem('username', currentUser);
        
        document.getElementById('login-modal').style.display = 'none';
        document.getElementById('user-bar').style.display = 'block';
        document.getElementById('username-display').textContent = `👤 ${currentUser}`;
        
        startMetricsPolling();
        addAlert('info', `User ${currentUser} logged in`);
        
    } catch (error) {
        errorEl.textContent = error.message;
        errorEl.style.display = 'block';
    }
}

async function logout() {
    try {
        await fetch(`${API_BASE}/logout`, {
            method: 'POST',
            headers: { 'X-Session-Token': sessionToken }
        });
    } catch (error) {
        console.error('Logout error:', error);
    }
    
    localStorage.removeItem('session_token');
    localStorage.removeItem('username');
    sessionToken = null;
    currentUser = null;
    
    stopMetricsPolling();
    
    document.getElementById('login-modal').style.display = 'block';
    document.getElementById('user-bar').style.display = 'none';
}

function handleSessionExpired() {
    addAlert('warning', 'Session expired, please log in again');
    logout();
}

// =====================================================
// UTILITY FUNCTIONS
// =====================================================
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatBytesShort(bytes) {
    if (bytes === 0) return '0';
    const k = 1024;
    const sizes = ['', 'K', 'M', 'G', 'T'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + sizes[i];
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num || 0);
}

function formatUptime(seconds) {
    if (!seconds) return '0s';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

// =====================================================
// INITIALIZATION
// =====================================================
window.addEventListener('DOMContentLoaded', () => {
    document.getElementById('login-form').addEventListener('submit', login);
    document.getElementById('logout-btn').addEventListener('click', logout);
    
    if (sessionToken) {
        document.getElementById('login-modal').style.display = 'none';
        document.getElementById('user-bar').style.display = 'block';
        document.getElementById('username-display').textContent = `👤 ${currentUser}`;
        startMetricsPolling();
    } else {
        document.getElementById('login-modal').style.display = 'block';
    }
    
    renderAlerts();
});
