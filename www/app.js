const API_BASE = "http://localhost:8082";

// Session management
let sessionToken = localStorage.getItem("session_token");
let currentUser = localStorage.getItem("username");
let metricsInterval;

// Real-time Bandwidth Visualization
let bandwidthData = [];
const MAX_DATA_POINTS = 60;

// Initialize D3 chart
const margin = { top: 20, right: 30, bottom: 30, left: 60 };
const width = 800 - margin.left - margin.right;
const height = 300 - margin.top - margin.bottom;

const svg = d3.select("#bandwidth-chart")
    .append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("transform", `translate(${margin.left},${margin.top})`);

// X, Y scales
const x = d3.scaleTime().range([0, width]);
const y = d3.scaleLinear().range([height, 0]);

// Line generator
const line = d3.line()
    .x(d => x(d.timestamp))
    .y(d => y(d.bytes_per_second));

// Append path for line
const path = svg.append("path")
    .attr("class", "line")
    .attr("fill", "none")
    .attr("stroke", "#4CAF50")
    .attr("stroke-width", 2);

// Axes
const xAxis = svg.append("g")
    .attr("transform", `translate(0,${height})`);
const yAxis = svg.append("g");

// Y-axis label
svg.append("text")
    .attr("transform", "rotate(-90)")
    .attr("y", 0 - margin.left)
    .attr("x", 0 - (height / 2))
    .attr("dy", "1em")
    .style("text-anchor", "middle")
    .text("Bytes/Second");

function updateBandwidthChart(data) {
    const now = Date.now();

    // Add new data point
    bandwidthData.push({
        timestamp: now,
        bytes_per_second: data.bytes_per_second || 0
    });

    // Retain last MAX_DATA_POINTS only
    if (bandwidthData.length > MAX_DATA_POINTS) {
        bandwidthData.shift();
    }

    // Update scales
    x.domain(d3.extent(bandwidthData, d => d.timestamp));
    y.domain([0, d3.max(bandwidthData, d => d.bytes_per_second) || 1000]);

    // Update line
    path.datum(bandwidthData)
        .transition()
        .duration(500)
        .attr("d", line);
    
    // Update axes
    xAxis.transition()
        .duration(500)
        .call(d3.axisBottom(x)
            .ticks(5)
            .tickFormat(d3.timeFormat("%H:%M:%S")));
            
    yAxis.transition()
        .duration(500)
        .call(d3.axisLeft(y)
            .ticks(5)
            .tickFormat(d => formatBytes(d)));
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]; // Fixed math
}

async function fetchMetrics() {
    try {
        const token = localStorage.getItem('session_token');
        const response = await fetch(`${API_BASE}/metrics`, {
            headers: { "X-Session-Token": token },
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                await logout();
                return; 
            }
            throw new Error('Metric fetch FAILED');
        }

        const data = await response.json();

        // Update bandwidth chart
        updateBandwidthChart(data);

        // Update stats display
        document.getElementById('total-bytes').textContent = formatBytes(data.total_bytes);
        document.getElementById('total-packets').textContent = data.total_packets.toLocaleString(); // Fixed method
        document.getElementById('active-flows').textContent = data.active_flows.length;
        
        // Update status
        document.getElementById("status-text").textContent = "Connected";
        document.getElementById("status-text").style.color = "#4caf50";
    } catch (error) {
        console.error("Metrics fetch FAILED: ", error);
        document.getElementById("status-text").textContent = "DISCONNECTED";
        document.getElementById("status-text").style.color = "#f44336";
    }
}

function startMetricsPolling() {
    fetchMetrics();
    metricsInterval = setInterval(fetchMetrics, 1000);
}

function stopMetricsPolling() {
    if (metricsInterval) {
        clearInterval(metricsInterval);
        metricsInterval = null;
    }
}

// Login handler
async function login(e) {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;   

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            sessionToken = data.token;
            currentUser = data.username;
            
            localStorage.setItem('session_token', sessionToken);
            localStorage.setItem('username', currentUser);

            document.getElementById('login-modal').style.display = 'none';
            document.getElementById('user-bar').style.display = 'block';
            document.getElementById('username-display').textContent = `Current User: ${currentUser}`;

            // Start metrics polling
            startMetricsPolling();
        } else {
            document.getElementById('login-error').textContent = data.error || 'Login FAILED';
            document.getElementById('login-error').style.display = 'block';
        }
    } catch (error) {
        document.getElementById('login-error').textContent = 'Network error';
        document.getElementById('login-error').style.display = 'block';
    }
}

// Logout handler
async function logout() {
    stopMetricsPolling();

    if (sessionToken) {
        try {
            await fetch(`${API_BASE}/logout`, {
                method: 'POST',
                headers: { 'X-Session-Token': sessionToken }
            });
        } catch (error) {
            console.error("Logout error:", error);
        }
    }

    localStorage.removeItem('session_token');
    localStorage.removeItem('username');
    sessionToken = null;
    currentUser = null;

    document.getElementById('login-modal').style.display = 'block';
    document.getElementById('user-bar').style.display = 'none';

    // Clear chart data
    bandwidthData = [];
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('session_token');
    const username = localStorage.getItem('username');

    if (token && username) {
        sessionToken = token;
        currentUser = username;
        
        document.getElementById('login-modal').style.display = 'none';
        document.getElementById('user-bar').style.display = 'block';
        document.getElementById('username-display').textContent = `Current User: ${currentUser}`;

        // Start metrics polling 
        startMetricsPolling();
    } else {
        document.getElementById('login-modal').style.display = 'block';
        document.getElementById('user-bar').style.display = 'none';
    }

    document.getElementById('login-form').addEventListener('submit', login);
    document.getElementById('logout-btn').addEventListener('click', logout);
});
