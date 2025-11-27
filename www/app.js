const API_BASE = "http://localhost:8082";

// Session management
let sessionToken = localStorage.getItem("session_token");
let currentUser = localStorage.getItem("username");

// Check if user is logged in
if (sessionToken && currentUser) {
    showDashboard();
} else {
    showLoginModal();
}

// Login form handler
document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            const data = await response.json();
            sessionToken = data.token;
            currentUser = data.username;

            localStorage.setItem("session_token", sessionToken);
            localStorage.setItem("username", currentUser);

            hideLoginModal();
            showDashboard();
        } else {
            const error = await response.json();
            document.getElementById("login-error").textContent =
                error.error || "Credentials Invalid";
            document.getElementById("login-error").style.display = "block";
        }
    } catch (err) {
        document.getElementById("login-error").textContent = "Connection Error";
        document.getElementById("login-error").style.display = "block";
    }
});

// Logout handler
document.getElementById("logout-btn").addEventListener("click", async () => {
    try {
        await fetch(`${API_BASE}/logout`, {
            method: "POST",
            headers: { "X-Session-Token": sessionToken },
        });
    } catch (err) {
        console.error("Logout FAILED:", err);
    }
    // Clear local storage
    localStorage.removeItem("session_token");
    localStorage.removeItem("username");
    sessionToken = null;
    currentUser = null;

    showLoginModal();
    hideDashboard();
});

function showLoginModal() {
    document.getElementById("login-modal").style.display = "block";
    document.getElementById("user-bar").style.display = "none";
}
function hideLoginModal() {
    document.getElementById("login-modal").style.display = "none";
}
function showDashboard() {
    document.getElementById("user-bar").style.display = "block";
    document.getElementById(
        "username-display"
    ).textContent = `Current User: ${currentUser}`;

    // Start metric polling
    fetchMetrics();
    setInterval(fetchMetrics, 2000);
}

function hideDashboard() {
    document.querySelector("main").style.display = "none";
}

// Real-time Bandwidth Visualization and Live Data Integration
let bandwidthData = [];
const MAX_DATA_POINTS = 60;

// Initialize D3 chart
const margin = { top: 20, right: 30, bottom: 30, left: 60 };
const width = 800 - margin.left + margin.right;
const height = 300 - margin.top - margin.bottom;

const svg = d3.select("#bandwidth-chart")
    .append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("trandform", `translate(${margin.left},${margin.top})`);

// X, Y scales
const x = d3.scaleTime().range([0, width]);
const y = d3.scaleLinear().range([height, 0]);

// Line generator
const line = d3.line()
    .x(d => x(d.timestamp))
    .y(d => y(d.bytes_per_second));

// Append path for line
const path =  svg.append("path")
    .attr("class", "line")
    .attr("fill", "none")
    .attr("stroke", "#4CAF50")
    .attr("stroke-width", 2);

// Axes
const xAxis = svg.append("g")
    .attr("transform", `translate(0,${height})`);
const yAxis = svg.append("g");

// y-axis label
svg.append("text")
    .attr("transform", "rotate(-90")
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


    // Update line
    
    
    // Update axes
}

async function fetchMetrics() {
    if (!sessionToken) return;

    try {
        const response = await fetch(`${API_BASE}/metrics`, {
            headers: { "X-Session-Token": sessionToken },
        });

        if (response.status === 401) {
            // Session Exiped
            localStorage.removeItem("session_token");
            localStorage.removeItem("username");
            sessionToken = null;
            showLoginModal();
            hideDashboard();
            return;
        }

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();

        // Update status
        document.getElementById("status-text").textContent = "Connected";
        document.getElementById("status-text").style.color = "#4caf50";

        // Add data point
        const now = new Date().toLocaleTimeString();
        bandwidthData.push({ time: now, bytes: data.total_bytes || 0 });
        if (bandwidthData.length > 20) bandwidthData.shift();

        updateBandwidthChart();
    } catch (err) {
        console.error("Metrics fetch FAILED: ", err);
        document.getElementById("status-text").textContent = "DISCONNECTED";
        document.getElementById("status-text").style.color = "#f44336";
    }
}

function updateBandwidthChart() {
    const x = d3
        .scalePoint()
        .domain(bandwidthData.map((d) => d.time))
        .range([margin.left, svgWidth - margin.right]);

    const y = d3
        .scaleLinear()
        .domain([0, d3.max(bandwidthData, (d) => d.bytes) || 1])
        .range([svgHeight - margin.bottom, margin.top]);

    const line = d3
        .line()
        .x((d) => x(d.time))
        .y((d) => y(d.bytes));

    svg.select(".line")
        .datum(bandwidthData)
        .attr("fill", "none")
        .attr("stroke", "#4caf50")
        .attr("stroke-width", "2")
        .attr("d", line);

    svg.select(".x-axis").call(
        d3.axisBottom(x).tickValues(bandwidthData.map((d) => d.time))
    );

    svg.select(".y-axis").call(d3.axisLeft(y));
}
