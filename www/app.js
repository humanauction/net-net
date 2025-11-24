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

// Bandwidth chart setup
let bandwidthData = [];
const svgWidth = 600,
    svgHeight = 300;
const margin = { top: 20, right: 20, bottom: 40, left: 50 };

const svg = d3
    .select("#bandwidth-chart")
    .append("svg")
    .attr("width", svgWidth)
    .attr("height", svgHeight);

svg.append("g")
    .attr("class", "x-axis")
    .attr("transform", `translate(0,${svgHeight - margin.bottom})`);
svg.append("g")
    .attr("class", "y-axis")
    .attr("transform", `translate(${margin.left}, 0)`);
svg.append("path").attr("class", "line");

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
