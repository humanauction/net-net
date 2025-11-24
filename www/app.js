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
            currentUser = data.user;

            localStorage.setItem("session_token", sessionToken);
            localStorage.setItem("username", currentUser);

            hideLoginModal();
            showDashboard();
        } else {
            const error = await response.json();
            document.getElementById("login-error").textContext =
                error.error || "Credentials Invalid";
            document.getElementById("login-error").style.display = "block";
        }
    } catch (err) {
        document.getElementById("login-error").textContext = "Connection Error";
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
    ).textContext = `Current User: ${currentUser}`;

    // Start metric polling
    fetchMetrics();
    setInterval(fetchMetrics, 2000);
}

function hideDashboard() {
    document.getElementById("main").style.display = "none";
}

// Bandwidth chart setup

// Update status

// Add data point
