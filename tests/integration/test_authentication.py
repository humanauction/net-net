import pytest
import requests
import time
import subprocess
import os
import signal
import yaml
import re


#  Test Configuration
BASE_URL = "https://localhost:8082"
CONFIG_PATH = "examples/sample-config.yaml"
DAEMON_PATH = "./build/netnet-daemon"


@pytest.fixture(scope="module")
def daemon_process():
    """Start daemon before test, stop daemon after"""
    # Kill exisiting daemon
    os.system("sudo pkill -9 netnet-daemon 2>/dev/null")
    time.sleep(1)

    # Start daemon
    proc = subprocess.Popen(
        ["sudo", DAEMON_PATH, "--config", CONFIG_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wait for daemon to start
    time.sleep(2)

    # Verify daemon is running
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        assert response.status_code in [200, 404], "Daemon not responding"
    except requests.exceptions.RequestException as e:
        proc.kill()
        pytest.fail(f"Daemon failed to start: {e}")

    yield proc

    # Clean up: daemon stop
    os.system("sudo pkill -9 netnet-daemon 2>/dev/null")
    proc.wait(timeout=5)


@pytest.fixture
def config_users():
    """Load valid users from config file."""
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
    return config['api']['users']


class TestAuthentication:
    """Integration testing for Authentication flow."""

    def test_login_with_valid_credentials(self, daemon_process, config_users):
        """Test POST /login with valid admin credentials."""
        admin_user = config_users[0]  # first user from config

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": admin_user['username'],
                "password": admin_user['password']
            },
            timeout=5
        )

        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}"
        )

        data = response.json()
        assert "token" in data, "Response missing 'token' field"
        assert "username" in data, "Response missing 'username' field"
        assert "expires_in" in data, "Response missing 'expires_in' field"

        # Validate token format (UUID v4)
        uuid_pattern = (
            r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
            r'[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        )
        assert re.match(uuid_pattern, data['token'], re.IGNORECASE), \
            f"Token is not valid UUID v4: {data['token']}"

        assert data['username'] == admin_user['username']
        assert data['expires_in'] == 3600  # see: sample-config.yaml

    def test_login_with_invalid_password(self, daemon_process, config_users):
        """Test POST /login with invalid password."""
        admin_user = config_users[0]

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": admin_user['username'],
                "password": "wrongpassword"
            },
            timeout=5
        )

        assert response.status_code == 401, (
            f"expected 401, but got {response.status_code}"
        )

        data = response.json()

        assert "error" in data, "Response should contain error field"
        assert (
            "invalid" in data['error'].lower() or
            "unautorized" in data['error'].lower()
        )

    def test_login_with_nonexistent_user(self, daemon_process):
        """Test POST /login with user that doesnt exist."""
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "nonexistent",
                "password": "password123"
            },
            timeout=5
        )

        assert response.status_code == 401, (
            f"expected 401, but got {response.status_code}"
        )

        data = response.json()
        assert "error" in data

    def test_login_with_missing_username(self, daemon_process):
        """Test POST /login with missing username field."""
        response = requests.post(
            f"{BASE_URL}/login",
            json={"password": "password123"},
            timeout=5
        )

        assert response.status_code == 400, (
            f"expected 400, but got {response.status_code}"
        )

        data = response.json()
        assert "error" in data

    def test_login_with_missing_password(self, daemon_process, config_users):
        """Test POST /login with missing password field."""
        admin_user = config_users[0]

        response = requests.post(
            f"{BASE_URL}/login",
            json={"username": admin_user['username']},
            timeout=5
        )

        assert response.status_code == 400, (
            f"expected 400, but got {response.status_code}"
        )

        data = response.json()
        assert "error" in data

    def test_login_with_empty_credentials(self, daemon_process):
        """Test POST /login with empty username and password fields."""
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "",
                "password": ""
            },
            timeout=5
        )

        assert response.status_code in [400, 401], \
            f"expected 400 or 401, but got {response.status_code}"

    def test_authenticated_request_with_valid_token(self, daemon_process, config_users):
        """Test making Authenticated request with valid token."""
        # Login to get token
        admin_user = config_users[0]
        login_response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": admin_user['username'],
                "password": admin_user['password']
            },
            timeout=5
        )

        assert login_response.status_code == 200
        token = login_response.json()['token']

        # Make authenticated  request to /stats
        response = requests.get(
            f"{BASE_URL}/stats/",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5 
        )

        assert response.status_code == 200, \
        f"Expected 200, got {response.status_code}"

    def test_authenticated_request_with_invalid_token(self, daemon_process):
        """Test making authenticated request with invalid token."""
        response = requests.get(
            f"{BASE_URL}/stats/",
            headers={"Authorization": f"Bearer invalid-token-12345"},
            timeout=5 
        )

        assert response.status_code == 401, \
            f"expected 401, but got {response.status_code}"

    def test_authenticated_request_without_token(self, daemon_process):
        """Test making authenticated request without authorization header."""
        response = requests.get(f"BASE_URL/stats", timeout=5)

        assert response.status_code == 401, \
            f"expected 401, but got {response.status_code}"

    def test_multiple_logins_generate_unique_tokens(self, daemon_process, config_users):
        """Test that multiple logins generate unique tokens."""
        admin_user = config_users[0]

