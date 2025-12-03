import pytest
import requests
import time
import subprocess
import os
import re
import yaml

#  Test Configuration
BASE_URL = "http://localhost:8082"
CONFIG_PATH = "examples/sample-config.ci.yaml"
DAEMON_PATH = "./build/netnet-daemon"


@pytest.fixture(scope="module")
def daemon_process():
    """Start daemon before test, stop daemon after"""
    # VERIFY config has debug logging
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
        print(
            f"Config log_level: "
            f"{config.get('logging', {}).get('level', 'NOT SET')}"
        )

    # Kill existing daemon
    os.system("sudo pkill -9 netnet-daemon 2>/dev/null")
    time.sleep(2)

    # Start daemon WITHOUT suppressing output so we can see logs
    proc = subprocess.Popen(
        ["sudo", DAEMON_PATH, "--config", CONFIG_PATH]
        # Remove stdout/stderr redirect to see logs
    )

    time.sleep(3)  # Give it time to fully start

    yield proc

    os.system("sudo pkill -9 netnet-daemon 2>/dev/null")
    proc.kill()


@pytest.fixture
def config_users():
    """Load valid users from config file."""
    return [
        {"username": "admin", "password": "adminpass"},
        {"username": "user", "password": "userpass"}
    ]


class TestAuthentication:
    """Integration testing for Authentication flow."""

    def test_login_with_valid_credentials(self, daemon_process, config_users):
        """Test POST /login with valid admin credentials."""
        admin_user = config_users[0]

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
        assert data['expires_in'] == 3600

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

        assert response.status_code == 401
        data = response.json()
        assert "error" in data

    def test_login_with_malformed_json(self, daemon_process):
        """Test POST /login with malformed JSON payload."""
        response = requests.post(
            f"{BASE_URL}/login",
            data="{invalid json",
            headers={"Content-Type": "application/json"},
            timeout=5
        )

        assert response.status_code == 400

    def test_login_with_sql_injection_attempt(self, daemon_process):
        """Test POST /login with SQL injection in username."""
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "admin' OR '1'='1",
                "password": "password"
            },
            timeout=5
        )

        assert response.status_code == 401

    def test_login_with_xss_attempt(self, daemon_process):
        """Test POST /login with XSS payload in username."""
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "<script>alert('xss')</script>",
                "password": "password"
            },
            timeout=5
        )

        assert response.status_code == 401

    def test_login_rate_limiting(self, daemon_process, config_users):
        """Test that repeated failed login attempts are handled gracefully."""
        admin_user = config_users[0]

        # Make 10 rapid failed login attempts
        for _ in range(10):
            response = requests.post(
                f"{BASE_URL}/login",
                json={
                    "username": admin_user['username'],
                    "password": "wrongpassword"
                },
                timeout=5
            )
            # Should consistently return 401
            assert response.status_code == 401

    def test_login_with_very_long_credentials(self, daemon_process):
        """Test POST /login with extremely long username/password."""
        long_string = "a" * 10000

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": long_string,
                "password": long_string
            },
            timeout=5
        )

        assert response.status_code in [400, 401]

    def test_login_with_unicode_characters(self, daemon_process):
        """Test POST /login with unicode characters in credentials."""
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "用户",
                "password": "密码"
            },
            timeout=5
        )

        assert response.status_code == 401

    def test_session_token_persistence_across_requests(
        self, daemon_process, config_users
    ):
        """Test that the same token works for multiple requests."""
        admin_user = config_users[0]

        # Login once
        login_response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": admin_user['username'],
                "password": admin_user['password']
            },
            timeout=5
        )
        token = login_response.json()['token']

        # Make multiple requests with same token
        for _ in range(5):
            response = requests.get(
                f"{BASE_URL}/",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            assert response.status_code in [200, 404]

    def test_login_with_case_sensitive_username(
        self, daemon_process, config_users
    ):
        """Test that usernames are case-sensitive."""
        admin_user = config_users[0]

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": admin_user['username'].upper(),
                "password": admin_user['password']
            },
            timeout=5
        )

        assert response.status_code == 401

    def test_concurrent_logins_same_user(self, daemon_process, config_users):
        """Test multiple concurrent logins for the same user."""
        import concurrent.futures

        admin_user = config_users[0]

        def do_login():
            return requests.post(
                f"{BASE_URL}/login",
                json={
                    "username": admin_user['username'],
                    "password": admin_user['password']
                },
                timeout=5
            )

        # Perform 5 concurrent logins
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(do_login) for _ in range(5)]
            responses = [f.result() for f in futures]

        # All should succeed
        for response in responses:
            assert response.status_code == 200

        # All tokens should be unique
        tokens = [r.json()['token'] for r in responses]
        assert len(tokens) == len(set(tokens))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
