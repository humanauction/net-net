import pytest
import requests
import time
import subprocess
import os

TOKEN = "af9ff608895efc542d80b608a24c13d2"
BASE = "http://localhost:8082"
CONFIG_PATH = "examples/sample-config.ci.yaml"
DAEMON_PATH = "./build/netnet-daemon"


@pytest.fixture(scope="module")
def daemon_process():
    """Start daemon before tests, stop after"""
    # Kill existing daemon
    os.system("sudo pkill -9 netnet-daemon 2>/dev/null")
    time.sleep(1)

    # Start daemon
    proc = subprocess.Popen(
        ["sudo", DAEMON_PATH, "--config", CONFIG_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wait for daemon to start with exponential backoff
    max_retries = 10
    for i in range(max_retries):
        time.sleep(0.5 * (i + 1))
        try:
            response = requests.get(f"{BASE}/", timeout=2)
            if response.status_code in [200, 404]:
                break
        except requests.exceptions.RequestException:
            if i == max_retries - 1:
                stdout, stderr = proc.communicate(timeout=1)
                proc.kill()
                pytest.fail(
                    f"Daemon failed to start after {max_retries} retries.\n"
                    f"STDOUT: {stdout.decode()}\n"
                    f"STDERR: {stderr.decode()}"
                )
            continue

    yield proc

    # Clean up
    os.system("sudo pkill -9 netnet-daemon 2>/dev/null")
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_metrics(daemon_process):
    r = requests.get(
        f"{BASE}/metrics",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert "active_flows" in r.json()


def test_unauthorized(daemon_process):
    r = requests.get(f"{BASE}/metrics")
    assert r.status_code == 401


def test_reload(daemon_process):
    r = requests.post(
        f"{BASE}/control/reload",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "reloaded"


def test_start(daemon_process):
    r = requests.post(
        f"{BASE}/control/start",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "started"


def test_stop(daemon_process):
    r = requests.post(
        f"{BASE}/control/stop",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"
