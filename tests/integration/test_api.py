import requests

TOKEN = "af9ff608895efc542d80b608a24c13d2"
BASE = "http://localhost:8000"


def test_metrics():
    r = requests.get(
        f"{BASE}/metrics",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert "flows" in r.json()


def test_unauthorized():
    r = requests.get(f"{BASE}/metrics")
    assert r.status_code == 401


def test_reload():
    r = requests.post(
        f"{BASE}/control/reload",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "reloaded"


def test_start():
    r = requests.post(
        f"{BASE}/control/start",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "started"


def test_stop():
    r = requests.post(
        f"{BASE}/control/stop",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"
