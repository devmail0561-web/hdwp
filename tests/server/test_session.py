def test_new_session_auto_mode(client):
    r = client.post("/api/session/new", json={
        "target_url": "https://example.com",
        "mode": "auto",
    })
    assert r.status_code == 200
    data = r.json()
    assert "session_id" in data
    assert data["status"] == "ready"
    assert data["target_url"] == "https://example.com"


def test_new_session_invalid_url_rejected(client):
    r = client.post("/api/session/new", json={
        "target_url": "not-a-url",
        "mode": "auto",
    })
    assert r.status_code == 422


def test_new_session_missing_url_rejected(client):
    r = client.post("/api/session/new", json={"mode": "auto"})
    assert r.status_code == 422


def test_get_state_without_session(client):
    r = client.get("/api/state")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "idle"


def test_get_findings_without_session(client):
    r = client.get("/api/findings")
    assert r.status_code == 200
    assert r.json() == []
