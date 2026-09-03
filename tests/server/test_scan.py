def test_start_scan_without_session_returns_404(client):
    r = client.post("/api/scan/start")
    assert r.status_code == 404


def test_stop_scan_without_session_returns_404(client):
    r = client.post("/api/scan/stop")
    assert r.status_code == 404
