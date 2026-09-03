def test_websocket_connects(client):
    with client.websocket_connect("/ws/events") as ws:
        pass


def test_websocket_multiple_connections(client):
    with client.websocket_connect("/ws/events") as ws1:
        with client.websocket_connect("/ws/events") as ws2:
            pass
