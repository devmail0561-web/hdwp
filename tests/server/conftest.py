# Copyright (c) 2026 M. TENDENG
import pytest
from starlette.testclient import TestClient
from hdwp.server.app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)
