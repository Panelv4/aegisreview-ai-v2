"""Test configuration — isolate the database before the app is imported."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="aegis_test_"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'test.db'}"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["SEED_DEMO"] = "true"
os.environ["ALLOW_REGISTRATION"] = "true"

# make the package importable when pytest is run from the repo root
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from aegis.api.app import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def demo_token(client) -> str:
    r = client.post("/api/auth/login", json={"email": "demo@aegis.dev", "password": "aegis-demo-2024"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def auth(demo_token):
    return {"Authorization": f"Bearer {demo_token}"}
