from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from server.main import PORT, app, require_token


@asynccontextmanager
async def no_database_lifespan(_app):
    yield


@pytest.fixture(autouse=True)
def allow_testclient_without_database(monkeypatch):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", no_database_lifespan)
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: None)


def test_dashboard_is_served_without_database():
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("host", [f"127.0.0.1:{PORT}", f"localhost:{PORT}"])
def test_local_host_is_accepted(host):
    with TestClient(app) as client:
        response = client.get("/", headers={"host": host})

    assert response.status_code == 200


def test_foreign_host_is_rejected():
    with TestClient(app) as client:
        response = client.get("/", headers={"host": "example.com"})

    assert response.status_code == 403


def test_foreign_origin_on_post_is_rejected():
    with TestClient(app) as client:
        response = client.post(
            "/does-not-exist",
            headers={"host": f"127.0.0.1:{PORT}", "origin": "http://example.com"},
        )

    assert response.status_code == 403


def test_same_origin_post_is_allowed():
    with TestClient(app) as client:
        response = client.post(
            "/does-not-exist",
            headers={
                "host": f"127.0.0.1:{PORT}",
                "origin": f"http://127.0.0.1:{PORT}",
            },
        )

    assert response.status_code == 404


def test_post_without_origin_is_allowed():
    with TestClient(app) as client:
        response = client.post(
            "/does-not-exist",
            headers={"host": f"127.0.0.1:{PORT}"},
        )

    assert response.status_code == 404
