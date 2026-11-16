from contextlib import asynccontextmanager

from fastapi.testclient import TestClient

from server.main import app, require_token


@asynccontextmanager
async def no_database_lifespan(_app):
    yield


def test_dashboard_is_served_without_database(monkeypatch):
    monkeypatch.setattr(app.router, "lifespan_context", no_database_lifespan)
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: None)

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
