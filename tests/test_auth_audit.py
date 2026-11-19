import csv
import io
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from server import main as main_module
from server.main import app


@asynccontextmanager
async def no_database_lifespan(_app):
    yield


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    async def fetchall(self):
        return self.rows


class FakePool:
    def __init__(self, audit_rows=None):
        self.audit_rows = audit_rows or []
        self.calls = []

    @asynccontextmanager
    async def connection(self):
        yield self

    async def execute(self, query, params=()):
        self.calls.append((query, params))
        if "ORDER BY a.created_at DESC, a.id DESC LIMIT %s OFFSET %s" in query:
            return FakeCursor(self.audit_rows)
        if query.startswith("WITH recent_sessions AS"):
            return FakeCursor()
        if query.startswith("SELECT * FROM sessions"):
            return FakeCursor()
        if query.startswith("SELECT a.id, a.session_id"):
            return FakeCursor()
        if query.startswith("SELECT a.tool_name, a.summary, s.cwd"):
            return FakeCursor()
        return FakeCursor()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", no_database_lifespan)
    pool = FakePool()
    monkeypatch.setattr(app.state, "pool", pool, raising=False)
    with main_module._auth_lock:
        main_module._sessions.clear()
        main_module._login_failures.clear()
    with TestClient(app) as test_client:
        yield test_client, pool
    with main_module._auth_lock:
        main_module._sessions.clear()
        main_module._login_failures.clear()


def _set_token(monkeypatch, token="test-secret"):
    monkeypatch.setenv("ACP_TOKEN", token)


def test_login_sets_cookie_and_cookie_or_header_protects_dashboard(client, monkeypatch):
    _set_token(monkeypatch)
    test_client, _pool = client

    assert test_client.get("/").status_code == 401
    assert test_client.get("/healthz").status_code == 401
    assert test_client.get("/agents").status_code == 401
    assert test_client.get("/audit").status_code == 401
    assert test_client.post("/approvals/1/decide", json={"decision": "deny"}).status_code == 401

    login = test_client.post("/login", json={"token": "test-secret"})
    assert login.status_code == 200
    cookie = login.headers["set-cookie"]
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()
    assert "path=/" in cookie.lower()
    assert "max-age=43200" in cookie.lower()
    assert "secure" not in cookie.lower()
    assert test_client.get("/").status_code == 200
    assert test_client.get("/healthz").status_code == 200
    assert test_client.get("/agents").status_code == 200
    assert test_client.get("/audit").status_code == 200
    assert test_client.get("/audit.csv").status_code == 200

    with TestClient(app) as header_client:
        assert header_client.get(
            "/agents", headers={"x-acp-token": "test-secret"}
        ).status_code == 200
        assert header_client.get(
            "/healthz", headers={"x-acp-token": "test-secret"}
        ).status_code == 200
        assert header_client.get(
            "/audit", headers={"x-acp-token": "test-secret"}
        ).status_code == 200


def test_login_secure_cookie_on_https(client, monkeypatch):
    _set_token(monkeypatch)
    _client, _pool = client
    with TestClient(app, base_url="https://127.0.0.1:8787") as https_client:
        response = https_client.post("/login", json={"token": "test-secret"})

    assert response.status_code == 200
    assert "secure" in response.headers["set-cookie"].lower()


def test_bad_login_rate_limit(client, monkeypatch):
    _set_token(monkeypatch)
    test_client, _pool = client

    for _ in range(5):
        response = test_client.post("/login", json={"token": "wrong-secret"})
        assert response.status_code == 401
        assert "wrong-secret" not in response.text
    assert test_client.post("/login", json={"token": "wrong-secret"}).status_code == 429


def test_logout_invalidates_session(client, monkeypatch):
    _set_token(monkeypatch)
    test_client, _pool = client
    assert test_client.post("/login", json={"token": "test-secret"}).status_code == 200
    assert test_client.get("/audit").status_code == 200

    logout = test_client.post("/logout")
    assert logout.status_code == 200
    assert "max-age=0" in logout.headers["set-cookie"].lower()
    assert test_client.get("/audit").status_code == 401


def test_hooks_keep_header_auth_and_do_not_accept_dashboard_cookie(client, monkeypatch):
    _set_token(monkeypatch)
    test_client, _pool = client

    async def permission(*_args, **_kwargs):
        return {}

    monkeypatch.setattr("server.main._permission", permission)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)
    test_client.post("/login", json={"token": "test-secret"})
    payload = {"sessionId": "auth-test", "toolName": "unknown", "toolArgs": {}}
    assert test_client.post("/hook/copilot", json=payload).status_code == 401
    assert test_client.post(
        "/hook/copilot",
        headers={"x-acp-token": "test-secret"},
        json=payload,
    ).status_code == 200


def test_token_source_prefers_environment_and_strips_file(tmp_path, monkeypatch):
    token_file = tmp_path / ".acp-token"
    token_file.write_text("  file-secret \t\nignored-second-line\n", encoding="utf-8")
    monkeypatch.setenv("ACP_TOKEN", "environment-secret")

    assert main_module._load_token(token_file) == "environment-secret"

    monkeypatch.delenv("ACP_TOKEN")
    assert main_module._load_token(token_file) == "file-secret"


def test_missing_token_file_disables_auth(client, tmp_path, monkeypatch):
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    monkeypatch.setattr(main_module, "TOKEN_FILE", tmp_path / ".acp-token")
    test_client, _pool = client

    assert main_module._load_token() == ""
    assert test_client.get("/agents").status_code == 200
    assert test_client.post("/login", json={"token": "anything"}).status_code == 404


def test_copilot_hook_accepts_token_from_file(client, tmp_path, monkeypatch):
    token_file = tmp_path / ".acp-token"
    token_file.write_text(" file-hook-secret \n", encoding="utf-8")
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    monkeypatch.setattr(main_module, "TOKEN_FILE", token_file)
    test_client, _pool = client

    async def permission(*_args, **_kwargs):
        return {}

    monkeypatch.setattr("server.main._permission", permission)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)
    response = test_client.post(
        "/hook/copilot",
        headers={"x-acp-token": "file-hook-secret"},
        json={"sessionId": "file-token-test", "toolName": "unknown", "toolArgs": {}},
    )

    assert response.status_code == 200


def test_hook_auth_rejection_warning_is_rate_limited(client, monkeypatch, caplog):
    _set_token(monkeypatch)
    test_client, _pool = client
    monkeypatch.setattr(main_module, "_last_hook_auth_warning", 0.0)

    assert test_client.post("/hook/copilot", json={}).status_code == 401
    assert test_client.post("/hook/copilot", json={}).status_code == 401

    warnings = [
        record for record in caplog.records
        if "hook request rejected: missing or invalid token" in record.message
    ]
    assert len(warnings) == 1


def test_unset_token_keeps_routes_open_and_disables_login(client, monkeypatch):
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    test_client, _pool = client

    assert test_client.get("/").status_code == 200
    assert test_client.get("/agents").status_code == 200
    assert test_client.get("/audit").status_code == 200
    assert test_client.post("/login", json={"token": "anything"}).status_code == 404


def test_audit_filters_pagination_and_literal_query_matching(client, monkeypatch):
    _set_token(monkeypatch)
    test_client, pool = client
    pool.audit_rows = [
        {
            "id": 8,
            "created_at": datetime(2026, 11, 19, tzinfo=timezone.utc),
            "agent": "copilot",
            "tool_name": "Bash",
            "command": "echo x%_ ' OR 1=1 --",
            "summary": "command summary",
            "risk": "high",
            "status": "denied",
            "decided_by": "human",
            "reason": "reviewed",
        },
        {"id": 7},
    ]
    response = test_client.get(
        "/audit",
        headers={"x-acp-token": "test-secret"},
        params={
            "since": "2026-11-01T00:00:00Z",
            "until": "2026-11-20T00:00:00Z",
            "agent": "copilot",
            "status": "denied",
            "risk": "high",
            "decided_by": "human",
            "q": "x%_ ' OR 1=1 --",
            "limit": 1,
            "offset": 4,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert [row["id"] for row in body["items"]] == [8]
    assert body["has_more"] is True
    assert body["offset"] == 4
    sql, params = pool.calls[-1]
    assert "ORDER BY a.created_at DESC, a.id DESC" in sql
    assert "OR 1=1" not in sql
    assert params[-4:] == ("%x\\%\\_ ' OR 1=1 --%", "%x\\%\\_ ' OR 1=1 --%", 2, 4)
    assert params[2:6] == ("copilot", "denied", "high", "human")


def test_audit_csv_neutralizes_formula_cells(client, monkeypatch):
    _set_token(monkeypatch)
    test_client, pool = client
    pool.audit_rows = [{
        "id": 1,
        "created_at": datetime(2026, 11, 19, tzinfo=timezone.utc),
        "agent": "@SUM(1,1)",
        "tool_name": "+tool",
        "command": "=1+1",
        "summary": "unused",
        "risk": "-risk",
        "status": "allowed",
        "decided_by": "human",
        "reason": "@cmd",
    }]

    response = test_client.get("/audit.csv", headers={"x-acp-token": "test-secret"})

    assert response.status_code == 200
    row = next(csv.reader(io.StringIO(response.text)))
    assert row == [
        "time", "agent", "tool", "command", "risk", "decision", "decided_by", "reason",
    ]
    values = next(csv.reader(io.StringIO(response.text.splitlines()[1])))
    assert values[1:] == ["'@SUM(1,1)", "'+tool", "'=1+1", "'-risk", "allowed", "human", "'@cmd"]
