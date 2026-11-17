import asyncio
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from server.main import (
    DATABASE_URL,
    TOKEN,
    UPSERT_SESSION,
    app,
    compute_agent_state,
    copilot_hook,
    folder_name,
    list_agents,
)


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    async def fetchall(self):
        return self.rows


class FakePool:
    def __init__(self):
        self.calls = []

    @asynccontextmanager
    async def connection(self):
        yield self

    async def execute(self, query, params=None):
        self.calls.append((query, params))
        if "WITH recent_sessions AS" in query:
            return FakeCursor()
        return None


def fake_request(pool, payload=None):
    async def json():
        return payload

    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(pool=pool)),
        json=json,
    )


@pytest.mark.parametrize(
    ("tool_name", "expected_tool", "expected_classification"),
    [
        ("view", "Read", "Read"),
        ("rg", "Grep", "Grep"),
    ],
)
def test_copilot_hook_maps_read_only_tools(
    monkeypatch, tool_name, expected_tool, expected_classification,
):
    pool = FakePool()
    permission_calls = []

    async def allow_permission(*args, **kwargs):
        permission_calls.append((args, kwargs))
        return {}

    monkeypatch.setattr("server.main._permission", allow_permission)

    asyncio.run(
        copilot_hook(
            fake_request(
                pool,
                {"sessionId": "copilot-session", "toolName": tool_name, "cwd": "/repo"},
            )
        )
    )

    assert pool.calls[0] == (
        UPSERT_SESSION,
        ("copilot-session", "copilot", "/repo", None, "waiting"),
    )
    assert permission_calls[0][0][1]["tool_name"] == expected_tool
    assert permission_calls[0][1]["classification_tool"] == expected_classification
    assert "agent = EXCLUDED.agent" in UPSERT_SESSION


def test_agents_query_excludes_seed_session():
    pool = FakePool()

    asyncio.run(list_agents(fake_request(pool)))

    assert "WHERE id <> 'seed'" in pool.calls[0][0]


def test_agents_endpoint_with_postgres(monkeypatch):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=2):
            pass
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres is unavailable: {exc}")

    policy = asyncio.get_event_loop_policy()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        with TestClient(app) as client:
            response = client.get("/agents", headers={"x-acp-token": TOKEN})
    finally:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(policy)

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.parametrize(
    ("pending_count", "age_seconds", "expected"),
    [
        (1, 3600, "waiting"),
        (0, 0, "active"),
        (0, 59, "active"),
        (0, 60, "idle"),
        (0, 899, "idle"),
        (0, 900, "inactive"),
        (0, 86400, "inactive"),
    ],
)
def test_compute_agent_state(pending_count, age_seconds, expected):
    now = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
    last_seen_at = now - timedelta(seconds=age_seconds)

    assert compute_agent_state(pending_count, last_seen_at, now) == expected


@pytest.mark.parametrize(
    ("cwd", "expected"),
    [
        (r"C:\Users\dev\my-project", "my-project"),
        ("/home/dev/my-project", "my-project"),
        (None, "unknown"),
        ("", "unknown"),
        ("/", "unknown"),
    ],
)
def test_folder_name(cwd, expected):
    assert folder_name(cwd) == expected
