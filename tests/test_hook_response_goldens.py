from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from server import main as main_module
from server.main import app


@pytest.mark.parametrize(
    ("renderer", "expected_allow", "expected_deny"),
    [
        (
            main_module.perm_response,
            {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"},
                }
            },
            {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "deny", "message": "golden reason"},
                }
            },
        ),
        (
            main_module.copilot_perm_response,
            {"permissionDecision": "allow"},
            {
                "permissionDecision": "deny",
                "permissionDecisionReason": "golden reason",
            },
        ),
    ],
)
def test_existing_hook_response_contracts(
    renderer, expected_allow, expected_deny
):
    assert renderer("allow") == expected_allow
    assert renderer("deny", "golden reason") == expected_deny


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/hook",
            {
                "session_id": "golden-claude",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
            },
        ),
        (
            "/hook/copilot",
            {
                "sessionId": "golden-copilot",
                "toolName": "bash",
                "toolArgs": {"command": "git status"},
            },
        ),
    ],
)
def test_existing_hook_endpoints_preserve_allow_deny_and_fallback(
    monkeypatch, path, payload
):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)
    monkeypatch.setattr(app.state, "pool", _NoopPool(), raising=False)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)

    async def permission(_request, _normalized, _sid, **kwargs):
        response = kwargs.get("response", main_module.perm_response)
        if _endpoint_result[0] == "allow":
            return response("allow")
        if _endpoint_result[0] == "deny":
            return response("deny", "golden reason")
        return {}

    monkeypatch.setattr("server.main._permission", permission)
    _endpoint_result = ["allow"]
    with TestClient(app) as client:
        assert client.post(path, json=payload).json() == (
            main_module.perm_response("allow")
            if path == "/hook"
            else main_module.copilot_perm_response("allow")
        )

        _endpoint_result[0] = "deny"
        assert client.post(path, json=payload).json() == (
            main_module.perm_response("deny", "golden reason")
            if path == "/hook"
            else main_module.copilot_perm_response("deny", "golden reason")
        )

        _endpoint_result[0] = "fallback"
        assert client.post(path, json=payload).json() == {}


@asynccontextmanager
async def _no_database_lifespan(_app):
    yield


class _NoopPool:
    class _Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def execute(self, *_args, **_kwargs):
            return None

    def connection(self):
        return self._Connection()


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/hook", {}),
        ("/hook/copilot", {}),
    ],
)
def test_existing_hook_endpoints_preserve_401(monkeypatch, path, payload):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setenv("ACP_TOKEN", "golden-secret")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)
    with TestClient(app) as client:
        response = client.post(path, json=payload)

    assert response.status_code == 401
    assert response.json() == {"detail": "bad token"}
