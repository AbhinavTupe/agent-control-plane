import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from hooks import client as hook_client
from server import adapters, main as main_module
from server.main import app
from server.policy import Verdict


@pytest.mark.parametrize(
    ("agent", "payload", "expected"),
    [
        (
            "cursor",
            {
                "command": "git status",
                "cwd": "C:\\repo",
                "conversation_id": "cursor-session",
                "hook_event_name": "beforeShellExecution",
            },
            ("cursor", "cursor-session", "C:\\repo", "git status"),
        ),
        (
            "antigravity",
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git status", "Cwd": "C:\\repo"},
                },
                "conversationId": "gravity-session",
            },
            ("antigravity", "gravity-session", "C:\\repo", "git status"),
        ),
        (
            "codex",
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "cwd": "C:\\repo",
                "session_id": "codex-session",
            },
            ("codex", "codex-session", "C:\\repo", "git status"),
        ),
    ],
)
def test_adapter_parsers_normalize_supported_shell_payloads(agent, payload, expected):
    call = adapters.ADAPTERS[agent].parse(payload)

    assert (call.agent, call.session_id, call.cwd, call.command) == expected


@pytest.mark.parametrize(
    ("agent", "payload"),
    [
        ("cursor", {"command": "git status", "cwd": 1}),
        ("antigravity", {"toolCall": {"name": "open_file", "args": {}}}),
        ("codex", {"hook_event_name": "PreToolUse", "tool_name": "Read"}),
        ("codex", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": []}),
    ],
)
def test_adapter_parsers_abstain_on_malformed_or_unsupported_payloads(agent, payload):
    assert adapters.ADAPTERS[agent].parse(payload) is None


def test_adapter_renderers_follow_agent_reply_shapes():
    assert adapters.ADAPTERS["cursor"].render("deny", "reason") == {
        "permission": "deny",
        "user_message": "reason",
        "agent_message": "reason",
    }
    assert adapters.ADAPTERS["antigravity"].render("allow", None) == {
        "decision": "allow",
    }
    assert adapters.ADAPTERS["codex"].render("allow", None) is None
    assert adapters.ADAPTERS["codex"].render("deny", "reason") == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "reason",
        }
    }


@pytest.mark.parametrize(
    ("agent", "decision", "reason", "expected"),
    [
        ("cursor", "allow", None, {"permission": "allow"}),
        ("cursor", "deny", "reason", {
            "permission": "deny",
            "user_message": "reason",
            "agent_message": "reason",
        }),
        ("cursor", "ask", "reason", {
            "permission": "ask",
            "user_message": "reason",
            "agent_message": "reason",
        }),
        ("antigravity", "allow", None, {"decision": "allow"}),
        ("antigravity", "deny", "reason", {"decision": "deny", "reason": "reason"}),
        ("antigravity", "ask", "reason", {"decision": "ask", "reason": "reason"}),
        ("codex", "allow", None, None),
        ("codex", "deny", "reason", {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "reason",
            }
        }),
        ("codex", "ask", "reason", None),
    ],
)
def test_adapter_renderers_handle_every_verdict(agent, decision, reason, expected):
    assert adapters.ADAPTERS[agent].render(decision, reason) == expected


class _Pool:
    def __init__(self):
        self.calls = []

    @asynccontextmanager
    async def connection(self):
        yield self

    async def execute(self, query, params=()):
        self.calls.append((query, params))


@asynccontextmanager
async def _no_database_lifespan(_app):
    yield


@pytest.mark.parametrize(
    ("agent", "path", "payload", "expected"),
    [
        (
            "cursor",
            "/hook/cursor",
            {
                "command": "git status",
                "cwd": "C:\\repo",
                "conversation_id": "cursor-session",
                "hook_event_name": "beforeShellExecution",
            },
            {
                "permission": "deny",
                "user_message": "policy reason",
                "agent_message": "policy reason",
            },
        ),
        (
            "antigravity",
            "/hook/antigravity",
            {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "git status", "Cwd": "C:\\repo"},
                },
                "conversationId": "gravity-session",
            },
            {"decision": "deny", "reason": "policy reason"},
        ),
        (
            "codex",
            "/hook/codex",
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "cwd": "C:\\repo",
                "session_id": "codex-session",
            },
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "policy reason",
                }
            },
        ),
    ],
)
def test_adapter_endpoint_uses_shared_permission_flow(
    monkeypatch, agent, path, payload, expected
):
    pool = _Pool()
    calls = []
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)
    monkeypatch.setattr(app.state, "pool", pool, raising=False)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)

    async def permission(request, normalized, session_id, **kwargs):
        calls.append((normalized, session_id, kwargs))
        return kwargs["response"]("deny", "policy reason")

    monkeypatch.setattr("server.main._permission", permission)
    with TestClient(app) as test_client:
        response = test_client.post(path, json=payload)

    assert response.status_code == 200
    assert response.json() == expected
    normalized, session_id, kwargs = calls[0]
    assert normalized["tool_input"] == {"command": "git status"}
    assert normalized["cwd"] == "C:\\repo"
    assert session_id == payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId")
    assert kwargs["agent"] == agent
    assert kwargs["classification_tool"] == "UnknownShell"
    assert kwargs["repo_cwd"] == "C:\\repo"
    assert len(pool.calls) == 2
    assert pool.calls[0][1][1] == agent


@pytest.mark.parametrize(
    ("path", "payload", "expected"),
    [
        (
            "/hook/cursor",
            b"{",
            {
                "permission": "deny",
                "user_message": "Invalid hook payload",
                "agent_message": "Invalid hook payload",
            },
        ),
        (
            "/hook/antigravity",
            json.dumps({"toolCall": {"name": "open_file", "args": {}}}).encode(),
            {"decision": "ask", "reason": "Agent Control Plane unreachable"},
        ),
        ("/hook/codex", b"{", None),
    ],
)
def test_adapter_endpoint_fails_safe_for_bad_json_or_non_shell(
    monkeypatch, path, payload, expected
):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)
    with TestClient(app) as test_client:
        response = test_client.post(path, content=payload)

    assert response.status_code == 200
    if expected is None:
        assert response.content == b""
    else:
        assert response.json() == expected


class _MemoryResult:
    def __init__(self, row=None, rows=None, rowcount=0):
        self.row = row
        self.rows = rows or []
        self.rowcount = rowcount

    async def fetchone(self):
        return self.row

    async def fetchall(self):
        return self.rows


class _MemoryPool:
    def __init__(self):
        self.approval = None
        self.approval_ready = threading.Event()

    @asynccontextmanager
    async def connection(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, query, params=()):
        if query.startswith("INSERT INTO approvals"):
            self.approval = {
                "id": 1,
                "status": params[5],
                "reason": params[7],
            }
            self.approval_ready.set()
            return _MemoryResult({"id": 1})
        if query.startswith("SELECT status, reason FROM approvals"):
            return _MemoryResult(dict(self.approval))
        if query.startswith("UPDATE approvals SET status"):
            if self.approval and self.approval["status"] == "pending":
                self.approval["status"] = params[0]
                self.approval["reason"] = params[1]
                return _MemoryResult({"id": 1}, rowcount=1)
            return _MemoryResult()
        return _MemoryResult(rowcount=0)


_ENDPOINTS = {
    "cursor": (
        "/hook/cursor",
        lambda command: {
            "command": command,
            "cwd": "C:\\repo",
            "conversation_id": "session-cursor",
            "hook_event_name": "beforeShellExecution",
        },
    ),
    "antigravity": (
        "/hook/antigravity",
        lambda command: {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": command, "Cwd": "C:\\repo"},
            },
            "conversationId": "session-antigravity",
        },
    ),
    "codex": (
        "/hook/codex",
        lambda command: {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": "C:\\repo",
            "session_id": "session-codex",
        },
    ),
}


def _expected_adapter_body(agent, decision, reason=None):
    if agent == "cursor":
        if decision == "allow":
            return {"permission": "allow"}
        return {
            "permission": decision,
            "user_message": reason or "",
            "agent_message": reason or "",
        }
    if agent == "antigravity":
        if decision == "allow":
            return {"decision": "allow"}
        return {"decision": decision, "reason": reason or ""}
    if decision == "deny":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason or "",
            }
        }
    return None


@pytest.mark.parametrize("agent", ["codex", "cursor", "antigravity"])
@pytest.mark.parametrize(
    "scenario", ["allow", "deny", "human_allow", "human_deny", "unknown"]
)
def test_adapter_endpoints_run_real_permission_flow(monkeypatch, agent, scenario):
    path, payload_for = _ENDPOINTS[agent]
    pool = _MemoryPool()
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)
    monkeypatch.setattr(app.state, "pool", pool, raising=False)
    monkeypatch.setattr(main_module, "_schedule_notification", lambda _app: None)
    monkeypatch.setattr(main_module, "_schedule_task", lambda _app, task: task.close())
    monkeypatch.setattr(main_module, "schedule_human_decision", lambda _decision: None)
    monkeypatch.setattr(main_module, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(main_module, "WAIT_SECONDS", 2)

    command = {
        "allow": "git status",
        "deny": "vssadmin delete shadows /all /quiet",
        "human_allow": "git status > out.txt",
        "human_deny": "git status > out.txt",
        "unknown": "git status",
    }[scenario]
    if scenario == "unknown":
        monkeypatch.setattr(
            main_module, "classify_bash",
            lambda _command: Verdict("allow", "low", "bash allows"),
        )
        monkeypatch.setattr(
            main_module, "classify_powershell",
            lambda _command: Verdict("deny", "high", "powershell denies"),
        )

    with TestClient(app) as test_client:
        if scenario.startswith("human_"):
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(
                    test_client.post, path, json=payload_for(command)
                )
                assert pool.approval_ready.wait(timeout=2)
                decision = "allow" if scenario == "human_allow" else "deny"
                decided = test_client.post(
                    f"/approvals/{pool.approval['id']}/decide",
                    json={"decision": decision, "reason": "human reason"},
                )
                assert decided.status_code == 200
                assert decided.json() == {
                    "id": 1,
                    "status": "allowed" if decision == "allow" else "denied",
                    "decided_count": 1,
                }
                response = pending.result(timeout=2)
            decision = "allow" if scenario == "human_allow" else "deny"
            reason = "human reason" if decision == "deny" else None
        else:
            response = test_client.post(path, json=payload_for(command))
            decision = "deny" if scenario in {"deny", "unknown"} else "allow"
            if scenario == "deny":
                reason = (
                    "Blocked by policy: "
                    + main_module._classify_unknown_shell(command).reason
                )
            elif scenario == "unknown":
                reason = "Blocked by policy: powershell denies"
            else:
                reason = None

    assert response.status_code == 200
    expected = _expected_adapter_body(agent, decision, reason)
    assert response.content == b"" if expected is None else response.json() == expected


@pytest.mark.parametrize(
    ("agent", "payload", "expected"),
    [
        (
            "cursor",
            b"{",
            {
                "permission": "deny",
                "user_message": "Invalid hook payload",
                "agent_message": "Invalid hook payload",
            },
        ),
        (
            "antigravity",
            b"{",
            {"decision": "ask", "reason": "Agent Control Plane unreachable"},
        ),
        ("codex", b"{", None),
        (
            "cursor",
            b'{"hook_event_name":"other"}',
            {
                "permission": "ask",
                "user_message": "Agent Control Plane unreachable",
            },
        ),
        (
            "antigravity",
            b'{"toolCall":{"name":"open_file","args":{}}}',
            {"decision": "ask", "reason": "Agent Control Plane unreachable"},
        ),
        (
            "codex",
            b'{"hook_event_name":"PreToolUse","tool_name":"Read"}',
            None,
        ),
    ],
)
def test_adapter_endpoints_return_exact_failsafe_for_bad_or_non_shell_payload(
    monkeypatch, agent, payload, expected
):
    path, _payload_for = _ENDPOINTS[agent]
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)
    with TestClient(app) as test_client:
        response = test_client.post(path, content=payload)

    assert response.status_code == 200
    if expected is None:
        assert response.content == b""
    else:
        assert response.json() == expected


@pytest.mark.parametrize("path", ["/hook/codex", "/hook/cursor", "/hook/antigravity"])
def test_adapter_routes_require_hook_token(monkeypatch, path):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setenv("ACP_TOKEN", "hook-secret")
    monkeypatch.setattr(app.router, "lifespan_context", _no_database_lifespan)

    with TestClient(app) as test_client:
        response = test_client.post(path, json={})

    assert response.status_code == 401
    assert response.json() == {"detail": "bad token"}


def test_unknown_shell_uses_strictest_verdict_from_both_shell_classifiers(monkeypatch):
    seen = []
    monkeypatch.setattr(
        main_module,
        "classify_bash",
        lambda command: (seen.append(("bash", command)) or Verdict("allow", "low", "bash")),
    )
    monkeypatch.setattr(
        main_module,
        "classify_powershell",
        lambda command: (seen.append(("powershell", command)) or Verdict("deny", "high", "powershell")),
    )

    verdict = main_module._classify_unknown_shell("danger")

    assert verdict == Verdict("deny", "high", "powershell")
    assert seen == [("bash", "danger"), ("powershell", "danger")]


class _Input:
    def __init__(self, value):
        self.buffer = io.BytesIO(value)


@pytest.mark.parametrize(
    ("agent", "response_body", "expected_stdout", "expected_exit"),
    [
        ("cursor", b'{"permission":"deny","user_message":"no","agent_message":"no"}', '{"permission":"deny","user_message":"no","agent_message":"no"}', 2),
        ("cursor", b"", '{"permission":"ask","user_message":"Agent Control Plane unreachable"}', 0),
        ("antigravity", b"", '{"decision":"ask","reason":"Agent Control Plane unreachable"}', 0),
        ("codex", b"", "", 0),
    ],
)
def test_shared_hook_client_prints_valid_fail_safe_or_server_response(
    monkeypatch, agent, response_body, expected_stdout, expected_exit
):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return response_body

    monkeypatch.setattr(hook_client.sys, "stdin", _Input(b'{"payload":true}'))
    stdout = io.StringIO()
    monkeypatch.setattr(hook_client.sys, "stdout", stdout)
    monkeypatch.setattr(hook_client.sys, "stderr", io.StringIO())
    monkeypatch.setattr(hook_client.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())

    assert hook_client.run(agent, "http://127.0.0.1/hook") == expected_exit
    assert stdout.getvalue() == expected_stdout
    if stdout.getvalue():
        json.loads(stdout.getvalue())


def test_shared_hook_client_unauthorized_uses_agent_failsafe(monkeypatch):
    import urllib.error

    monkeypatch.setattr(hook_client.sys, "stdin", _Input(b'{"payload":true}'))
    stdout = io.StringIO()
    monkeypatch.setattr(hook_client.sys, "stdout", stdout)
    monkeypatch.setattr(hook_client.sys, "stderr", io.StringIO())

    def unauthorized(*_args, **_kwargs):
        raise urllib.error.HTTPError("url", 401, "Unauthorized", {}, None)

    monkeypatch.setattr(hook_client.urllib.request, "urlopen", unauthorized)

    assert hook_client.run("cursor", "http://127.0.0.1/hook") == 0
    assert json.loads(stdout.getvalue()) == {
        "permission": "ask",
        "user_message": "Agent Control Plane unreachable",
    }


def test_cursor_hook_client_blocks_invalid_json_with_valid_json(monkeypatch):
    monkeypatch.setattr(hook_client.sys, "stdin", _Input(b"{"))
    stdout = io.StringIO()
    monkeypatch.setattr(hook_client.sys, "stdout", stdout)
    monkeypatch.setattr(hook_client.sys, "stderr", io.StringIO())

    assert hook_client.run("cursor", "http://127.0.0.1/hook") == 2
    assert json.loads(stdout.getvalue()) == {
        "permission": "deny",
        "user_message": "Invalid hook payload",
        "agent_message": "Invalid hook payload",
    }
