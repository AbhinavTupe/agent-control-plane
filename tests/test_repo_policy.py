import os
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from server.main import app, require_token
from server.policy import Verdict
from server.repo_policy import (
    RepoRules,
    _MISSING_WARNED,
    _RULE_CACHE,
    _parse_rules,
    apply_repo_rules,
    load_repo_rules,
)


@pytest.fixture(autouse=True)
def clear_repo_policy_cache():
    _RULE_CACHE.clear()
    _MISSING_WARNED.clear()


def test_missing_policy_file_keeps_rules_empty_and_warns(tmp_path, caplog):
    assert load_repo_rules(str(tmp_path)) == RepoRules()
    assert "no .acp-policy.yml found" in caplog.text


def test_missing_policy_warning_cache_is_capped(tmp_path):
    _MISSING_WARNED.update(f"missing-{index}" for index in range(200))

    load_repo_rules(str(tmp_path))

    assert len(_MISSING_WARNED) == 200


@pytest.mark.parametrize(
    "content",
    [
        "deny_contains: [\n",
        "deny_contains: not-a-list\n",
        "ask_contains:\n  - ''\n",
        "ask_contains:\n  - 42\n",
        "deny_contains:\n" + "".join(f"  - rule-{i}\n" for i in range(51)),
    ],
)
def test_malformed_or_invalid_policy_is_ignored(tmp_path, content, caplog):
    (tmp_path / ".acp-policy.yml").write_text(content, encoding="utf-8")

    assert load_repo_rules(str(tmp_path)) == RepoRules()
    assert "ignoring invalid repository policy" in caplog.text


def test_oversized_policy_is_ignored(tmp_path, caplog):
    (tmp_path / ".acp-policy.yml").write_bytes(b"#" + b"x" * (16 * 1024))

    assert load_repo_rules(str(tmp_path)) == RepoRules()
    assert "exceeds" in caplog.text


def test_deny_match_and_builtin_deny_cannot_be_weakened():
    rules = RepoRules(deny_contains=("terraform apply",), ask_contains=("status",))
    allowed = Verdict("allow", "low", "read-only or test command")
    built_in_deny = Verdict("deny", "high", "built-in reason")

    assert apply_repo_rules(allowed, "terraform apply now", rules) == Verdict(
        "deny", "high", "repo policy: contains 'terraform apply'"
    )
    assert apply_repo_rules(built_in_deny, "status", rules) == built_in_deny


def test_ask_match_downgrades_allow_only():
    rules = RepoRules(ask_contains=("npm publish",))
    allowed = Verdict("allow", "low", "read-only or test command")
    built_in_ask = Verdict("ask", "medium", "needs human review")

    assert apply_repo_rules(allowed, "npm publish", rules) == Verdict(
        "ask", "medium", "repo policy: contains 'npm publish'"
    )
    assert apply_repo_rules(built_in_ask, "npm publish", rules) == built_in_ask


def test_matching_is_case_insensitive():
    rules = RepoRules(deny_contains=("terraform apply",))

    assert apply_repo_rules(
        Verdict("allow", "low", "read-only or test command"),
        "TERRAFORM APPLY",
        rules,
    ).action == "deny"


def test_matching_normalizes_whitespace():
    rules = RepoRules(deny_contains=("terraform apply",))

    assert apply_repo_rules(
        Verdict("allow", "low", "read-only or test command"),
        "terraform   apply",
        rules,
    ).action == "deny"


def test_unknown_keys_are_ignored_and_rules_are_literal_substrings():
    policy = _parse_rules(
        {"allow_contains": ["git push"], "deny_contains": ["git * --force"]}
    )
    allowed = Verdict("allow", "low", "read-only or test command")

    assert apply_repo_rules(allowed, "git push --force", policy) == allowed


def test_policy_is_found_in_parent_directory(tmp_path):
    repo = tmp_path / "repo"
    nested = repo / "src" / "module"
    nested.mkdir(parents=True)
    (repo / ".acp-policy.yml").write_text(
        "deny_contains: [git push --force]\n", encoding="utf-8"
    )

    assert load_repo_rules(str(nested)).deny_contains == ("git push --force",)


def test_policy_cache_refreshes_when_mtime_changes(tmp_path):
    policy_path = tmp_path / ".acp-policy.yml"
    policy_path.write_text("deny_contains: [alpha]\n", encoding="utf-8")
    mtime = policy_path.stat().st_mtime_ns
    assert load_repo_rules(str(tmp_path)).deny_contains == ("alpha",)

    for rule in ("bravo", "charlie"):
        mtime += 2_000_000_000
        policy_path.write_text(f"deny_contains: [{rule}]\n", encoding="utf-8")
        os.utime(policy_path, ns=(mtime, mtime))
        assert load_repo_rules(str(tmp_path)).deny_contains == (rule,)

    path = str(policy_path.resolve())
    assert sum(key[0] == path for key in _RULE_CACHE) == 1


class FakeCursor:
    rowcount = 1

    def __init__(self, row=None):
        self.row = row or {"id": 17}

    async def fetchone(self):
        return self.row


class FakePool:
    def __init__(self):
        self.calls = []

    @asynccontextmanager
    async def connection(self):
        yield self

    async def execute(self, query, params=None):
        self.calls.append((query, params))
        if query.startswith("SELECT status, reason"):
            return FakeCursor({"status": "pending", "reason": None})
        return FakeCursor()


@asynccontextmanager
async def no_database_lifespan(_app):
    yield


@pytest.mark.parametrize(
    ("endpoint", "payload", "policy", "reason"),
    [
        (
            "/hook",
            {
                "session_id": "repo-policy-test",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "npm publish"},
                "cwd": "",
            },
            "deny_contains: [npm publish]\n",
            "repo policy: contains 'npm publish'",
        ),
        (
            "/hook/copilot",
            {
                "sessionId": "repo-policy-test",
                "toolName": "bash",
                "toolArgs": {"command": "npm publish"},
                "cwd": "",
            },
            "deny_contains: [npm publish]\n",
            "repo policy: contains 'npm publish'",
        ),
        (
            "/hook/copilot",
            {
                "sessionId": "repo-policy-read-test",
                "toolName": "view",
                "toolArgs": {"path": "restricted.txt"},
                "cwd": "",
            },
            "deny_contains: [restricted.txt]\n",
            "repo policy: contains 'restricted.txt'",
        ),
    ],
)
def test_hook_endpoints_apply_repo_policy(
    monkeypatch, tmp_path, endpoint, payload, policy, reason
):
    policy_path = tmp_path / ".acp-policy.yml"
    policy_path.write_text(policy, encoding="utf-8")
    payload["cwd"] = str(tmp_path)
    pool = FakePool()
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", no_database_lifespan)
    monkeypatch.setattr(app.state, "pool", pool, raising=False)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)
    monkeypatch.setattr(
        "server.main._schedule_task",
        lambda _app, coroutine: coroutine.close(),
    )
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: None)

    try:
        with TestClient(app) as client:
            response = client.post(endpoint, json=payload)
    finally:
        app.dependency_overrides.pop(require_token, None)

    assert response.status_code == 200
    if endpoint == "/hook":
        assert response.json()["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    else:
        assert response.json()["permissionDecision"] == "deny"
    approval_insert = next(
        params for query, params in pool.calls if query.startswith("INSERT INTO approvals")
    )
    assert approval_insert[5] == "denied"
    assert approval_insert[7] == reason


def test_hook_keeps_builtin_decision_if_repo_policy_raises(monkeypatch, tmp_path):
    def fail_load(_cwd):
        raise RuntimeError("policy read failed")

    pool = FakePool()
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", no_database_lifespan)
    monkeypatch.setattr(app.state, "pool", pool, raising=False)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)
    monkeypatch.setattr(
        "server.main._schedule_task",
        lambda _app, coroutine: coroutine.close(),
    )
    monkeypatch.setattr(
        "server.main.load_repo_rules",
        fail_load,
    )
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: None)

    try:
        with TestClient(app) as client:
            response = client.post(
                "/hook/copilot",
                json={
                    "sessionId": "repo-policy-failure-test",
                    "toolName": "bash",
                    "toolArgs": {"command": "git status"},
                    "cwd": str(tmp_path),
                },
            )
    finally:
        app.dependency_overrides.pop(require_token, None)

    assert response.status_code == 200
    assert response.json() == {"permissionDecision": "allow"}


def test_ask_user_message_is_not_checked_by_repo_rules(monkeypatch, tmp_path):
    pool = FakePool()
    policy_path = tmp_path / ".acp-policy.yml"
    policy_path.write_text("deny_contains: [do not reveal]\n", encoding="utf-8")
    load_calls = []

    def load_rules(cwd):
        load_calls.append(cwd)
        return RepoRules(deny_contains=("do not reveal",))

    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr(app.router, "lifespan_context", no_database_lifespan)
    monkeypatch.setattr(app.state, "pool", pool, raising=False)
    monkeypatch.setattr("server.main._schedule_notification", lambda _app: None)
    monkeypatch.setattr("server.main._schedule_task", lambda _app, coroutine: coroutine.close())
    monkeypatch.setattr("server.main.load_repo_rules", load_rules)
    monkeypatch.setattr("server.main.QUESTION_SECONDS", 0)
    monkeypatch.setitem(app.dependency_overrides, require_token, lambda: None)

    try:
        with TestClient(app) as client:
            response = client.post(
                "/hook/copilot",
                json={
                    "sessionId": "repo-policy-ask-user-test",
                    "toolName": "ask_user",
                    "toolArgs": {"message": "do not reveal"},
                    "cwd": str(tmp_path),
                },
            )
    finally:
        app.dependency_overrides.pop(require_token, None)

    assert response.status_code == 200
    assert response.json() == {}
    assert load_calls == []
    approval_insert = next(
        params for query, params in pool.calls if query.startswith("INSERT INTO approvals")
    )
    assert approval_insert[5] == "pending"
