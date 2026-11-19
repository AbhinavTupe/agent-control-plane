import asyncio
import sys
import uuid
from contextlib import contextmanager

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from server.main import DATABASE_URL, app


def _require_postgres():
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=2):
            pass
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres is unavailable: {exc}")


def _insert_approval(
    conn,
    session_id,
    cwd,
    tool_name,
    summary,
    status="pending",
    decided_by=None,
    embedding=None,
):
    conn.execute(
        "INSERT INTO sessions (id, agent, cwd, status) VALUES (%s, 'copilot', %s, 'waiting')",
        (session_id, cwd),
    )
    cur = conn.execute(
        "INSERT INTO approvals "
        "(session_id, tool_name, tool_input, summary, risk, status, decided_by, embedding) "
        "VALUES (%s, %s, %s, %s, 'low', %s, %s, %s::vector) RETURNING id",
        (session_id, tool_name, Jsonb({}), summary, status, decided_by, embedding),
    )
    return cur.fetchone()[0]


async def _skip_embedding_warmup():
    return None


@contextmanager
def _dashboard_client(monkeypatch, notifications):
    monkeypatch.setenv("ACP_ALLOW_TESTCLIENT", "1")
    monkeypatch.setattr("server.main._warm_embeddings", _skip_embedding_warmup)
    monkeypatch.setattr(
        "server.main._schedule_notification",
        lambda _app: notifications.append(True),
    )
    policy = asyncio.get_event_loop_policy()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        with TestClient(app) as client:
            yield client
    finally:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(policy)


def test_identical_approval_batch_is_scoped_and_only_decides_pending(monkeypatch):
    _require_postgres()
    prefix = "identical-" + uuid.uuid4().hex
    cwd = f"/tmp/{prefix}/repo"
    ids = {}
    with psycopg.connect(DATABASE_URL, connect_timeout=2, autocommit=True) as conn:
        ids["target"] = _insert_approval(conn, prefix + "-target", cwd, "Bash", "git status -sb")
        ids["same"] = _insert_approval(
            conn, prefix + "-same", cwd, "Bash", "  GIT   STATUS -sb  "
        )
        ids["different_cwd"] = _insert_approval(
            conn, prefix + "-different-cwd", cwd + "-other", "Bash", "git status -sb"
        )
        ids["different_command"] = _insert_approval(
            conn, prefix + "-different-command", cwd, "Bash", "git diff"
        )
        ids["question"] = _insert_approval(
            conn, prefix + "-question", cwd, "ask_user", "git status -sb"
        )
        single_cwd = cwd + "-single"
        ids["single_target"] = _insert_approval(
            conn, prefix + "-single-target", single_cwd, "Bash", "git log -1"
        )
        ids["single_other"] = _insert_approval(
            conn, prefix + "-single-other", single_cwd, "Bash", "GIT   LOG -1"
        )

    notifications = []
    try:
        with _dashboard_client(monkeypatch, notifications) as client:
            headers = {}
            pending = client.get(
                "/approvals?status=pending&limit=200", headers=headers
            ).json()
            by_id = {approval["id"]: approval for approval in pending}
            assert by_id[ids["target"]]["identical_count"] == 1
            assert by_id[ids["question"]]["identical_count"] == 0

            response = client.post(
                f"/approvals/{ids['target']}/decide",
                headers=headers,
                json={"decision": "allow", "apply_to_identical": True},
            )
            assert response.status_code == 200
            assert response.json()["decided_count"] == 2
            assert client.post(
                f"/approvals/{ids['target']}/decide",
                headers=headers,
                json={"decision": "deny", "apply_to_identical": True},
            ).status_code == 409

            single_response = client.post(
                f"/approvals/{ids['single_target']}/decide",
                headers=headers,
                json={"decision": "deny"},
            )
            assert single_response.status_code == 200
            assert single_response.json()["decided_count"] == 1

        with psycopg.connect(DATABASE_URL, connect_timeout=2) as conn:
            rows = conn.execute(
                "SELECT id, status, decided_by FROM approvals WHERE id = ANY(%s)",
                (list(ids.values()),),
            ).fetchall()
        statuses = {row[0]: (row[1], row[2]) for row in rows}

        assert statuses[ids["target"]] == ("allowed", "human")
        assert statuses[ids["same"]] == ("allowed", "human")
        for key in ("different_cwd", "different_command", "question", "single_other"):
            assert statuses[ids[key]][0] == "pending"
        assert statuses[ids["single_target"]] == ("denied", "human")
        assert len(notifications) == 2
    finally:
        with psycopg.connect(DATABASE_URL, connect_timeout=2, autocommit=True) as conn:
            conn.execute("DELETE FROM sessions WHERE id LIKE %s", (prefix + "-%",))


def test_similar_approvals_prioritize_humans_then_mark_seed_examples(monkeypatch):
    _require_postgres()
    prefix = "similar-" + uuid.uuid4().hex
    embedding = "[" + ",".join(["1"] + ["0"] * 383) + "]"
    ids = {}
    with psycopg.connect(DATABASE_URL, connect_timeout=2, autocommit=True) as conn:
        ids["query"] = _insert_approval(
            conn, prefix + "-query", f"/tmp/{prefix}", "Bash", "query", embedding=embedding
        )
        ids["human"] = _insert_approval(
            conn, prefix + "-human", f"/tmp/{prefix}", "Bash", "human example",
            status="allowed", decided_by="human", embedding=embedding,
        )
        for index in range(2):
            ids[f"seed{index}"] = _insert_approval(
                conn, f"{prefix}-seed-{index}", f"/tmp/{prefix}", "Bash",
                f"seed example {index}", status="denied", decided_by="seed",
                embedding=embedding,
            )

    try:
        with _dashboard_client(monkeypatch, []) as client:
            response = client.get(
                f"/approvals/{ids['query']}/similar?limit=3",
            )
        assert response.status_code == 200
        examples = response.json()
        assert len(examples) == 3
        assert examples[0]["id"] == ids["human"]
        assert examples[0]["example"] is False
        assert all(row["decided_by"] == "seed" and row["example"] is True for row in examples[1:])
    finally:
        with psycopg.connect(DATABASE_URL, connect_timeout=2, autocommit=True) as conn:
            conn.execute("DELETE FROM sessions WHERE id LIKE %s", (prefix + "-%",))
