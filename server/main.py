"""Agent control plane, Step 1: hook receiver + approvals API on Postgres.

Flow for a PermissionRequest hook:
  classify -> allow/deny immediately, or park as 'pending' and wait for a human
  (POST /approvals/{id}/decide). On timeout or client disconnect we return {}
  so Claude Code falls back to its own native prompt (fail-safe, never auto-allow).
"""
from __future__ import annotations

import asyncio
import csv
import hmac
import io
import json
import logging
import os
import secrets
import threading
import time
from collections import Counter, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel, Field

from .embed import embed, to_pgvector
from .events import EventBroadcaster, listen_for_events, notify_changed
from .notify import (
    DecisionNotification,
    log_enabled_channels,
    schedule_human_decision,
)
from .policy import (
    classify,
    question_answer_reply,
    question_declined_reply,
    parse_question_fields,
    question_summary,
    summarize,
)
from .repo_policy import apply_repo_rules, load_repo_rules

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://acp:acp@127.0.0.1:5435/acp")
TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"


def _load_token(token_file: Path | None = None) -> str:
    environment_token = os.getenv("ACP_TOKEN", "")
    if environment_token:
        return environment_token
    try:
        with (token_file or TOKEN_FILE).open(encoding="utf-8") as token_stream:
            return token_stream.readline().strip()
    except FileNotFoundError:
        return ""


WAIT_SECONDS = float(os.getenv("ACP_WAIT_SECONDS", "45"))  # keep below the hook timeout
QUESTION_SECONDS = float(os.getenv("ACP_QUESTION_SECONDS", "50"))
SIM_MIN = float(os.getenv("ACP_SIM_MIN", "0.80"))
PORT = int(os.getenv("ACP_PORT", "8787"))
POLL_SECONDS = 0.5
SESSION_TTL_SECONDS = 12 * 60 * 60
LOGIN_FAILURE_WINDOW_SECONDS = 60
LOGIN_FAILURE_LIMIT = 5
logger = logging.getLogger(__name__)
_sessions: dict[str, float] = {}
_login_failures: dict[str, deque[float]] = {}
_auth_lock = threading.Lock()
_hook_auth_warning_lock = threading.Lock()
_last_hook_auth_warning: float | None = None

UPSERT_SESSION = """
INSERT INTO sessions (id, agent, cwd, model, status) VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (id) DO UPDATE SET
  agent = EXCLUDED.agent,
  cwd = COALESCE(EXCLUDED.cwd, sessions.cwd),
  model = COALESCE(EXCLUDED.model, sessions.model),
  status = EXCLUDED.status,
  last_seen_at = now()
"""


def folder_name(cwd: str | None) -> str:
    if not cwd:
        return "unknown"
    folder = cwd.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1]
    return folder or "unknown"


def _normalized_summary(summary: str) -> str:
    return " ".join(summary.split()).casefold()


def compute_agent_state(
    pending_count: int,
    last_seen_at: datetime,
    now: datetime | None = None,
) -> str:
    if pending_count > 0:
        return "waiting"
    elapsed = (now or datetime.now(timezone.utc)) - last_seen_at
    if elapsed.total_seconds() < 60:
        return "active"
    if elapsed.total_seconds() < 15 * 60:
        return "idle"
    return "inactive"


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_enabled_channels()
    pool = AsyncConnectionPool(
        DATABASE_URL, min_size=1, max_size=10, open=False,
        kwargs={"row_factory": dict_row, "autocommit": True},
    )
    await pool.open(wait=True, timeout=10)
    app.state.pool = pool
    app.state.background_tasks = set()
    app.state.event_broadcaster = EventBroadcaster()
    app.state.event_listener_task = asyncio.create_task(
        listen_for_events(DATABASE_URL, app.state.event_broadcaster)
    )
    _schedule_task(app, _warm_embeddings())
    yield
    app.state.event_listener_task.cancel()
    await asyncio.gather(app.state.event_listener_task, return_exceptions=True)
    if app.state.background_tasks:
        await asyncio.gather(*app.state.background_tasks, return_exceptions=True)
    await pool.close()


def _schedule_task(app: FastAPI, coroutine) -> None:
    task = asyncio.create_task(coroutine)
    app.state.background_tasks.add(task)
    task.add_done_callback(app.state.background_tasks.discard)


def _schedule_notification(app: FastAPI) -> None:
    _schedule_task(app, notify_changed(app.state.pool))


async def _warm_embeddings() -> None:
    try:
        await asyncio.to_thread(embed, "warmup")
    except Exception as exc:
        logger.warning(
            "embedding model warmup failed: %s",
            (str(exc).splitlines() or [type(exc).__name__])[0],
        )


async def _embed_approval(pool: AsyncConnectionPool, aid: int, text: str) -> None:
    try:
        vector = await asyncio.to_thread(embed, text)
        async with pool.connection() as conn:
            await conn.execute(
                "UPDATE approvals SET embedding = %s::vector WHERE id = %s",
                (to_pgvector(vector), aid),
            )
        await notify_changed(pool)
    except Exception as exc:
        logger.warning(
            "approval embedding failed: %s",
            (str(exc).splitlines() or [type(exc).__name__])[0],
        )


def _valid_session(session_id: str | None) -> bool:
    if not session_id:
        return False
    now = time.monotonic()
    with _auth_lock:
        expiry = _sessions.get(session_id)
        if expiry is None:
            return False
        if expiry <= now:
            del _sessions[session_id]
            return False
        return True


def _has_dashboard_auth(
    request: Request,
    configured_token: str | None = None,
) -> bool:
    expected_token = _load_token() if configured_token is None else configured_token
    request_token = request.headers.get("x-acp-token", "")
    return bool(
        (expected_token and secrets.compare_digest(request_token, expected_token))
        or _valid_session(request.cookies.get("acp_session"))
    )


def _is_dashboard_route(path: str) -> bool:
    return (
        path in {"/", "/healthz", "/events", "/agents", "/sessions", "/logout"}
        or path == "/approvals"
        or path.startswith("/approvals/")
        or path == "/audit"
        or path == "/audit.csv"
        or path.startswith("/audit/")
    )


def _warn_hook_auth_rejection() -> None:
    global _last_hook_auth_warning
    now = time.monotonic()
    with _hook_auth_warning_lock:
        if (
            _last_hook_auth_warning is None
            or now - _last_hook_auth_warning >= 60
        ):
            logger.warning("hook request rejected: missing or invalid token")
            _last_hook_auth_warning = now


def require_token(
    request: Request,
    x_acp_token: str = Header(default=""),
) -> None:
    token = _load_token()
    if not token or request.url.path in {"/", "/login", "/auth/status"}:
        return
    if request.url.path in {"/hook", "/hook/copilot"}:
        if not hmac.compare_digest(x_acp_token, token):
            _warn_hook_auth_rejection()
            raise HTTPException(status_code=401, detail="bad token")
        return
    if _is_dashboard_route(request.url.path):
        if not _has_dashboard_auth(request, token):
            raise HTTPException(status_code=401, detail="authentication required")
        return
    if not hmac.compare_digest(x_acp_token, token):
        raise HTTPException(status_code=401, detail="bad token")


app = FastAPI(title="agent-control-plane", lifespan=lifespan, dependencies=[Depends(require_token)])


@app.middleware("http")
async def validate_local_request(request: Request, call_next):
    allowed_hosts = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
    host = request.headers.get("host", "").lower()
    if host not in allowed_hosts:
        if not (host == "testserver" and os.getenv("ACP_ALLOW_TESTCLIENT") == "1"):
            return PlainTextResponse("Forbidden", status_code=403)

    origin = request.headers.get("origin")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and origin is not None:
        allowed_origins = {
            f"http://127.0.0.1:{PORT}",
            f"http://localhost:{PORT}",
            f"https://127.0.0.1:{PORT}",
            f"https://localhost:{PORT}",
        }
        if origin.lower() not in allowed_origins:
            return PlainTextResponse("Forbidden", status_code=403)

    return await call_next(request)


class LoginIn(BaseModel):
    token: str


@app.post("/login")
async def login(body: LoginIn, request: Request):
    token = _load_token()
    if not token:
        raise HTTPException(status_code=404, detail="login is not enabled")
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _auth_lock:
        failures = _login_failures.setdefault(client_ip, deque())
        while failures and now - failures[0] >= LOGIN_FAILURE_WINDOW_SECONDS:
            failures.popleft()
        if len(failures) >= LOGIN_FAILURE_LIMIT:
            raise HTTPException(status_code=429, detail="too many failed login attempts")
        if not secrets.compare_digest(body.token, token):
            failures.append(now)
            raise HTTPException(status_code=401, detail="invalid token")
        _login_failures.pop(client_ip, None)
        session_id = secrets.token_urlsafe(32)
        _sessions[session_id] = now + SESSION_TTL_SECONDS

    response = Response(content='{"ok":true}', media_type="application/json")
    response.set_cookie(
        "acp_session",
        session_id,
        max_age=SESSION_TTL_SECONDS,
        path="/",
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )
    return response


@app.post("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("acp_session")
    if session_id:
        with _auth_lock:
            _sessions.pop(session_id, None)
    response = Response(content='{"ok":true}', media_type="application/json")
    response.delete_cookie(
        "acp_session",
        path="/",
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )
    return response


@app.get("/auth/status")
async def auth_status(request: Request):
    token = _load_token()
    return {
        "login_enabled": bool(token),
        "authenticated": not token or _has_dashboard_auth(request, token),
    }


@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    token = _load_token()
    status_code = 401 if token and not _has_dashboard_auth(request, token) else 200
    return FileResponse(
        Path(__file__).parent / "static" / "index.html",
        status_code=status_code,
    )


@app.get("/events")
async def dashboard_events(request: Request):
    async def stream():
        queue = request.app.state.event_broadcaster.subscribe()
        try:
            while True:
                try:
                    await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                else:
                    yield "data: changed\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            request.app.state.event_broadcaster.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def perm_response(behavior: str, message: str | None = None) -> dict:
    decision: dict = {"behavior": behavior}
    if behavior == "deny" and message:
        decision["message"] = message
    return {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": decision}}


@app.get("/healthz")
async def healthz(request: Request):
    async with request.app.state.pool.connection() as conn:
        await conn.execute("SELECT 1")
    return {"ok": True}


@app.post("/hook")
async def hook(request: Request):
    p = await request.json()
    pool = request.app.state.pool
    sid = p.get("session_id") or "unknown"
    kind = p.get("hook_event_name") or "unknown"
    status = {"Stop": "idle", "SessionEnd": "ended", "PermissionRequest": "waiting"}.get(kind, "active")
    async with pool.connection() as conn:
        await conn.execute(UPSERT_SESSION, (sid, "claude-code", p.get("cwd"), p.get("model"), status))
        await conn.execute(
            "INSERT INTO events (session_id, kind, tool_name, payload) VALUES (%s, %s, %s, %s)",
            (sid, kind, p.get("tool_name"), Jsonb(p)),
        )
    _schedule_notification(request.app)
    if kind != "PermissionRequest":
        return {}
    return await _permission(request, p, sid, agent="claude-code")


@app.post("/hook/copilot")
async def copilot_hook(request: Request):
    p = await request.json()
    pool = request.app.state.pool
    sid = p.get("sessionId") or "unknown"
    original_tool = p.get("toolName") or ""
    tool_key = original_tool.lower()
    if tool_key in {"powershell", "bash"}:
        tool_name = "Bash"
        classification_tool = "PowerShell" if tool_key == "powershell" else "Bash"
    elif tool_key == "view":
        tool_name = "Read"
        classification_tool = "Read"
    elif tool_key == "rg":
        tool_name = "Grep"
        classification_tool = "Grep"
    elif tool_key in {"apply_patch", "edit", "create"}:
        tool_name = "Write"
        classification_tool = "Write"
    elif tool_key == "ask_user":
        tool_name = "ask_user"
        classification_tool = "ask_user"
    else:
        tool_name = original_tool
        classification_tool = "CopilotUnknown"
    tool_args = p.get("toolArgs") or {}
    if tool_key in {"powershell", "bash"}:
        tool_input = {"command": tool_args.get("command", "")}
    else:
        tool_input = tool_args

    async with pool.connection() as conn:
        await conn.execute(
            UPSERT_SESSION,
            (sid, "copilot", p.get("cwd"), None, "waiting"),
        )
        await conn.execute(
            "INSERT INTO events (session_id, kind, tool_name, payload) VALUES (%s, %s, %s, %s)",
            (sid, "PreToolUse", original_tool, Jsonb(p)),
        )

    _schedule_notification(request.app)
    normalized = {"tool_name": tool_name, "tool_input": tool_input}
    return await _permission(
        request, normalized, sid, response=copilot_perm_response,
        classification_tool=classification_tool,
        repo_cwd=p.get("cwd"),
        agent="copilot",
    )


def copilot_perm_response(behavior: str, message: str | None = None) -> dict:
    if behavior == "allow":
        return {"permissionDecision": "allow"}
    response = {"permissionDecision": "deny"}
    if message:
        response["permissionDecisionReason"] = message
    return response


async def _set_active(app, sid: str) -> None:
    async with app.state.pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE sessions SET status = 'active', last_seen_at = now() WHERE id = %s AND status = 'waiting'",
            (sid,),
        )
        if cur.rowcount:
            _schedule_notification(app)


async def _expire(app, aid: int, who: str) -> bool:
    async with app.state.pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE approvals SET status = 'expired', decided_by = %s, decided_at = now() "
            "WHERE id = %s AND status = 'pending'",
            (who, aid),
        )
        expired = cur.rowcount == 1
    if expired:
        _schedule_notification(app)
    return expired


async def _permission(
    request: Request,
    p: dict,
    sid: str,
    response: Callable[[str, str | None], dict] = perm_response,
    classification_tool: str | None = None,
    repo_cwd: str | None = None,
    agent: str = "unknown",
) -> dict:
    pool = request.app.state.pool
    tool = p.get("tool_name") or ""
    tin = p.get("tool_input") or {}
    verdict = classify(classification_tool or tool, tin)
    if tool != "ask_user":
        try:
            rules = load_repo_rules(repo_cwd if repo_cwd is not None else p.get("cwd"))
            if classification_tool in {"Bash", "PowerShell"} or tool in {"Bash", "PowerShell"}:
                policy_text = str(tin.get("command", ""))
            else:
                policy_text = summarize(tool, tin)
            verdict = apply_repo_rules(verdict, policy_text, rules)
        except Exception:
            logger.exception("repository policy application failed; keeping built-in decision")
    initial = {"allow": "allowed", "deny": "denied"}.get(verdict.action, "pending")
    summary = question_summary(tin) if tool == "ask_user" else summarize(tool, tin)
    decided = initial != "pending"
    async with pool.connection() as conn:
        cur = await conn.execute(
            "INSERT INTO approvals (session_id, tool_name, tool_input, summary, risk, status, decided_by, reason, decided_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (sid, tool, Jsonb(tin), summary, verdict.risk, initial,
             "policy" if decided else None, verdict.reason,
             datetime.now(timezone.utc) if decided else None),
        )
        aid = (await cur.fetchone())["id"]
    _schedule_notification(request.app)
    if initial == "pending":
        try:
            schedule_human_decision(
                DecisionNotification(
                    agent=agent,
                    risk=verdict.risk,
                    summary=summary,
                    question=tool == "ask_user",
                )
            )
        except Exception:
            logger.exception("human-decision notification scheduling failed")

    if tool != "ask_user":
        _schedule_task(
            request.app,
            _embed_approval(pool, aid, f"{tool}: {summary}"),
        )

    if initial == "allowed":
        await _set_active(request.app, sid)
        return response("allow")
    if initial == "denied":
        await _set_active(request.app, sid)
        return response("deny", f"Blocked by policy: {verdict.reason}")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + (QUESTION_SECONDS if tool == "ask_user" else WAIT_SECONDS)
    while True:
        async with pool.connection() as conn:
            cur = await conn.execute("SELECT status, reason FROM approvals WHERE id = %s", (aid,))
            row = await cur.fetchone()
        if row["status"] != "pending":
            break
        if loop.time() >= deadline:
            if await _expire(request.app, aid, "timeout"):
                await _set_active(request.app, sid)
                return {}
            continue  # a human decided at the last moment; re-read
        if await request.is_disconnected():
            await _expire(request.app, aid, "client_gone")
            return {}
        await asyncio.sleep(POLL_SECONDS)

    await _set_active(request.app, sid)
    if row["status"] == "allowed":
        if tool == "ask_user":
            return response("deny", question_answer_reply(row["reason"]))
        return response("allow")
    if tool == "ask_user":
        return response("deny", question_declined_reply())
    return response("deny", row["reason"] or "Denied by user")


@app.get("/sessions")
async def list_sessions(request: Request):
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute("SELECT * FROM sessions ORDER BY last_seen_at DESC LIMIT 100")
        return await cur.fetchall()


@app.get("/agents")
async def list_agents(request: Request):
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(
            """
            WITH recent_sessions AS (
                SELECT id, agent, cwd, last_seen_at
                FROM sessions
                WHERE id <> 'seed'
                  AND last_seen_at >= now() - (%s * interval '1 hour')
            ),
            pending AS (
                SELECT a.session_id, count(*) AS pending_count
                FROM approvals AS a
                JOIN recent_sessions AS s ON s.id = a.session_id
                WHERE a.status = 'pending'
                GROUP BY a.session_id
            )
            SELECT s.id, s.agent, s.cwd, s.last_seen_at,
                   COALESCE(p.pending_count, 0) AS pending_count,
                   a.last_tool, LEFT(a.last_summary, 120) AS last_summary
            FROM recent_sessions AS s
            LEFT JOIN pending AS p ON p.session_id = s.id
            LEFT JOIN LATERAL (
                SELECT activity.last_tool, activity.last_summary
                FROM (
                    (
                        SELECT e.tool_name AS last_tool,
                               COALESCE(
                                   e.payload->>'summary',
                                   e.payload->'tool_input'->>'command',
                                   e.payload->'toolArgs'->>'command',
                                   e.kind
                               ) AS last_summary,
                               e.created_at
                        FROM events AS e
                        WHERE e.session_id = s.id
                        ORDER BY e.created_at DESC
                        LIMIT 1
                    )
                    UNION ALL
                    (
                        SELECT approval.tool_name AS last_tool,
                               approval.summary AS last_summary,
                               approval.created_at
                        FROM approvals AS approval
                        WHERE approval.session_id = s.id
                        ORDER BY approval.created_at DESC
                        LIMIT 1
                    )
                ) AS activity
                ORDER BY activity.created_at DESC
                LIMIT 1
            ) AS a ON TRUE
            ORDER BY s.last_seen_at DESC
            """,
            (24,),
        )
        agents = await cur.fetchall()
    for agent in agents:
        agent["folder"] = folder_name(agent["cwd"])
        agent["state"] = compute_agent_state(agent["pending_count"], agent["last_seen_at"])
    return agents


@app.get("/approvals")
async def list_approvals(request: Request, status: str = "pending", limit: int = Query(50, le=200)):
    if status == "pending":
        sql = (
            "SELECT a.id, a.session_id, a.tool_name, a.tool_input, a.summary, a.risk, a.status, "
            "a.decided_by, a.reason, a.created_at, a.decided_at, s.cwd "
            "FROM approvals AS a LEFT JOIN sessions AS s ON s.id = a.session_id"
        )
    else:
        sql = (
            "SELECT a.id, a.session_id, a.tool_name, a.summary, a.risk, a.status, "
            "a.decided_by, a.reason, a.created_at, a.decided_at, s.cwd "
            "FROM approvals AS a LEFT JOIN sessions AS s ON s.id = a.session_id"
        )
    params: tuple = ()
    if status != "all":
        sql += " WHERE a.status = %s"
        params = (status,)
    sql += " ORDER BY a.created_at DESC LIMIT %s"
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(sql, params + (limit,))
        approvals = await cur.fetchall()
        if status == "pending":
            cur = await conn.execute(
                "SELECT a.tool_name, a.summary, s.cwd "
                "FROM approvals AS a JOIN sessions AS s ON s.id = a.session_id "
                "WHERE a.status = 'pending' AND a.tool_name <> 'ask_user' AND s.cwd IS NOT NULL"
            )
            pending_identities = await cur.fetchall()
    if status == "pending":
        identity_counts = Counter(
            (row["tool_name"], _normalized_summary(row["summary"]), row["cwd"])
            for row in pending_identities
        )
    for approval in approvals:
        approval["folder"] = folder_name(approval["cwd"])
        if status == "pending":
            if approval["tool_name"] == "ask_user":
                approval["question_fields"] = parse_question_fields(approval["tool_input"])
                approval["identical_count"] = 0
            elif approval["cwd"] is None:
                approval["identical_count"] = 0
            else:
                key = (
                    approval["tool_name"],
                    _normalized_summary(approval["summary"]),
                    approval["cwd"],
                )
                approval["identical_count"] = identity_counts[key] - 1
    return approvals


def _audit_sql(
    since: datetime | None,
    until: datetime | None,
    agent: str | None,
    status: str | None,
    risk: str | None,
    decided_by: str | None,
    q: str | None,
) -> tuple[str, tuple]:
    clauses = []
    params = []
    for column, value in (
        ("a.created_at >= %s", since),
        ("a.created_at <= %s", until),
        ("s.agent = %s", agent),
        ("a.status = %s", status),
        ("a.risk = %s", risk),
        ("a.decided_by = %s", decided_by),
    ):
        if value is not None:
            clauses.append(column)
            params.append(value)
    if q is not None:
        escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_q}%"
        clauses.append(
            "(a.summary ILIKE %s ESCAPE E'\\\\' "
            "OR COALESCE(a.tool_input->>'command', '') ILIKE %s ESCAPE E'\\\\')"
        )
        params.extend((pattern, pattern))

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        "SELECT a.id, a.created_at, s.agent, a.tool_name, "
        "COALESCE(NULLIF(a.tool_input->>'command', ''), a.summary) AS command, "
        "a.summary, a.risk, a.status, a.decided_by, a.reason "
        "FROM approvals AS a LEFT JOIN sessions AS s ON s.id = a.session_id"
        f"{where} ORDER BY a.created_at DESC, a.id DESC LIMIT %s OFFSET %s"
    )
    return sql, tuple(params)


async def _fetch_audit_rows(
    request: Request,
    since: datetime | None,
    until: datetime | None,
    agent: str | None,
    status: str | None,
    risk: str | None,
    decided_by: str | None,
    q: str | None,
    limit: int,
    offset: int,
):
    sql, params = _audit_sql(since, until, agent, status, risk, decided_by, q)
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(sql, params + (limit + 1, offset))
        rows = await cur.fetchall()
    return rows


@app.get("/audit")
async def audit(
    request: Request,
    since: datetime | None = None,
    until: datetime | None = None,
    agent: str | None = None,
    status: str | None = None,
    risk: str | None = None,
    decided_by: str | None = None,
    q: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows = await _fetch_audit_rows(
        request, since, until, agent, status, risk, decided_by, q, limit, offset
    )
    return {
        "items": rows[:limit],
        "has_more": len(rows) > limit,
        "limit": limit,
        "offset": offset,
    }


def _csv_safe(value) -> str:
    if value is None:
        text = ""
    elif isinstance(value, datetime):
        text = value.isoformat()
    else:
        text = str(value)
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text


@app.get("/audit.csv")
async def audit_csv(
    request: Request,
    since: datetime | None = None,
    until: datetime | None = None,
    agent: str | None = None,
    status: str | None = None,
    risk: str | None = None,
    decided_by: str | None = None,
    q: str | None = None,
    limit: int = Query(5000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    rows = await _fetch_audit_rows(
        request, since, until, agent, status, risk, decided_by, q, limit, offset
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        ("time", "agent", "tool", "command", "risk", "decision", "decided_by", "reason")
    )
    for row in rows[:limit]:
        writer.writerow(
            _csv_safe(row[key])
            for key in (
                "created_at", "agent", "tool_name", "command",
                "risk", "status", "decided_by", "reason",
            )
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit.csv"'},
    )


@app.get("/approvals/{aid}/similar")
async def similar_approvals(
    aid: int,
    request: Request,
    limit: int = Query(3, ge=1, le=3),
):
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(
            """
            WITH query AS (SELECT embedding FROM approvals WHERE id = %s)
            SELECT a.id, a.summary, a.status, a.decided_by,
                   1 - (a.embedding <=> query.embedding) AS similarity,
                   a.decided_by = 'seed' AS example
            FROM approvals AS a
            CROSS JOIN query
            WHERE query.embedding IS NOT NULL
              AND a.embedding IS NOT NULL
              AND a.status IN ('allowed', 'denied')
              AND a.decided_by IN ('human', 'seed')
              AND a.id <> %s
              AND (a.embedding <=> query.embedding) <= %s
            ORDER BY CASE WHEN a.decided_by = 'human' THEN 0 ELSE 1 END,
                     a.embedding <=> query.embedding
            LIMIT %s
            """,
            (aid, aid, 1 - SIM_MIN, limit),
        )
        return await cur.fetchall()


class DecisionIn(BaseModel):
    decision: Literal["allow", "deny"]
    reason: str | None = None
    apply_to_identical: bool = False


class AnswerIn(BaseModel):
    answer: dict[str, str | bool | int | float] = Field(min_length=1)


@app.post("/approvals/{aid}/decide")
async def decide(aid: int, body: DecisionIn, request: Request):
    status = "allowed" if body.decision == "allow" else "denied"
    decided_count = 0
    async with request.app.state.pool.connection() as conn:
        if body.apply_to_identical:
            async with conn.transaction():
                cur = await conn.execute(
                    "SELECT a.tool_name, a.summary, s.cwd "
                    "FROM approvals AS a LEFT JOIN sessions AS s ON s.id = a.session_id "
                    "WHERE a.id = %s AND a.status = 'pending'",
                    (aid,),
                )
                target = await cur.fetchone()
                if not target or (target["tool_name"] == "ask_user" and body.decision == "allow"):
                    raise HTTPException(status_code=409, detail="approval is not pending")

                approval_ids = [aid]
                if target["tool_name"] != "ask_user" and target["cwd"] is not None:
                    cur = await conn.execute(
                        "SELECT a.id, a.summary "
                        "FROM approvals AS a JOIN sessions AS s ON s.id = a.session_id "
                        "WHERE a.status = 'pending' AND a.tool_name = %s "
                        "AND a.tool_name <> 'ask_user' AND a.id <> %s AND s.cwd = %s",
                        (target["tool_name"], aid, target["cwd"]),
                    )
                    normalized = _normalized_summary(target["summary"])
                    approval_ids.extend(
                        row["id"]
                        for row in await cur.fetchall()
                        if _normalized_summary(row["summary"]) == normalized
                    )

                cur = await conn.execute(
                    "UPDATE approvals SET status = %s, decided_by = 'human', reason = %s, decided_at = now() "
                    "WHERE id = ANY(%s) AND status = 'pending' "
                    "AND NOT (tool_name = 'ask_user' AND %s = 'allow') RETURNING id",
                    (status, body.reason, approval_ids, body.decision),
                )
                decided_ids = [row["id"] for row in await cur.fetchall()]
                if aid not in decided_ids:
                    raise HTTPException(status_code=409, detail="approval is not pending")
                decided_count = len(decided_ids)
        else:
            cur = await conn.execute(
                "UPDATE approvals SET status = %s, decided_by = 'human', reason = %s, decided_at = now() "
                "WHERE id = %s AND status = 'pending' "
                "AND NOT (tool_name = 'ask_user' AND %s = 'allow') RETURNING id",
                (status, body.reason, aid, body.decision),
            )
            if not await cur.fetchone():
                raise HTTPException(status_code=409, detail="approval is not pending")
            decided_count = 1
    _schedule_notification(request.app)
    return {"id": aid, "status": status, "decided_count": decided_count}


@app.post("/approvals/{aid}/answer")
async def answer_question(aid: int, body: AnswerIn, request: Request):
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE approvals SET status = 'allowed', decided_by = 'human', reason = %s, decided_at = now() "
            "WHERE id = %s AND status = 'pending' AND tool_name = 'ask_user' RETURNING id",
            (json.dumps(body.answer), aid),
        )
        if not await cur.fetchone():
            raise HTTPException(status_code=409, detail="question is not pending")
    _schedule_notification(request.app)
    return {"id": aid, "status": "allowed"}
