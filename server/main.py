"""Agent control plane, Step 1: hook receiver + approvals API on Postgres.

Flow for a PermissionRequest hook:
  classify -> allow/deny immediately, or park as 'pending' and wait for a human
  (POST /approvals/{id}/decide). On timeout or client disconnect we return {}
  so Claude Code falls back to its own native prompt (fail-safe, never auto-allow).
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel, Field

from .embed import embed, to_pgvector
from .events import EventBroadcaster, listen_for_events, notify_changed
from .policy import (
    classify,
    question_answer_reply,
    question_declined_reply,
    parse_question_fields,
    question_summary,
    summarize,
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://acp:acp@127.0.0.1:5435/acp")
TOKEN = os.getenv("ACP_TOKEN", "")
WAIT_SECONDS = float(os.getenv("ACP_WAIT_SECONDS", "45"))  # keep below the hook timeout
QUESTION_SECONDS = float(os.getenv("ACP_QUESTION_SECONDS", "50"))
SIM_MIN = float(os.getenv("ACP_SIM_MIN", "0.80"))
PORT = int(os.getenv("ACP_PORT", "8787"))
POLL_SECONDS = 0.5
logger = logging.getLogger(__name__)

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


def require_token(x_acp_token: str = Header(default="")) -> None:
    if TOKEN and not hmac.compare_digest(x_acp_token, TOKEN):
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
        }
        if origin.lower() not in allowed_origins:
            return PlainTextResponse("Forbidden", status_code=403)

    return await call_next(request)


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


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
    return await _permission(request, p, sid)


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
) -> dict:
    pool = request.app.state.pool
    tool = p.get("tool_name") or ""
    tin = p.get("tool_input") or {}
    verdict = classify(classification_tool or tool, tin)
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
    for approval in approvals:
        approval["folder"] = folder_name(approval["cwd"])
        if status == "pending" and approval["tool_name"] == "ask_user":
            approval["question_fields"] = parse_question_fields(approval["tool_input"])
    return approvals


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
                   1 - (a.embedding <=> query.embedding) AS similarity
            FROM approvals AS a
            CROSS JOIN query
            WHERE query.embedding IS NOT NULL
              AND a.embedding IS NOT NULL
              AND a.status IN ('allowed', 'denied')
              AND a.decided_by IN ('human', 'seed')
              AND a.id <> %s
              AND (a.embedding <=> query.embedding) <= %s
            ORDER BY a.embedding <=> query.embedding
            LIMIT %s
            """,
            (aid, aid, 1 - SIM_MIN, limit),
        )
        return await cur.fetchall()


class DecisionIn(BaseModel):
    decision: Literal["allow", "deny"]
    reason: str | None = None


class AnswerIn(BaseModel):
    answer: dict[str, str | bool | int | float] = Field(min_length=1)


@app.post("/approvals/{aid}/decide")
async def decide(aid: int, body: DecisionIn, request: Request):
    status = "allowed" if body.decision == "allow" else "denied"
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE approvals SET status = %s, decided_by = 'human', reason = %s, decided_at = now() "
            "WHERE id = %s AND status = 'pending' "
            "AND NOT (tool_name = 'ask_user' AND %s = 'allow') RETURNING id",
            (status, body.reason, aid, body.decision),
        )
        if not await cur.fetchone():
            raise HTTPException(status_code=409, detail="approval is not pending")
    _schedule_notification(request.app)
    return {"id": aid, "status": status}


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
