"""Agent control plane, Step 1: hook receiver + approvals API on Postgres.

Flow for a PermissionRequest hook:
  classify -> allow/deny immediately, or park as 'pending' and wait for a human
  (POST /approvals/{id}/decide). On timeout or client disconnect we return {}
  so Claude Code falls back to its own native prompt (fail-safe, never auto-allow).
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel

from .embed import embed, to_pgvector
from .policy import classify, summarize

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://acp:acp@127.0.0.1:5435/acp")
TOKEN = os.getenv("ACP_TOKEN", "")
WAIT_SECONDS = float(os.getenv("ACP_WAIT_SECONDS", "45"))  # keep below the hook timeout
SIM_MIN = float(os.getenv("ACP_SIM_MIN", "0.80"))
POLL_SECONDS = 0.5  # Step 2 replaces polling with LISTEN/NOTIFY
logger = logging.getLogger(__name__)

UPSERT_SESSION = """
INSERT INTO sessions (id, cwd, model, status) VALUES (%s, %s, %s, %s)
ON CONFLICT (id) DO UPDATE SET
  cwd = COALESCE(EXCLUDED.cwd, sessions.cwd),
  model = COALESCE(EXCLUDED.model, sessions.model),
  status = EXCLUDED.status,
  last_seen_at = now()
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = AsyncConnectionPool(
        DATABASE_URL, min_size=1, max_size=10, open=False,
        kwargs={"row_factory": dict_row, "autocommit": True},
    )
    await pool.open(wait=True, timeout=10)
    app.state.pool = pool
    app.state.embedding_tasks = set()
    _schedule_task(app, _warm_embeddings())
    yield
    if app.state.embedding_tasks:
        await asyncio.gather(*app.state.embedding_tasks, return_exceptions=True)
    await pool.close()


def _schedule_task(app: FastAPI, coroutine) -> None:
    task = asyncio.create_task(coroutine)
    app.state.embedding_tasks.add(task)
    task.add_done_callback(app.state.embedding_tasks.discard)


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
    except Exception as exc:
        logger.warning(
            "approval embedding failed: %s",
            (str(exc).splitlines() or [type(exc).__name__])[0],
        )


def require_token(x_acp_token: str = Header(default="")) -> None:
    if TOKEN and not hmac.compare_digest(x_acp_token, TOKEN):
        raise HTTPException(status_code=401, detail="bad token")


app = FastAPI(title="agent-control-plane", lifespan=lifespan, dependencies=[Depends(require_token)])


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


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
        await conn.execute(UPSERT_SESSION, (sid, p.get("cwd"), p.get("model"), status))
        await conn.execute(
            "INSERT INTO events (session_id, kind, tool_name, payload) VALUES (%s, %s, %s, %s)",
            (sid, kind, p.get("tool_name"), Jsonb(p)),
        )
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
    elif tool_key in {"apply_patch", "edit", "create"}:
        tool_name = "Write"
        classification_tool = "Write"
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
            (sid, p.get("cwd"), None, "active" if tool_key == "ask_user" else "waiting"),
        )
        await conn.execute(
            "INSERT INTO events (session_id, kind, tool_name, payload) VALUES (%s, %s, %s, %s)",
            (sid, "PreToolUse", original_tool, Jsonb(p)),
        )

    if tool_key == "ask_user":
        return {}
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


async def _set_active(pool, sid: str) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE sessions SET status = 'active', last_seen_at = now() WHERE id = %s AND status = 'waiting'",
            (sid,),
        )


async def _expire(pool, aid: int, who: str) -> bool:
    async with pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE approvals SET status = 'expired', decided_by = %s, decided_at = now() "
            "WHERE id = %s AND status = 'pending'",
            (who, aid),
        )
        return cur.rowcount == 1


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
    decided = initial != "pending"
    async with pool.connection() as conn:
        cur = await conn.execute(
            "INSERT INTO approvals (session_id, tool_name, tool_input, summary, risk, status, decided_by, reason, decided_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (sid, tool, Jsonb(tin), summarize(tool, tin), verdict.risk, initial,
             "policy" if decided else None, verdict.reason,
             datetime.now(timezone.utc) if decided else None),
        )
        aid = (await cur.fetchone())["id"]

    _schedule_task(
        request.app,
        _embed_approval(pool, aid, f"{tool}: {summarize(tool, tin)}"),
    )

    if initial == "allowed":
        await _set_active(pool, sid)
        return response("allow")
    if initial == "denied":
        await _set_active(pool, sid)
        return response("deny", f"Blocked by policy: {verdict.reason}")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + WAIT_SECONDS
    while True:
        async with pool.connection() as conn:
            cur = await conn.execute("SELECT status, reason FROM approvals WHERE id = %s", (aid,))
            row = await cur.fetchone()
        if row["status"] != "pending":
            break
        if loop.time() >= deadline:
            if await _expire(pool, aid, "timeout"):
                await _set_active(pool, sid)
                return {}
            continue  # a human decided at the last moment; re-read
        if await request.is_disconnected():
            await _expire(pool, aid, "client_gone")
            return {}
        await asyncio.sleep(POLL_SECONDS)

    await _set_active(pool, sid)
    if row["status"] == "allowed":
        return response("allow")
    return response("deny", row["reason"] or "Denied by user")


@app.get("/sessions")
async def list_sessions(request: Request):
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute("SELECT * FROM sessions ORDER BY last_seen_at DESC LIMIT 100")
        return await cur.fetchall()


@app.get("/approvals")
async def list_approvals(request: Request, status: str = "pending", limit: int = Query(50, le=200)):
    sql = "SELECT id, session_id, tool_name, summary, risk, status, decided_by, reason, created_at, decided_at FROM approvals"
    params: tuple = ()
    if status != "all":
        sql += " WHERE status = %s"
        params = (status,)
    sql += " ORDER BY created_at DESC LIMIT %s"
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(sql, params + (limit,))
        return await cur.fetchall()


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


@app.post("/approvals/{aid}/decide")
async def decide(aid: int, body: DecisionIn, request: Request):
    status = "allowed" if body.decision == "allow" else "denied"
    async with request.app.state.pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE approvals SET status = %s, decided_by = 'human', reason = %s, decided_at = now() "
            "WHERE id = %s AND status = 'pending' RETURNING id",
            (status, body.reason, aid),
        )
        if not await cur.fetchone():
            raise HTTPException(status_code=409, detail="approval is not pending")
    return {"id": aid, "status": status}
