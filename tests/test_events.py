import asyncio
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from server.events import EventBroadcaster
from server.main import DATABASE_URL, TOKEN, app, dashboard_events


def test_broadcaster_fans_out_changed_and_coalesces():
    broadcaster = EventBroadcaster()
    first = broadcaster.subscribe()
    second = broadcaster.subscribe()

    broadcaster.broadcast()
    broadcaster.broadcast()

    assert first.get_nowait() == "changed"
    assert second.get_nowait() == "changed"
    assert first.empty()
    broadcaster.unsubscribe(first)
    broadcaster.broadcast()
    assert first.empty()
    assert second.get_nowait() == "changed"


def test_events_stream_unsubscribes_when_cancelled():
    async def cancel_stream():
        broadcaster = EventBroadcaster()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(event_broadcaster=broadcaster))
        )
        response = await dashboard_events(request)
        stream_task = asyncio.create_task(response.body_iterator.__anext__())
        await asyncio.sleep(0)
        assert len(broadcaster._subscribers) == 1

        stream_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stream_task

        assert len(broadcaster._subscribers) == 0

    asyncio.run(cancel_stream())


def test_copilot_hook_publishes_postgres_notification(monkeypatch):
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
        monkeypatch.setattr("server.main._warm_embeddings", _skip_embedding_warmup)
        _assert_copilot_notification()
    finally:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(policy)


async def _skip_embedding_warmup():
    return None


def _assert_copilot_notification():
    session_id = "sse-test-" + uuid.uuid4().hex
    with psycopg.connect(DATABASE_URL, autocommit=True) as listener:
        listener.execute("LISTEN acp_events")
        with TestClient(app) as client:
            with ThreadPoolExecutor(max_workers=1) as executor:
                request = executor.submit(
                    client.post,
                    "/hook/copilot",
                    headers={"x-acp-token": TOKEN},
                    json={
                        "sessionId": session_id,
                        "toolName": "unknown-test-tool",
                        "toolArgs": {},
                        "cwd": "/tmp/sse-test",
                    },
                )
                approval_row = None
                notification = None
                for _ in range(2):
                    notification = next(
                        listener.notifies(timeout=10, stop_after=1),
                        None,
                    )
                    assert notification is not None, (
                        f"hook returned early with status {request.result().status_code}"
                        if request.done() else "no dashboard notification received"
                    )
                    cur = listener.execute(
                        "SELECT id FROM approvals WHERE session_id = %s AND status = 'pending'",
                        (session_id,),
                    )
                    approval_row = cur.fetchone()
                    if approval_row:
                        break
                assert notification.channel == "acp_events"
                assert notification.payload == "changed"
                assert approval_row is not None
                decided = client.post(
                    f"/approvals/{approval_row[0]}/decide",
                    headers={"x-acp-token": TOKEN},
                    json={"decision": "deny"},
                )
                assert decided.status_code == 200
                assert request.result(timeout=10).status_code == 200
        listener.execute("DELETE FROM approvals WHERE session_id = %s", (session_id,))
        listener.execute("DELETE FROM events WHERE session_id = %s", (session_id,))
        listener.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
