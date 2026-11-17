from __future__ import annotations

import asyncio
import logging

import psycopg

logger = logging.getLogger(__name__)


class EventBroadcaster:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)

    def broadcast(self) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait("changed")


async def notify_changed(pool) -> None:
    try:
        async with pool.connection() as conn:
            await conn.execute("SELECT pg_notify(%s, %s)", ("acp_events", "changed"))
    except Exception as exc:
        logger.warning(
            "dashboard notification failed: %s",
            (str(exc).splitlines() or [type(exc).__name__])[0],
        )


async def listen_for_events(dsn: str, broadcaster: EventBroadcaster) -> None:
    backoff = 0.5
    while True:
        try:
            async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
                await conn.execute("LISTEN acp_events")
                backoff = 0.5
                async for _notification in conn.notifies():
                    broadcaster.broadcast()
                raise ConnectionError("Postgres notification stream ended")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "dashboard LISTEN connection failed: %s",
                (str(exc).splitlines() or [type(exc).__name__])[0],
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
