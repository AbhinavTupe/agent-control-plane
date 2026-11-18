from __future__ import annotations

import html
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)
_RATE_LIMIT_SECONDS = 5.0
_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>' + $env:ACP_NOTIFY_TITLE + '</text><text>' + $env:ACP_NOTIFY_BODY + '</text></binding></visual></toast>')
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show($toast)
"""


@dataclass(frozen=True)
class DecisionNotification:
    agent: str
    risk: str
    summary: str
    question: bool = False


@dataclass(frozen=True)
class NotificationConfig:
    desktop: bool
    topic: str
    server: str
    detail: bool

    @property
    def phone(self) -> bool:
        return bool(self.topic)

    @property
    def enabled(self) -> bool:
        return self.desktop or self.phone


def _config_from_env() -> NotificationConfig:
    return NotificationConfig(
        desktop=os.getenv("ACP_NOTIFY_DESKTOP") == "1" and sys.platform == "win32",
        topic=os.getenv("ACP_NTFY_TOPIC", "").strip(),
        server=os.getenv("ACP_NTFY_SERVER", "https://ntfy.sh").rstrip("/"),
        detail=os.getenv("ACP_NTFY_DETAIL") == "1",
    )


def log_enabled_channels() -> None:
    config = _config_from_env()
    logger.info(
        "human-decision notifications: desktop=%s phone=%s",
        config.desktop,
        config.phone,
    )


def _clean_text(value: str) -> str:
    return "".join(
        char for char in str(value)
        if ord(char) >= 32 and not 127 <= ord(char) <= 159
    )


def _header_value(value: str) -> str:
    return _clean_text(value).strip()


def _notification_text(events: tuple[DecisionNotification, ...], detail: bool) -> str:
    agents = ", ".join(sorted({_clean_text(event.agent).strip() or "unknown" for event in events}))
    if len(events) > 1:
        return f"{len(events)} approvals waiting — {agents}"

    event = events[0]
    label = "Agent question" if event.question else f"Approval needed ({_clean_text(event.risk).upper()})"
    text = f"{label} — {event.agent}"
    if detail and event.summary:
        text += f": {_clean_text(event.summary)}"
    return text


def _priority(events: tuple[DecisionNotification, ...]) -> str:
    priorities = {"low": 3, "medium": 4, "high": 5, "critical": 5}
    value = max(
        (priorities.get(event.risk.casefold(), 4) for event in events),
        default=3,
    )
    return str(value)


def _send_desktop(title: str, message: str) -> None:
    env = os.environ.copy()
    env["ACP_NOTIFY_TITLE"] = html.escape(_clean_text(title)[:120], quote=True)
    env["ACP_NOTIFY_BODY"] = html.escape(_clean_text(message)[:120], quote=True)
    process = subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _POWERSHELL_SCRIPT,
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        logger.warning("desktop notification timed out")
        return
    if process.returncode:
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        error_line = (str(stderr or "").splitlines() or [
            f"PowerShell exited with code {process.returncode}"
        ])[0]
        logger.warning("desktop notification failed: %s", error_line[:200])


def _send_phone(config: NotificationConfig, title: str, message: str, priority: str) -> None:
    topic = urllib.parse.quote(config.topic, safe="")
    request = urllib.request.Request(
        f"{config.server}/{topic}",
        data=message.encode("utf-8"),
        headers={
            "Title": _header_value(title),
            "Priority": _header_value(priority),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5):
        pass


class NotificationDispatcher:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: list[DecisionNotification] = []
        self._timer: threading.Timer | None = None
        self._last_sent: float | None = None

    def schedule(self, event: DecisionNotification) -> None:
        config = _config_from_env()
        if not config.enabled:
            return

        with self._lock:
            self._pending.append(event)
            if self._timer is not None:
                return

            delay = _RATE_LIMIT_SECONDS
            if self._last_sent is not None:
                delay = max(0.0, _RATE_LIMIT_SECONDS - (time.monotonic() - self._last_sent))
            try:
                timer = threading.Timer(delay, self._flush)
                timer.daemon = True
                self._timer = timer
                timer.start()
            except Exception:
                self._timer = None
                self._pending.clear()
                raise

    def _flush(self) -> None:
        with self._lock:
            events = tuple(self._pending)
            self._pending.clear()
            self._timer = None
            self._last_sent = time.monotonic()

        if not events:
            return
        try:
            config = _config_from_env()
            if not config.enabled:
                return
            self._deliver(events, config)
        except Exception as exc:
            logger.warning("human-decision notification failed: %s", _error_line(exc))

    def _deliver(
        self,
        events: tuple[DecisionNotification, ...],
        config: NotificationConfig,
    ) -> None:
        message = _notification_text(events, config.detail)
        title = "Agent Control Plane"
        if config.desktop:
            try:
                _send_desktop(title, message)
            except Exception as exc:
                logger.warning("desktop notification failed: %s", _error_line(exc))
        if config.phone:
            try:
                _send_phone(config, title, message, _priority(events))
            except Exception as exc:
                logger.warning("phone notification failed: %s", _error_line(exc))


def _error_line(exc: Exception) -> str:
    return (str(exc).splitlines() or [type(exc).__name__])[0]


_dispatcher = NotificationDispatcher()


def schedule_human_decision(event: DecisionNotification) -> None:
    try:
        _dispatcher.schedule(event)
    except Exception as exc:
        logger.warning("human-decision notification scheduling failed: %s", _error_line(exc))
