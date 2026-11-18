import asyncio
import html
from types import SimpleNamespace

import pytest

from server import main, notify


class FakeTimer:
    instances = []

    def __init__(self, interval, function):
        self.interval = interval
        self.function = function
        self.daemon = False
        self.started = False
        self.instances.append(self)

    def start(self):
        self.started = True

    def fire(self):
        self.function()


@pytest.fixture(autouse=True)
def clear_notification_environment(monkeypatch):
    for name in (
        "ACP_NOTIFY_DESKTOP",
        "ACP_NTFY_TOPIC",
        "ACP_NTFY_SERVER",
        "ACP_NTFY_DETAIL",
    ):
        monkeypatch.delenv(name, raising=False)
    FakeTimer.instances.clear()
    monkeypatch.setattr(notify.threading, "Timer", FakeTimer)


def test_notifications_are_off_without_configuration(monkeypatch):
    dispatcher = notify.NotificationDispatcher()
    dispatcher.schedule(notify.DecisionNotification("copilot", "high", "git status"))
    assert FakeTimer.instances == []


def test_desktop_text_is_escaped_and_never_put_in_powershell_source(monkeypatch):
    calls = []

    class Process:
        returncode = 0

        def communicate(self, timeout):
            assert timeout == 5
            return None, None

    def fake_popen(args, **kwargs):
        calls.append((args, kwargs))
        return Process()

    monkeypatch.setattr(notify.subprocess, "Popen", fake_popen)
    hostile = '"; Invoke-Expression "Write-Output pwned"; <toast>'
    notify._send_desktop("ACP", hostile)

    args, kwargs = calls[0]
    script = args[-1]
    assert hostile not in script
    assert kwargs["env"]["ACP_NOTIFY_BODY"] == html.escape(hostile, quote=True)
    assert kwargs["stderr"] == notify.subprocess.PIPE
    assert "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]" in script
    assert "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]" in script
    assert r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe" in script
    assert "powershell.exe" == args[0]
    assert "-NoProfile" in args
    assert "-NonInteractive" in args


def test_desktop_timeout_kills_powershell(monkeypatch):
    class Process:
        returncode = 0

        def __init__(self):
            self.communicate_calls = 0
            self.killed = False

        def communicate(self, timeout=None):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise notify.subprocess.TimeoutExpired("powershell.exe", timeout)
            return None, None

        def kill(self):
            self.killed = True

    process = Process()
    monkeypatch.setattr(notify.subprocess, "Popen", lambda *_args, **_kwargs: process)

    notify._send_desktop("ACP", "Approval needed (high)")

    assert process.killed
    assert process.communicate_calls == 2


def test_desktop_failure_logs_only_first_stderr_line_truncated(monkeypatch, caplog):
    class Process:
        returncode = 1

        def communicate(self, timeout):
            assert timeout == 5
            return None, (b"X" * 250 + b"\nsecond line")

    calls = []

    def fake_popen(args, **kwargs):
        calls.append(kwargs)
        return Process()

    monkeypatch.setattr(notify.subprocess, "Popen", fake_popen)
    notify._send_desktop("ACP", "approval")

    assert calls[0]["stderr"] == notify.subprocess.PIPE
    warning = next(record.getMessage() for record in caplog.records if record.levelname == "WARNING")
    assert warning == f"desktop notification failed: {'X' * 200}"


def test_phone_notification_uses_post_and_sanitizes_headers(monkeypatch):
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    hostile = '"; Invoke-Expression "no";'
    config = notify.NotificationConfig(False, "private-topic", "https://ntfy.example", False)
    notify._send_phone(config, "ACP\r\nX-Injected: yes", hostile, "5")

    request, timeout = requests[0]
    assert request.method == "POST"
    assert request.full_url == "https://ntfy.example/private-topic"
    assert request.data == hostile.encode("utf-8")
    assert request.get_header("Title") == "ACPX-Injected: yes"
    assert request.get_header("Priority") == "5"
    assert timeout == 5


def test_single_notification_omits_summary_unless_detail_is_enabled():
    event = notify.DecisionNotification("copilot", "high", "git push --force")
    assert notify._notification_text((event,), False) == "Approval needed (HIGH) — copilot"
    assert notify._notification_text((event,), True) == (
        "Approval needed (HIGH) — copilot: git push --force"
    )
    question = notify.DecisionNotification("copilot", "medium", "Pick a color", question=True)
    assert notify._notification_text((question,), False) == "Agent question — copilot"


def test_rate_limit_coalesces_burst_and_delays_next_notification(monkeypatch):
    monkeypatch.setenv("ACP_NTFY_TOPIC", "topic")
    delivered = []
    dispatcher = notify.NotificationDispatcher()
    monkeypatch.setattr(dispatcher, "_deliver", lambda events, config: delivered.append((events, config)))
    dispatcher.schedule(notify.DecisionNotification("copilot", "low", "one"))
    dispatcher.schedule(notify.DecisionNotification("copilot", "high", "two"))

    assert len(FakeTimer.instances) == 1
    FakeTimer.instances[0].fire()
    events, config = delivered[0]
    assert len(events) == 2
    assert notify._notification_text(events, config.detail) == "2 approvals waiting — copilot"

    dispatcher.schedule(notify.DecisionNotification("copilot", "low", "three"))
    assert len(FakeTimer.instances) == 2
    assert 4.9 <= FakeTimer.instances[1].interval <= 5.0


def test_channel_failures_are_logged_and_do_not_escape(monkeypatch, caplog):
    monkeypatch.setenv("ACP_NOTIFY_DESKTOP", "1")
    monkeypatch.setattr(notify.sys, "platform", "win32")
    monkeypatch.setenv("ACP_NTFY_TOPIC", "topic")
    monkeypatch.setattr(
        notify.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("desktop unavailable")),
    )
    monkeypatch.setattr(
        notify.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("phone unavailable")),
    )
    dispatcher = notify.NotificationDispatcher()
    dispatcher.schedule(notify.DecisionNotification("copilot", "high", "summary"))

    FakeTimer.instances[0].fire()

    assert "desktop notification failed" in caplog.text
    assert "phone notification failed" in caplog.text


def test_hook_response_is_unchanged_when_notification_raises(monkeypatch):
    class Cursor:
        rowcount = 1

        def __init__(self, result=None):
            self.result = result

        async def fetchone(self):
            return self.result

    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def execute(self, query, _params=None):
            if "INSERT INTO approvals" in query:
                return Cursor({"id": 1})
            if "SELECT status, reason FROM approvals" in query:
                return Cursor({"status": "denied", "reason": "declined"})
            return Cursor()

    class Pool:
        def connection(self):
            return Connection()

    class Request:
        def __init__(self, payload, app):
            self.payload = payload
            self.app = app

        async def json(self):
            return self.payload

    async def run_hook():
        app = SimpleNamespace(state=SimpleNamespace(pool=Pool()))
        request = Request(
            {
                "sessionId": "notify-test",
                "toolName": "ask_user",
                "toolArgs": {"message": "Pick a color"},
            },
            app,
        )
        return await main.copilot_hook(request)

    monkeypatch.setattr(main, "_schedule_notification", lambda _app: None)
    monkeypatch.setattr(
        main,
        "classify",
        lambda *_args: SimpleNamespace(action="ask", risk="high", reason="needs review"),
    )
    monkeypatch.setattr(
        main,
        "schedule_human_decision",
        lambda _event: (_ for _ in ()).throw(RuntimeError("notification failed")),
    )
    result = asyncio.run(run_hook())

    assert result == main.copilot_perm_response("deny", "The user declined to answer.")
