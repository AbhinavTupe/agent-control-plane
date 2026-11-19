import io
import urllib.error

import pytest

from hooks import acp_hook, copilot_hook


class MockResponse:
    def __init__(self, body=b'{"ok":true}'):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class HookStdin:
    def __init__(self, payload):
        self.buffer = io.BytesIO(payload)


class HookStdout:
    def __init__(self):
        self.buffer = io.BytesIO()

    def write(self, value):
        return self.buffer.write(value.encode())


@pytest.mark.parametrize(
    ("hook", "input_value", "stdout_value", "stderr_value"),
    [
        (copilot_hook, "buffer", HookStdout, io.StringIO),
        (acp_hook, "text", io.StringIO, io.StringIO),
    ],
)
def test_hooks_send_token_header(
    monkeypatch, tmp_path, hook, input_value, stdout_value, stderr_value
):
    token_file = tmp_path / ".acp-token"
    token_file.write_text(" file-hook-token \n", encoding="utf-8")
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    monkeypatch.setattr(hook, "TOKEN_FILE", token_file)
    stdin = HookStdin(b'{"toolName":"view"}')
    if input_value == "text":
        stdin = io.StringIO('{"toolName":"view"}')
    stdout = stdout_value()
    stderr = stderr_value()
    monkeypatch.setattr(hook.sys, "stdin", stdin)
    monkeypatch.setattr(hook.sys, "stdout", stdout)
    monkeypatch.setattr(hook.sys, "stderr", stderr)
    requests = []

    def urlopen(request, timeout):
        requests.append((request, timeout))
        return MockResponse()

    monkeypatch.setattr(hook.urllib.request, "urlopen", urlopen)

    assert hook.main() == 0
    headers = {
        name.lower(): value for name, value in requests[0][0].headers.items()
    }
    assert headers["x-acp-token"] == "file-hook-token"
    if hook is copilot_hook:
        assert stdout.buffer.getvalue() == b'{"ok":true}'
    else:
        assert stdout.getvalue() == '{"ok":true}'
    assert stderr.getvalue() == ""


@pytest.mark.parametrize(
    ("hook", "stdin", "stdout", "read_output"),
    [
        (
            copilot_hook,
            HookStdin(b'{"toolName":"view"}'),
            HookStdout(),
            lambda output: output.buffer.getvalue().decode(),
        ),
        (
            acp_hook,
            io.StringIO('{"toolName":"view"}'),
            io.StringIO(),
            lambda output: output.getvalue(),
        ),
    ],
)
def test_bad_token_fails_safe_with_empty_reply(
    monkeypatch, hook, stdin, stdout, read_output
):
    monkeypatch.setenv("ACP_TOKEN", "rejected-token")
    stderr = io.StringIO()
    monkeypatch.setattr(hook.sys, "stdin", stdin)
    monkeypatch.setattr(hook.sys, "stdout", stdout)
    monkeypatch.setattr(hook.sys, "stderr", stderr)

    def unauthorized(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://127.0.0.1/hook", 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr(hook.urllib.request, "urlopen", unauthorized)

    assert hook.main() == 0
    assert read_output(stdout).strip() == "{}"
    assert stderr.getvalue() == "ACP token missing or rejected\n"


def test_hook_file_token_loader_uses_first_line_and_missing_is_disabled(
    tmp_path, monkeypatch
):
    token_file = tmp_path / ".acp-token"
    monkeypatch.delenv("ACP_TOKEN", raising=False)

    assert copilot_hook._load_token(token_file) == ""
    token_file.write_text(" \tfirst-token \r\nsecond-token\n", encoding="utf-8")
    assert copilot_hook._load_token(token_file) == "first-token"
    monkeypatch.setenv("ACP_TOKEN", "environment-token")
    assert acp_hook._load_token(token_file) == "environment-token"
