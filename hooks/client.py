import json
import os
import sys
import urllib.request
from pathlib import Path


TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"


def load_token(token_file: Path | None = None) -> str:
    environment_token = os.environ.get("ACP_TOKEN", "")
    if environment_token:
        return environment_token
    try:
        with (token_file or TOKEN_FILE).open(encoding="utf-8") as token_stream:
            return token_stream.readline().strip()
    except FileNotFoundError:
        return ""


def fail_safe(agent: str) -> dict | None:
    if agent == "codex":
        return None
    if agent == "cursor":
        return {"permission": "ask", "user_message": "Agent Control Plane unreachable"}
    return {"decision": "ask", "reason": "Agent Control Plane unreachable"}


def _reject_json_constant(value: str):
    raise ValueError(f"invalid JSON constant: {value}")


def _write_error() -> None:
    try:
        sys.stderr.write("Agent Control Plane request failed\n")
    except Exception:
        pass


def _write_json(output: dict) -> None:
    try:
        sys.stdout.write(json.dumps(output, separators=(",", ":"), allow_nan=False))
    except Exception:
        _write_error()


def run(agent: str, endpoint: str) -> int:
    output = fail_safe(agent)
    try:
        raw = sys.stdin.buffer.read()
        try:
            payload = json.loads(raw, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            if agent == "cursor":
                # UNVERIFIED: Cursor specifies exit 2 for denial but not this
                # malformed-input message text.
                output = {
                    "permission": "deny",
                    "user_message": "Invalid hook payload",
                    "agent_message": "Invalid hook payload",
                }
                _write_json(output)
                return 2
            raise
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be an object")
        request = urllib.request.Request(
            endpoint,
            data=raw,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-ACP-Token": load_token(),
            },
        )
        with urllib.request.urlopen(request, timeout=55) as response:
            body = response.read()
        if body:
            parsed = json.loads(body, parse_constant=_reject_json_constant)
            if not isinstance(parsed, dict):
                raise ValueError("hook response must be an object")
            output = parsed
        elif agent == "codex":
            output = None
    except Exception:
        _write_error()

    if output is not None:
        _write_json(output)
    if agent == "cursor" and output is not None and output.get("permission") == "deny":
        return 2
    return 0
