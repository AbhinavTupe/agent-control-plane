#!/usr/bin/env python3
"""Claude Code hook -> agent-control-plane server. Standard library only.

Reads the hook JSON from stdin, POSTs it to the server, prints the server's reply
verbatim (a hookSpecificOutput JSON) or nothing. Fail-safe: if the server is down
we print nothing and exit 0, so Claude Code shows its own native prompt.
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

URL = os.environ.get("ACP_URL", "http://127.0.0.1:8787/hook")
TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"
TIMEOUT = float(os.environ.get("ACP_TIMEOUT", "55"))  # must stay below the hook "timeout" in settings


def _load_token(token_file: Path | None = None) -> str:
    environment_token = os.environ.get("ACP_TOKEN", "")
    if environment_token:
        return environment_token
    try:
        with (token_file or TOKEN_FILE).open(encoding="utf-8") as token_stream:
            return token_stream.readline().strip()
    except FileNotFoundError:
        return ""


def main() -> int:
    raw = sys.stdin.read()
    try:
        json.loads(raw)
    except ValueError:
        print("{}", file=sys.stdout)
        print("ACP token missing or rejected", file=sys.stderr)
        return 0
    req = urllib.request.Request(
        URL, data=raw.encode(), method="POST",
        headers={"Content-Type": "application/json", "X-ACP-Token": _load_token()},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode().strip()
    except Exception:
        print("{}", file=sys.stdout)
        print("ACP token missing or rejected", file=sys.stderr)
        return 0
    if body and body != "{}":
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
