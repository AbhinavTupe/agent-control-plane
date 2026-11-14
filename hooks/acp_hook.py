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

URL = os.environ.get("ACP_URL", "http://127.0.0.1:8787/hook")
TOKEN = os.environ.get("ACP_TOKEN", "")
TIMEOUT = float(os.environ.get("ACP_TIMEOUT", "55"))  # must stay below the hook "timeout" in settings


def main() -> int:
    raw = sys.stdin.read()
    try:
        json.loads(raw)
    except ValueError:
        return 0
    req = urllib.request.Request(
        URL, data=raw.encode(), method="POST",
        headers={"Content-Type": "application/json", "X-ACP-Token": TOKEN},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode().strip()
    except Exception as exc:  # server down, timeout, 401...
        print(f"acp: {exc}; falling back to Claude Code's own prompt", file=sys.stderr)
        return 0
    if body and body != "{}":
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
