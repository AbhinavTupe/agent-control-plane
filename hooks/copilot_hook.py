import os
import sys
import urllib.request


try:
    request = urllib.request.Request(
        "http://127.0.0.1:8787/hook/copilot",
        data=sys.stdin.buffer.read(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-ACP-Token": os.environ.get("ACP_TOKEN", ""),
        },
    )
    with urllib.request.urlopen(request, timeout=55) as response:
        sys.stdout.buffer.write(response.read())
except Exception:
    sys.stdout.write("{}")
