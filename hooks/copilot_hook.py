import os
import sys
import urllib.request
from pathlib import Path


TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"


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
    try:
        request = urllib.request.Request(
            "http://127.0.0.1:8787/hook/copilot",
            data=sys.stdin.buffer.read(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-ACP-Token": _load_token(),
            },
        )
        with urllib.request.urlopen(request, timeout=55) as response:
            sys.stdout.buffer.write(response.read())
    except Exception:
        sys.stdout.write("{}")
        print("ACP token missing or rejected", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
