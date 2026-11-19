import sys
import urllib.request
from pathlib import Path

if __package__:
    from .client import load_token
else:
    from client import load_token


TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"


def _load_token(token_file: Path | None = None) -> str:
    return load_token(token_file or TOKEN_FILE)


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
