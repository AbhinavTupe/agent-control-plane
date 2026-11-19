#!/usr/bin/env python3
if __package__:
    from .client import run
else:
    from client import run


URL = "http://127.0.0.1:8787/hook/codex"


def main() -> int:
    return run("codex", URL)


if __name__ == "__main__":
    raise SystemExit(main())
