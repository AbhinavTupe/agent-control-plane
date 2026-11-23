from __future__ import annotations

import asyncio
import sys

from server import judge


SAMPLES = (
    ("clearly safe", "git status --short"),
    ("clearly dangerous", "Remove-Item -Recurse -Force C:\\important"),
    ("ambiguous", "python -m http.server 8000"),
)


async def _check() -> int:
    config, error = judge.load_config()
    if config is None:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    print(f"Provider: {config.provider}")
    print(f"Model: {config.model}")
    results = []
    for label, command in SAMPLES:
        result = await judge.judge_command(command)
        results.append(result)
        if result is None:
            print(f"{label}: ERROR (no verdict)")
        else:
            print(f"{label}: {result['verdict']} — {result['reason']}")

    reachable = any(result is not None for result in results)
    print(f"Reachability: {'reachable' if reachable else 'unreachable'}")
    if not reachable:
        print(
            "ERROR: the judge endpoint did not return a usable response; "
            "check ACP_JUDGE_URL, credentials, model name, and provider status",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    try:
        return asyncio.run(_check())
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
