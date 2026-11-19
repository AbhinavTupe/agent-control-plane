import argparse
import secrets
import sys
from pathlib import Path
from typing import Callable


TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path | None = None,
    output: Callable[[str], None] = print,
) -> int:
    parser = argparse.ArgumentParser(description="Create the local ACP authentication token.")
    parser.add_argument("--force", action="store_true", help="replace an existing token file")
    args = parser.parse_args(argv)

    token_path = (repo_root / ".acp-token") if repo_root is not None else TOKEN_FILE
    token = secrets.token_urlsafe(24)
    try:
        if args.force:
            token_path.write_text(token + "\n", encoding="utf-8")
        else:
            with token_path.open("x", encoding="utf-8") as token_file:
                token_file.write(token + "\n")
    except FileExistsError:
        print(f"Refusing to overwrite {token_path}; use --force", file=sys.stderr)
        return 1

    output(str(token_path.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
