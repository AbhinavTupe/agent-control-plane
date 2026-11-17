import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable


def _quoted_path(path: Path) -> str:
    value = path.resolve().as_posix()
    return f'"{value}"' if " " in value else value


def _hook_config(repo_root: Path, python_executable: str) -> dict:
    python_path = Path(python_executable)
    script_path = repo_root / "hooks" / "copilot_hook.py"
    command = f"{_quoted_path(python_path)} {_quoted_path(script_path)}"
    return {
        "version": 1,
        "hooks": {
            "preToolUse": [
                {
                    "type": "command",
                    "command": command,
                    "timeoutSec": 60,
                }
            ]
        },
    }


def _atomic_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(contents)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def install(repo_root: Path, python_executable: str) -> None:
    config_path = repo_root / ".github" / "hooks" / "acp.json"
    desired = (json.dumps(_hook_config(repo_root, python_executable), indent=2) + "\n").encode()
    if config_path.is_file():
        existing = config_path.read_bytes()
        if existing == desired:
            return
        (config_path.parent / "acp.json.bak").write_bytes(existing)
    _atomic_write(config_path, desired)


def _script_path(config_path: Path, repo_root: Path) -> Path:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    command = config["hooks"]["preToolUse"][0]["command"]
    parts = shlex.split(command)
    if len(parts) < 2:
        raise ValueError("hook command does not include a script path")
    script_path = Path(parts[1])
    return script_path if script_path.is_absolute() else repo_root / script_path


def _report(output: Callable[[str], None], status: str, message: str) -> None:
    output(f"{status} {message}")


def _check_health() -> tuple[str, str]:
    request = urllib.request.Request("http://127.0.0.1:8787/healthz", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            if response.status == 200:
                return "PASS", "server health endpoint responded"
            return "FAIL", f"server health endpoint returned HTTP {response.status}"
    except urllib.error.HTTPError as error:
        return "FAIL", f"server health endpoint returned HTTP {error.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return "WARN", f"server is unavailable ({error})"


def check(
    repo_root: Path,
    python_executable: str,
    output: Callable[[str], None] = print,
) -> int:
    statuses = []

    def report(status: str, message: str) -> None:
        statuses.append(status)
        _report(output, status, message)

    config_path = repo_root / ".github" / "hooks" / "acp.json"
    script_path = None
    try:
        script_path = _script_path(config_path, repo_root)
        if not script_path.is_file():
            raise FileNotFoundError(f"hook script does not exist: {script_path}")
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        report("FAIL", f"acp.json is invalid or its hook script is missing ({error})")
    else:
        report("PASS", "acp.json is valid JSON and the hook script exists")

    if script_path is None or not script_path.is_file():
        report("FAIL", "hook script did not print valid JSON for a sample payload")
    else:
        payload = {
            "sessionId": "acp-install-check",
            "toolName": "view",
            "toolArgs": {"path": str(repo_root / "README.md")},
            "cwd": str(repo_root),
        }
        try:
            result = subprocess.run(
                [python_executable, str(script_path)],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            json.loads(result.stdout)
            if result.returncode != 0:
                raise ValueError(f"hook exited with status {result.returncode}")
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as error:
            report("FAIL", f"hook script did not print valid JSON for a sample payload ({error})")
        else:
            report("PASS", "hook script prints valid JSON for a harmless sample payload")

    health_status, health_message = _check_health()
    report(health_status, health_message)
    report(
        "PASS",
        f"VS Code must open THIS folder as the workspace root: {repo_root}",
    )
    return int("FAIL" in statuses)


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path | None = None,
    python_executable: str | None = None,
    output: Callable[[str], None] = print,
) -> int:
    parser = argparse.ArgumentParser(description="Install the local Copilot hook.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--print", action="store_true", help="print the hook JSON without writing it")
    modes.add_argument("--check", action="store_true", help="check the installed hook and local server")
    args = parser.parse_args(argv)

    root = (repo_root or Path(__file__).resolve().parent.parent).resolve()
    python_path = python_executable or sys.executable
    if args.print:
        output(json.dumps(_hook_config(root, python_path), indent=2))
        return 0
    if args.check:
        return check(root, python_path, output)
    install(root, python_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
