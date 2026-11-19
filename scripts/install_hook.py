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


TOKEN_FILE = Path(__file__).resolve().parent.parent / ".acp-token"
AGENTS = ("copilot", "codex", "cursor", "antigravity")
HOOK_FILES = {
    "codex": "codex_hook.py",
    "cursor": "cursor_hook.py",
    "antigravity": "antigravity_hook.py",
}


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


def _agent_config(agent: str, repo_root: Path, python_executable: str) -> dict:
    if agent == "copilot":
        return _hook_config(repo_root, python_executable)
    script_path = repo_root / "hooks" / HOOK_FILES[agent]
    command = f"{_quoted_path(Path(python_executable))} {_quoted_path(script_path)}"
    if agent == "cursor":
        return {
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    {"command": command, "timeout": 60, "failClosed": True}
                ]
            },
        }
    if agent == "antigravity":
        return {
            "acp": {
                "PreToolUse": [
                    {
                        "matcher": "run_command",
                        "hooks": [
                            {"type": "command", "command": command, "timeout": 60}
                        ],
                    }
                ]
            }
        }
    if agent == "codex":
        return {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": command}],
                    }
                ]
            }
        }
    raise ValueError(f"unknown agent: {agent}")


def _agent_config_path(agent: str, repo_root: Path, scope: str) -> Path:
    if scope == "user":
        home = Path.home()
        if agent == "copilot":
            raise ValueError("Copilot does not support --scope user")
        if agent == "codex":
            return home / ".codex" / "hooks.json"
        if agent == "cursor":
            return home / ".cursor" / "hooks.json"
        if agent == "antigravity":
            return home / ".gemini" / "config" / "hooks.json"
    if agent == "copilot":
        return repo_root / ".github" / "hooks" / "acp.json"
    project_paths = {
        "codex": (".codex", "hooks.json"),
        "cursor": (".cursor", "hooks.json"),
        "antigravity": (".agents", "hooks.json"),
    }
    parts = project_paths[agent]
    return repo_root.joinpath(*parts)


def _command_uses_script(value: object, filename: str) -> bool:
    return isinstance(value, str) and filename.casefold() in value.casefold()


def _merge_hook_config(agent: str, existing: dict, desired: dict) -> dict:
    merged = json.loads(json.dumps(existing))
    if agent == "cursor":
        hooks = merged.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError("Cursor hooks config must contain an object at 'hooks'")
        entries = hooks.setdefault("beforeShellExecution", [])
        if not isinstance(entries, list):
            raise ValueError("Cursor beforeShellExecution must be a list")
        filename = HOOK_FILES[agent]
        entries[:] = [
            item for item in entries
            if not isinstance(item, dict)
            or not _command_uses_script(item.get("command"), filename)
        ]
        entries.extend(desired["hooks"]["beforeShellExecution"])
        merged["version"] = desired["version"]
        return merged

    section = "acp" if agent == "antigravity" else "hooks"
    hook_name = "PreToolUse"
    root = merged.setdefault(section, {})
    if not isinstance(root, dict):
        raise ValueError(f"{agent} hooks config must contain an object at '{section}'")
    entries = root.setdefault(hook_name, [])
    if not isinstance(entries, list):
        raise ValueError(f"{agent} {hook_name} hooks must be a list")
    filename = HOOK_FILES[agent]
    retained = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
            retained.append(entry)
            continue
        hooks = [
            item for item in entry["hooks"]
            if not isinstance(item, dict)
            or not _command_uses_script(item.get("command"), filename)
        ]
        if hooks or len(hooks) == len(entry["hooks"]):
            copy = dict(entry)
            copy["hooks"] = hooks
            retained.append(copy)
    retained.extend(desired[section][hook_name])
    root[hook_name] = retained
    return merged


def install_agent(
    agent: str,
    repo_root: Path,
    python_executable: str,
    scope: str = "project",
) -> None:
    config_path = _agent_config_path(agent, repo_root, scope)
    desired = _agent_config(agent, repo_root, python_executable)
    if agent == "copilot":
        install(repo_root, python_executable)
        return
    if config_path.is_file():
        existing_bytes = config_path.read_bytes()
        existing = json.loads(existing_bytes.decode("utf-8"))
        if not isinstance(existing, dict):
            raise ValueError(f"{config_path} must contain a JSON object")
        merged = _merge_hook_config(agent, existing, desired)
    else:
        existing_bytes = None
        merged = desired
    contents = (json.dumps(merged, indent=2) + "\n").encode()
    if existing_bytes == contents:
        return
    if existing_bytes is not None:
        config_path.with_name(config_path.name + ".bak").write_bytes(existing_bytes)
    _atomic_write(config_path, contents)


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


def _token_source(token_file: Path) -> str | None:
    if os.environ.get("ACP_TOKEN", ""):
        return "env"
    try:
        with token_file.open(encoding="utf-8") as token_stream:
            if token_stream.readline().strip():
                return "file"
    except FileNotFoundError:
        pass
    return None


def _load_token(token_file: Path | None = None) -> str:
    environment_token = os.environ.get("ACP_TOKEN", "")
    if environment_token:
        return environment_token
    try:
        with (token_file or TOKEN_FILE).open(encoding="utf-8") as token_stream:
            return token_stream.readline().strip()
    except FileNotFoundError:
        return ""


def _check_health(token: str = "") -> tuple[str, str]:
    request = urllib.request.Request(
        "http://127.0.0.1:8787/healthz",
        method="GET",
        headers={"X-ACP-Token": token},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            if response.status == 200:
                return "PASS", "server health endpoint responded"
            return "FAIL", f"server health endpoint returned HTTP {response.status}"
    except urllib.error.HTTPError as error:
        if error.code == 401 and token:
            return (
                "FAIL",
                "server rejected the token: it was likely started with a different "
                "ACP_TOKEN (restart it, clear the ACP_TOKEN env var)",
            )
        if error.code == 401:
            return (
                "FAIL",
                "login is enabled but no token found (run python -m scripts.set_token)",
            )
        return "FAIL", f"server health endpoint returned HTTP {error.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return "WARN", f"server is unavailable ({error})"


def check(
    repo_root: Path,
    python_executable: str,
    output: Callable[[str], None] = print,
    token_file: Path | None = None,
) -> int:
    statuses = []

    def report(status: str, message: str) -> None:
        statuses.append(status)
        _report(output, status, message)

    config_path = repo_root / ".github" / "hooks" / "acp.json"
    token_path = token_file or TOKEN_FILE
    token = _load_token(token_path)
    token_source = _token_source(token_path)
    if token_source:
        report("PASS", f"token: found ({token_source})")
    else:
        report("WARN", "token: missing")

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

    health_status, health_message = _check_health(token)
    report(health_status, health_message)
    report(
        "PASS",
        f"VS Code must open THIS folder as the workspace root: {repo_root}",
    )
    return int("FAIL" in statuses)


def _find_agent_script(value: object, filename: str) -> str | None:
    if isinstance(value, dict):
        command = value.get("command")
        if _command_uses_script(command, filename):
            return command
        for nested in value.values():
            found = _find_agent_script(nested, filename)
            if found:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _find_agent_script(nested, filename)
            if found:
                return found
    return None


def _sample_payload(agent: str, repo_root: Path) -> dict:
    if agent == "cursor":
        return {
            "command": "Get-Date",
            "cwd": str(repo_root),
            "conversation_id": "acp-install-check",
            "hook_event_name": "beforeShellExecution",
        }
    if agent == "antigravity":
        return {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "Get-Date", "Cwd": str(repo_root)},
            },
            "conversationId": "acp-install-check",
        }
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": str(repo_root),
        "session_id": "acp-install-check",
    }


def check_agent(
    agent: str,
    repo_root: Path,
    python_executable: str,
    scope: str = "project",
    output: Callable[[str], None] = print,
    token_file: Path | None = None,
) -> int:
    statuses = []

    def report(status: str, message: str) -> None:
        statuses.append(status)
        _report(output, status, message)

    token_path = token_file or (repo_root / ".acp-token")
    token = _load_token(token_path)
    token_source = _token_source(token_path)
    report(
        "PASS" if token_source else "WARN",
        f"token: found ({token_source})" if token_source else "token: missing",
    )

    script_path = None
    config_path = _agent_config_path(agent, repo_root, scope)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        command = _find_agent_script(config, HOOK_FILES[agent])
        if command is None:
            raise ValueError(f"{HOOK_FILES[agent]} is not configured")
        parts = shlex.split(command)
        if len(parts) < 2:
            raise ValueError("hook command does not include a script path")
        script_path = Path(parts[1])
        if not script_path.is_absolute():
            script_path = repo_root / script_path
        if not script_path.is_file():
            raise FileNotFoundError(f"hook script does not exist: {script_path}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        report("FAIL", f"{config_path.name} is invalid or its hook script is missing ({error})")
    else:
        report("PASS", f"{config_path.name} is valid JSON and the hook script exists")

    if script_path is None or not script_path.is_file():
        report("FAIL", "hook script did not produce a valid sample response")
    else:
        try:
            result = subprocess.run(
                [python_executable, str(script_path)],
                input=json.dumps(_sample_payload(agent, repo_root)),
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                raise ValueError(f"hook exited with status {result.returncode}")
            if result.stdout:
                decoded = json.loads(result.stdout)
                if not isinstance(decoded, dict):
                    raise ValueError("hook output must be a JSON object")
            elif agent != "codex":
                raise ValueError("hook output was empty")
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as error:
            report("FAIL", f"hook script did not produce a valid sample response ({error})")
        else:
            report("PASS", "hook script produced a valid sample response")

    health_status, health_message = _check_health(token)
    report(health_status, health_message)
    return int("FAIL" in statuses)


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path | None = None,
    python_executable: str | None = None,
    output: Callable[[str], None] = print,
) -> int:
    parser = argparse.ArgumentParser(description="Install local agent hooks.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--print", action="store_true", help="print the hook JSON without writing it")
    modes.add_argument("--check", action="store_true", help="check the installed hook and local server")
    parser.add_argument("--agent", choices=(*AGENTS, "all"), default="copilot")
    parser.add_argument("--scope", choices=("project", "user"), default="project")
    args = parser.parse_args(argv)

    root = (repo_root or Path(__file__).resolve().parent.parent).resolve()
    python_path = python_executable or sys.executable
    agents = AGENTS if args.agent == "all" else (args.agent,)
    if args.scope == "user" and "copilot" in agents:
        output("FAIL Copilot does not support --scope user")
        return 1
    if args.print:
        for agent in agents:
            config_path = _agent_config_path(agent, root, args.scope)
            output(f"Target: {config_path}")
            output(json.dumps(_agent_config(agent, root, python_path), indent=2))
        return 0
    if args.check:
        token_file = (repo_root / ".acp-token") if repo_root is not None else None
        results = []
        for agent in agents:
            if agent == "copilot":
                results.append(check(root, python_path, output, token_file))
            else:
                results.append(
                    check_agent(
                        agent,
                        root,
                        python_path,
                        args.scope,
                        output,
                        token_file,
                    )
                )
        return int(any(results))
    for agent in agents:
        install_agent(agent, root, python_path, args.scope)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
