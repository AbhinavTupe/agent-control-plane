import json
import sys
import urllib.error
from pathlib import Path

import pytest

from scripts.install_hook import main


def _config_path(repo_root: Path) -> Path:
    return repo_root / ".github" / "hooks" / "acp.json"


def test_install_writes_valid_json(tmp_path):
    repo_root = tmp_path / "repo"
    (repo_root / "hooks").mkdir(parents=True)
    script_path = repo_root / "hooks" / "copilot_hook.py"
    script_path.write_text("", encoding="utf-8")

    assert main([], repo_root=repo_root, python_executable=sys.executable) == 0

    config = json.loads(_config_path(repo_root).read_text(encoding="utf-8"))
    command = config["hooks"]["preToolUse"][0]["command"]
    assert config["version"] == 1
    assert config["hooks"]["preToolUse"][0]["timeoutSec"] == 60
    assert command.endswith(script_path.resolve().as_posix())
    assert "\\" not in command


def test_install_quotes_only_paths_with_spaces(tmp_path):
    repo_root = tmp_path / "repo with spaces"
    script_path = repo_root / "hooks" / "copilot_hook.py"
    (repo_root / "hooks").mkdir(parents=True)
    script_path.write_text("", encoding="utf-8")
    python_path = tmp_path / "python dir" / "python.exe"

    main([], repo_root=repo_root, python_executable=str(python_path))

    command = json.loads(_config_path(repo_root).read_text(encoding="utf-8"))[
        "hooks"
    ]["preToolUse"][0]["command"]
    assert command == f'"{python_path.as_posix()}" "{script_path.resolve().as_posix()}"'


def test_install_is_idempotent(tmp_path):
    repo_root = tmp_path / "repo"
    (repo_root / "hooks").mkdir(parents=True)
    (repo_root / "hooks" / "copilot_hook.py").write_text("", encoding="utf-8")

    main([], repo_root=repo_root, python_executable=sys.executable)
    config_path = _config_path(repo_root)
    original_bytes = config_path.read_bytes()
    original_stat = config_path.stat()

    main([], repo_root=repo_root, python_executable=sys.executable)

    assert config_path.read_bytes() == original_bytes
    assert config_path.stat().st_mtime_ns == original_stat.st_mtime_ns
    assert not config_path.with_name("acp.json.bak").exists()


def test_install_backs_up_changed_config(tmp_path):
    repo_root = tmp_path / "repo"
    config_path = _config_path(repo_root)
    config_path.parent.mkdir(parents=True)
    old_content = b'{"version":0}\n'
    config_path.write_bytes(old_content)

    main([], repo_root=repo_root, python_executable=sys.executable)

    assert config_path.with_name("acp.json.bak").read_bytes() == old_content
    assert json.loads(config_path.read_text(encoding="utf-8"))["version"] == 1


def test_print_does_not_write(tmp_path, capsys):
    repo_root = tmp_path / "repo"

    assert main(
        ["--print"],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == f"Target: {repo_root / '.github' / 'hooks' / 'acp.json'}"
    printed = json.loads("\n".join(lines[1:]))
    assert printed["version"] == 1
    assert not (repo_root / ".github").exists()


@pytest.mark.parametrize(
    ("agent", "scope", "relative_path"),
    [
        ("antigravity", "user", (".gemini", "config", "hooks.json")),
        ("cursor", "user", (".cursor", "hooks.json")),
        ("codex", "user", (".codex", "hooks.json")),
        ("copilot", "project", (".github", "hooks", "acp.json")),
        ("antigravity", "project", (".agents", "hooks.json")),
        ("cursor", "project", (".cursor", "hooks.json")),
        ("codex", "project", (".codex", "hooks.json")),
    ],
)
def test_print_reports_target_before_config(
    monkeypatch, tmp_path, capsys, agent, scope, relative_path
):
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home)
    repo_root = tmp_path / "repo"

    assert main(
        ["--agent", agent, "--scope", scope, "--print"],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0

    lines = capsys.readouterr().out.splitlines()
    expected_target = (
        home.joinpath(*relative_path)
        if scope == "user"
        else repo_root.joinpath(*relative_path)
    )
    assert lines[0] == f"Target: {expected_target}"
    assert isinstance(json.loads("\n".join(lines[1:])), dict)


def test_check_fails_when_hook_script_is_missing(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    main([], repo_root=repo_root, python_executable=sys.executable)
    monkeypatch.setattr(
        "scripts.install_hook._check_health",
        lambda _token="": ("WARN", "server unavailable"),
    )
    output = []

    result = main(
        ["--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    )

    assert result == 1
    assert any(line.startswith("FAIL ") for line in output)


def test_check_warns_when_server_is_unavailable_without_failing(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo with spaces"
    script_path = repo_root / "hooks" / "copilot_hook.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("print('{}')\n", encoding="utf-8")
    main([], repo_root=repo_root, python_executable=sys.executable)
    monkeypatch.setattr(
        "scripts.install_hook._check_health",
        lambda _token="": ("WARN", "server is unavailable"),
    )
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    output = []

    result = main(
        ["--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    )

    assert result == 0
    assert [line.split(" ", 1)[0] for line in output] == [
        "WARN",
        "PASS",
        "PASS",
        "WARN",
        "PASS",
    ]
    assert "WARN token: missing" in output
    assert any("VS Code must open THIS folder as the workspace root:" in line for line in output)


@pytest.mark.parametrize(
    ("token_env", "token_file", "expected"),
    [
        ("environment-secret", "file-secret\n", "PASS token: found (env)"),
        ("", " file-secret \nignored\n", "PASS token: found (file)"),
        ("", "", "WARN token: missing"),
    ],
)
def test_check_reports_token_source(
    tmp_path, monkeypatch, token_env, token_file, expected
):
    repo_root = tmp_path / "repo"
    script_path = repo_root / "hooks" / "copilot_hook.py"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("print('{}')\n", encoding="utf-8")
    main([], repo_root=repo_root, python_executable=sys.executable)
    (repo_root / ".acp-token").write_text(token_file, encoding="utf-8")
    monkeypatch.setenv("ACP_TOKEN", token_env)
    monkeypatch.setattr(
        "scripts.install_hook._check_health",
        lambda _token="": ("WARN", "server unavailable"),
    )
    output = []

    assert main(
        ["--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    ) == 0
    assert expected in output


def _prepare_check_repo(repo_root: Path) -> None:
    script_path = repo_root / "hooks" / "copilot_hook.py"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text("print('{}')\n", encoding="utf-8")
    main([], repo_root=repo_root, python_executable=sys.executable)


def test_check_sends_token_and_passes_health_probe(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    _prepare_check_repo(repo_root)
    (repo_root / ".acp-token").write_text("file-secret\n", encoding="utf-8")
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    output = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def open_url(request, timeout):
        assert timeout == 2
        assert request.get_header("X-acp-token") == "file-secret"
        return Response()

    monkeypatch.setattr("scripts.install_hook.urllib.request.urlopen", open_url)

    assert main(
        ["--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    ) == 0
    assert "PASS server health endpoint responded" in output


@pytest.mark.parametrize(
    ("token_env", "token_file", "message"),
    [
        (
            "environment-secret",
            "",
            "FAIL server rejected the token: it was likely started with a different "
            "ACP_TOKEN (restart it, clear the ACP_TOKEN env var)",
        ),
        (
            "",
            "",
            "FAIL login is enabled but no token found (run python -m scripts.set_token)",
        ),
    ],
)
def test_check_reports_helpful_message_for_unauthorized_health_probe(
    tmp_path, monkeypatch, token_env, token_file, message
):
    repo_root = tmp_path / "repo"
    _prepare_check_repo(repo_root)
    if token_file:
        (repo_root / ".acp-token").write_text(token_file, encoding="utf-8")
    monkeypatch.setenv("ACP_TOKEN", token_env)
    output = []

    def reject_request(request, timeout):
        if token_env:
            assert request.get_header("X-acp-token") == token_env
        else:
            assert request.get_header("X-acp-token") in ("", None)
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", None, None
        )

    monkeypatch.setattr("scripts.install_hook.urllib.request.urlopen", reject_request)

    assert main(
        ["--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    ) == 1
    assert message in output


@pytest.mark.parametrize(
    ("agent", "relative_path"),
    [
        ("cursor", (".cursor", "hooks.json")),
        ("antigravity", (".agents", "hooks.json")),
        ("codex", (".codex", "hooks.json")),
    ],
)
def test_install_agent_writes_documented_project_config(
    tmp_path, agent, relative_path
):
    repo_root = tmp_path / "repo"
    script_name = f"{agent}_hook.py"
    (repo_root / "hooks").mkdir(parents=True)
    (repo_root / "hooks" / script_name).write_text("", encoding="utf-8")

    assert main(
        ["--agent", agent],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0

    config = json.loads(repo_root.joinpath(*relative_path).read_text(encoding="utf-8"))
    if agent == "cursor":
        entry = config["hooks"]["beforeShellExecution"][0]
        assert config["version"] == 1
        assert entry["timeout"] > 45
        assert entry["failClosed"] is True
        assert entry["command"].endswith(script_name)
    elif agent == "antigravity":
        entry = config["acp"]["PreToolUse"][0]
        assert entry["matcher"] == "run_command"
        assert entry["hooks"][0]["timeout"] > 45
        assert entry["hooks"][0]["command"].endswith(script_name)
    else:
        entry = config["hooks"]["PreToolUse"][0]
        assert entry["matcher"] == "Bash"
        assert entry["hooks"][0]["command"].endswith(script_name)


def test_install_all_agents_keeps_copilot_default_and_adds_adapters(tmp_path):
    repo_root = tmp_path / "repo"
    (repo_root / "hooks").mkdir(parents=True)
    for script_name in (
        "copilot_hook.py",
        "codex_hook.py",
        "cursor_hook.py",
        "antigravity_hook.py",
    ):
        (repo_root / "hooks" / script_name).write_text("", encoding="utf-8")

    assert main(
        ["--agent", "all"],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0

    assert _config_path(repo_root).is_file()
    assert (repo_root / ".codex" / "hooks.json").is_file()
    assert (repo_root / ".cursor" / "hooks.json").is_file()
    assert (repo_root / ".agents" / "hooks.json").is_file()


@pytest.mark.parametrize(
    ("agent", "relative_path", "initial"),
    [
        (
            "cursor",
            (".cursor", "hooks.json"),
            {"version": 1, "hooks": {"beforeShellExecution": [{"command": "other"}], "keep": []}},
        ),
        (
            "antigravity",
            (".agents", "hooks.json"),
            {"other": True, "acp": {"PreToolUse": [{"matcher": "other", "hooks": []}]}},
        ),
        (
            "codex",
            (".codex", "hooks.json"),
            {"other": True, "hooks": {"PreToolUse": [{"matcher": "Read", "hooks": []}]}},
        ),
    ],
)
def test_install_agent_merges_existing_config_and_is_idempotent(
    tmp_path, agent, relative_path, initial
):
    repo_root = tmp_path / "repo"
    config_path = repo_root.joinpath(*relative_path)
    config_path.parent.mkdir(parents=True)
    original = json.dumps(initial).encode()
    config_path.write_bytes(original)
    (repo_root / "hooks").mkdir(parents=True)
    (repo_root / "hooks" / f"{agent}_hook.py").write_text("", encoding="utf-8")

    assert main(
        ["--agent", agent],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0
    installed = json.loads(config_path.read_text(encoding="utf-8"))
    installed_bytes = config_path.read_bytes()
    installed_stat = config_path.stat().st_mtime_ns
    assert config_path.with_name("hooks.json.bak").read_bytes() == original
    assert main(
        ["--agent", agent],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0
    assert config_path.read_bytes() == installed_bytes
    assert config_path.stat().st_mtime_ns == installed_stat
    assert json.loads(config_path.read_text(encoding="utf-8")) == installed
    assert installed.get("other") is True if agent != "cursor" else "keep" in installed["hooks"]
    if agent == "antigravity":
        assert any(
            item.get("matcher") == "other"
            for item in installed["acp"]["PreToolUse"]
        )
    if agent == "codex":
        assert any(
            item.get("matcher") == "Read"
            for item in installed["hooks"]["PreToolUse"]
        )


@pytest.mark.parametrize(
    ("agent", "relative_path"),
    [
        ("cursor", (".cursor", "hooks.json")),
        ("antigravity", (".gemini", "config", "hooks.json")),
        ("codex", (".codex", "hooks.json")),
    ],
)
def test_install_agent_supports_documented_user_scope(
    monkeypatch, tmp_path, agent, relative_path
):
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home)
    repo_root = tmp_path / "repo"
    (repo_root / "hooks").mkdir(parents=True)
    (repo_root / "hooks" / f"{agent}_hook.py").write_text("", encoding="utf-8")

    assert main(
        ["--agent", agent, "--scope", "user"],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 0
    assert home.joinpath(*relative_path).is_file()
    assert not repo_root.joinpath(*relative_path).exists()


def test_user_scope_rejects_copilot_without_writing(tmp_path, capsys):
    repo_root = tmp_path / "repo"

    assert main(
        ["--scope", "user"],
        repo_root=repo_root,
        python_executable=sys.executable,
    ) == 1
    assert "Copilot does not support --scope user" in capsys.readouterr().out
    assert not repo_root.exists()


def test_check_agent_validates_config_and_hook_output(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    script = repo_root / "hooks" / "codex_hook.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('{}')\n", encoding="utf-8")
    main(["--agent", "codex"], repo_root=repo_root, python_executable=sys.executable)
    monkeypatch.setattr(
        "scripts.install_hook._check_health",
        lambda _token="": ("WARN", "server is unavailable"),
    )
    output = []

    assert main(
        ["--agent", "codex", "--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    ) == 0
    assert "PASS hooks.json is valid JSON and the hook script exists" in output
    assert "PASS hook script produced a valid sample response" in output
