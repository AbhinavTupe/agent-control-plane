import json
import sys
from pathlib import Path

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

    printed = json.loads(capsys.readouterr().out)
    assert printed["version"] == 1
    assert not (repo_root / ".github").exists()


def test_check_fails_when_hook_script_is_missing(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    main([], repo_root=repo_root, python_executable=sys.executable)
    monkeypatch.setattr("scripts.install_hook._check_health", lambda: ("WARN", "server unavailable"))
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
        lambda: ("WARN", "server is unavailable"),
    )
    output = []

    result = main(
        ["--check"],
        repo_root=repo_root,
        python_executable=sys.executable,
        output=output.append,
    )

    assert result == 0
    assert [line.split(" ", 1)[0] for line in output] == [
        "PASS",
        "PASS",
        "WARN",
        "PASS",
    ]
    assert any("VS Code must open THIS folder as the workspace root:" in line for line in output)
