from pathlib import Path


def test_claude_and_copilot_instructions_are_identical():
    repo_root = Path(__file__).resolve().parents[1]

    assert (repo_root / "CLAUDE.md").read_bytes() == (
        repo_root / ".github" / "copilot-instructions.md"
    ).read_bytes()
