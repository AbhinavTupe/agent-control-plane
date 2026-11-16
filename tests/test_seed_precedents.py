from scripts.seed_precedents import ALLOWED_COMMANDS, COMMAND_GROUPS, DENIED_COMMANDS


def test_seed_precedents_are_valid_and_unique():
    assert len(ALLOWED_COMMANDS) + len(DENIED_COMMANDS) >= 60
    assert all(status in {"allowed", "denied"} for _, status in COMMAND_GROUPS)
    assert all(
        risk in {"low", "medium", "high"} and reason
        for commands, _ in COMMAND_GROUPS
        for _, risk, reason in commands
    )

    allowed = [command for command, _, _ in ALLOWED_COMMANDS]
    denied = [command for command, _, _ in DENIED_COMMANDS]
    all_commands = allowed + denied
    assert len(all_commands) == len(set(all_commands))
    assert not set(allowed) & set(denied)
