import pytest


@pytest.fixture(autouse=True)
def isolate_acp_token(monkeypatch, tmp_path):
    monkeypatch.delenv("ACP_TOKEN", raising=False)
    token_file = tmp_path / "token-isolation" / ".acp-token"

    from hooks import acp_hook, copilot_hook
    from scripts import install_hook, set_token
    from server import main

    for module in (main, acp_hook, copilot_hook, install_hook, set_token):
        monkeypatch.setattr(module, "TOKEN_FILE", token_file)
