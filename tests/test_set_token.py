from scripts import set_token


def test_set_token_refuses_overwrite_without_printing_token(tmp_path, capsys, monkeypatch):
    token_file = tmp_path / ".acp-token"
    token_file.write_text("existing-secret\n", encoding="utf-8")
    monkeypatch.setattr(set_token.secrets, "token_urlsafe", lambda _length: "generated-secret")

    assert set_token.main([], repo_root=tmp_path) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "generated-secret" not in captured.err
    assert "existing-secret" not in captured.err
    assert token_file.read_text(encoding="utf-8") == "existing-secret\n"


def test_set_token_prints_only_file_path(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(set_token.secrets, "token_urlsafe", lambda _length: "generated-secret")

    assert set_token.main([], repo_root=tmp_path) == 0

    captured = capsys.readouterr()
    assert captured.out == str((tmp_path / ".acp-token").resolve()) + "\n"
    assert captured.err == ""
    assert "generated-secret" not in captured.out
    assert (tmp_path / ".acp-token").read_text(encoding="utf-8") == "generated-secret\n"


def test_set_token_force_replaces_existing_file(tmp_path, monkeypatch):
    token_file = tmp_path / ".acp-token"
    token_file.write_text("existing-secret\n", encoding="utf-8")
    monkeypatch.setattr(set_token.secrets, "token_urlsafe", lambda _length: "replacement-secret")

    assert set_token.main(["--force"], repo_root=tmp_path, output=lambda _path: None) == 0
    assert token_file.read_text(encoding="utf-8") == "replacement-secret\n"
