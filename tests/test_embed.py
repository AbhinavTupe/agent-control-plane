from server import embed as embed_module
from server.embed import embed, to_pgvector


def test_to_pgvector_formats_float_values():
    assert to_pgvector([0.1, -0.25, 1]) == "[0.1,-0.25,1.0]"


def test_embed_uses_model_without_downloading(monkeypatch):
    expected = [0.25] * 384

    class Model:
        def embed(self, texts):
            assert texts == ["Bash: git status"]
            return iter([expected])

    monkeypatch.setattr(embed_module, "_get_model", lambda: Model())
    assert embed("Bash: git status") == expected
