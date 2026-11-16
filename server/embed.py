from __future__ import annotations

from threading import Lock

_model = None
_model_lock = Lock()


def _get_model():
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                from fastembed import TextEmbedding

                _model = TextEmbedding("BAAI/bge-small-en-v1.5")
    return _model


def embed(text: str) -> list[float]:
    vector = [float(value) for value in next(_get_model().embed([text]))]
    if len(vector) != 384:
        raise ValueError(f"expected a 384-dimensional embedding, got {len(vector)}")
    return vector


def to_pgvector(vec: list[float]) -> str:
    return "[" + ",".join(repr(float(value)) for value in vec) + "]"
