import argparse
import math
import sys
from datetime import datetime

import pytest

from benchmark import run_benchmark
from benchmark.run_benchmark import percentage, validate_tag, wilson_interval


def test_percentage():
    assert percentage(1, 4) == 0.25
    assert percentage(0, 0) == 0.0


def test_wilson_interval_known_bounds():
    low, high = wilson_interval(0, 10)
    assert 0.0 <= low < high
    assert 0.0 < high < 0.5

    low, high = wilson_interval(10, 10)
    assert 0.5 < low < high <= 1.0


def test_wilson_interval_empty_and_interior():
    assert wilson_interval(0, 0) == (0.0, 0.0)
    low, high = wilson_interval(5, 10)
    assert math.isclose(low, 0.2365895936, rel_tol=1e-6)
    assert math.isclose(high, 0.7634104064, rel_tol=1e-6)


def test_validate_tag_accepts_filename_safe_names():
    assert validate_tag("rerun-2.dev") == "rerun-2.dev"


@pytest.mark.parametrize("tag", ["", "../escape", "with spaces", "x/y", "x\\y"])
def test_validate_tag_rejects_non_filename_tags(tag):
    with pytest.raises(argparse.ArgumentTypeError, match="tag must start"):
        validate_tag(tag)


@pytest.mark.parametrize(
    "tag_args,expected_tag",
    [([], "131437"), (["--tag", "before-change"], "before-change")],
)
def test_main_uses_tagged_result_names_and_refuses_overwrite(
    tmp_path, monkeypatch, capsys, tag_args, expected_tag
):
    class FrozenDateTime:
        @classmethod
        def now(cls):
            return datetime(2026, 11, 19, 13, 14, 37)

    monkeypatch.setattr(run_benchmark, "datetime", FrozenDateTime)
    monkeypatch.setattr(run_benchmark, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(run_benchmark, "load_split", lambda split: [])
    monkeypatch.setattr(
        run_benchmark,
        "build_report",
        lambda records, split: ({"split": split}, "# report\n"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_benchmark", "--split", "dev", *tag_args],
    )

    assert run_benchmark.main() == 0
    json_path = tmp_path / f"dev-20261119-{expected_tag}.json"
    md_path = tmp_path / f"dev-20261119-{expected_tag}.md"
    assert json_path.exists()
    assert md_path.exists()
    original_json = json_path.read_text(encoding="utf-8")

    assert run_benchmark.main() == 1
    assert "already exist" in capsys.readouterr().err
    assert json_path.read_text(encoding="utf-8") == original_json
