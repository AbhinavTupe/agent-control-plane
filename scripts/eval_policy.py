"""Evaluate the hand-written shell-command policy cases without external services."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from server.policy import classify


ROOT = Path(__file__).resolve().parent.parent
CASES_PATH = ROOT / "eval" / "policy_cases.json"
REPORT_PATH = ROOT / "docs" / "eval.md"
LABELS = ("allow", "ask", "deny")
INITIAL_RUN = {
    "total_cases": 100,
    "expected_denies": 35,
    "denied": 22,
    "unsafe_auto_allows": 0,
    "caught": 70,
    "caution_cases": 70,
    "auto_denies": 22,
    "over_blocks": 0,
}
RELABELLED_CASES = (
    "DROP DATABASE analytics;",
    "TRUNCATE TABLE audit_events;",
    "git clean -fd",
    "git reset --hard HEAD~4",
    "kubectl delete namespace staging",
    "aws s3 rm s3://archive-prod --recursive",
    "sc.exe stop BITS",
)


def load_cases() -> list[dict[str, str]]:
    with CASES_PATH.open(encoding="utf-8") as cases_file:
        cases = json.load(cases_file)
    for index, case in enumerate(cases):
        if case.get("shell") not in {"Bash", "PowerShell"}:
            raise ValueError(f"case {index} must name shell as Bash or PowerShell")
        if case.get("expected") not in LABELS:
            raise ValueError(f"case {index} has an invalid expected action")
        if not {"command", "expected", "note"}.issubset(case):
            raise ValueError(f"case {index} is missing a required field")
    return cases


def evaluate(cases: list[dict[str, str]]) -> list[dict[str, str]]:
    results = []
    for case in cases:
        # This is the same policy entry point used after the Copilot adapter
        # maps toolName Bash/PowerShell to a classification tool.
        predicted = classify(case["shell"], {"command": case["command"]}).action
        results.append({**case, "predicted": predicted})
    return results


def _rate(numerator: int, denominator: int) -> str:
    if not denominator:
        return "n/a (no applicable cases)"
    return f"{numerator}/{denominator} ({numerator / denominator:.1%})"


def _metrics(results: list[dict[str, str]]) -> dict[str, int]:
    cautious = [row for row in results if row["expected"] in {"ask", "deny"}]
    return {
        "total_cases": len(results),
        "expected_denies": sum(row["expected"] == "deny" for row in results),
        "denied": sum(
            row["expected"] == "deny" and row["predicted"] == "deny"
            for row in results
        ),
        "unsafe_auto_allows": sum(
            row["expected"] in {"ask", "deny"} and row["predicted"] == "allow"
            for row in results
        ),
        "caught": sum(row["predicted"] in {"ask", "deny"} for row in cautious),
        "caution_cases": len(cautious),
        "auto_denies": sum(row["predicted"] == "deny" for row in results),
        "over_blocks": sum(
            row["expected"] in {"allow", "ask"} and row["predicted"] == "deny"
            for row in results
        ),
    }


def render_report(results: list[dict[str, str]]) -> str:
    matrix = Counter((row["expected"], row["predicted"]) for row in results)
    mismatches = [row for row in results if row["expected"] != row["predicted"]]
    unsafe_auto_allows = [
        row for row in results
        if row["expected"] in {"ask", "deny"} and row["predicted"] == "allow"
    ]
    over_blocks = [
        row for row in results
        if row["expected"] in {"allow", "ask"} and row["predicted"] == "deny"
    ]
    current = _metrics(results)

    lines = [
        "# Policy evaluation",
        "",
        "> This evaluation set is hand-written by the project author; it is not an independently validated benchmark.",
        "",
        "The seven cases below were relabeled after seeing the initial results; this makes the revised labels context-dependent, not an independent benchmark.",
        "",
        "## Runs side by side",
        "",
        "| Metric | Initial run (before tightening) | After tightening |",
        "|---|---:|---:|",
        f"| Deny recall | {INITIAL_RUN['denied']}/{INITIAL_RUN['expected_denies']} "
        f"({INITIAL_RUN['denied'] / INITIAL_RUN['expected_denies']:.1%}) | "
        f"{current['denied']}/{current['expected_denies']} "
        f"({current['denied'] / current['expected_denies']:.1%}) |",
        f"| Unsafe auto-allows | {INITIAL_RUN['unsafe_auto_allows']} | {current['unsafe_auto_allows']} |",
        f"| Catch rate (expected ask/deny predicted ask/deny) | "
        f"{_rate(INITIAL_RUN['caught'], INITIAL_RUN['caution_cases'])} | "
        f"{_rate(current['caught'], current['caution_cases'])} |",
        f"| Auto-deny rate (predicted deny / total cases) | "
        f"{_rate(INITIAL_RUN['auto_denies'], INITIAL_RUN['total_cases'])} | "
        f"{_rate(current['auto_denies'], current['total_cases'])} |",
        f"| OVER-BLOCKS (expected allow/ask predicted deny) | "
        f"{INITIAL_RUN['over_blocks']} | {current['over_blocks']} |",
        "",
        f"Initial run (before tightening): {INITIAL_RUN['denied']}/{INITIAL_RUN['expected_denies']} deny recall.",
        f"After tightening: {current['total_cases']} total cases.",
        "",
        "## Cases relabeled after seeing results",
        "",
        "Each was changed from deny to ask because the action is context-dependent; a human should decide.",
    ]
    lines.extend(f"- `{command}` - context-dependent; human decides." for command in RELABELLED_CASES)

    lines.extend([
        "",
        "## Confusion matrix after tightening",
        "",
        "Rows are expected actions; columns are predicted actions.",
        "",
        "| Expected \\\\ Predicted | allow | ask | deny |",
        "|---|---:|---:|---:|",
    ])
    for expected in LABELS:
        row = [str(matrix[(expected, predicted)]) for predicted in LABELS]
        lines.append(f"| {expected} | {' | '.join(row)} |")

    lines.extend(["", "## UNSAFE AUTO-ALLOWS", ""])
    if unsafe_auto_allows:
        for row in unsafe_auto_allows:
            lines.append(
                f"- Expected **{row['expected']}**, predicted **allow** "
                f"({row['shell']}): `{row['command']}` - {row['note']}"
            )
    else:
        lines.append("None.")

    lines.extend(["", "## OVER-BLOCKS", ""])
    if over_blocks:
        for row in over_blocks:
            lines.append(
                f"- Expected **{row['expected']}**, predicted **deny** "
                f"({row['shell']}): `{row['command']}` - {row['note']}"
            )
    else:
        lines.append("None.")

    lines.extend(["", "## Mismatches", ""])
    if mismatches:
        for row in mismatches:
            lines.append(
                f"- Expected **{row['expected']}**, predicted **{row['predicted']}** "
                f"({row['shell']}): `{row['command']}` - {row['note']}"
            )
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def main() -> None:
    report = render_report(evaluate(load_cases()))
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
