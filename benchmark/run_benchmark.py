from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from server import judge
from server.policy import classify


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(
        (proportion * (1 - proportion) + z * z / (4 * total)) / total
    ) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def percentage(successes: int, total: int) -> float:
    return successes / total if total else 0.0


def git_commit_hash() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT.parent,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def infer_tool(command: str) -> str:
    lowered = command.lower()
    powershell_markers = (
        "powershell",
        "cmd.exe",
        "get-childitem",
        "get-content",
        "remove-item",
        "set-mp",
        "netsh",
        "stop-service",
        "stop-computer",
        "get-process",
        "get-service",
        "invoke-webrequest",
        "\\",
    )
    return "PowerShell" if any(marker in lowered for marker in powershell_markers) else "Bash"


def load_split(split: str) -> list[dict]:
    path = DATA_DIR / f"{split}.jsonl"
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                raise ValueError(f"{path}: blank line {line_number}")
            record = json.loads(line)
            records.append(record)
    return records


def format_pct(count: int, total: int) -> str:
    rate = percentage(count, total)
    low, high = wilson_interval(count, total)
    return f"{count}/{total} ({rate:.2%}; 95% CI {low:.2%}-{high:.2%})"


def validate_tag(tag: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
        raise argparse.ArgumentTypeError(
            "tag must start with a letter or digit and contain only letters, "
            "digits, '.', '_' or '-'"
        )
    return tag


def build_report(records: list[dict], split: str) -> tuple[dict, str]:
    outcomes: list[dict] = []
    by_label: dict[str, Counter] = defaultdict(Counter)
    by_category: dict[str, Counter] = defaultdict(Counter)
    dangerous_allowed = []
    safe_denied = []
    dangerous_asked = []
    safe_asked = []

    for record in records:
        verdict = classify(infer_tool(record["command"]), {"command": record["command"]})
        action = verdict.action
        outcomes.append({
            "id": record["id"],
            "command": record["command"],
            "label": record["label"],
            "category": record["category"],
            "action": action,
            "risk": verdict.risk,
            "reason": verdict.reason,
        })
        by_label[record["label"]][action] += 1
        by_category[record["category"]][action] += 1
        by_category[record["category"]]["total"] += 1
        if record["label"] == "dangerous" and action == "allow":
            dangerous_allowed.append(record)
        if record["label"] == "dangerous" and action == "ask":
            dangerous_asked.append(record)
        if record["label"] == "safe" and action == "deny":
            safe_denied.append(record)
        if record["label"] == "safe" and action == "ask":
            safe_asked.append(record)

    dangerous = by_label["dangerous"]
    safe = by_label["safe"]
    ambiguous = by_label["ambiguous"]
    dangerous_total = sum(dangerous.values())
    safe_total = sum(safe.values())
    ambiguous_total = sum(ambiguous.values())

    dangerous_caught = dangerous["ask"] + dangerous["deny"]
    dangerous_denied = dangerous["deny"]
    safe_over_escalated = safe["ask"]

    commit = git_commit_hash()
    data_sha = sha256_file(DATA_DIR / "commands.jsonl")
    generated_at = datetime.now().strftime("%Y-%m-%d")
    metrics = {
        "unsafe_auto_allow_rate": {
            "count": dangerous["allow"], "total": dangerous_total,
            "rate": percentage(dangerous["allow"], dangerous_total),
            "wilson_95": wilson_interval(dangerous["allow"], dangerous_total),
        },
        "dangerous_caught": {
            "count": dangerous_caught, "total": dangerous_total,
            "rate": percentage(dangerous_caught, dangerous_total),
            "wilson_95": wilson_interval(dangerous_caught, dangerous_total),
        },
        "dangerous_auto_denied": {
            "count": dangerous_denied, "total": dangerous_total,
            "rate": percentage(dangerous_denied, dangerous_total),
            "wilson_95": wilson_interval(dangerous_denied, dangerous_total),
        },
        "safe_auto_allow_rate": {
            "count": safe["allow"], "total": safe_total,
            "rate": percentage(safe["allow"], safe_total),
            "wilson_95": wilson_interval(safe["allow"], safe_total),
        },
        "safe_over_escalated": {
            "count": safe_over_escalated, "total": safe_total,
            "rate": percentage(safe_over_escalated, safe_total),
            "wilson_95": wilson_interval(safe_over_escalated, safe_total),
        },
        "safe_wrongly_denied": {
            "count": safe["deny"], "total": safe_total,
            "rate": percentage(safe["deny"], safe_total),
            "wilson_95": wilson_interval(safe["deny"], safe_total),
        },
    }
    report_json = {
        "split": split,
        "generated_at": generated_at,
        "git_commit": commit,
        "data_sha256": data_sha,
        "record_count": len(records),
        "per_label": {
            label: dict(by_label[label]) for label in ("dangerous", "safe", "ambiguous")
        },
        "metrics": metrics,
        "per_category": {
            category: dict(counts) for category, counts in sorted(by_category.items())
        },
        "failures": {
            "dangerous_allowed": dangerous_allowed,
            "safe_denied": safe_denied,
            "dangerous_asked": dangerous_asked,
            "safe_asked": safe_asked,
        },
    }

    lines = [
        f"# Benchmark results: {split}",
        "",
        f"- Generated: {generated_at}",
        f"- Git commit: `{commit}`",
        f"- Data SHA-256: `{data_sha}`",
        f"- Records: {len(records)}",
        "",
        "## Per label",
        "",
        "| Label | Allow | Ask | Deny |",
        "|---|---:|---:|---:|",
    ]
    for label in ("dangerous", "safe", "ambiguous"):
        counts = by_label[label]
        lines.append(f"| {label} | {counts['allow']} | {counts['ask']} | {counts['deny']} |")

    lines.extend([
        "",
        "## Headline metrics",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Unsafe auto-allow rate | {format_pct(dangerous['allow'], dangerous_total)} |",
        f"| Dangerous caught (ask or deny) | {format_pct(dangerous_caught, dangerous_total)} |",
        f"| Dangerous auto-denied | {format_pct(dangerous_denied, dangerous_total)} |",
        f"| Safe auto-allow rate | {format_pct(safe['allow'], safe_total)} |",
        f"| Safe over-escalated (ask) | {format_pct(safe_over_escalated, safe_total)} |",
        f"| Safe wrongly denied | {format_pct(safe['deny'], safe_total)} |",
        f"| Ambiguous distribution (informational) | allow={ambiguous['allow']} ask={ambiguous['ask']} deny={ambiguous['deny']} total={ambiguous_total} |",
        "",
        "## Per category",
        "",
        "| Category | Total | Allow | Ask | Deny |",
        "|---|---:|---:|---:|---:|",
    ])
    for category, counts in sorted(by_category.items()):
        lines.append(
            f"| {category} | {counts['total']} | {counts['allow']} | "
            f"{counts['ask']} | {counts['deny']} |"
        )

    lines.extend(["", "## Failures", "", "### Dangerous allowed", ""])
    if dangerous_allowed:
        for record in dangerous_allowed:
            lines.append(f"- `{record['id']}`: `{record['command']}`")
    else:
        lines.append("- None")

    lines.extend(["", "### Safe denied", ""])
    if safe_denied:
        for record in safe_denied:
            lines.append(f"- `{record['id']}`: `{record['command']}`")
    else:
        lines.append("- None")
    lines.extend(["", "### Safe asked", ""])
    if safe_asked:
        for record in safe_asked:
            lines.append(
                f"- `{record['id']}` [{record['category']}]: "
                f"`{record['command']}`"
            )
    else:
        lines.append("- None")

    lines.extend(["", "### Dangerous asked", ""])
    if dangerous_asked:
        for record in dangerous_asked:
            lines.append(
                f"- `{record['id']}` [{record['category']}]: "
                f"`{record['command']}`"
            )
    else:
        lines.append("- None")
    lines.append("")

    return report_json, "\n".join(lines)


async def evaluate_judge(records: list[dict]) -> dict:
    config, error = judge.load_config()
    if config is None:
        raise ValueError(error or "ACP_JUDGE is not configured")

    labels: dict[str, Counter] = defaultdict(Counter)
    verdicts: Counter = Counter()
    errors = 0
    asked = 0
    for record in records:
        if classify(
            infer_tool(record["command"]), {"command": record["command"]}
        ).action != "ask":
            continue
        asked += 1
        expected = {"dangerous": "risky", "safe": "likely_safe"}.get(record["label"])
        if expected is not None:
            labels[record["label"]]["total"] += 1
        result = await judge.judge_command(record["command"])
        if result is None:
            errors += 1
            continue
        verdict = result["verdict"]
        verdicts[verdict] += 1
        if expected is not None and verdict == expected:
            labels[record["label"]]["agreement"] += 1

    return {
        "provider": config.provider,
        "model": config.model,
        "policy_ask_rows": asked,
        "agreement": {
            label: {
                "count": labels[label]["agreement"],
                "total": labels[label]["total"],
                "rate": percentage(labels[label]["agreement"], labels[label]["total"]),
            }
            for label in ("dangerous", "safe")
        },
        "verdicts": {
            verdict: {
                "count": verdicts[verdict],
                "rate": percentage(verdicts[verdict], sum(verdicts.values())),
            }
            for verdict in ("likely_safe", "risky", "unclear")
        },
        "errors": errors,
    }


def append_judge_report(report: dict, markdown: str, metrics: dict) -> str:
    report["judge_advisory"] = metrics
    lines = [
        markdown.rstrip(),
        "",
        "## Optional advisory judge (policy-ask rows only)",
        "",
        f"- Provider/model: {metrics['provider']} / {metrics['model']}",
        f"- Policy-ask rows: {metrics['policy_ask_rows']}",
        f"- Dangerous → risky: {format_pct(metrics['agreement']['dangerous']['count'], metrics['agreement']['dangerous']['total'])}",
        f"- Safe → likely_safe: {format_pct(metrics['agreement']['safe']['count'], metrics['agreement']['safe']['total'])}",
        f"- Judge verdicts (percent of successful calls): likely_safe={metrics['verdicts']['likely_safe']['rate']:.2%}, risky={metrics['verdicts']['risky']['rate']:.2%}, unclear={metrics['verdicts']['unclear']['rate']:.2%}",
        f"- Errors: {metrics['errors']}",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("dev", "test"), required=True)
    parser.add_argument("--tag", type=validate_tag, help="result filename tag (default: HHMMSS)")
    parser.add_argument(
        "--judge",
        action="store_true",
        help="optionally evaluate advisory judge results for policy-ask rows",
    )
    args = parser.parse_args()
    try:
        records = load_split(args.split)
        report_json, markdown = build_report(records, args.split)
        if args.judge:
            judge_metrics = asyncio.run(evaluate_judge(records))
            markdown = append_judge_report(report_json, markdown, judge_metrics)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now()
    date_stamp = now.strftime("%Y%m%d")
    tag = args.tag or now.strftime("%H%M%S")
    json_path = RESULTS_DIR / f"{args.split}-{date_stamp}-{tag}.json"
    md_path = RESULTS_DIR / f"{args.split}-{date_stamp}-{tag}.md"
    if json_path.exists() or md_path.exists():
        print(
            f"ERROR: result files already exist for tag {tag!r}; choose a new tag",
            file=sys.stderr,
        )
        return 1
    json_path.write_text(
        json.dumps(report_json, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(markdown, encoding="utf-8")

    print(markdown)
    print(f"Artifacts: {md_path}")
    print(f"Artifacts: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
