import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
INPUT = DATA_DIR / "commands.jsonl"
DEV = DATA_DIR / "dev.jsonl"
TEST = DATA_DIR / "test.jsonl"
ALLOWED_LABELS = {"dangerous", "safe", "ambiguous"}


def main() -> int:
    if not INPUT.is_file():
        print(f"ERROR: missing input file: {INPUT}", file=sys.stderr)
        return 1

    records = []
    ids = set()
    commands = set()

    with INPUT.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                print(f"ERROR: blank line at {line_number}", file=sys.stderr)
                return 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"ERROR: invalid JSON at line {line_number}: {exc}", file=sys.stderr)
                return 1

            required = {"id", "command", "label", "category", "source"}
            missing = required - record.keys()
            if missing:
                print(
                    f"ERROR: line {line_number} missing fields: {sorted(missing)}",
                    file=sys.stderr,
                )
                return 1
            if record["label"] not in ALLOWED_LABELS:
                print(
                    f"ERROR: line {line_number} has invalid label {record['label']!r}",
                    file=sys.stderr,
                )
                return 1
            if record["id"] in ids:
                print(f"ERROR: duplicate id {record['id']!r}", file=sys.stderr)
                return 1
            if record["command"] in commands:
                print(
                    f"ERROR: duplicate command at line {line_number}: {record['command']!r}",
                    file=sys.stderr,
                )
                return 1

            ids.add(record["id"])
            commands.add(record["command"])
            records.append(record)

    counts = Counter(record["label"] for record in records)
    minimums = {"dangerous": 150, "safe": 150, "ambiguous": 60}
    for label, minimum in minimums.items():
        if counts[label] < minimum:
            print(
                f"ERROR: label {label!r} has {counts[label]} records; need at least {minimum}",
                file=sys.stderr,
            )
            return 1

    categories = Counter(record["category"] for record in records)
    if categories["evasion"] < 40:
        print(
            f"ERROR: category 'evasion' has {categories['evasion']} records; need at least 40",
            file=sys.stderr,
        )
        return 1
    if categories["hard_negative"] < 40:
        print(
            f"ERROR: category 'hard_negative' has {categories['hard_negative']} records; need at least 40",
            file=sys.stderr,
        )
        return 1

    dev = []
    test = []
    for record in records:
        bucket = int(hashlib.sha256(record["id"].encode("utf-8")).hexdigest(), 16) % 10
        split = "dev" if bucket <= 2 else "test"
        split_record = dict(record)
        split_record["split"] = split
        (dev if split == "dev" else test).append(split_record)

    with DEV.open("w", encoding="utf-8", newline="\n") as handle:
        for record in dev:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    with TEST.open("w", encoding="utf-8", newline="\n") as handle:
        for record in test:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    split_counts = Counter(record["split"] for record in dev + test)
    print(f"total={len(records)} dev={split_counts['dev']} test={split_counts['test']}")
    print("labels:")
    for label in ("dangerous", "safe", "ambiguous"):
        print(f"  {label}={counts[label]}")
    print("categories:")
    for category, count in sorted(categories.items()):
        print(f"  {category}={count}")
    print("splits:")
    for split in ("dev", "test"):
        split_records = [record for record in dev + test if record["split"] == split]
        split_labels = Counter(record["label"] for record in split_records)
        print(
            f"  {split}={split_counts[split]} "
            f"dangerous={split_labels['dangerous']} "
            f"safe={split_labels['safe']} "
            f"ambiguous={split_labels['ambiguous']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
