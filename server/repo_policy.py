"""Optional, restrictive per-repository policy rules."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from .policy import Verdict

logger = logging.getLogger(__name__)

POLICY_FILENAME = ".acp-policy.yml"
MAX_FILE_SIZE = 16 * 1024
MAX_RULES = 50
MAX_RULE_LENGTH = 200
MAX_PARENT_LEVELS = 6


@dataclass(frozen=True)
class RepoRules:
    deny_contains: tuple[str, ...] = ()
    ask_contains: tuple[str, ...] = ()


_RULE_CACHE: dict[tuple[str, int], RepoRules | None] = {}
_MISSING_WARNED: set[str] = set()


def _cache_rules(path: str, mtime: int, rules: RepoRules | None) -> None:
    key = (path, mtime)
    for cached_key in tuple(_RULE_CACHE):
        if cached_key[0] == path and cached_key != key:
            del _RULE_CACHE[cached_key]
    _RULE_CACHE[key] = rules


def _find_policy_file(cwd: str | None) -> Path | None:
    if not cwd:
        return None
    directory = Path(cwd).resolve()
    for _ in range(MAX_PARENT_LEVELS + 1):
        candidate = directory / POLICY_FILENAME
        if candidate.is_file():
            return candidate
        parent = directory.parent
        if parent == directory:
            break
        directory = parent
    return None


def _parse_rules(data: object) -> RepoRules:
    if not isinstance(data, dict):
        raise ValueError("policy root must be a mapping")

    parsed: dict[str, tuple[str, ...]] = {}
    for key in ("deny_contains", "ask_contains"):
        if key not in data:
            parsed[key] = ()
            continue
        values = data[key]
        if not isinstance(values, list) or len(values) > MAX_RULES:
            raise ValueError(f"{key} must be a list of at most {MAX_RULES} strings")
        if any(
            not isinstance(value, str) or not 1 <= len(value) <= MAX_RULE_LENGTH
            for value in values
        ):
            raise ValueError(f"{key} entries must be strings of 1-{MAX_RULE_LENGTH} characters")
        parsed[key] = tuple(values)
    return RepoRules(**parsed)


def load_repo_rules(cwd: str | None) -> RepoRules:
    try:
        policy_path = _find_policy_file(cwd)
    except (OSError, ValueError) as exc:
        logger.warning("ignoring unavailable repository policy from %r: %s", cwd, exc)
        return RepoRules()
    if policy_path is None:
        search_path = str(Path(cwd).resolve()) if cwd else "<unknown>"
        if search_path not in _MISSING_WARNED:
            logger.warning("no %s found from %s; using built-in policy", POLICY_FILENAME, search_path)
            if len(_MISSING_WARNED) >= 200:
                _MISSING_WARNED.pop()
            _MISSING_WARNED.add(search_path)
        return RepoRules()

    path_key = str(policy_path)
    try:
        mtime = policy_path.stat().st_mtime_ns
        cache_key = (path_key, mtime)
        if cache_key in _RULE_CACHE:
            cached = _RULE_CACHE[cache_key]
            return cached if cached is not None else RepoRules()

        if policy_path.stat().st_size > MAX_FILE_SIZE:
            raise ValueError(f"policy exceeds {MAX_FILE_SIZE} bytes")
        content = policy_path.read_bytes()
        if len(content) > MAX_FILE_SIZE:
            raise ValueError(f"policy exceeds {MAX_FILE_SIZE} bytes")
        data = yaml.safe_load(content.decode("utf-8"))
        rules = _parse_rules(data)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        logger.warning("ignoring invalid repository policy %s: %s", path_key, exc)
        try:
            _cache_rules(path_key, policy_path.stat().st_mtime_ns, None)
        except OSError:
            pass
        return RepoRules()

    _cache_rules(path_key, mtime, rules)
    return rules


def apply_repo_rules(decision: Verdict, text: str, rules: RepoRules) -> Verdict:
    if decision.action == "deny":
        return decision

    lowered_text = " ".join(text.split()).casefold()
    for rule in rules.deny_contains:
        normalized_rule = " ".join(rule.split()).casefold()
        if normalized_rule in lowered_text:
            return Verdict("deny", "high", f"repo policy: contains '{rule}'")
    if decision.action == "allow":
        for rule in rules.ask_contains:
            normalized_rule = " ".join(rule.split()).casefold()
            if normalized_rule in lowered_text:
                return Verdict("ask", "medium", f"repo policy: contains '{rule}'")
    return decision
