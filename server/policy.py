"""Rules layer: classify a permission request as allow / deny / ask.

Pure functions, no I/O, so they are trivial to unit test.
Order of checks for Bash: block -> high-risk ask -> safe allow -> default ask.
Fail-safe: anything we do not clearly understand becomes "ask" (a human decides).
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    action: str  # allow | deny | ask
    risk: str    # low | medium | high
    reason: str


# Shell metacharacters: if present we never auto-allow (blocks "ls; rm -rf x").
_META = re.compile(r"[;&|<>`$\\\n]")

_SAFE_CMD = re.compile(
    r"^(ls|pwd|whoami|date|which \S+|git (status|diff|log|branch|show)|pytest|"
    r"python3? -m pytest|npm (test|run (test|lint|build))|pnpm (test|lint|build)|"
    r"cargo (test|check|build)|go (test|build|vet)|ruff( check)?|mypy|tsc)(\s|$)"
)

_POWERSHELL_CHAIN = re.compile(r"[;|&>\r\n]")
_POWERSHELL_SAFE = re.compile(
    r"^(?:git\s+(?:status|diff|log)|Get-ChildItem|ls|dir|Get-Content|cat|pytest|"
    r"docker\s+compose\s+ps)(?:\s|$)",
    re.I,
)
_PS_REMOVE = re.compile(r"\bRemove-Item\b([^\r\n]*)", re.I)
_PS_DANGEROUS_TARGET = re.compile(
    r"(?:"
    r"(?<![\w])[A-Za-z]:[\\/]*(?:\*)?(?=\s|$|[\"'])|"
    r"(?<![\w])~(?:[\\/][^\s\"']*)?|"
    r"\$HOME(?:[\\/][^\s\"']*)?|"
    r"\$env:USERPROFILE(?:[\\/][^\s\"']*)?|"
    r"[A-Za-z]:[\\/]Users(?:[\\/][^\s\"']*)?|"
    r"/home/[^/\s\"']+(?:/[^/\s\"']*)?"
    r")",
    re.I,
)
_PS_GIT_FORCE = re.compile(
    r"\bgit\s+push\b[^\r\n]*(?:--force\b(?!-)|(?<!\S)-[a-z]*f[a-z]*(?=\s|$))",
    re.I,
)
_PS_DOWNLOAD = re.compile(r"\b(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b", re.I)
_PS_EXECUTE = re.compile(r"\b(?:iex|Invoke-Expression)\b", re.I)
_PS_DOWNLOAD_PIPE = re.compile(
    r"\b(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^\r\n]*\|\s*"
    r"(?:iex|Invoke-Expression)\b",
    re.I,
)

_BLOCK = [
    (re.compile(r"\bgit\s+push\b[^\n;&|]*(--force\b(?!-)|\s-[a-zA-Z]*f[a-zA-Z]*(\s|$))"),
     "force push can destroy remote history"),
    (re.compile(r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
     "piping a download into a shell"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "formats a filesystem"),
    (re.compile(r"\bdd\s+[^\n]*of=/dev/"), "writes directly to a device"),
    (re.compile(r":\s*\(\s*\)\s*\{"), "fork bomb pattern"),
    (re.compile(r"\bchmod\s+(-\w+\s+)*777\s+/(\s|$)"), "world-writable root"),
    (re.compile(r">\s*/dev/(sd|nvme|disk)"), "overwrites a disk device"),
]

_HIGH_ASK = [
    (re.compile(r"\bsudo\b"), "runs with elevated privileges"),
    (re.compile(r"\bgit\s+(reset\s+--hard|clean\s+-\w*f|checkout\s+--\s+\.)"), "discards local work"),
    (re.compile(r"\bgit\s+push\b[^\n;&|]*--force-with-lease"), "force push (with lease)"),
    (re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE)\b", re.I), "destructive SQL"),
    (re.compile(r"\bkill(all)?\s+-9\b"), "force-kills processes"),
    (re.compile(r"\b(chmod|chown)\s+-R\b"), "recursive permission change"),
    (re.compile(r"\bnpm\s+publish\b"), "publishes a package"),
    (re.compile(r"\bdocker\s+(system\s+prune|rm\s+-f)"), "removes containers or images"),
    (re.compile(r"(\.env\b|id_rsa|\.pem\b|\.aws/credentials|\.ssh/)"), "touches secrets or keys"),
]

_RM_RECURSIVE = re.compile(r"\brm\b[^\n;&|]*\s(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\b")
_RM_CATASTROPHIC = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "*", ".", "./", "..", "../"}

_READ_ONLY = {"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoWrite"}
_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_SENSITIVE_PATH = re.compile(r"(\.env\b|\.git/|id_rsa|\.ssh/|\.pem$|credentials|secrets?)", re.I)


def _rm_verdict(cmd: str) -> Verdict | None:
    if not _RM_RECURSIVE.search(cmd):
        return None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return Verdict("ask", "high", "recursive delete (unparseable command)")
    targets = [t for t in toks[toks.index("rm") + 1:] if not t.startswith("-")] if "rm" in toks else []
    if any(t in _RM_CATASTROPHIC for t in targets):
        return Verdict("deny", "high", "recursive delete of root, home or working tree")
    return Verdict("ask", "high", "recursive delete")


def classify_bash(cmd: str) -> Verdict:
    cmd = (cmd or "").strip()
    if not cmd:
        return Verdict("ask", "medium", "empty command")
    rm = _rm_verdict(cmd)
    if rm:
        return rm
    for rx, why in _BLOCK:
        if rx.search(cmd):
            return Verdict("deny", "high", why)
    for rx, why in _HIGH_ASK:
        if rx.search(cmd):
            return Verdict("ask", "high", why)
    if not _META.search(cmd) and _SAFE_CMD.match(cmd):
        return Verdict("allow", "low", "read-only or test command")
    return Verdict("ask", "medium", "needs human review")


def classify_powershell(cmd: str) -> Verdict:
    cmd = (cmd or "").strip()
    if not cmd:
        return Verdict("ask", "medium", "empty command")
    if _PS_GIT_FORCE.search(cmd):
        return Verdict("deny", "high", "force push can destroy remote history")
    remove = _PS_REMOVE.search(cmd)
    if remove:
        args = remove.group(1)
        if (
            re.search(r"(?<!\S)-Recurse\b", args, re.I)
            and re.search(r"(?<!\S)-Force\b", args, re.I)
            and _PS_DANGEROUS_TARGET.search(args)
        ):
            return Verdict("deny", "high", "recursive delete of root or home")
    if re.search(r"\bFormat-Volume\b", cmd, re.I):
        return Verdict("deny", "high", "formats a volume")
    if _PS_DOWNLOAD_PIPE.search(cmd) or (
        _PS_EXECUTE.search(cmd) and _PS_DOWNLOAD.search(cmd)
    ):
        return Verdict("deny", "high", "executes downloaded content")
    if not _POWERSHELL_CHAIN.search(cmd) and _POWERSHELL_SAFE.match(cmd):
        return Verdict("allow", "low", "read-only or test command")
    return Verdict("ask", "medium", "needs human review")


def _path(tool_input: dict) -> str:
    return str(tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path") or "")


def classify(tool: str, tool_input: dict | None) -> Verdict:
    tin = tool_input or {}
    if tool == "PowerShell":
        return classify_powershell(str(tin.get("command", "")))
    if tool == "Bash":
        return classify_bash(str(tin.get("command", "")))
    path = _path(tin)
    if tool in _READ_ONLY:
        if _SENSITIVE_PATH.search(path):
            return Verdict("ask", "high", "reads a sensitive path")
        return Verdict("allow", "low", "read-only tool")
    if tool in _WRITE:
        if _SENSITIVE_PATH.search(path):
            return Verdict("ask", "high", "writes to a sensitive path")
        return Verdict("ask", "medium", "file modification")
    return Verdict("ask", "medium", "needs human review")


def summarize(tool: str, tool_input: dict | None, limit: int = 300) -> str:
    tin = tool_input or {}
    if tool == "Bash":
        text = str(tin.get("command", ""))
    elif tool in _WRITE or tool in _READ_ONLY:
        text = f"{tool} {_path(tin)}".strip()
    else:
        text = f"{tool} {json.dumps(tin, default=str)}"
    return text[:limit]
