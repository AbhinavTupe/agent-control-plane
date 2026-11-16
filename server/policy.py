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


_SAFE_COMMAND = re.compile(
    r"^(?:"
    r"git\s+(?:--no-pager\s+)?(?:status|diff|log|show|branch)(?:\s+--no-pager)?|"
    r"Get-ChildItem|ls|dir|Get-Content|cat|Select-String|Get-Process|Get-Date|"
    r"Select-Object|Sort-Object|Measure-Object|Format-Table|Where-Object|pytest|"
    r"\.venv[\\/]Scripts[\\/]python\.exe\s+-m\s+pytest"
    r")(\s|$)",
    re.I,
)
_GIT_UNSAFE_OPTION = re.compile(
    r"\bgit\b[^\r\n;&|]*(?:--output(?:=|\s|$)|--ext-diff(?:=|\s|$)|"
    r"--textconv(?:=|\s|$)|(?<!\S)-o(?=\s|=|$))",
    re.I,
)
_GIT_BRANCH = re.compile(r"^git\s+(?:--no-pager\s+)?branch(?=\s|$)", re.I)
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
    (re.compile(r"\b(?:Stop-Computer|Restart-Computer)\b", re.I),
     "stops or restarts the computer"),
    (re.compile(r"\bshutdown(?:\.exe)?\b[^\r\n]*(?<!\S)/[srp](?=\s|$)", re.I),
     "shuts down or restarts the computer"),
    (re.compile(
        r"\bSet-MpPreference\b[^\r\n]*(?<!\S)-Disable[\w-]*(?:\s*:\s*|\s+)\$?true\b", re.I,
    ), "disables Microsoft Defender protection"),
    (re.compile(
        r"\bnetsh(?:\.exe)?\s+advfirewall\s+set\b[^\r\n]*\bstate\s+off\b", re.I,
    ), "disables a Windows firewall profile"),
    (re.compile(
        r"\bSet-NetFirewallProfile\b[^\r\n]*(?<!\S)-Enabled(?:\s*:\s*|\s+)\$?false\b", re.I,
    ), "disables a Windows firewall profile"),
    (re.compile(
        r"\breg(?:\.exe)?\s+delete\b[^\r\n]*\b(?:HKLM|HKEY_LOCAL_MACHINE)\\", re.I,
    ), "deletes machine-wide registry data"),
    (re.compile(
        r"\bterraform(?:\.exe)?\s+destroy\b[^\r\n]*(?<!\S)-auto-approve(?:\s|=|$)", re.I,
    ), "destroys infrastructure without confirmation"),
    (re.compile(
        r"(?:^|[;&|]\s*)(?:cmd(?:\.exe)?\s+/c\s+)?(?:del|erase)\b"
        r"(?=[^\r\n]*?(?<!\S)/s(?=\s|$))"
        r"(?=[^\r\n]*?(?<![\w])[A-Z]:[\\/])[^\r\n]*",
        re.I,
    ), "recursively deletes an absolute drive path"),
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
    (re.compile(r"(\.env\b|id_rsa|\.pem\b|\.aws[\\/]+credentials|\.ssh(?:[\\/]|$)|\.git[\\/]|credentials|secrets?)", re.I), "touches secrets or keys"),
]

_RM_RECURSIVE = re.compile(r"\brm\b[^\n;&|]*\s(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\b")
_RM_CATASTROPHIC = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "*", ".", "./", "..", "../"}

_READ_ONLY = {"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoWrite"}
_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_SENSITIVE_PATH = re.compile(
    r"(\.env\b|\.git[\\/]|id_rsa|\.ssh(?:[\\/]|$)|\.pem(?:$|[\\/])|credentials|secrets?)",
    re.I,
)


def _safe_command_segments(cmd: str) -> list[str] | None:
    if "$(" in cmd or "<(" in cmd or any(char in cmd for char in "$`<"):
        return None
    segments: list[str] = []
    start = 0
    quote: str | None = None
    i = 0
    while i < len(cmd):
        char = cmd[i]
        if quote:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and i + 1 < len(cmd):
                i += 1
            elif char == "`" and quote == '"' and i + 1 < len(cmd):
                i += 1
        elif char in "'\"":
            quote = char
        elif char in "\r\n>&`{}":
            return None
        elif char == "$" and cmd[i + 1:i + 2] == "(":
            return None
        elif char == "|" and cmd[i + 1:i + 2] == "|":
            return None
        elif char in ";|":
            segment = cmd[start:i].strip()
            if not segment:
                return None
            segments.append(segment)
            start = i + 1
        i += 1
    if quote:
        return None
    segment = cmd[start:].strip()
    if not segment:
        return None
    segments.append(segment)
    for segment in segments:
        if not _SAFE_COMMAND.match(segment) or _GIT_UNSAFE_OPTION.search(segment):
            return None
        branch = _GIT_BRANCH.match(segment)
        if branch and segment[branch.end():].strip() not in {
            "", "-a", "-r", "-v", "-vv", "--list", "--show-current",
        }:
            return None
    return segments


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
    if _safe_command_segments(cmd):
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
    for rx, why in _BLOCK:
        if rx.search(cmd):
            return Verdict("deny", "high", why)
    for rx, why in _HIGH_ASK:
        if rx.search(cmd):
            return Verdict("ask", "high", why)
    if _safe_command_segments(cmd):
        return Verdict("allow", "low", "read-only or test command")
    return Verdict("ask", "medium", "needs human review")


def _path(tool_input: dict) -> str:
    return str(tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path") or "")


def classify(tool: str, tool_input: dict | None) -> Verdict:
    tin = tool_input or {}
    if tool == "ask_user":
        return Verdict("ask", "low", "question for user")
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


def question_summary(tool_args: object) -> str:
    if not isinstance(tool_args, dict):
        return ""
    message = tool_args.get("message")
    return message if isinstance(message, str) else ""


def parse_question_fields(tool_args: object) -> list[dict[str, object]]:
    if not isinstance(tool_args, dict):
        return []
    schema = tool_args.get("requestedSchema")
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []

    fields = []
    for name, spec in properties.items():
        if not isinstance(name, str):
            continue
        spec = spec if isinstance(spec, dict) else {}
        field_type = spec.get("type")
        if field_type not in {"string", "boolean", "integer", "number"}:
            field_type = "string"
        title = spec.get("title")
        options = spec.get("enum")
        fields.append({
            "name": name,
            "title": title if isinstance(title, str) and title else name,
            "type": field_type,
            "enum": [
                option for option in options
                if type(option) in {str, bool, int, float}
            ] if isinstance(options, list) else [],
        })
    return fields


def question_answer_reply(answer_json: str | None) -> str:
    answer = answer_json or "{}"
    return (
        "The user already answered this question via the control-plane dashboard. "
        f"Answer: {answer}. Do not ask again; continue using this answer."
    )


def question_declined_reply() -> str:
    return "The user declined to answer."
