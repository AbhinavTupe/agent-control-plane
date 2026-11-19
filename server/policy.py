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
_RM_CATASTROPHIC = {
    "/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$home", "$home/",
    "*", ".", "./", "..", "../",
}

_READ_ONLY = {"Read", "Glob", "Grep", "LS", "NotebookRead"}
_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_SENSITIVE_PATH = re.compile(
    r"(\.env\b|\.git[\\/]|id_rsa|\.ssh(?:[\\/]|$)|\.pem(?:$|[\\/])|credentials|secrets?)",
    re.I,
)


def _normalize_for_match(cmd: str) -> str:
    text = cmd.lower()
    text = text.replace("://", "__scheme__")
    out = []
    quote = None
    i = 0
    while i < len(text):
        char = text[i]
        if char in "'\"":
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            out.append(char)
        elif char == "^" and quote is None:
            i += 1
            if i < len(text):
                out.append(text[i])
        elif char == "`":
            i += 1
            if i < len(text):
                out.append(text[i])
        else:
            out.append(char)
        i += 1

    text = "".join(out)
    text = re.sub(r"(?<=\w)[\"'](?=\w)", "", text)
    text = re.sub(r"(?<!\w)[\"']{2}(?!\w)", "", text)
    text = re.sub(r"[\"']{2}", "", text)
    text = re.sub(r"/{2,}", "/", text)
    text = re.sub(r"\\{2,}", r"\\", text)
    text = re.sub(r"\s+", " ", text)
    text = text.replace("__scheme__", "://")
    return text.strip()


def _split_segments_simple(cmd: str) -> list[str] | None:
    text = cmd
    segments = []
    start = 0
    quote = None
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "\r\n":
            segments.append(text[start:i].strip())
            start = i + 1
        elif char == ";":
            segments.append(text[start:i].strip())
            start = i + 1
        elif char == "&":
            segments.append(text[start:i].strip())
            start = i + 2 if i + 1 < len(text) and text[i + 1] == "&" else i + 1
            i = start - 1
        elif char == "|":
            segments.append(text[start:i].strip())
            start = i + 2 if i + 1 < len(text) and text[i + 1] == "|" else i + 1
            i = start - 1
        i += 1
    if quote:
        return None
    segments.append(text[start:].strip())
    if any(not segment for segment in segments):
        return None
    return segments


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


def _literal_command_tokens(cmd: str) -> list[str] | None:
    if any(char in cmd for char in "\r\n$`") or re.search(
        r"%[^%\s]+%", cmd,
    ):
        return None
    tokens: list[str] = []
    token: list[str] = []
    quote: str | None = None
    active = False
    for index, char in enumerate(cmd):
        if quote:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and cmd[index + 1:index + 2] == '"':
                return None
            else:
                token.append(char)
        elif char in "'\"":
            quote = char
            active = True
        elif char in ";&|<>(){}":
            return None
        elif char.isspace():
            if active:
                tokens.append("".join(token))
                token = []
                active = False
        else:
            token.append(char)
            active = True
    if quote:
        return None
    if active:
        tokens.append("".join(token))
    return tokens or None


_UNSAFE_RELATIVE_PATH = re.compile(
    r"(?:"
    r"^(?:/|\\|[A-Za-z]:[\\/]|~(?:[\\/]|$))|"
    r"(?:^|[\\/])\.\.(?:[\\/]|$)|"
    r"\.env|\.ssh|\.aws|credentials|id_rsa|secret|token"
    r")",
    re.I,
)


def _safe_relative_path(value: str) -> bool:
    return bool(value) and not _UNSAFE_RELATIVE_PATH.search(value)


def _narrow_read_only_allow(cmd: str) -> bool:
    tokens = _literal_command_tokens(cmd)
    if not tokens:
        return False
    words = [token.lower() for token in tokens]
    command = words[0]

    def paths_are_safe(paths: list[str]) -> bool:
        return all(_safe_relative_path(path) for path in paths)

    if command == "git":
        args = words[1:]
        if args == ["tag"] or args in (["tag", "--list"], ["tag", "-l"]):
            return True
        if len(args) == 3 and args[0] == "tag" and args[1] in {"--list", "-l"}:
            return not tokens[3].startswith("-") and _safe_relative_path(tokens[3])
        if args in (["rev-parse", "head"], ["rev-parse", "--short", "head"],
                    ["rev-parse", "--abbrev-ref", "head"]):
            return True
        if args == ["ls-files"]:
            return True
        if len(args) == 2 and args[0] == "ls-files":
            return not tokens[2].startswith("-") and paths_are_safe(tokens[2:])
        if len(args) >= 2 and args[0] == "grep":
            options = {"-n", "-i", "-F", "-l", "-c", "-w"}
            index = 1
            while index < len(args) and tokens[index + 1] in options:
                index += 1
            if index < len(args) and not args[index].startswith("-"):
                paths = tokens[index + 2:]
                return all(not path.startswith("-") for path in paths) and paths_are_safe(paths)
        return False

    if command in {"pwd", "get-location"}:
        return len(tokens) == 1
    if command == "pip":
        return words[1:] in (["--version"], ["freeze"], ["list"]) or (
            len(words) == 3 and words[1] == "list"
            and words[2].startswith("--format=")
            and bool(words[2][9:])
        )
    if command == "python":
        return words[1:] == ["--version"] or words[1:] == ["-m", "pip", "--version"] or (
            words[1:] in (["-m", "pip", "freeze"], ["-m", "pip", "list"])
        ) or (
            len(words) == 5 and words[1:4] == ["-m", "pip", "list"]
            and words[4].startswith("--format=") and bool(words[4][9:])
        )
    if command == "npm":
        args = words[1:]
        return (
            args in (["--version"], ["-v"])
            or args in (["outdated"], ["outdated", "--json"], ["outdated", "--long"])
            or args in (["audit"], ["audit", "--json"], ["audit", "--omit=dev"])
        )
    if command == "docker":
        args = words[1:]
        if args and args[0] in {"ps", "images"}:
            return len(args) == 1 or (len(args) == 2 and args[1] in {"-a", "-q"})
        if len(args) >= 2 and args[:2] == ["compose", "ps"]:
            return len(args) == 2 or (len(args) == 3 and args[2] in {"-a", "-q"})
        if len(args) >= 2 and args[:2] == ["compose", "logs"]:
            index = 2
            if index < len(args) and re.fullmatch(r"--tail=\d+", args[index]):
                index += 1
            if index < len(args) and args[index] == "--no-color":
                index += 1
            if index == len(args):
                return True
            return (
                index + 1 == len(args)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", tokens[index + 1])
                is not None
            )
        return False
    if command == "tasklist":
        return words[1:] in ([], ["/svc"], ["/v"])
    if command == "netstat":
        return words[1:] in (["-an"], ["-ano"])
    if command == "get-scheduledtask":
        return len(tokens) == 1
    if command == "type":
        return len(tokens) == 2 and _safe_relative_path(tokens[1])
    if command in {"rg", "grep"}:
        options = {"-n", "-i", "-F", "-l", "-c", "-w", "-r", "--no-heading"}
        index = 1
        while index < len(words) and tokens[index] in options:
            index += 1
        if index >= len(words) or words[index].startswith("-"):
            return False
        paths = tokens[index + 1:]
        return all(not path.startswith("-") for path in paths) and paths_are_safe(paths)
    return False


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


def _strictest(left: Verdict | None, right: Verdict) -> Verdict:
    if left is None:
        return right
    rank = {"allow": 0, "ask": 1, "deny": 2}
    return right if rank[right.action] > rank[left.action] else left


def _literal_text_or_search_segment(cmd: str) -> bool:
    if re.match(r"^echo\b", cmd, re.I):
        return not re.search(r"[|;&]", cmd) and not re.search(
            r"(?:@reboot|\* \* \* \* \*|crontab\b)", cmd, re.I,
        )
    return bool(re.match(
        r"^(?:rg\b|grep\b|git\s+grep\b)",
        cmd,
        re.I,
    )) or bool(re.search(r"^git\s+log\b.*--grep\b", cmd, re.I))


def _mask_read_only_search_literals(cmd: str) -> str | None:
    if "$" in cmd or "`" in cmd:
        return None
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if not tokens:
        return None

    executable = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if executable in {"rg", "rg.exe", "grep", "grep.exe", "select-string"}:
        is_search = True
    elif executable in {"git", "git.exe"} and len(tokens) > 1:
        subcommand_index = 2 if tokens[1].lower() == "--no-pager" else 1
        if subcommand_index >= len(tokens):
            return None
        subcommand = tokens[subcommand_index].lower()
        is_search = subcommand == "grep" or (
            subcommand == "log"
            and any(
                token == "--grep" or token.startswith("--grep=")
                for token in tokens[subcommand_index + 1:]
            )
        )
    else:
        is_search = False
    if not is_search:
        return None
    if any(
        re.match(r"^(?:--pre|--hostname-bin|-exec|--output)(?:=|$)", token, re.I)
        for token in tokens[1:]
    ):
        return None

    masked = []
    quote = None
    had_quoted_argument = False
    i = 0
    while i < len(cmd):
        char = cmd[i]
        if quote:
            if char == quote:
                quote = None
                masked.append(char)
            elif char == "\\" and quote == '"' and i + 1 < len(cmd):
                masked.extend((" ", " "))
                i += 1
            else:
                masked.append(" ")
        elif char in "'\"":
            quote = char
            had_quoted_argument = True
            masked.append(char)
        elif char in "\r\n;&|<>(){}":
            return None
        else:
            masked.append(char)
        i += 1
    if quote or not had_quoted_argument:
        return None
    return "".join(masked)


def _mask_single_quoted_output(cmd: str) -> str | None:
    match = re.fullmatch(
        r"[ \t]*(echo|printf|write-output|write-host)[ \t]+'([^'\r\n]*)'[ \t]*",
        cmd,
        re.I,
    )
    if not match:
        return None
    return f"{match.group(1)} ''"


def _has_encoded_powershell_switch(cmd: str) -> bool:
    segments = _split_segments_simple(_normalize_for_match(cmd))
    if not segments:
        return False
    for segment in segments:
        try:
            tokens = shlex.split(segment, posix=False)
        except ValueError:
            continue
        normalized_tokens = [token.strip("'\"").lower() for token in tokens]
        has_powershell = any(
            token.replace("0", "o").replace("/", "\\").rsplit("\\", 1)[-1]
            in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
            for token in normalized_tokens
        )
        has_encoded_flag = any(
            token in {"-e", "-ec", "-enc"}
            or (
                len(token) > 2
                and len(token) <= len("-encodedcommand")
                and "-encodedcommand".startswith(token)
            )
            for token in normalized_tokens
        )
        if has_powershell and has_encoded_flag:
            return True
    return False


def _new_deny_verdict(cmd: str) -> Verdict | None:
    if re.search(r"\b(?:del|erase|rd|rmdir)\b", cmd, re.I) and re.search(r"(?:^|\s)/s(?:\s|$)", cmd, re.I):
        if re.search(
            r"(?:[a-z]:[\\/]*(?:\s|$)|"
            r"[a-z]:[\\/]+(?:windows|users)(?:[\\/]*\*?)?(?:\s|$)|"
            r"%systemroot%(?:[\\/]|$|\s))",
            cmd,
            re.I,
        ):
            return Verdict("deny", "high", "recursive delete of a drive root or system path")
    if re.search(
        r"\b(?:del|erase|rd|rmdir)\b[^\r\n]*\b/s\b[^\r\n]*"
        r"(?:[a-z]:[\\/]*(?:\s|$)|"
        r"[a-z]:[\\/]?(?:windows|users)(?:[\\/]*\*?)?(?:\s|$)|"
        r"%systemroot%(?:[\\/]|$))",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "recursive delete of a drive root or system path")
    if re.search(r"^format\s+[a-z]:(?:\s|/|$)", cmd, re.I):
        return Verdict("deny", "high", "formats a disk volume")
    if re.search(r"\bcipher\b.*(?:^|\s)/w\s*:", cmd, re.I):
        return Verdict("deny", "high", "wipes a drive or directory")
    if re.search(r"\bwipefs\b.*(?:^|\s)-a(?:\s|$)", cmd, re.I):
        return Verdict("deny", "high", "wipes filesystem signatures")
    if re.search(r"\bmkfs(?:\.[\w-]+)?\b", cmd, re.I):
        return Verdict("deny", "high", "formats a filesystem")
    if re.search(r"\bremove-partition\b", cmd, re.I) or re.search(
        r"\bclear-disk\b.*-removedata\b", cmd, re.I,
    ):
        return Verdict("deny", "high", "removes disk partitions or data")

    if re.search(
        r"\b(?:del|erase|rd|rmdir)\b[^\r\n]*\b/s\b"
        r"[^\r\n]*(?:"
        r"[a-z]:[\\/]*$|"
        r"[a-z]:[\\/]?(?:windows|users)(?:[\\/]*\*?)?(?:\s|$)|"
        r"%systemroot%(?:[\\/]|$)"
        r")",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "recursive delete of a drive root or system path")

    if re.search(r"\bgit\s+reflog\s+expire\b.*--expire\s*=\s*now\b", cmd, re.I):
        return Verdict("deny", "high", "expires Git reflog history")
    if re.search(r"\bgit\s+update-ref\s+(?:-[a-z]*d[a-z]*|--delete)\b", cmd, re.I):
        return Verdict("deny", "high", "deletes a Git reference")
    if re.search(r"\bgit\s+gc\b.*--prune\s*=\s*now\b", cmd, re.I):
        return Verdict("deny", "high", "permanently prunes Git objects")

    if re.search(r"\breg(?:\.exe)?\s+add\b.*\\run(?:\\[^ ]*)?(?:\s|$)", cmd, re.I):
        return Verdict("deny", "high", "adds a Run registry persistence entry")
    if re.search(r"\bset-itemproperty\b[^\r\n]*\\run(?:\\|\s|:|$)", cmd, re.I):
        return Verdict("deny", "high", "adds a Run registry persistence entry")
    if re.search(
        r"\bschtasks(?:\.exe)?\s+/create\b.*(?:/sc\s+(?:onstart|onlogon)\b|/on(?:start|logon)\b)",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "creates a startup scheduled task")
    if re.search(
        r"(?:>\s*|>>\s*|tee\s+)"
        r"[^\r\n]*(?:/etc/cron\.d/|/etc/crontab|/var/spool/cron)",
        cmd,
        re.I,
    ) or re.search(
        r"\becho\b.*(?:@reboot|\* \* \* \* \*)[^\r\n]*\|\s*crontab\b",
        cmd,
        re.I,
    ) or re.search(r"\bcrontab\b.*(?:/etc/cron|@reboot)", cmd, re.I):
        return Verdict("deny", "high", "writes a startup cron entry")

    if re.search(r"\bget-credential\b.*\|\s*export-clixml\b", cmd, re.I):
        return Verdict("deny", "high", "exports credentials")
    if re.search(
        r"(?:cat|type)\b[^\r\n]*"
        r"(?:~[/\\]\.ssh[/\\](?:id_[\w-]+)|\.ssh[/\\]id_[\w-]+)",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "reads an SSH private key")
    if re.search(
        r"(?:cat|type|get-content|gc)\b[^\r\n]*"
        r"(?:\.aws[/\\]credentials|"
        r"\.config[/\\]gcloud[/\\]application_default_credentials\.json)",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "reads stored credentials")

    if re.search(r"\brundll32(?:\.exe)?\b.*\bjavascript\s*:", cmd, re.I):
        return Verdict("deny", "high", "executes JavaScript through rundll32")
    if re.search(r"\bmshta(?:\.exe)?\b.*https?://", cmd, re.I):
        return Verdict("deny", "high", "executes remote HTA content")
    if _has_encoded_powershell_switch(cmd):
        return Verdict("deny", "high", "executes encoded PowerShell")

    if re.search(r"\bbcdedit(?:\.exe)?\b.*\/set\b.*\brecoveryenabled\b", cmd, re.I):
        return Verdict("deny", "high", "changes boot recovery settings")
    if re.search(r"\bvssadmin(?:\.exe)?\b.*\bdelete\s+shadows\b", cmd, re.I):
        return Verdict("deny", "high", "deletes volume shadow copies")
    if re.search(r"\bwmic(?:\.exe)?\b.*\bshadowcopy\s+delete\b", cmd, re.I):
        return Verdict("deny", "high", "deletes volume shadow copies")
    if re.search(r"\bwevtutil(?:\.exe)?\b.*\bcl\b", cmd, re.I):
        return Verdict("deny", "high", "clears Windows event logs")

    if re.search(
        r"\bcurl(?:\.exe)?\b.*(?:"
        r"--upload-file(?:\s|=)|(?:^|\s)-t(?:\s|=)|"
        r"--data-binary(?:\s|=)[^\r\n]*@|(?:^|\s)-d(?:\s|=)[^\r\n]*@"
        r")",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "uploads or posts file data")

    if re.search(r"\bdrop\s+database\b", cmd, re.I):
        return Verdict("deny", "high", "drops a database")
    if re.search(r"\b(?:redis-cli\b.*\bflush(?:all|db)\b|flush(?:all|db)\b)", cmd, re.I):
        return Verdict("deny", "high", "flushes Redis data")
    if re.search(
        r"\bmongo(?:db)?\b[^\r\n]*(?:\bdropdatabase\s*\(|\.drop\s*\(|dropdatabase\s*\b)",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "drops MongoDB data")

    if "/dev/tcp" in cmd:
        return Verdict("deny", "high", "uses a reverse-shell TCP device")
    if re.search(r"\b(?:nc|ncat)(?:\.exe)?\b.*(?:-e\b|--exec\b)", cmd, re.I):
        return Verdict("deny", "high", "executes a process through a network connection")
    if re.search(
        r"(?:python(?:3)?\b|ruby\b|perl\b)[^\r\n]*"
        r"(?:socket|tcpsocket|fsockopen)[^\r\n]*(?:exec|dup2|popen|open\s*\(|getstream)",
        cmd,
        re.I,
    ):
        return Verdict("deny", "high", "combines a network socket with process execution")

    if re.search(r"\b(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\r\n]*\|"
                 r"\s*(?:iex|invoke-expression)\b", cmd, re.I):
        return Verdict("deny", "high", "executes downloaded content")
    if re.search(r"\b(?:curl|wget)\b[^\r\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", cmd, re.I):
        return Verdict("deny", "high", "piping a download into a shell")
    return None


def _whole_string_deny_verdict(cmd: str, powershell: bool) -> Verdict | None:
    verdict = None

    recursive_delete = _rm_verdict(cmd)
    if recursive_delete and recursive_delete.action == "deny":
        verdict = _strictest(verdict, recursive_delete)

    new_deny = _new_deny_verdict(cmd)
    if new_deny:
        verdict = _strictest(verdict, new_deny)

    if powershell:
        if _PS_GIT_FORCE.search(cmd):
            verdict = _strictest(
                verdict,
                Verdict("deny", "high", "force push can destroy remote history"),
            )
        remove = _PS_REMOVE.search(cmd)
        if remove:
            args = remove.group(1)
            if (
                re.search(r"(?<!\S)-Recurse\b", args, re.I)
                and re.search(r"(?<!\S)-Force\b", args, re.I)
                and _PS_DANGEROUS_TARGET.search(args)
            ):
                verdict = _strictest(
                    verdict,
                    Verdict("deny", "high", "recursive delete of root or home"),
                )
        if re.search(r"\bFormat-Volume\b", cmd, re.I):
            verdict = _strictest(verdict, Verdict("deny", "high", "formats a volume"))
        if _PS_EXECUTE.search(cmd) and _PS_DOWNLOAD.search(cmd):
            verdict = _strictest(
                verdict,
                Verdict("deny", "high", "executes downloaded content"),
            )

    for rx, why in _BLOCK:
        if rx.search(cmd):
            verdict = _strictest(verdict, Verdict("deny", "high", why))
    return verdict


def classify_bash(cmd: str) -> Verdict:
    original = (cmd or "").strip()
    if not original:
        return Verdict("ask", "medium", "empty command")
    output_masked = _mask_single_quoted_output(original)
    scan_source = output_masked if output_masked is not None else original
    masked = _mask_read_only_search_literals(scan_source)
    normalized = _normalize_for_match(masked if masked is not None else scan_source)
    scan_masked = output_masked is not None or masked is not None
    strictest = _whole_string_deny_verdict(normalized, powershell=False)
    if re.search(r"\btruncate\s+(?:table|database|schema)\b", normalized, re.I):
        strictest = _strictest(
            strictest,
            Verdict("ask", "high", "destructive SQL"),
        )
    if "\n" in original or "\r" in original:
        return _strictest(strictest, Verdict("ask", "medium", "newline-separated command"))
    segments = _split_segments_simple(original)
    if segments is None:
        return _strictest(strictest, Verdict("ask", "medium", "needs human review"))

    for segment in segments:
        match_segment = normalized if scan_masked else _normalize_for_match(segment)
        if _literal_text_or_search_segment(match_segment) and not (
            masked is not None and _safe_command_segments(segment)
        ):
            verdict = Verdict("ask", "high", "literal text or read-only search")
        else:
            verdict = None
            rm = _rm_verdict(match_segment)
            if rm:
                verdict = rm
            if re.search(r"\b(?:chmod|chown)\s+-r\b", match_segment, re.I):
                verdict = _strictest(
                    verdict,
                    Verdict("ask", "high", "recursive permission change"),
                )
            if re.search(r"\btruncate\s+(?:table|database|schema)\b", match_segment, re.I):
                verdict = _strictest(
                    verdict,
                    Verdict("ask", "high", "destructive SQL"),
                )
            new_deny = _new_deny_verdict(match_segment)
            if new_deny:
                verdict = _strictest(verdict, new_deny)
            if verdict is None:
                for rx, why in _BLOCK:
                    if rx.search(match_segment):
                        verdict = Verdict("deny", "high", why)
                        break
            if verdict is None:
                for rx, why in _HIGH_ASK:
                    if rx.search(match_segment):
                        verdict = Verdict("ask", "high", why)
                        break
            if verdict is None:
                if _safe_command_segments(segment):
                    verdict = Verdict("allow", "low", "read-only or test command")
                else:
                    verdict = Verdict("ask", "medium", "needs human review")
        strictest = _strictest(strictest, verdict)
    result = strictest or Verdict("ask", "medium", "needs human review")
    if (
        result.action == "ask"
        and result.reason in {"needs human review", "literal text or read-only search"}
        and _narrow_read_only_allow(original)
    ):
        return Verdict("allow", "low", "narrow read-only command")
    return result


def classify_powershell(cmd: str) -> Verdict:
    original = (cmd or "").strip()
    if not original:
        return Verdict("ask", "medium", "empty command")
    output_masked = _mask_single_quoted_output(original)
    scan_source = output_masked if output_masked is not None else original
    masked = _mask_read_only_search_literals(scan_source)
    normalized = _normalize_for_match(masked if masked is not None else scan_source)
    scan_masked = output_masked is not None or masked is not None
    strictest = _whole_string_deny_verdict(normalized, powershell=True)
    if "\n" in original or "\r" in original:
        return _strictest(strictest, Verdict("ask", "medium", "newline-separated command"))
    segments = _split_segments_simple(original)
    if segments is None:
        return _strictest(strictest, Verdict("ask", "medium", "needs human review"))

    for segment in segments:
        match_segment = normalized if scan_masked else _normalize_for_match(segment)
        if _literal_text_or_search_segment(match_segment) and not (
            masked is not None and _safe_command_segments(segment)
        ):
            verdict = Verdict("ask", "high", "literal text or read-only search")
        else:
            verdict = None
            if _PS_GIT_FORCE.search(match_segment):
                verdict = Verdict("deny", "high", "force push can destroy remote history")
            if re.search(r"\b(?:chmod|chown)\s+-r\b", match_segment, re.I):
                verdict = _strictest(
                    verdict,
                    Verdict("ask", "high", "recursive permission change"),
                )
            remove = _PS_REMOVE.search(match_segment)
            if remove:
                args = remove.group(1)
                if (
                    re.search(r"(?<!\S)-Recurse\b", args, re.I)
                    and re.search(r"(?<!\S)-Force\b", args, re.I)
                    and _PS_DANGEROUS_TARGET.search(args)
                ):
                    verdict = _strictest(
                        verdict,
                        Verdict("deny", "high", "recursive delete of root or home"),
                    )
            if re.search(r"\bFormat-Volume\b", match_segment, re.I):
                verdict = _strictest(
                    verdict,
                    Verdict("deny", "high", "formats a volume"),
                )
            if _PS_EXECUTE.search(match_segment) and _PS_DOWNLOAD.search(match_segment):
                verdict = _strictest(
                    verdict,
                    Verdict("deny", "high", "executes downloaded content"),
                )
            new_deny = _new_deny_verdict(match_segment)
            if new_deny:
                verdict = _strictest(verdict, new_deny)
            if verdict is None:
                for rx, why in _BLOCK:
                    if rx.search(match_segment):
                        verdict = Verdict("deny", "high", why)
                        break
            if verdict is None:
                for rx, why in _HIGH_ASK:
                    if rx.search(match_segment):
                        verdict = Verdict("ask", "high", why)
                        break
            if verdict is None:
                if _safe_command_segments(segment):
                    verdict = Verdict("allow", "low", "read-only or test command")
                else:
                    verdict = Verdict("ask", "medium", "needs human review")
        strictest = _strictest(strictest, verdict)
    result = strictest or Verdict("ask", "medium", "needs human review")
    if (
        result.action == "ask"
        and result.reason in {"needs human review", "literal text or read-only search"}
        and _narrow_read_only_allow(original)
    ):
        return Verdict("allow", "low", "narrow read-only command")
    return result


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
        search_targets = [path]
        if tool == "Grep":
            for target in (tin.get("paths"), tin.get("pattern")):
                if isinstance(target, (list, tuple)):
                    search_targets.extend(str(item) for item in target)
                elif target is not None:
                    search_targets.append(str(target))
        if any(_SENSITIVE_PATH.search(target) for target in search_targets):
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
