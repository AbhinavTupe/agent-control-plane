from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class NormalizedCall:
    agent: str
    session_id: str
    cwd: str | None
    command: str


@dataclass(frozen=True)
class Adapter:
    parse: Callable[[object], NormalizedCall | None]
    render: Callable[[str, str | None], dict | None]


def _cursor_parse(payload: object) -> NormalizedCall | None:
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "beforeShellExecution":
        return None
    command = payload.get("command")
    cwd = payload.get("cwd")
    session_id = payload.get("conversation_id")
    if (
        not isinstance(command, str)
        or not isinstance(cwd, str)
        or not isinstance(session_id, str)
    ):
        return None
    return NormalizedCall("cursor", session_id, cwd, command)


def _cursor_render(decision: str, reason: str | None = None) -> dict:
    if decision == "allow":
        return {"permission": "allow"}
    message = reason or ""
    # UNVERIFIED: Cursor's docs specify these fields, but not their exact mapping
    # to policy messages. Keep the reason visible in both UI message fields.
    return {
        "permission": decision,
        "user_message": message,
        "agent_message": message,
    }


def _antigravity_parse(payload: object) -> NormalizedCall | None:
    if not isinstance(payload, dict):
        return None
    tool_call = payload.get("toolCall")
    if not isinstance(tool_call, dict) or tool_call.get("name") != "run_command":
        return None
    args = tool_call.get("args")
    if not isinstance(args, dict):
        return None
    command = args.get("CommandLine")
    cwd = args.get("Cwd")
    session_id = payload.get("conversationId")
    if (
        not isinstance(command, str)
        or not isinstance(cwd, str)
        or not isinstance(session_id, str)
    ):
        return None
    return NormalizedCall("antigravity", session_id, cwd, command)


def _antigravity_render(decision: str, reason: str | None = None) -> dict:
    if decision == "allow":
        return {"decision": "allow"}
    # UNVERIFIED: The decision/reason fields are specified; exact reason text
    # semantics are not documented.
    return {"decision": decision, "reason": reason or ""}


def _codex_parse(payload: object) -> NormalizedCall | None:
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "PreToolUse":
        return None
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    cwd = payload.get("cwd")
    session_id = payload.get("session_id")
    if (
        not isinstance(command, str)
        or not isinstance(cwd, str)
        or (session_id is not None and not isinstance(session_id, str))
    ):
        return None
    return NormalizedCall("codex", session_id or "unknown", cwd, command)


def _codex_render(decision: str, reason: str | None = None) -> dict | None:
    if decision != "deny":
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason or "",
        }
    }


ADAPTERS = {
    "cursor": Adapter(_cursor_parse, _cursor_render),
    "antigravity": Adapter(_antigravity_parse, _antigravity_render),
    "codex": Adapter(_codex_parse, _codex_render),
}


def fail_safe(agent: str) -> dict | None:
    if agent == "codex":
        return None
    if agent == "cursor":
        return {"permission": "ask", "user_message": "Agent Control Plane unreachable"}
    if agent == "antigravity":
        return {"decision": "ask", "reason": "Agent Control Plane unreachable"}
    raise ValueError(f"unknown hook adapter: {agent}")
