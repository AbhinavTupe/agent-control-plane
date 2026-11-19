<!-- Copy of CLAUDE.md for GitHub Copilot (it auto-loads this path). Keep both files in sync. -->
# agent-control-plane

One local dashboard to see every running AI coding agent, answer their permission prompts from one inbox, and auto-triage by risk. Postgres + pgvector. Portfolio project (AI + backend roles).

## Stack
FastAPI + psycopg3 (async pool) · Postgres 16 + pgvector (docker) · Claude Code hooks · React UI (Step 2)

## Flow
Claude Code hook (`hooks/acp_hook.py`) → `POST /hook` → classify (`server/policy.py`)
→ allow / deny immediately, or park as `pending` → human `POST /approvals/{id}/decide` → hook gets the answer.
Timeout (45s) or client disconnect → server returns `{}` → Claude Code shows its own prompt.

## Rules (non-negotiable)
- Fail-safe: anything unclear or any error = ask a human. NEVER auto-allow on failure.
- Server binds 127.0.0.1 only. Optional shared secret via `ACP_TOKEN`.
- With `ACP_TOKEN` set, dashboard login uses an in-memory 12-hour HttpOnly session cookie; hook endpoints still require the existing token header.
- Parameterized SQL only. No string-formatted queries.
- `server/policy.py` stays pure (no I/O) and fully unit-tested. Every new rule needs a test.
- No new dependencies without asking. Small diffs. Run `pytest -q` before saying done.
- Repository rules are a convenience layer, not a security boundary.

benchmark/: never tune policy on the test split; benchmark/results/test-final.* is frozen.

## What's new in v2
- Push updates with Postgres LISTEN/NOTIFY and SSE, polling fallback, and fast graceful shutdown.
- Restrictive `.acp-policy.yml` rules (`deny_contains` / `ask_contains`) use substring matching only, can never loosen built-ins, and invalid files are ignored.
- One-command hook setup: `python -m scripts.install_hook`; validate with `python -m scripts.install_hook --check`.
- Batch approve or deny identical pending requests (same command and repo), never `ask_user` requests.
- Similar-decision hints show real human decisions first; synthetic seeds are badged "example".
- Codex, Cursor, and Antigravity shell adapters share the existing approval flow; install with `python -m scripts.install_hook --agent <codex|cursor|antigravity|all>`. User scope is available for those three agents; Copilot remains project-scoped.
- Evaluation: 112 cases and 0 unsafe auto-allows. This is a regression suite, not an independent benchmark.
- Automated tests: 766 passing.

## Commands
```
docker compose up -d --wait
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt  # Windows
.venv/bin/python -m pip install -r requirements.txt      # macOS/Linux
python -m server.run
bash scripts/smoke_test.sh        # expects 7/7
python -m pytest -q               # policy tests
```

## Verified facts (Claude Code hooks, checked against public docs Nov 2026)
- `PermissionRequest` hook reply: `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow|deny","message":"..."}}}`; empty output = no opinion.
- `PreToolUse` reply uses `permissionDecision: allow|deny|ask` and runs BEFORE permission checks, so it can enforce deny even in bypass mode.
- Exit 2 blocks; exit 1 does NOT block. Our script always exits 0.
- pgvector DDL works on `pgvector/pgvector:pg16`.
- Windows: uvicorn 0.54 uses ProactorEventLoop and ignores loop policies; psycopg async needs SelectorEventLoop; server/run.py passes loop='asyncio:SelectorEventLoop'.
- Host port is 5435 because 5432 conflicts on dev machines.

## Copilot hook — live verification
- Verified live with Copilot in VS Code on 2026-11-17: SSE push; shutdown with an open SSE connection; repository deny and ask rules; installer-generated hook configuration; batch deny of two identical pending approvals.
- Similar-decision real-first ordering is integration-tested only, not visually verified live.
- `preToolUse` payload fields are camelCase: `cwd`, `sessionId`, `toolName`, `toolArgs`, `timestamp`, and `toolCallId`. There is no model field.
- `ask_user` fires the hook with `toolArgs` containing the question `message` and `requestedSchema` enum. The dashboard shows a Question card. The chosen answer is returned by denying the tool call with reason `The user already answered ... Answer: {json}`; Copilot replied "You chose: blue" without its own question box.
- If no answer arrives within 50 seconds (`ACP_QUESTION_SECONDS`), the hook returns `{}` and Copilot shows its own question box.
- The `ask_user` answer flow relies on the model following the message and was tested in one setup only. Copilot labels the denied call "Ask User failed" (cosmetic).
- `/agents` lists sessions from the last 24 hours with agent, folder, state (`waiting`/`active`/`idle`/`inactive`), pending count, and last tool. Two concurrent Copilot chats were both shown as `waiting`.
- Copilot tool names seen: `apply_patch`, `ask_user`, `bash`, `powershell`, `rg`, `view`, `skill`, `stop_powershell`, `tool_search_tool`, and Pylance tools. `rg` and `view` are read-only; sensitive paths still ask. Unknown tools always ask.
- Deny works: Copilot shows "Denied by preToolUse hook: <reason>".
- Pending then human allow works: the command ran after approval.
- Auto-allow (`git status`) works; `decided_by=policy`.
- After 45 seconds, the hook returns `{}`, Copilot shows its own prompt, and the row is expired/timeout.
- Chained commands (`;` or `|`) arrive as one string; any deny pattern blocks the whole line.
- The hook loads only if the VS Code workspace root is the folder that directly contains `.github`.
- Server down: the hook prints `{}` and Copilot falls back to its own approval prompt; no hang, no auto-allow (verified live 2026-11-17).

## Demo
1. Auto-allow `Get-Date`.
2. Deny `Stop-Computer`.
3. Escalate an uncertain command to a human and decide it in the inbox.
4. Answer an agent's `ask_user` question from its Question card.
5. Run two agents at once and see both waiting in the Agents panel.

## Limitations
- Only GitHub Copilot in VS Code has been verified; testing has been on Windows only. Claude Code adapter, other agents, and Mac/Linux remain unverified.
- Repository rules are a convenience layer, not a security boundary.
- `PermissionRequest` only fires when Claude Code would have prompted anyway. To enforce blocks on commands the user's settings already allow, add a `PreToolUse` hook (Step 3).

## Roadmap
- Verify the Claude Code adapter, other agents, and Mac/Linux.
- Consider an optional LLM judge for uncertain commands only.
- Build and report an independent benchmark.
