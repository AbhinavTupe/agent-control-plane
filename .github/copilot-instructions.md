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
- Parameterized SQL only. No string-formatted queries.
- `server/policy.py` stays pure (no I/O) and fully unit-tested. Every new rule needs a test.
- No new dependencies without asking. Small diffs. Run `pytest -q` before saying done.

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
- `preToolUse` payload fields are camelCase: `cwd`, `sessionId`, `toolName`, `toolArgs`, `timestamp`, and `toolCallId`. There is no model field.
- `ask_user` also fires the hook with `toolArgs` containing `message` and `requestedSchema` enum. Answering it from the hook is untested.
- Deny works: Copilot shows "Denied by preToolUse hook: <reason>".
- Pending then human allow works: the command ran after approval.
- Auto-allow (`git status`) works; `decided_by=policy`.
- After 45 seconds, the hook returns `{}`, Copilot shows its own prompt, and the row is expired/timeout.
- Chained commands (`;` or `|`) arrive as one string; any deny pattern blocks the whole line.
- The hook loads only if the VS Code workspace root is the folder containing `.github/hooks`.
- Server-down behavior is untested.

## Known limitation
`PermissionRequest` only fires when Claude Code would have prompted anyway. To enforce blocks on commands the user's settings already allow, add a `PreToolUse` hook (Step 3).

## Roadmap
1. [x] Walking skeleton: schema, hook receiver, rules, approvals API, smoke test. **Live verification with real Claude Code = remaining Step 1 work.**
2. [ ] React inbox + live updates (replace polling with Postgres LISTEN/NOTIFY + WebSocket)
3. [ ] PreToolUse enforcement + per-repo YAML policy + audit view
4. [ ] pgvector precedent memory: embed `approvals.summary` (384-dim), HNSW cosine search, "similar past decisions" badge; seed ~100 labeled commands
5. [ ] LLM judge for ambiguous cases + eval (precision/recall) + README numbers + demo video
