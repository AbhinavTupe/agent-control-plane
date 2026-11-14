# Step 1 prompt for GitHub Copilot (Agent mode)

Open this folder in VS Code, switch Copilot Chat to **Agent mode**, paste everything inside the block below.
The prompt is self-contained: it names the files to read, so it works even if Copilot ignores CLAUDE.md.

Windows: run the terminal commands in WSL or Git Bash (the smoke test is a bash script). If `python3` is not found, use `python`.

```
You are working in the agent-control-plane repo (open in this workspace).
FIRST read these files fully, before doing anything else: CLAUDE.md, README.md, db/init.sql,
server/main.py, server/policy.py, hooks/acp_hook.py, scripts/smoke_test.sh.

What it is: a local FastAPI server that receives Claude Code permission-request hooks, applies safety
rules, stores everything in Postgres + pgvector, and lets a human approve or deny.

Rules for everything you do:
- Fail-safe: on any error, timeout or unclear case, ask a human. Never auto-allow on failure.
- Server binds 127.0.0.1 only. Parameterized SQL only.
- server/policy.py stays pure (no I/O) and every rule has a unit test.
- No new dependencies, no redesign, no new features, minimal diffs. Run pytest -q before saying done.
- Do not edit CLAUDE.md or .github/copilot-instructions.md, except to replace an UNVERIFIED item
  with an observed fact.

TASK A (do now, in the terminal):
1. docker compose up -d ; pip install -r requirements.txt ;
   start the server in the background: python3 -m uvicorn server.main:app --host 127.0.0.1 --port 8787
2. Run bash scripts/smoke_test.sh (must print "7 passed, 0 failed") and pytest -q (must pass).
   If db/init.sql fails (pgvector extension, vector column or HNSW index), fix it with the smallest
   change and tell me exactly what you changed.
3. Create docs/day1-findings.md: a table with columns check | expected | observed | status and one row per
   live check a-f listed below, observed left empty.
Then STOP and tell me to run the live checks myself. Do not continue to Task B.

Live checks (I will run these in Claude Code in a scratch repo):
 a. Ask Claude to "create hello.txt containing hi": the Write request appears in GET /approvals; I approve it with
    curl; the file is created.
 b. Same request, but I deny it with a reason: Claude reports the denial and the reason.
 c. Ask Claude to run "git push --force origin main": auto-denied by policy, and Claude sees the message.
 d. Server stopped, ask for an edit: Claude Code falls back to its own native prompt.
 e. Leave a request unanswered for 45s: the native prompt appears and the approval row is expired/timeout.
 f. Ask Claude to ask me a question with its question tool: record whether any hook fires and what the payload is.

TASK B (only after I paste my results):
1. Fill in docs/day1-findings.md from my results. Use SELECT kind, tool_name, payload FROM events for evidence.
2. Fix only what failed: minimal diff, add or adjust a test, rerun smoke test and pytest.
3. Replace each UNVERIFIED item in CLAUDE.md and .github/copilot-instructions.md with the observed fact.
4. Report: pass/fail table, differences between real hook payloads and what CLAUDE.md assumed,
   and a one-paragraph recommendation for Step 2.
```

## Your part (Task A to Task B)
In a scratch git repo (not a real project): copy hooks/settings.example.json to `.claude/settings.local.json`,
replace `/ABSOLUTE/PATH` with this project's path, start Claude Code, run checks a to f, then paste what you saw
into Copilot chat. Approve a request with:
`curl -X POST 127.0.0.1:8787/approvals/1/decide -H "Content-Type: application/json" -d '{"decision":"allow"}'`
