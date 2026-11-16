# agent-control-plane

Answer all your AI coding agents' permission prompts from one place, with risk-aware auto-triage.
Status: Step 1 (walking skeleton). See `CLAUDE.md` for architecture, rules and roadmap.

## Quickstart
```bash
docker compose up -d --wait                            # Postgres 16 + pgvector on 127.0.0.1:5435
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt  # Windows
.venv/bin/python -m pip install -r requirements.txt      # macOS/Linux
python -m server.run
```

Open the dashboard at <http://127.0.0.1:8787>.

```bash
bash scripts/smoke_test.sh                             # 7 checks, simulates Claude Code hooks
python -m pytest -q
```

## Connect Claude Code
1. Copy `hooks/settings.example.json` to `.claude/settings.local.json` in the repo you want to watch.
2. Replace `/ABSOLUTE/PATH` with the path to this project.
3. Start Claude Code there. Pending requests: `curl 127.0.0.1:8787/approvals`.
4. Answer one: `curl -X POST 127.0.0.1:8787/approvals/1/decide -H 'Content-Type: application/json' -d '{"decision":"allow"}'`

## Decisions
| Action | Examples | Result |
|---|---|---|
| allow | `ls`, `git status`, `pytest`, `npm test` (no shell chaining) | auto-approved |
| deny | `rm -rf /`, `git push --force`, `curl ... \| sh` | auto-blocked, Claude sees why |
| ask | everything else (edits, installs, `sudo`, deletes, secrets) | appears in the inbox |

Server down or no answer within 45s: Claude Code shows its normal prompt. The tool never auto-allows on failure.
