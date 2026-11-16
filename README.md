# Agent Control Plane

One local inbox for GitHub Copilot tool approvals, with a policy engine that blocks risky actions and routes uncertain ones to a human.

![dashboard](docs/img/dashboard.png)

## Why

Coding agents can ask for permission repeatedly while working. Agent Control Plane collects those requests in one inbox and uses risk-aware auto-triage: clearly safe actions can proceed, known-dangerous actions are denied, and uncertain actions wait for a person.

## How it works

```mermaid
flowchart LR
    A[Copilot preToolUse hook] --> B[hooks/copilot_hook.py]
    B --> C[POST /hook/copilot]
    C --> D{Policy: deny / allow / ask}
    D -->|deny| H[Return deny to Copilot]
    D -->|allow| I[Return allow to Copilot]
    D -->|ask| E[(Pending approval in Postgres)]
    E --> F[Dashboard: Approve or Deny]
    F --> G[Decision returned to waiting hook]
    G --> C
    E -->|45-second timeout| J[Return {}]
    J --> K[Copilot shows its own prompt]
```

The Copilot hook sends its `preToolUse` request to the local API. The policy either responds immediately or records a pending approval and waits. If there is no decision within 45 seconds, the API returns `{}` so Copilot can show its own prompt.

## Features

- **Policy engine:** deny rules run before auto-allow rules. Safe-command recognition handles quoted separators and command chains; all unrecognized or uncertain actions require human review.
- **Dashboard:** vanilla HTML/CSS/JavaScript served by FastAPI, with pending approvals, Approve/Deny controls, recent decisions, sessions, and 1-second polling.
- **Precedent memory:** FastEmbed `BAAI/bge-small-en-v1.5` creates 384-dimensional embeddings stored in pgvector with an HNSW cosine index. Similarity results use human and seed decisions only. They are advisory; the policy engine decides first.

## Quickstart (Windows)

Install Python and Docker Desktop first. In PowerShell:

```powershell
git clone <repository-url> agent-control-plane
cd agent-control-plane
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
docker compose up -d --wait
.\.venv\Scripts\python.exe -m scripts.seed_precedents
.\.venv\Scripts\python.exe -m server.run
```

Open <http://127.0.0.1:8787>.

### Connect GitHub Copilot in VS Code

1. Edit `.github/hooks/acp.json` and set its command to use the **absolute path** to this repo's `hooks/copilot_hook.py` and the absolute path to this repo's `.venv\Scripts\python.exe`. For example, replace the command with a form like:

   ```json
   "command": "\"C:/absolute/path/agent-control-plane/.venv/Scripts/python.exe\" \"C:/absolute/path/agent-control-plane/hooks/copilot_hook.py\""
   ```

2. Open this repository folder itself as the VS Code workspace root (the folder containing `.github`). The hook will not load if the workspace root is a parent or another folder.
3. Use Copilot Chat normally. Requests routed to a person appear in the dashboard inbox.

## Verified with GitHub Copilot in VS Code

| Check | Result |
|---|---|
| Deny | Copilot displays the hook's denial reason. |
| Auto-allow | `git status` proceeds and is recorded as decided by policy. |
| Human approval | A pending command proceeds after approval in the dashboard. |
| 45-second timeout | The hook returns `{}`; Copilot shows its own prompt and the approval expires. |
| Retry and empty states | The dashboard implements retry for similar-decision lookups and empty states for approvals and sessions. |
| Automated tests | `pytest -q`: 137 passed. |

## Limitations

- Only GitHub Copilot in VS Code has been verified live; Copilot hooks are a preview feature.
- Tested on Windows only.
- A Claude Code hook adapter exists, but it has not been verified live.
- Copilot's `ask_user` tool is logged, but its question cannot yet be answered from the dashboard.
- Dashboard updates use polling, not push notifications.
- This is a single-user local service. `ACP_TOKEN` is optional; the dashboard does not send the token, so enabling it also requires a way to authenticate dashboard API requests.
- The 81 seed decisions are synthetic and hand-labeled.
- Embeddings capture topic, not risk. For example, `docker compose down` scores about 82% similar to `docker compose logs`; precedent matches are advisory and policy always decides first.

## Roadmap

- Answer `ask_user` questions from the dashboard.
- Replace polling with Postgres LISTEN/NOTIFY and WebSockets.
- Add per-repository YAML policy.
- Add an LLM judge for ambiguous cases.
- Evaluate policy precision and recall.
