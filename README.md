# Agent Control Plane

One local inbox for GitHub Copilot tool approvals, with a policy engine that blocks risky actions and routes uncertain ones to a human.

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

- **What's new in v2:**
  - Push updates with Postgres LISTEN/NOTIFY and SSE, polling fallback, and fast graceful shutdown.
  - Restrictive per-repository rules in `.acp-policy.yml` (`deny_contains` / `ask_contains`): substring matching only, never loosen built-ins, and invalid files are ignored.
  - One-command hook setup with `python -m scripts.install_hook` and `--check`.
  - Batch approve or deny identical pending requests (same command and repo), never `ask_user` requests.
  - Similar-decision hints show real human decisions first; synthetic seeds are badged "example".
- **Policy engine:** deny rules run before auto-allow rules. Safe-command recognition handles quoted separators and command chains; all unrecognized or uncertain actions require human review.
- **Per-repo rules:** an optional `.acp-policy.yml` in a repository or one of its parent directories can add case-insensitive substring deny/ask rules. These rules can only make decisions more restrictive; invalid files are ignored and the built-in policy remains in effect. They are a convenience layer, not a security boundary. See [.acp-policy.example.yml](./.acp-policy.example.yml).
- **Question cards:** `ask_user` questions appear in the dashboard with their message and answer choices. The chosen answer is returned by denying the tool call with a reason containing the answer.
- **Agents panel:** `/agents` lists sessions from the last 24 hours with agent, folder, state, pending count, and last tool.
- **Dashboard:** vanilla HTML/CSS/JavaScript served by FastAPI, with pending approvals, Approve/Deny controls, recent decisions, an Agents panel, SSE push updates, and polling fallback.
- **Local-only protection:** requests with a non-local Host header, or a foreign Origin on state-changing requests, are rejected (blocks DNS-rebinding and cross-site requests).
- **Precedent memory:** FastEmbed `BAAI/bge-small-en-v1.5` creates 384-dimensional embeddings stored in pgvector with an HNSW cosine index. Similarity results are advisory; real human decisions are shown first and synthetic seeds are badged "example". The policy engine decides first.
- **Evaluation:** [Policy evaluation](docs/eval.md) remains a 112-case regression suite with 0 unsafe auto-allows. It is not an independent benchmark.

## Safety benchmark

The safety benchmark contains 448 labelled commands: 215 dangerous, 161 safe,
and 72 ambiguous. A deterministic hash split assigns 152 to `dev` and 296 to
`test`. The policy was tuned on `dev` only. The frozen test split was run once
at commit `759539d` (see [the final report](benchmark/results/test-final.md)).
This evaluation used the built-in policy only: no repository rules, database,
or embeddings.

| Test metric | v2.0.0 | Current |
|---|---:|---:|
| Unsafe auto-allow | 0/136 (95% CI upper bound 2.75%) | 0/136 (95% CI upper bound 2.75%) |
| Dangerous caught | 136/136 | 136/136 |
| Dangerous auto-denied | 19/136 (14%) | 59/136 (43%) |
| Safe auto-allow | 27/113 (24%) | 35/113 (31%) |
| Safe over-escalated | 84/113 (74%) | 74/113 (65%) |
| Safe wrongly denied | 2/113 | 4/113 |

The safe auto-allow rate was 32/48 on `dev` but 35/113 on `test`; the allow-list
overfit `dev`. Four safe commands were wrongly denied, reflecting the
conservative failure mode:

- `echo 'DROP DATABASE production'`
- `Write-Output 'Set-MpPreference ...'`
- `node -e "console.log('curl | sh')"`
- `mysql -e 'SHOW DATABASES'`

Labels are AI-written from public references, not human-audited. `dev` and
`test` come from one generator, and commands are judged in isolation.

To reproduce the split and a dev run (do not re-evaluate the frozen test split):

```powershell
python -m benchmark.make_split
python -m benchmark.run_benchmark --split dev --tag dev-reproduction
python -m pytest -q
```

## Quickstart (Windows)

First run downloads the ~130MB embedding model; the Postgres container listens on 127.0.0.1:5435.

Install Python and Docker Desktop first. In PowerShell:

```powershell
git clone https://github.com/AbhinavTupe/agent-control-plane.git
cd agent-control-plane
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
docker compose up -d --wait
.\.venv\Scripts\python.exe -m scripts.seed_precedents
.\.venv\Scripts\python.exe -m server.run
```

Run tests: `.\.venv\Scripts\python.exe -m pytest -q`

Open <http://127.0.0.1:8787>.

### Configuration

| Variable | Default |
|---|---|
| `DATABASE_URL` | `postgresql://acp:acp@127.0.0.1:5435/acp` |
| `ACP_PORT` | `8787` |
| `ACP_WAIT_SECONDS` | `45` |
| `ACP_QUESTION_SECONDS` | `50` |
| `ACP_SIM_MIN` | `0.80` |
| `ACP_TOKEN` | Optional; takes precedence over `.acp-token` when non-empty |

### Advisory LLM judge

The advisory judge is built but **unverified against a real model**. It is off
by default (`ACP_JUDGE` unset or `off`), makes no network calls while off, and
never changes policy, approval defaults, or batch decisions. It runs only in the
background for command approvals already marked `ask`; its opinion is display
text for the human reviewer. Results are held in an in-memory TTL cache keyed by
approval ID and normalized-command hash, not in the database.

To try it locally with Ollama, start Ollama and pull a model, then set:

```powershell
ollama pull llama3.2
$env:ACP_JUDGE = "ollama"
$env:ACP_JUDGE_MODEL = "llama3.2"
.\.venv\Scripts\python.exe -m scripts.judge_check
```

Ollama uses `http://127.0.0.1:11434/api/chat` by default; `ACP_JUDGE_URL` can
override it. The OpenAI-compatible `openai` mode requires `ACP_JUDGE_URL`,
`ACP_JUDGE_MODEL`, and a key from `ACP_JUDGE_KEY` or the ignored
`.acp-judge-key` file. **OpenAI mode sends command text outside this machine**;
the server logs a startup warning when that mode is selected. Before sending,
the judge redacts common credential forms and long token-like strings and caps
the command text at 2,000 characters. Requests time out after 8 seconds, at
most two run concurrently, and errors produce no opinion.

`python -m benchmark.run_benchmark --split dev --judge` optionally reports
agreement only for rows the policy marked `ask`; this is separate from policy
metrics. Benchmark use is opt-in and should not be run on the frozen test split.

### Dashboard login

Set a token with `.\.venv\Scripts\python.exe -m scripts.set_token`; use `--force` to replace an existing `.acp-token`. The command prints only the file path. The server and hooks use a non-empty `ACP_TOKEN` environment variable first, otherwise the stripped first line of `.acp-token` in the repository root. If both are missing or empty, login is disabled and the existing open-dashboard behavior is unchanged.

When a token is configured, open the dashboard and enter it in the login form. A successful login sets an in-memory, 12-hour `HttpOnly`, `SameSite=Strict` session cookie; HTTPS requests also receive a `Secure` cookie. Failed logins are limited to five per minute per client IP. Use **Logout** to invalidate the session. Hook requests authenticate with the `X-ACP-Token` header. `python -m scripts.install_hook --check` reports whether a token is available from the environment or file.

### Audit view

Select **Audit** in the dashboard to search approval history by time range, agent, status, risk, decision source, or a substring of the command/summary. Results are newest first and paginated; **Export CSV** downloads up to 5,000 matching rows with spreadsheet formula cells neutralized. The database records `human`, `policy`, `timeout`, `client_gone`, and synthetic `seed` decision sources; it does not distinguish automatic decisions from repository-rule decisions.

### Notifications

Notifications are off by default. Set `ACP_NOTIFY_DESKTOP=1` for Windows desktop toasts, labelled "Windows PowerShell", or `ACP_NTFY_TOPIC=<topic>` for phone alerts via ntfy; optionally set `ACP_NTFY_SERVER` (default `https://ntfy.sh`) and `ACP_NTFY_DETAIL=1` to include command/question summaries. Desktop toasts and phone alerts were both verified live on Windows. ntfy topics are case-sensitive and effectively a password; use a long random topic for real use and keep it private. By default, alerts contain no command text. Phone alerts are inform-only and do not approve or deny requests.

### Connect GitHub Copilot in VS Code

1. Install the hook using the active Python interpreter:

   ```powershell
   python -m scripts.install_hook
   python -m scripts.install_hook --check
   ```

2. Open the repo root (the folder that directly contains `.github`) as the VS Code workspace.
3. Use Copilot Chat normally. Requests routed to a person appear in the dashboard inbox.

### Connect Codex, Cursor, or Antigravity

Install one adapter, or all adapters, from the project root:

```powershell
python -m scripts.install_hook --agent codex
python -m scripts.install_hook --agent cursor
python -m scripts.install_hook --agent antigravity
python -m scripts.install_hook --agent all
```

`--scope project` is the default. Use `--scope user` for Codex (`~/.codex/hooks.json`),
Cursor (`~/.cursor/hooks.json`), or Antigravity (`~/.gemini/config/hooks.json`).
Copilot supports project scope only. `--print` previews configuration and `--check`
validates the selected agent's hook and server connection. Existing configuration
entries are preserved; modified files are backed up as `*.bak`.

All adapters use the same policy and human-approval inbox as Copilot. Unknown shell
types are checked against both Bash and PowerShell rules, taking the stricter result.
Codex cannot express an allow or ask response through this adapter, so those cases
produce no hook output; its native permission flow remains available. Cursor and
Antigravity fall back to asking when the server is unreachable or a human decision
times out.

### Troubleshooting

Hooks load only if the VS Code workspace is the repo root (the folder that directly contains `.github`).

## Demo

1. Auto-allow `Get-Date`.
2. Deny `Stop-Computer`.
3. Escalate an uncertain command to a human and decide it in the inbox.
4. Answer an agent's `ask_user` question from its Question card.
5. Run two agents at once and see both waiting in the Agents panel.

## Verified with GitHub Copilot in VS Code

| Check | Result |
|---|---|
| SSE push updates | Verified live 2026-11-17. |
| Graceful shutdown with an open SSE connection | Verified live 2026-11-17. |
| Repository deny rule | Verified live 2026-11-17. |
| Repository ask rule | Verified live 2026-11-17. |
| Installer-generated hook configuration | Verified live 2026-11-17. |
| Batch deny | Two identical pending approvals were denied together; verified live 2026-11-17. |
| Similar-decision ordering | Real human decisions sort first; integration-tested only, not visually verified live. |
| Server down | The hook prints `{}` and Copilot falls back to its own approval prompt; no hang, no auto-allow (verified live 2026-11-17). |
| Deny | Copilot displays the hook's denial reason. |
| Auto-allow | `git status` proceeds and is recorded as decided by policy. |
| Human approval | A pending command proceeds after approval in the dashboard. |
| 45-second timeout | The hook returns `{}`; Copilot shows its own prompt and the approval expires. |
| `ask_user` answer | The hook receives the question message and enum schema. The dashboard shows a Question card; its answer is returned by denying the tool call with reason `The user already answered ... Answer: {json}`. Copilot replied "You chose: blue" without its own question box. |
| `ask_user` timeout | With no answer within 50 seconds (`ACP_QUESTION_SECONDS`), the hook returns `{}` and Copilot shows its own question box. |
| Agents panel | `/agents` lists sessions from the last 24 hours with agent, folder, state, pending count, and last tool. Two concurrent Copilot chats were both shown as `waiting`. |
| Tool names | Observed Copilot tools include `apply_patch`, `ask_user`, `bash`, `powershell`, `rg`, `view`, `skill`, `stop_powershell`, `tool_search_tool`, and Pylance tools. |
| Similar-decision cards | Precedents appear on a pending card (verified live, incl. retry while the embedding is computed); synthetic seeds are badged "example". |
| Policy evaluation | 112-case regression suite; 0 unsafe auto-allows (not an independent benchmark; see docs/eval.md). |
| Automated tests | `.venv\Scripts\python.exe -m pytest -q`: 766 passed. |

## Limitations / Roadmap

- Only GitHub Copilot in VS Code has been verified; testing has been on Windows only. Claude Code adapter, other agents, and Mac/Linux remain unverified.
- Copilot hooks are a preview feature.
- Verify the Claude Code adapter, other agents, and Mac/Linux.
- Repository rules are a convenience layer, not a security boundary.
- Returning an `ask_user` answer denies the tool call with the answer in its reason. Copilot's UI labels this "Ask User failed" (cosmetic); this relies on the model following the message and has been tested in one setup only.
- Only Copilot is verified for the Agents panel; the Claude Code adapter is untested.
- `rg` and `view` are read-only, but sensitive paths still ask for approval. Unknown tools always ask, so some Copilot tools still wait for a human.
- This is a single-user local service. `ACP_TOKEN` is optional; when set, use the dashboard login form to obtain a session cookie.
- The 81 seed decisions are synthetic and hand-labeled.
- Embeddings capture topic, not risk. For example, `docker compose down` scores about 82% similar to `docker compose logs`; precedent matches are advisory and policy always decides first.
- Consider an optional LLM judge for uncertain commands only.
- Build and report an independent benchmark.

## License

MIT. See LICENSE.
