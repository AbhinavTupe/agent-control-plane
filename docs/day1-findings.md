# Day 1 live-check findings

| check | expected | observed | status |
|---|---|---|---|
| Copilot `preToolUse` payload | Payload includes `cwd`, `sessionId`, `toolName`, `toolArgs`, `timestamp`, and `toolCallId`; model field presence is recorded. | Payload uses camelCase fields `cwd`, `sessionId`, `toolName`, `toolArgs`, `timestamp`, and `toolCallId`. No model field. | observed |
| `ask_user` answer | The hook receives the question and answer choices; record whether a dashboard answer reaches Copilot. | The hook receives `message` and `requestedSchema` enum. The dashboard shows a Question card; the selected answer is returned by denying the tool call with reason `The user already answered ... Answer: {json}`. Copilot replied "You chose: blue" without its own question box. The UI labels the call "Ask User failed" (cosmetic). The flow relies on the model following the message and was tested in one setup only. | observed |
| `ask_user` timeout | Record behavior when there is no dashboard answer within `ACP_QUESTION_SECONDS`. | With no answer within 50 seconds, the hook returns `{}` and Copilot shows its own question box. | observed |
| Agents panel | Verify the `/agents` session list and its fields with concurrent Copilot chats. | `/agents` lists sessions from the last 24 hours with agent, folder, state (`waiting`/`active`/`idle`/`inactive`), pending count, and last tool. Two concurrent Copilot chats were both shown as `waiting`. Claude Code adapter is untested. | observed |
| Deny | A denied request shows the hook's reason in Copilot. | Copilot shows "Denied by preToolUse hook: <reason>". | observed |
| Pending human allow | A pending command runs after a human allows it. | The command ran after approval. | observed |
| Auto-allow | `git status` is allowed by policy and recorded as decided by policy. | Auto-allow works; `decided_by=policy`. | observed |
| 45-second timeout | The hook returns `{}`, Copilot shows its own prompt, and the row is expired/timeout. | After 45 seconds, the hook returns `{}`, Copilot shows its own prompt, and the row is expired/timeout. | observed |
| Chained commands | A chained command is handled as one line for deny-pattern matching. | Commands joined with `;` or `|` arrive as one string; any deny pattern blocks the whole line. | observed |
| Hook loading | The hook loads when the VS Code workspace root contains `.github/hooks`. | The hook loads only if the VS Code workspace root is the folder containing `.github/hooks`. | observed |

Server-down behavior was verified live on 2026-11-17: the hook prints `{}` and Copilot falls back to its own approval prompt, with no hang or auto-allow.
