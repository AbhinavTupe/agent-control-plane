# Day 1 live-check findings

| check | expected | observed | status |
|---|---|---|---|
| Copilot `preToolUse` payload | Payload includes `cwd`, `sessionId`, `toolName`, `toolArgs`, `timestamp`, and `toolCallId`; model field presence is recorded. | Payload uses camelCase fields `cwd`, `sessionId`, `toolName`, `toolArgs`, `timestamp`, and `toolCallId`. No model field. | observed |
| `ask_user` hook | Record whether the hook fires, its arguments, and whether answering from the hook works. | The hook fires with `toolArgs` containing `message` and `requestedSchema` enum. Answering it from the hook is untested. | partially observed |
| Deny | A denied request shows the hook's reason in Copilot. | Copilot shows "Denied by preToolUse hook: <reason>". | observed |
| Pending human allow | A pending command runs after a human allows it. | The command ran after approval. | observed |
| Auto-allow | `git status` is allowed by policy and recorded as decided by policy. | Auto-allow works; `decided_by=policy`. | observed |
| 45-second timeout | The hook returns `{}`, Copilot shows its own prompt, and the row is expired/timeout. | After 45 seconds, the hook returns `{}`, Copilot shows its own prompt, and the row is expired/timeout. | observed |
| Chained commands | A chained command is handled as one line for deny-pattern matching. | Commands joined with `;` or `|` arrive as one string; any deny pattern blocks the whole line. | observed |
| Hook loading | The hook loads when the VS Code workspace root contains `.github/hooks`. | The hook loads only if the VS Code workspace root is the folder containing `.github/hooks`. | observed |
| Server down | Record the hook behavior when the server is unavailable. | Untested. | untested |
