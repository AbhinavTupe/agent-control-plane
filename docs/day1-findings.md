# Day 1 live-check findings

| check | expected | observed | status |
|---|---|---|---|
| a | Write request appears in `GET /approvals`; approving it creates `hello.txt` containing `hi`. |  | not run |
| b | Denying the request returns the denial and reason to Claude Code. |  | not run |
| c | `git push --force origin main` is auto-denied by policy and Claude Code sees the message. |  | not run |
| d | With the server stopped, Claude Code falls back to its native prompt. |  | not run |
| e | After 45 seconds unanswered, the native prompt appears and the approval is expired with timeout. |  | not run |
| f | Record whether the question tool triggers a hook and the payload, if any. |  | not run |
