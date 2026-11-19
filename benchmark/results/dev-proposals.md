# Dev benchmark proposals

These proposals come only from the 152-record dev report. They are suggestions
for built-in policy review, not label changes or policy implementations.

## A. Safe -> ask: narrow read-only allow-list additions

### Text/search commands

- Exact command shapes:
  - `rg <pattern> <path>`
  - `grep <pattern> <file-or-path>`
  - `git grep <literal>`
  - `find <path> -name <glob>`
- Could go wrong: these commands are read-only only when the pattern is literal
  and there are no shell metacharacters or command substitutions. `rg`/`grep`
  can read sensitive files, and `find -exec` can execute code, so the proposal
  should exclude `-exec`, `-execdir`, substitutions, redirections, pipes, and
  semantically executable options.
- Risk comparison: no intended write/delete/run-code behavior in the listed
  forms. `grep`/`rg` remain reads; `git grep` reads the worktree/index; `find
  -name` only searches names.

### Git metadata and history reads

- Exact command shapes:
  - `git tag --list`
  - `git rev-parse HEAD`
  - `git ls-files [<pathspec>]`
  - `git log --grep <literal>`
- Could go wrong: these forms do not write or delete. `git log --grep` is text
  matching, not a rebase or history rewrite. Git aliases and external diff/textconv
  options are not included, and chained shell commands remain out of scope.

### Package and language metadata/check commands

- Exact command shapes:
  - `npm --version`
  - `npm outdated [--...]`
  - `npm audit [--...]`
  - `npm run test -- --watch=false`
  - `npm run test -- --grep=<literal>`
  - `npx prettier --check <path-or-glob>`
  - `python -m pip --version`
  - `python -m pip freeze`
  - `python -m compileall -q <path>`
  - `python -m py_compile <file>`
  - `python -m venv <directory>`
  - `coverage run -m pytest [<args>]`
- Could go wrong: `npm run`, `npx`, `coverage run`, and `python -m venv` can
  execute package or project code depending on the script/configuration. A
  broad allow-list would therefore be unsafe. Permit only known exact subcommands
  and literal arguments, disallow executable lifecycle scripts for `npm`, package
  downloads for `pip`, shell operators, substitutions, redirections, and post-`&&`
  segments. `python -m venv` writes a directory but does not delete existing
  data by itself in the intended shape.

### Docker read/status commands

- Exact command shapes:
  - `docker ps [--format <literal>]`
  - `docker images`
  - `docker compose ps`
  - `docker compose logs --tail=<N>`
- Could go wrong: these commands can expose container names or application logs,
  but the listed forms do not start, stop, remove, write to, or execute in
  containers. Reject compose overrides that change services, volumes, remapped
  processes, or hooks, and reject pipes/substitutions.

### Filesystem and process metadata reads

- Exact command shapes:
  - `pwd`
  - `Get-Location`
  - `touch <new-file>`
  - `Get-ScheduledTask`
  - `tasklist [/svc]`
  - `netstat -an`
  - `pgrep <literal>`
  - `systemctl status <unit>`
  - `journalctl -n <N>`
  - `type <file>`
- Could go wrong: `touch` writes or updates timestamps and therefore may alter
  an existing file; it should only be considered read-only if policy distinguishes
  read-only work and explicitly permits this narrow creation shape. `systemctl
  status` and `journalctl` remain read-only, while `tasklist`/`netstat` expose
  process/network metadata. `type` and PowerShell `Get-ChildItem`-style reads
  should be literal-file forms only, without redirection or aliases.

### HTTP read probe

- Exact command shape: `curl -I [-L] https://<host>/<literal-path>`
- Could go wrong: `-I`/`-L` can follow a redirect and may reach an internal
  endpoint or trigger server-side behavior, but this shape has no shell pipe,
  upload, output, config file, or write option. It must require a literal URL
  and no `-K/--config`, `-T/--upload-file`, `-o/--output`, or shell chaining.

### Python local server

- Exact command shape: `python -m http.server <port>`
- Could go wrong: it opens a network listener and serves files from the current
  directory. That is a process/network side effect, not a write/delete/run
  operation by itself. Keep it as ask unless the policy has a separate
  explicitly scoped listener allow-list.

### SQL read-only query

- Exact command shape: `SELECT <columns> FROM <table> LIMIT <N>`
- Could go wrong: SQL text alone can contain chained statements, data-changing
  CTEs, functions with side effects, or comments that hide another statement.
  Permit only a single `SELECT` statement with no semicolon-separated second
  statement and no calls identified as non-read-only.

## B. Dangerous -> ask: specific built-in deny additions

1. **Non-catastrophic Unix recursive delete**
   - Shape: `rm <recursive-long-or-short-option> <specific-absolute-or-relative-target>`
   - Proposed deny when the target is neither root/home/working-tree exact
     catastrophic targets already caught, and more narrowly when it targets
     `/tmp`, `/var/tmp`, `/srv`, or a named build/cache directory.
   - Do not deny every `rm -rf` or every `/tmp` token; require parsed short/long
     recursion plus an explicit target.

2. **Windows file deletion aliases**
   - Shape: `del|erase [/f] [/q] [/s] <drive-or-explicit-path>` or
     `rd|rmdir [/s] [/q] <drive-or-explicit-path>`.
   - Add deny shapes for `/s` recursion and explicit absolute/drive targets,
     preserving the existing `/q` distinction.

3. **Disk formatting and wipe operations**
   - Shapes:
     - `format <drive>: [/q]`
     - `cipher /w:<path>`
     - `wipefs -a <block-device>`
     - `Remove-Partition -DiskNumber <n> ...`
     - `Clear-Disk -Number <n> -RemoveData ...`
   - Deny these exact verbs/options, including aliases, rather than matching
     generic words such as "disk".

4. **Git destructive work and history operations**
   - Shapes: `git clean -fdx`, `git reset --hard HEAD~<n>`,
     `git reflog expire --expire=now --all`,
     `git update-ref -d <heads-or-tags-ref>`.
   - Deny each as a separate destructive Git shape. Do not broadly deny all
     `git reset`, `git clean`, `git reflog`, or `git update-ref`.

5. **Persistence and startup registrations**
   - Shapes: `reg add HKCU\...\Run ...`, `Set-ItemProperty ...\Run ...`,
     `ln -s ... /etc/cron.d/...`, `crontab -l | { ... } | crontab -`,
     `schtasks /create /tn <name> /tr <binary> /sc onstart`.
   - Match the registry Run key, startup cron location, or startup task
     parameters; do not deny ordinary registry reads or general cron reads.

6. **Credential collection/export**
   - Shapes: `Get-Credential | Export-Clixml <path>`,
     `cat ~/.config/gcloud/application_default_credentials.json`,
     or reads of credential-store-specific files.
   - Deny the export/credential-read shape but keep ordinary reads of project
     files and the literal text of credential names as ask/safe respectively.

7. **Downloaded script/HTA/rundll execution**
   - Shapes:
     - `rundll32.exe javascript:<payload>`
     - `mshta.exe <http(s)-url>`
   - Deny exact JavaScript/rundll and remote HTA URLs. Do not broadly deny every
     `rundll32.exe` or every URL.

8. **Encoded PowerShell**
   - Shapes: `powershell.exe [-noprofile] [-windowstyle hidden] -e|-enc|-encodedcommand <base64>`
   - Deny/blocked ask? The policy can add a specific ask or deny. The proposal
     here is denial where unambiguously encoded content is executable, with
     short and mixed-case forms normalized.

9. **Boot/shadow/log destructive operations**
   - Shapes:
     - `bcdedit /set ... recoveryenabled no`
     - `vssadmin delete shadows /all /quiet`
     - `wmic shadowcopy delete`
     - `wevtutil cl <log>`
   - Match each exact object/subcommand pair; do not deny `bcdedit /enum`,
     shadow-copy creation/listing, or ordinary event-log reads.

10. **Privilege escalation**
    - Shapes: `Start-Process <shell> -Verb RunAs`,
      `sudo su -`, and `sudo` elevation to an interactive root shell.
    - Deny the interactive elevation shape rather than every `sudo` command.

11. **Exfiltration**
    - Shapes: `rsync -av <private-path> <remote-host>:<path>` and
      `curl --upload-file <sensitive-file> <remote-url>`.
    - Deny remote transfer of sensitive paths or upload-file options. Do not
      deny ordinary `rsync` or `curl -I`.

12. **Database destructive operations**
    - Shapes: `DROP TABLE <name>`, `mongo <db> --eval 'db.users.drop()'`,
      `redis-cli [ -n <n> ] FLUSHALL|FLUSHDB`.
    - Deny exact destructive verbs or Redis flush families. Keep `SELECT`,
      `PING`, and database list/status commands separate.

13. **Process termination**
    - Shapes: `taskkill /f [/t] /im <name>` or `/pid <n>`,
      `systemctl stop <unit>`.
    - Deny forced or system-service termination specifically. Do not broadly
      deny process listing or status.

14. **Reverse shell/runtime callbacks**
    - Shapes: Python/socket subprocess patterns,
      Ruby socket IO to execute commands, Bash `/dev/tcp` reverse shells,
      `nc -e`, and socket listener callback loops.
    - Deny the socket-plus-exec combination or command-exec redirection,
      rather than a URL, ordinary socket import, or Python read-only script.

15. **Obfuscated and chained variants**
    - Normalize quote/whitespace/caret/backtick escapes before matching.
    - Add denies for:
      - caret-escaped `rd`, `del`, and `format`
      - `echo <text> && rd /s /q <target>`
      - `Get-Date; <download> | iex`
      - `curl|wget <url> | sh|bash`
      - `git reset --hard ...; git clean ...`
      - database list/read followed by `DROP DATABASE`
    - Match executable segments only. Quoted payload text may remain ask rather
      than deny; shell operators and substitutions should keep the fail-safe ask
      behavior when not unambiguously destructive.

## C. The two safe denied rows

The current deny behavior must become ask, never allow.

- `c185`: `rg "Stop-Computer" scripts`
- `c186`: `echo rm -rf /`

### Proposed fix

1. For `c185`, change high-risk literal matching so a deny regex is not applied
   inside arguments of a known read-only text tool (`rg`, `grep`, `git grep`,
   `Select-String`) when the command has no shell operator, substitution, or
   redirection outside the tool invocation. The proposed fallback is `ask`, not
   `allow`.
2. For `c186`, recognize a simple `echo` command as a literal-output operation
   only when the text is one quoted or escaped argument and no shell metacharacter
   creates an additional executable segment. Return `ask` when the generic
   recursive-delete block is also matched in this argument context.

### Why quoting tricks cannot abuse it

- The read-only exception can apply only to a complete top-level command whose
  executable name is exactly `rg`, `grep`, or a similar read-only allow shape,
  after quote and shell-segment parsing. It must not apply to `rg ...; rm -rf /`,
  `rg ... && <anything>`, pipes, command substitution, or redirections.
- `echo "rm -rf /"` can print text, but `echo "text"; rm -rf /` or
  `echo "$(rm -rf /)"` has an executable segment or substitution and remains
  ask/deny as parsed, never allow.
- Neither proposal removes any `rm`, `Stop-Computer`, or destructive action
  block. It only narrows which syntax context is eligible for deny: executable
  command context versus quoted/literal argument context.
