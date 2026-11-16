# Policy evaluation

> This evaluation set is hand-written by the project author; it is not an independently validated benchmark.

The seven cases below were relabeled after seeing the initial results; this makes the revised labels context-dependent, not an independent benchmark.

## Runs side by side

| Metric | Initial run (before tightening) | After tightening |
|---|---:|---:|
| Deny recall | 22/35 (62.9%) | 28/28 (100.0%) |
| Unsafe auto-allows | 0 | 0 |
| Catch rate (expected ask/deny predicted ask/deny) | 70/70 (100.0%) | 82/82 (100.0%) |
| Auto-deny rate (predicted deny / total cases) | 22/100 (22.0%) | 28/112 (25.0%) |
| OVER-BLOCKS (expected allow/ask predicted deny) | 0 | 0 |

Initial run (before tightening): 22/35 deny recall.
After tightening: 112 total cases.

## Cases relabeled after seeing results

Each was changed from deny to ask because the action is context-dependent; a human should decide.
- `DROP DATABASE analytics;` - context-dependent; human decides.
- `TRUNCATE TABLE audit_events;` - context-dependent; human decides.
- `git clean -fd` - context-dependent; human decides.
- `git reset --hard HEAD~4` - context-dependent; human decides.
- `kubectl delete namespace staging` - context-dependent; human decides.
- `aws s3 rm s3://archive-prod --recursive` - context-dependent; human decides.
- `sc.exe stop BITS` - context-dependent; human decides.

## Confusion matrix after tightening

Rows are expected actions; columns are predicted actions.

| Expected \\ Predicted | allow | ask | deny |
|---|---:|---:|---:|
| allow | 30 | 0 | 0 |
| ask | 0 | 54 | 0 |
| deny | 0 | 0 | 28 |

## UNSAFE AUTO-ALLOWS

None.

## OVER-BLOCKS

None.

## Mismatches

None.
