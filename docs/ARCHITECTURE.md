# Architecture

Status: M1. The authoritative design is CLAUDE.md sections 3 and 4. This document describes the implemented system as milestones land.

## Package layout

`models`, `evidence`, `platform` and `platform/fake` are implemented (M1). The other packages are still empty `doc.go` stubs.

| Package | Role |
|---|---|
| `cmd/canaveral` | Entry point and CLI |
| `internal/models` | Pure shared types |
| `internal/evidence` | Evidence graph, classes, dedup, retention |
| `internal/platform` | OS-facing interfaces |
| `internal/platform/windows` | Windows implementations (`//go:build windows`) |
| `internal/platform/fake` | Fakes for tests and `fixture` builds only |
| `internal/collectors/*` | process, network, persistence, artifacts, history, netconfig |
| `internal/integrity` | Hashing, file identity, signatures |
| `internal/baseline` | Trust baselines and trust rules |
| `internal/detection` | Rule engine |
| `internal/correlation` | Cross-evidence linking |
| `internal/verification` | Re-verification and corroboration |
| `internal/scoring` | Severity, confidence, host verdict |
| `internal/report` | JSON, Markdown, checksums |
| `internal/redact` | Report redaction |
| `internal/runtime` | Output validation, footprint, cleanup, memory budget |
| `internal/runtime/output` | The only package allowed to write files |
| `internal/tui` | Terminal UI |

## Evidence graph (`internal/evidence`, M1)

- **Nodes** are created by `Observe` and deduplicated by kind and key. A node's ID is a kind prefix plus 64 bits of SHA-256 over kind and key (`SOC-6d32170cd6ec1b0b`), so the same fact has the same ID in every scan. Collisions are detected, not merged.
- **Evidence class** comes from node kind: Process is PROC, Socket is NET, File is FILE, PersistenceEntry is PERSIST, HistoryRecord is HISTORY, ConfigFact is CONFIG. Findings have no class.
- **Unavailable data:** a failed collection attempt never erases or downgrades an earlier observation; it increments `UnavailableAttempts`. A later success upgrades an `Unavailable` node to `Observed`, with a recorded reason.
- **States.** Nodes start Observed or Unavailable. Legal moves:

  | From | To |
  |---|---|
  | Observed | Verified, Corroborated, Contradicted, Inconclusive |
  | Verified | Corroborated, Contradicted, Inconclusive |
  | Corroborated | Contradicted, Inconclusive |
  | Contradicted | Inconclusive |
  | Inconclusive | Verified, Corroborated, Contradicted |
  | Unavailable | Observed |

  Every change needs a reason and is kept in history. Corroborated needs at least two distinct evidence classes across the node and its cited evidence. Contradicted needs at least one evidence node. Subject linkage for corroboration is checked by `internal/verification` (M7), not here.
- **Severity** changes are recorded with reasons. `MaxSeverity` keeps the highest value ever held. `Observe` only raises severity.
- **Edges** are checked against their endpoint kinds (for example `OwnsSocket` must go Process to Socket).
- **Memory budget (A13).** `EnforceBudget`, called by the engine after each snapshot is fully linked, evicts the least recently observed unprotected nodes until estimated usage is within budget (default 256 MiB). Protected roots are findings and nodes whose `MaxSeverity` is at or above the threshold (default Medium). Protection spreads to explanatory context:

  | Edge | Protection flows |
  |---|---|
  | `SupportsFinding`, `ContradictsFinding` | finding to its evidence |
  | `OwnsSocket` | socket to owning process |
  | `ImageOf` | process to image file |
  | `ParentOf` | child to parent (ancestors only, never children) |
  | `LaunchesFile`, `RecordedExecutionOf` | both ways between the entry and its file |

  Evicted nodes are summarized per kind and collector as `Truncated` coverage notes. If protected evidence alone exceeds the budget, it is all kept and a `BudgetExceeded` note is recorded.

## Platform boundary (`internal/platform`, M1)

Collectors depend only on these interfaces: `Clock`, `ProcessSource`, `SocketSource` (one table per call), `FileSystem`/`File` (identity read from the same handle as the content), `SignatureVerifier`, `RegistryReader` (no write or hive-load methods exist) and `EventLogReader`. Failures wrap `ErrNotFound`, `ErrAccessDenied` or `ErrUnsupported`. `internal/platform/fake` implements all of them for tests.

## Enforced boundaries

`.golangci.yml` enforces CLAUDE.md 1.2 in CI, on both the host OS and `GOOS=windows`:

- No process creation anywhere (`os/exec`, `os.StartProcess`, `syscall`/`x/sys/windows` process APIs).
- Host writes (file, directory and registry) only in `internal/runtime/output`. `_test.go` files are also exempt, since tests run on dev and CI machines, never on a customer host.
- Network code only in `internal/reputation`, which is not built in v1.
- `internal/platform/fake` is importable only from `_test.go` files and `fixture`-tagged files.

See `docs/LIMITATIONS.md` for what lint cannot catch.
