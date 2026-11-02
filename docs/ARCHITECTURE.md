# Architecture

Status: M4. The authoritative design is CLAUDE.md sections 3 and 4. This document describes the implemented system as milestones land.

## Package layout

Implemented: `models`, `evidence`, `platform`, `platform/fake` (M1); `runtime`, `runtime/output`, and the volume inspector in `platform/windows` (M2); `collectors/process`, `collectors/network`, and the process, socket and privilege sources in `platform/windows` (M3); `integrity`, and the file system and signature verifier in `platform/windows` (M4). The other packages are still empty `doc.go` stubs.

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

## Runtime and output safety (`internal/runtime`, `internal/runtime/output`, M2)

**Destination decision (`runtime.ValidateOutput`).** The default destination is `<volume root of the executable>\Canaveral_Reports`; `--output` gives an explicit one. Nothing is ever substituted: a refused request returns a `Rejection` listing every reason and no destination.

| Condition | Default | Explicit `--output` |
|---|---|---|
| System volume, or system status unknown | refused | refused |
| Removable drive type, or USB/SD/MMC bus | accepted | accepted |
| Fixed, non-USB, non-system | refused | accepted |
| Remote (network), CD-ROM, RAM disk, unknown | refused | refused |
| Read-only, free space unknown or below 50 MiB | refused | refused |
| Path through a symlink/junction/mount point, or not a directory | refused | refused |
| Relative path, or executable location unknown | refused | refused |

**Writer (`output.Writer`)**, the only code allowed to write files:
1. Re-inspects the destination volume before creating anything.
2. Creates missing parent directories one level at a time and a new `scan_<UTC timestamp>` directory (suffix `_2`, `_3`, ... on collision), recording each in the ledger.
3. Re-inspects the volume of the new directory, so a redirect between validation and creation is caught and undone.
4. Accepts only `report.json` and `report.md`. Each is written as `<name>.partial`, flushed, renamed into place, read back and hash-checked, then given a `<name>.sha256` companion (`<hex>  <name>`).
5. Before every flush, confirms the volume is still present and still the same device (volume GUID).

If the destination fails (device removed, a different device at the same mount point, write or read-back failure), the artifacts stay in memory (`Pending`), a warning says so, and an `AlternatePrompter` is asked for another destination, validated exactly like `--output`. Declining leaves the data in memory and returns `ErrNotSaved`.

**Ledger and cleanup.** `runtime.Ledger` records every directory and file the writer creates, with identity captured from the tool's own handle. `output.Cleanup` removes only temporary files and now-empty directories from the ledger, and only when the object at the path still has the recorded file ID and, for files, the recorded size. Final reports are never removed. `Ledger.Review` gives the footprint review: resources inside and outside approved roots, leftovers, and the Windows-generated artifacts the tool cannot control.

**Lifecycle (`runtime.Lifecycle`).** One cancellation context for the run. Shutdown hooks run once, newest first, each with an equal share of the remaining 5-second budget so a stuck hook cannot starve cleanup. Panics in `Lifecycle.Go` goroutines or in main (`RecoverTo`) are recorded and start shutdown. `os.Interrupt` and `SIGTERM` start shutdown; Go delivers Windows console close, logoff and shutdown events as `SIGTERM`.

**Diagnostic.** `Canaveral.exe diag-output [--output PATH]` prints the volume facts and the decision without writing anything.

## Processes, sockets and attribution (M3)

**Windows sources (`internal/platform/windows`).**
- `ProcessSource`: Toolhelp snapshot, then each process opened with `PROCESS_QUERY_LIMITED_INFORMATION` only. It reads creation time (`GetProcessTimes`), image path (`QueryFullProcessImageName`), command line (`NtQueryInformationProcess`, `ProcessCommandLineInformation`), protection level (`ProcessProtectionInformation`), session, and the token's user SID. Account names are resolved only for well-known, service and machine-local SIDs. `SeDebugPrivilege` is never enabled, because adjusting the token can write a 4703 audit event.
- `SocketSource`: `GetExtendedTcpTable(TCP_TABLE_OWNER_MODULE_ALL)` and `GetExtendedUdpTable(UDP_TABLE_OWNER_MODULE)` for IPv4 and IPv6, with `GetOwnerModuleFrom*Entry` per row for the owning module (the service name inside a shared `svchost.exe`). Row layouts are parsed by byte offset in `parse.go`, which has no build tag so it is unit-tested everywhere.
- `Privileges`: elevation, integrity level and Administrators membership of the tool's own token.

**Process collector (`internal/collectors/process`).** Identity is `ProcessKey{PID, CreateTime}`. A parent is accepted only if it is running and was created no later than the child; otherwise the parent is `Unavailable` with the reason (exited, PID reused, creation time unknown). Every process with unreadable fields produces a coverage note naming the field and the Windows error, plus the protection level when it explains the gap. These are coverage records, never findings.

**Network collector (`internal/collectors/network`).** `Collect` takes a process snapshot, reads the four tables, then takes a second process snapshot. Each socket gets an owner and a confidence:

| Situation | Confidence |
|---|---|
| PID present in both snapshots with the same identity | High |
| PID 4 (System) | High, with a note that the kernel is not the requesting component |
| Process exited or started during collection | Reduced |
| Creation time unreadable in either snapshot | Reduced; owner identity Unavailable |
| Socket entry created before the process started (A5, possible inherited handle) | Lowered to Reduced, not rejected |
| PID 0, PID in neither snapshot, or PID reused between snapshots | None (unattributed) |

Addresses are classified as Unspecified, Loopback, LinkLocal, Private (RFC 1918, ULA), Public, Multicast, Broadcast, Reserved or Unknown. IPv4-mapped and NAT64 addresses are classified by the embedded IPv4 address. No class is suspicious by itself.

**Manifest.** `cmd/canaveral/canaveral.manifest` requests `requireAdministrator` (A8). `tools/gensyso` turns it into a COFF `.syso` at build time. It is not committed, so `go build` and `go test` produce unmanifested binaries, and `build.ps1 -NoManifest` builds a standard-user test binary. This replaces the third-party `rsrc` tool named in CLAUDE.md section 8.

## Integrity: hashing and signatures (M4)

**File access.** `platform/windows.FileSystem` opens files with `FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE` only, sharing `READ | WRITE | DELETE` so investigated files are never locked, and `\\?\` paths for long names. `Identity()` comes from `GetFileInformationByHandle` on the same handle.

**Hashing (`internal/integrity`).** Streaming SHA-256. A digest is reported only when the file provably did not change while it was read: the identity before and after reading (same handle) must match, the byte count must equal the size, and re-opening the path must reach the same file. Otherwise the state is `ChangedDuringInspection` and no digest is given. Digests and conclusive signature results are cached by file identity, never by path.

**Signatures (`platform/windows.SignatureVerifier`).** For one file handle:

1. Embedded Authenticode with `WinVerifyTrust` (`WTD_CHOICE_FILE`).
2. If there is none, the catalog member hash (SHA-256, then SHA-1) is looked up in the system catalogs and verified with `WTD_CHOICE_CATALOG`.

Every call is offline (`WTD_REVOKE_NONE`, `WTD_REVOCATION_CHECK_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`) and its state is always closed. Results are `Valid`, `Invalid`, `Unsigned` or `Unavailable`, with the source (`Embedded`, `Catalog`, `None`), signer, timestamp, catalog file and the identity of the verified handle. `Invalid` is only reported for specific result codes that prove a signature is present and failing; unrecognized results are `Unavailable`. The result-code mapping lives in an untagged file and is unit-tested on every platform.

**Diagnostic.** `Canaveral.exe diag-integrity [--dir D] [--limit N] [FILE...]` hashes and verifies files read-only and lists anything not validly signed.

## Enforced boundaries

`.golangci.yml` enforces CLAUDE.md 1.2 in CI, on both the host OS and `GOOS=windows`:

- No process creation anywhere (`os/exec`, `os.StartProcess`, `syscall`/`x/sys/windows` process APIs).
- Host writes (file, directory and registry) only in `internal/runtime/output`. `_test.go` files are also exempt, since tests run on dev and CI machines, never on a customer host.
- Network code only in `internal/reputation`, which is not built in v1.
- `internal/platform/fake` is importable only from `_test.go` files and `fixture`-tagged files.

See `docs/LIMITATIONS.md` for what lint cannot catch.
