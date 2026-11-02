# Canaveral status ledger

Every feature has exactly one maturity level (CLAUDE.md 1.1). Levels are never written higher than what actually happened.

`SCAFFOLD` → `COMPILES` → `FIXTURE-TESTED` → `WINDOWS-VALIDATED` → `FOOTPRINT-AUDITED`

- `SCAFFOLD`: types or stubs only, not functional. A planned feature with no code yet is also `SCAFFOLD`; at most an empty package `doc.go` exists.
- `WINDOWS-VALIDATED` and `FOOTPRINT-AUDITED` can only be set from the owner's Windows VM runs, with evidence recorded in the [validation log](#validation-log). Claude Code on Linux never sets them.

Last updated: 2026-11-02 (M1).

## Milestone progress

| Milestone | State |
|---|---|
| M0 Bootstrap and tooling | Done (2026-11-02) |
| M1 Models, interfaces, evidence graph | In review |
| M2 to M16 | Not started |

## M0 tooling (not features; recorded for traceability)

| Item | State | Evidence |
|---|---|---|
| `go.mod`, Go 1.27.3 pinned (CI uses the same) | Done | `go.mod`, `.github/workflows/ci.yml` |
| Windows cross-build of skeleton | Passes in CI | Local (Debian 13) and CI run [41370427194](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41370427194), 2026-11-02 |
| Lint rules (depguard, forbidigo, staticcheck) | Proven in CI | Branch `throwaway/m0-lint-proof` (deliberate `os/exec` + `os.WriteFile`) failed the lint step in run [41370436114](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41370436114) with both violations reported |
| CI (ubuntu lint/test/race/cross-build; windows build/test) | Green on `main` | Run [41370427194](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41370427194) |
| `scripts/build.ps1` | Runs in CI | windows-latest, run 41370427194: built `dist\Canaveral.exe` 0.0.0-ci.1, SHA256 `8DE5D097FB32B746E7486FD63DC537F0EB95E9BBD754F53DB544686D98D4326E`. A CI build is not a Windows VM validation. |

## Features

| Feature | Milestone | Level | Notes |
|---|---|---|---|
| Shared data models | M1 | FIXTURE-TESTED | `Value[T]` (known or unavailable, never both), severity order and text round trip; record types are plain data |
| Evidence graph (nodes, edges, evidence states) | M1 | FIXTURE-TESTED | Stable IDs, edge-kind endpoint validation, deep-copy accessors, concurrent use under `-race` |
| Evidence-state transition rules | M1 | FIXTURE-TESTED | Full 6x6 matrix against an independent expected table; corroboration needs 2 classes, contradiction needs evidence |
| Observation deduplication | M1 | FIXTURE-TESTED | 500 identical observations become 1 node with count 500, sequentially and from 20 goroutines |
| Bounded retention and memory budget (A13) | M1 | FIXTURE-TESTED | Sizes are estimates; findings, Medium+ (by max severity) and their linked evidence are never evicted |
| Platform interfaces | M1 | SCAFFOLD | Interface definitions only, which is all M1 calls for; Windows implementations start in M3 |
| Platform fakes (test and fixture builds only) | M1 | FIXTURE-TESTED | Unconfigured fixtures return errors, never empty results |
| Executable-drive detection | M2 | SCAFFOLD | |
| Output-path validation | M2 | SCAFFOLD | |
| Output writer (sole writer) | M2 | SCAFFOLD | |
| Footprint ledger and footprint review | M2 | SCAFFOLD | |
| Cleanup of tool-owned resources only | M2 | SCAFFOLD | |
| Graceful shutdown and `recover` handler | M2 | SCAFFOLD | |
| Output device loss handling (retain in memory, alternate destination) | M2 | SCAFFOLD | |
| Elevation detection | M3 | SCAFFOLD | |
| `requireAdministrator` manifest `.syso` (A8) | M3 | SCAFFOLD | |
| Process enumeration (PID, PPID, creation time, image path) | M3 | SCAFFOLD | |
| Process command line | M3 | SCAFFOLD | |
| Process user context | M3 | SCAFFOLD | |
| Parent lineage | M3 | SCAFFOLD | |
| Module-aware TCP table, IPv4 and IPv6 (A5) | M3 | SCAFFOLD | |
| Module-aware UDP table, IPv4 and IPv6 (A5) | M3 | SCAFFOLD | |
| Owning service name for shared `svchost` sockets | M3 | SCAFFOLD | |
| Address classification | M3 | SCAFFOLD | |
| Process-socket correlation by PID + creation time | M3 | SCAFFOLD | |
| Socket attribution confidence | M3 | SCAFFOLD | |
| Inaccessible-process coverage records | M3 | SCAFFOLD | |
| Streaming SHA-256 hashing | M4 | SCAFFOLD | |
| File identity and hash cache | M4 | SCAFFOLD | |
| Change-during-inspection detection | M4 | SCAFFOLD | |
| Embedded Authenticode verification (A1) | M4 | SCAFFOLD | |
| Catalog signature verification (A1) | M4 | SCAFFOLD | |
| Offline, write-free trust configuration (A2) | M4 | SCAFFOLD | |
| Signer and publisher extraction | M4 | SCAFFOLD | |
| Timestamp-signature handling | M4 | SCAFFOLD | |
| Embedded `baseline.yaml`, `ruleset.yaml`, `remote_tools.yaml` | M5 | SCAFFOLD | |
| Config versioning | M5 | SCAFFOLD | |
| External config override, hash and banner | M5 | SCAFFOLD | |
| Trust-rule evaluator | M5 | SCAFFOLD | |
| Baseline proposals exporter (never auto-adds) | M5 | SCAFFOLD | |
| Self-recognition | M5 | SCAFFOLD | |
| Rule engine and rule loader validation | M6 | SCAFFOLD | |
| Starter rule catalog (CLAUDE.md section 6) | M6 | SCAFFOLD | |
| Dual-layer explanations | M6 | SCAFFOLD | |
| Per-process, per-connection and per-host assessments | M6 | SCAFFOLD | |
| Assessment history | M6 | SCAFFOLD | |
| False-positive suite | M6 | SCAFFOLD | |
| Suspicious-scenario suite | M6 | SCAFFOLD | |
| Re-verification pipeline | M7 | SCAFFOLD | |
| Corroboration (A12, section 4.2) | M7 | SCAFFOLD | |
| Contradiction handling | M7 | SCAFFOLD | |
| Host verdict derivation (section 4.3) | M7 | SCAFFOLD | |
| Critical-collector list | M7 | SCAFFOLD | |
| Run and RunOnce keys | M8 | SCAFFOLD | |
| Startup folders (all profiles) | M8 | SCAFFOLD | |
| Services with SCM cross-check | M8 | SCAFFOLD | |
| Scheduled tasks: XML compared against TaskCache | M8 | SCAFFOLD | |
| Winlogon `Shell` and `Userinit` | M8 | SCAFFOLD | |
| IFEO `Debugger` and `SilentProcessExit` | M8 | SCAFFOLD | |
| `AppInit_DLLs` | M8 | SCAFFOLD | |
| Unloaded-profile in-memory hive parsing (A3) | M8 | SCAFFOLD | |
| WMI permanent event subscriptions | M8 | SCAFFOLD | Tier 2 |
| COM hijacks (HKCU over HKLM CLSID) | M8 | SCAFFOLD | Tier 2 |
| BITS jobs | M8 | SCAFFOLD | Tier 2 |
| Active Setup `StubPath` | M8 | SCAFFOLD | Tier 2 |
| LSA authentication and security packages | M8 | SCAFFOLD | Tier 2 |
| Print monitors | M8 | SCAFFOLD | Tier 2 |
| Time providers | M8 | SCAFFOLD | Tier 2 |
| Netsh helpers | M8 | SCAFFOLD | Tier 2 |
| AppCertDLLs | M8 | SCAFFOLD | Tier 2 |
| Bounded profile directory walks | M9 | SCAFFOLD | |
| Executable and script discovery | M9 | SCAFFOLD | |
| Remote-tool family detection (A9, `remote_tools.yaml`) | M9 | SCAFFOLD | |
| ScreenConnect instance and relay parsing | M9 | SCAFFOLD | |
| Remote-tool session log parsing | M9 | SCAFFOLD | Log paths are unverified hypotheses until checked in the VM |
| Bounded script content scan | M9 | SCAFFOLD | |
| Event log reader (`EvtQuery`, read-only) | M10 | SCAFFOLD | |
| Event sources (System, Security, TerminalServices, TaskScheduler, Defender, Sysmon) | M10 | SCAFFOLD | |
| Prefetch parsing | M10 | SCAFFOLD | |
| BAM and DAM | M10 | SCAFFOLD | |
| ShimCache | M10 | SCAFFOLD | |
| Amcache | M10 | SCAFFOLD | |
| History source states (`Present`, `Disabled`, `Empty`, `Unavailable`) | M10 | SCAFFOLD | |
| DNS servers per adapter | M11 | SCAFFOLD | |
| DNS-over-HTTPS configuration | M11 | SCAFFOLD | |
| WinINET and WinHTTP proxy and PAC | M11 | SCAFFOLD | |
| `hosts` file diff | M11 | SCAFFOLD | |
| Static routes | M11 | SCAFFOLD | |
| VPN and TAP adapters | M11 | SCAFFOLD | |
| User-added root certificates | M11 | SCAFFOLD | |
| Inbound firewall rules for remote tools | M11 | SCAFFOLD | |
| RDP and NLA state | M11 | SCAFFOLD | |
| WinRM state | M11 | SCAFFOLD | |
| Local users and Administrators membership | M11 | SCAFFOLD | |
| Defender state, tamper protection and exclusions | M11 | SCAFFOLD | |
| Open shares | M11 | SCAFFOLD | |
| Canonical `report.json` (A11) | M12 | SCAFFOLD | |
| Markdown renderer | M12 | SCAFFOLD | |
| `.sha256` companions | M12 | SCAFFOLD | |
| Redaction (A14) | M12 | SCAFFOLD | |
| Full inventories | M12 | SCAFFOLD | |
| Footprint, coverage and limitations sections | M12 | SCAFFOLD | |
| Fixture-mode and custom-config banners | M12 | SCAFFOLD | |
| Fictional sample report | M12 | SCAFFOLD | |
| CLI (`scan`, `monitor`, `report`) | M13 | SCAFFOLD | `main.go` only prints its version and a pre-implementation notice |
| Snapshot scheduler | M13 | SCAFFOLD | |
| Bounded worker pools and async enrichment | M13 | SCAFFOLD | |
| Cancellation and signal handling | M13 | SCAFFOLD | |
| Engine event stream | M13 | SCAFFOLD | |
| TUI views, help and navigation | M14 | SCAFFOLD | |
| ASCII and no-color fallbacks | M14 | SCAFFOLD | |
| Authorization banner and consent record (A15) | M14 | SCAFFOLD | Consent record also goes in the report |
| BitLocker warning for output volume (A14) | Unassigned | SCAFFOLD | CLAUDE.md does not place it in a milestone |
| ETW real-time session (A4) | M15 | SCAFFOLD | |
| ETW event correlation | M15 | SCAFFOLD | |
| Code signing | M16 | SCAFFOLD | Owner decision pending (CLAUDE.md 10.1) |
| Reproducible build check | M16 | SCAFFOLD | |

## Validation log

Windows VM runs recorded by the owner: VM build, date, user type, command, observed output.

| Date | VM build | User | What was run | Result |
|---|---|---|---|---|
| | | | | |

## Defender and AV results

| Date | Build | Engine/version | Result |
|---|---|---|---|
| | | | |
