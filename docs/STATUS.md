# Canaveral status ledger

Every feature has exactly one maturity level (CLAUDE.md 1.1). Levels are never written higher than what actually happened.

`SCAFFOLD` → `COMPILES` → `FIXTURE-TESTED` → `WINDOWS-VALIDATED` → `FOOTPRINT-AUDITED`

- `SCAFFOLD`: types or stubs only, not functional. A planned feature with no code yet is also `SCAFFOLD`; at most an empty package `doc.go` exists.
- `WINDOWS-VALIDATED` and `FOOTPRINT-AUDITED` can only be set from the owner's Windows VM runs, with evidence recorded in the [validation log](#validation-log). Claude Code on Linux never sets them.
- Windows code that has run with passing assertions on GitHub's `windows-latest` runner is recorded as `FIXTURE-TESTED` plus a "Windows CI" note. That is more than `COMPILES` and less than `WINDOWS-VALIDATED`: the runner is real Windows, but it is an ephemeral, admin-run VM with no removable media, so it does not replace the owner's VM. See [Windows CI evidence](#windows-ci-evidence).

Last updated: 2026-11-02 (M4).

## Milestone progress

| Milestone | State |
|---|---|
| M0 Bootstrap and tooling | Done (2026-11-02) |
| M1 Models, interfaces, evidence graph | Done (2026-11-02), CI run [41371938185](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41371938185) |
| M2 Runtime and output safety | Done (2026-11-02), CI run [41374731797](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41374731797). Owner VM check of drive-type detection (`diag-output`) still pending |
| M3 Windows foundation: privilege, processes, sockets, correlation | Done (2026-11-02), CI run [41379188920](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41379188920). Owner VM runs and Defender run still pending |
| M4 Integrity: hashing and signatures | In review |
| M5 to M16 | Not started |

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
| Executable-drive detection | M2 | FIXTURE-TESTED | Windows `VolumeInspector` (drive type, bus type via `IOCTL_STORAGE_QUERY_PROPERTY`, volume GUID, read-only flag, free space, system-volume match). Windows CI (run 41379188920): system volume, NVMe and FileBackedVirtual bus types, missing drive letters, SUBST, junction and mapped-network-drive refusals all asserted. Removable/USB detection is untested: no removable media in CI. Owner VM check: `Canaveral.exe diag-output` |
| Output-path validation | M2 | FIXTURE-TESTED | Every rejection rule, all reasons reported, 72-combination sweep proving no system-drive fallback, link and junction refusal |
| Output writer (sole writer) | M2 | FIXTURE-TESTED | Strict layout, `.partial` + fsync + rename + read-back verification, `.sha256` companions; volume checked before and after creating directories. Windows CI (run 41379188920): real report written to a non-system NTFS volume, layout exact, companions match `Get-FileHash` |
| Footprint ledger and footprint review | M2 | FIXTURE-TESTED | Review splits inside/outside approved roots and leftovers, and discloses Windows-generated artifacts |
| Cleanup of tool-owned resources only | M2 | FIXTURE-TESTED | Ledger-only; removes a file only when the file ID and size match what the tool's own handle recorded |
| Graceful shutdown and `recover` handler | M2 | FIXTURE-TESTED | Hooks once, LIFO, fair share of a 5 s total; goroutine and main panics recovered; SIGINT/SIGTERM. Ctrl+C on a Windows console not yet exercised |
| Output device loss handling (retain in memory, alternate destination) | M2 | FIXTURE-TESTED | Simulated unplug, swapped stick at the same mount point, corrupted read-back; the prompt UI itself arrives with the CLI/TUI (M13/M14) |
| Elevation detection | M3 | FIXTURE-TESTED | Elevated, integrity level, Administrators membership from the tool's own token; never adjusts privileges. Windows CI: asserted on windows-latest (run 41379188920) |
| `requireAdministrator` manifest `.syso` (A8) | M3 | FIXTURE-TESTED | Generated by `tools/gensyso` (in-repo, reproducible); object parsed back with `debug/pe`; CI reads it from the release exe with `FindResource`. `build.ps1 -NoManifest` makes a standard-user test build. Windows CI (run 41379188920): Windows refused to start the manifested build for a standard user without elevation |
| Process enumeration (PID, PPID, creation time, image path) | M3 | FIXTURE-TESTED | Toolhelp + `PROCESS_QUERY_LIMITED_INFORMATION` only; no `SeDebugPrivilege`. Windows CI: asserted on windows-latest (run 41379188920) |
| Process command line | M3 | FIXTURE-TESTED | `NtQueryInformationProcess(ProcessCommandLineInformation)`. Windows CI: asserted on windows-latest (run 41379188920) |
| Process user context | M3 | FIXTURE-TESTED | Token user SID always; account name only for well-known and machine-local SIDs (domain/Azure AD lookups could leave the machine). Protection level (PPL) recorded. Windows CI: asserted on windows-latest (run 41379188920) |
| Parent lineage | M3 | FIXTURE-TESTED | Parent accepted only if created no later than the child; PID reuse, exited parents, self-parenting and cycles handled |
| Module-aware TCP table, IPv4 and IPv6 (A5) | M3 | FIXTURE-TESTED | Row parsers fixture-tested by byte offset; live tables checked against the test's own loopback sockets. Windows CI: asserted on windows-latest (run 41379188920) |
| Module-aware UDP table, IPv4 and IPv6 (A5) | M3 | FIXTURE-TESTED | As TCP. UDP rows carry no remote endpoint and no state. Windows CI: asserted on windows-latest (run 41379188920) |
| Owning service name for shared `svchost` sockets | M3 | FIXTURE-TESTED | `GetOwnerModuleFrom*Entry`; logic fixture-tested. Windows CI: asserted on windows-latest (run 41379188920) |
| Address classification | M3 | FIXTURE-TESTED | IPv4 and IPv6: unspecified, loopback, link-local, private/ULA, public, multicast, broadcast, reserved, unknown; mapped and NAT64 addresses unwrapped |
| Process-socket correlation by PID + creation time | M3 | FIXTURE-TESTED | Two process snapshots around the socket read expose exits, starts and PID reuse |
| Socket attribution confidence | M3 | FIXTURE-TESTED | High / Reduced / None, each with a reason; PID 0 and unresolvable owners are unattributed |
| Inaccessible-process coverage records | M3 | FIXTURE-TESTED | Per-process gaps with the Windows error, protection level named; never findings |
| Streaming SHA-256 hashing | M4 | FIXTURE-TESTED | 1 MiB chunks, cancellable; Windows file opener requests only `FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE` with full sharing. Windows CI checks pending the M4 run |
| File identity and hash cache | M4 | FIXTURE-TESTED | Keyed by volume serial + file index + size + last-write time, never by path; bounded LRU; only clean results cached |
| Change-during-inspection detection | M4 | FIXTURE-TESTED | Identity before/after on the same handle, byte count vs size, path re-opened afterwards; no digest is reported for a changed file |
| Embedded Authenticode verification (A1) | M4 | COMPILES | `WinVerifyTrust`, `WTD_CHOICE_FILE`, on the tool's own handle. Result-code mapping fixture-tested; Windows CI checks pending the M4 run |
| Catalog signature verification (A1) | M4 | COMPILES | `CryptCATAdminCalcHashFromFileHandle2` (SHA-256, then SHA-1), `CryptCATAdminEnumCatalogFromHash`, `WTD_CHOICE_CATALOG`. Windows CI checks pending the M4 run |
| Offline, write-free trust configuration (A2) | M4 | COMPILES | `WTD_REVOKE_NONE`, `WTD_REVOCATION_CHECK_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`, state always closed. CI footprint audit pending the M4 run |
| Signer and publisher extraction | M4 | COMPILES | `WTHelperGetProvSignerFromChain` + `CertGetNameString`; struct layouts asserted in Windows tests |
| Timestamp-signature handling | M4 | COMPILES | Counter-signer time from the provider data; Unavailable when there is no timestamp |
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

CLAUDE.md A7 and M3 require a Defender run from M3 on. The owner's VM run is still pending. CI scans every build on demand; those results are recorded here as CI evidence. The CI runner has real-time protection off, so its scans are signature scans only.

| Date | Build | Engine/version | Result |
|---|---|---|---|
| 2026-11-02 | CI run 41379188920: `Canaveral.exe` SHA256 C2623F3F…F2B2, `Canaveral-nomanifest.exe` SHA256 4509DB74…A286 | Engine 1.1.26100.4, signatures 1.463.33.0 (2026-10-29), real-time protection off (windows-latest) | On-demand scan: no threats in either file (CI evidence, not the owner's VM run) |

## Windows CI evidence

Real Windows runs on GitHub's `windows-latest` runner. Not a VM validation: the runner is ephemeral, runs as an administrator, and has no removable or USB media.

| Date | Run | What was asserted |
|---|---|---|
| 2026-11-02 | [41379188920](https://github.com/dashpalmer269-ai/canaveral/actions/runs/41379188920) | Full test suite, also under `-race` (cgo). Own process fully described (image, command line, SID, local account name, creation time); Idle has no invented values; 15 protected processes decoded, `csrss.exe` asserted WinTcb-Light; own TCPv4/TCPv6/UDPv4/UDPv6 sockets found with exact address, port, state and owner; all svchost sockets named their service; own listener attributed High end to end. Real report written to non-system NTFS, companions match `Get-FileHash`. System drive refused directly, via SUBST, via a junction and via `\\localhost\C$` mapped as a network drive; virtual disk reported as FileBackedVirtual, refused by default, accepted explicitly; nothing created by `diag-output`. As a fresh non-admin account: `elevated=false`, integrity Medium, 123 of 146 processes reported as coverage gaps, exit 0; the `requireAdministrator` build was refused by Windows without elevation. Defender on-demand scan clean. |
