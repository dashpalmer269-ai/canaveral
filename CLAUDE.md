# Canaveral: Build Guide (CLAUDE.md)

> Portable Windows forensic triage and network-integrity tool, written in Go, for repair-bench investigations.
> This file is the **build contract**. `docs/SPEC.md` is the product vision. Where the two conflict, **this file wins** (see Section 2).

---

## 0. How to use this file

1. Save the original master prompt as `docs/SPEC.md` (unchanged).
2. Save this file as `CLAUDE.md` in the repo root.
3. Work **one milestone at a time** (Section 5). Do not start milestone N+1 until every acceptance box in milestone N is checked.
4. At the end of each milestone, produce a **Milestone Report** (Section 9) and update `docs/STATUS.md`.
5. Prompt for each milestone with:

```text
Read CLAUDE.md and docs/SPEC.md. Implement milestone M<N> only.
Plan in 15 lines or fewer, implement, run the tests, update docs/STATUS.md,
then give me the Milestone Report. Do not start M<N+1>.
```

---

## 1. Working agreements

### 1.1 Honesty ledger (`docs/STATUS.md`)

Every feature carries exactly one maturity level. Never write a higher level than what actually happened.

| Level | Meaning |
|---|---|
| `SCAFFOLD` | Types or stubs only. Not functional. |
| `COMPILES` | Builds for `windows/amd64`. Not run. |
| `FIXTURE-TESTED` | Passes unit tests against fixtures or fakes. |
| `WINDOWS-VALIDATED` | Executed on a real Windows VM, with evidence recorded (VM build, date, observed output). |
| `FOOTPRINT-AUDITED` | `WINDOWS-VALIDATED` plus a Procmon and pktmon audit showing no unapproved writes or network traffic. |

Rules:
- Claude Code running on Linux or macOS can never mark anything `WINDOWS-VALIDATED`. Only the owner's VM runs can.
- No silent mocks. Fakes live in `internal/platform/fake` and are compiled **only** under `_test.go` files or the `fixture` build tag. If the binary is ever built with `-tags fixture`, every report must carry a **FIXTURE MODE** banner.
- A collector that cannot get data returns `Unavailable{reason}`. It never returns a guessed value.

### 1.2 Code rules enforced by CI

- **No process spawning.** `os/exec` is forbidden in all packages (depguard). Canaveral never shells out to `powershell`, `wmic`, `reg`, `schtasks`, and so on. This keeps its process tree clean and is part of self-recognition.
- **No host writes outside `internal/runtime/output`.** forbidigo blocks `os.Create`, `os.WriteFile`, `os.OpenFile` (write flags), `os.MkdirAll`, `os.Mkdir`, `os.TempDir`, `os.CreateTemp`, `ioutil.*`, and any registry `CreateKey`, `SetValue` or `DeleteKey` call outside that package.
- **No network code** outside the optional `internal/reputation` package, which is not built in v1 (see Section 10).
- Every Windows file is opened with `FILE_SHARE_READ|WRITE|DELETE` and minimal access rights so investigated files are never locked or modified.
- Platform code uses `//go:build windows`. Everything above the `internal/platform` interfaces must compile and test on Linux.

### 1.3 Things Claude Code must not do

- No AV-evasion techniques, packers, obfuscation or string-hiding. Handle antivirus friction transparently (Section 2, A7).
- No VSS or shadow-copy creation, no `RegLoadKey`, no ETL files, no event-log clearing, no settings changes.
- No real malware in tests. Lab fixtures are harmless lookalikes (Section 7).

---

## 2. Spec amendments (these override `docs/SPEC.md`)

| # | Amendment | Why |
|---|---|---|
| A1 | **Signature checks must be catalog-aware.** Verify embedded Authenticode (`WinVerifyTrust` with `WTD_CHOICE_FILE`), and if the file has no embedded signature, hash it with `CryptCATAdminCalcHashFromFileHandle2`, find the catalog with `CryptCATAdminEnumCatalogFromHash`, then verify with `WTD_CHOICE_CATALOG`. Report which path produced the result: `Embedded`, `Catalog`, `None`. | Most Windows system binaries are catalog-signed. File-only checks mark `svchost.exe` as unsigned and destroy the false-positive goal. |
| A2 | **Trust checks must be offline and write-free.** Set `WTD_REVOKE_NONE`, `WTD_REVOCATION_CHECK_NONE` and `WTD_CACHE_ONLY_URL_RETRIEVAL`. Always call `WTD_STATEACTION_CLOSE`. Revocation status is reported as `Unavailable (offline by design)`. Validate with Procmon (no writes under the user profile `CryptnetUrlCache`) and pktmon (no packets) in M4. | Default revocation checks write the CryptNet cache and can go online, violating the offline and zero-write rules. |
| A3 | **No `RegLoadKey` or `RegLoadAppKey`.** Loaded profiles are read via `HKEY_USERS\<SID>`. Unloaded profiles are parsed in memory from `NTUSER.DAT` with a pure-Go hive parser (evaluate `Velocidex/regparser`; license-check it). Transaction logs (`.LOG1`/`.LOG2`) are noted as a coverage limitation unless replay is implemented. | Mounting hives modifies the live registry. |
| A4 | **ETW is promoted** from "optional" to milestone M15, after snapshots are solid. It uses a real-time session only, with a fixed session name `Canaveral-Live`. At launch, enumerate and stop only a stale session with exactly that name. Stop it on every exit path (normal exit, panic via `recover`, signal). Providers to evaluate: `Microsoft-Windows-Kernel-Network`, `Microsoft-Windows-Kernel-Process`. Document that the session is visible to the host and can be orphaned by a hard kill. | ETW is the only way to catch connections between polls, but it is a named host-side session. |
| A5 | **Use module-aware tables.** `GetExtendedTcpTable` with `TCP_TABLE_OWNER_MODULE_ALL` and `GetExtendedUdpTable` with `UDP_TABLE_OWNER_MODULE`, plus `GetOwnerModuleFromTcpEntry` or `...UdpEntry` for the owning service name (resolves which service owns a socket in a shared `svchost`). **Note:** `liCreateTimestamp` is the *socket entry's* creation time, **not** the process creation time. Use it only as a consistency check (a socket created before the process started is possible via inherited handles, so lower the confidence instead of rejecting). Process identity is `PID + process creation FILETIME` from `GetProcessTimes`. | Gives better attribution and honest PID-reuse handling. |
| A6 | **Hash baselines are for third-party software only.** Microsoft and OS binaries are trusted by catalog/embedded signature + publisher + canonical path + expected lineage, never by pinned hash (Windows Update changes them constantly). | Pinned OS hashes cause constant false positives. |
| A7 | **Expect AV/EDR friction.** Go binaries that open handles to all processes look suspicious to heuristics. Plan: test against Defender at M3 and M16, record results, sign the binary (Section 10), submit it to Microsoft for false-positive analysis, and document exclusion guidance for the owner's own bench machines. No evasion. | Honest handling beats cat-and-mouse. |
| A8 | **Manifest:** embed `requireAdministrator` through a `.syso` resource. Document that every USB launch shows a UAC prompt. | Matches spec section 4; no UAC bypass. |
| A9 | **Expanded remote-tool coverage:** Quick Assist, Windows Remote Assistance (`msra.exe`), Splashtop, Zoho Assist, LogMeIn, Supremo, AnyViewer, SimpleHelp, plus common RMM agents (Atera, NinjaOne, N-able, Datto, Kaseya), in addition to the spec's list. All are `configs/remote_tools.yaml` data, not code. | Quick Assist is a very common scam vector. |
| A10 | **Added collectors:** event logs (read-only `EvtQuery`), execution-history artifacts, expanded persistence, and a network-integrity/configuration collector (Sections 5 M8 to M11). | The "history" and "network integrity" halves of the spec need concrete sources. |
| A11 | **JSON is the primary report format.** `report.json` is the canonical record; `report.md` is a rendering of it. Both get `.sha256` companions. | Easier to test, diff and re-render. |
| A12 | **"Corroborated" has a strict definition** (Section 4.2). | Prevents the same observation being counted twice. |
| A13 | **Memory is bounded.** Raw observations live in capped ring buffers (default 256 MB budget, configurable). Findings, high-severity observations and their linked evidence are never evicted. Eviction produces a rolled-up summary and a coverage note in the report. | "Everything in RAM" needs a ceiling on customer machines. |
| A14 | **Report privacy.** Reports contain customer PII (usernames, paths, command lines). Add `--redact` (stable tokens for usernames, hostnames, SIDs; mapping held in RAM, optionally exported separately). Warn at launch if the output volume is not BitLocker-protected (best-effort check). | A lost USB is a data leak. |
| A15 | **Authorization banner.** At launch the operator must acknowledge that the customer consented to the scan. The acknowledgement and timestamp are recorded in the report. | Operational and legal hygiene. |
| A16 | **Documented side effects of reading.** NTFS last-access updates, WMI service activity (`wmiprvse.exe`) and Windows Error Reporting on crash are outside the tool's control. They are listed in `docs/LIMITATIONS.md` and in every report's footprint section. | Honest footprint disclosure. |

---

## 3. Architecture rules

Package layout follows spec section 16, with these additions: `internal/evidence` (graph), `internal/runtime/output` (the **only** package allowed to write files), `internal/platform/fake` (test-only), `internal/redact`.

```text
cmd/canaveral/        entry point, flags, headless mode, TUI launch
internal/models/        pure types, no logic
internal/evidence/      evidence graph, evidence classes, dedup, retention
internal/platform/      interfaces (ProcessSource, SocketSource, FileIdentity, SignatureVerifier, RegistryReader, EventLogReader, ...)
internal/platform/windows/   //go:build windows implementations
internal/platform/fake/      fixtures, test-only
internal/collectors/{process,network,persistence,artifacts,history,netconfig}/
internal/integrity/     hashing, file identity, signature (embedded + catalog)
internal/baseline/      embedded defaults + external YAML, versioning
internal/detection/     rules engine
internal/correlation/   process/socket/file/persistence linking
internal/verification/  re-verification + corroboration
internal/scoring/       severity, confidence, host verdict
internal/report/        JSON, Markdown, checksums
internal/redact/
internal/runtime/       USB validation, footprint review, cleanup, memory budget
internal/tui/           Bubble Tea
configs/                ruleset.yaml, baseline.yaml, remote_tools.yaml (all embedded via go:embed, overridable from USB)
scripts/                build.ps1, test.ps1, lab/*.ps1
testdata/               deterministic fixtures + golden files
docs/                   SPEC.md, STATUS.md, ARCHITECTURE.md, LIMITATIONS.md, RULES.md
```

Design rules:
- **Engine first, UI last.** The headless engine emits typed events over a channel. The TUI only consumes them and never calls collectors directly.
- **Collectors return data plus coverage.** Each returns `(records, CoverageReport)` where coverage lists what was attempted, what failed and why.
- **Config:** YAML, embedded defaults plus optional `config/` directory beside the executable on the USB. The report records the SHA-256 of any external config used and prints `CUSTOM CONFIG IN EFFECT` when one is loaded. The tool **never writes** a baseline. Proposed additions are exported to `baseline_proposals.yaml` on the USB for manual merge.
- **File identity** = volume serial + file index (`GetFileInformationByHandle`) + size + mtime. Hash cache keys use file identity, never the path alone.

---

## 4. Evidence model, corroboration, verdict

### 4.1 Graph

Nodes: `Process`, `File`, `Socket/Connection`, `PersistenceEntry`, `HistoryRecord`, `ConfigFact`, `Finding`.
Edges: `ImageOf`, `ParentOf`, `OwnsSocket`, `LaunchesFile`, `RecordedExecutionOf`, `SupportsFinding`, `ContradictsFinding`.
Every node has: stable evidence ID, first/last observed (UTC, one clock source), collector, method, and **evidence state**: `Observed | Verified | Corroborated | Contradicted | Unavailable | Inconclusive`.

### 4.2 Evidence classes and the definition of "corroborated"

Classes: `PROC` (process identity, lineage, command line), `NET` (socket observations), `FILE` (on-disk properties, hash, signature, location), `PERSIST` (autoruns, services, tasks), `HISTORY` (event logs, execution artifacts, tool logs), `CONFIG` (system configuration).

- **Verification** = re-reading the *same fact* through another method or time (for example image path via `QueryFullProcessImageName` versus the PEB). It raises confidence in the fact but is **not** corroboration.
- **Corroboration** = at least **two different evidence classes** that independently support the **same hypothesis about the same subject**, where the subject is linked by process identity or file identity or hash. Repeated snapshots of the same socket count as one `NET` observation (they raise "persistence of observation" only).
- **High-Confidence Indicator** requires: corroboration across at least 2 classes, at least one class that is not merely path/name based, and **no contradicting evidence** (for example a matching approved baseline entry for that exact hash and publisher).
- Whitelist matches never delete evidence. They add `ContradictsFinding` edges and lower the finding's classification, but strong contradictory evidence (such as a trusted-signature binary behaving outside its lineage rules) still surfaces.

### 4.3 Host verdict derivation (explainable, in this precedence)

1. Any finding classified High-Confidence, then **HIGH-CONFIDENCE COMPROMISE INDICATORS**. Coverage gaps are still listed.
2. Else any **critical collector** returned `Unavailable` (Section 5 M7 defines the list), then **ASSESSMENT INCOMPLETE**. Needs-Review findings are still listed under it.
3. Else any Needs-Review finding, then **FURTHER REVIEW REQUIRED**.
4. Else **NO INDICATORS IDENTIFIED** (always printed with the "not proof of a clean system" sentence).

The report prints the exact chain: which findings and which gaps produced the verdict.

### 4.4 Scoring

No arbitrary totals. Each rule declares `base_severity` (`Info | Low | Medium | High`), required evidence, exceptions, and follow-up. Findings group by `subject + hypothesis`, so one behavior observed 500 times is **one** finding with an observation count. Severity changes keep a history (`time, old, new, reason, evidence IDs`). Short-lived high-confidence behavior is never averaged away: the maximum supported severity is retained.

---

## 5. Milestones

Each milestone ends with a **Milestone Report**. "Validate" says where it must be run.

### M0: Bootstrap and tooling
**Build:** repo, `go.mod` (pinned Go toolchain), `docs/` skeleton, `.golangci.yml` (depguard, forbidigo, staticcheck), CI (ubuntu: lint, `go test`, `-race`; windows-latest: build + `windows`-tagged tests), `scripts/build.ps1`, `docs/STATUS.md`.
**Acceptance:**
- [ ] `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/canaveral` succeeds from an empty skeleton.
- [ ] Lint fails if `os/exec` or a host-write call is introduced (prove with a deliberately failing commit on a throwaway branch).
- [ ] `docs/STATUS.md` lists every planned feature at `SCAFFOLD`.
**Validate:** CI only.

### M1: Models, interfaces, evidence graph
**Build:** `models`, `evidence` (graph, states, dedup, ring buffers with memory budget), `platform` interfaces, `platform/fake`.
**Acceptance:**
- [ ] Evidence-state transitions are unit tested (including illegal transitions).
- [ ] Dedup test: 500 identical observations produce 1 node with count 500.
- [ ] Memory-budget test: exceeding the budget evicts low-severity raw observations only, never findings or high-severity evidence, and records a coverage note.
- [ ] `go test -race ./internal/...` passes on Linux.
**Validate:** Linux.

### M2: Runtime and output safety
**Build:** `internal/runtime`: exe-drive detection, output-path validation, `output` writer (the only writer), footprint ledger, graceful shutdown, `recover` handler.
**Acceptance:**
- [ ] Path validation rejects: system drive, non-writable paths, paths outside the approved root, insufficient free space, and (on Windows) volumes that are not removable or USB-bus unless explicitly overridden with `--output` on a **non-system** drive.
- [ ] Never silently falls back to the host system drive (tested).
- [ ] USB-removed-mid-run simulation: results retained in memory, clear warning, alternate-destination prompt path works.
- [ ] Cleanup tracks only resources the tool itself created; test proves unrelated files with a near timestamp are never touched.
- [ ] Output layout is one directory per scan: `report.md`, `report.json`, and `.sha256` companions. Nothing else on the USB.
**Validate:** Linux (logic) and Windows VM (drive-type detection).

### M3: Windows foundation: privilege, processes, sockets, correlation
**Build:** elevation detection and manifest `.syso`; process enumeration (PID, PPID, `GetProcessTimes`, `QueryFullProcessImageName`, command line via `NtQueryInformationProcess` `ProcessCommandLineInformation`, user token, parent lineage); module-aware TCP and UDP tables for IPv4 and IPv6; address classification; correlation keyed by `PID + creation time`; attribution confidence field.
**Acceptance:**
- [ ] Every socket has `owner_confidence` (`High | Reduced | None`) and a reason. Sockets with PID 0 or unresolvable owners are shown as unattributed, never guessed.
- [ ] PID-reuse test: same PID with a different creation time is a distinct process identity.
- [ ] Socket entry timestamp earlier than process creation lowers confidence but is not rejected (documented, tested).
- [ ] Shared `svchost` sockets show the owning service name when Windows supplies it.
- [ ] Classification tests cover IPv4 and IPv6: loopback, link-local, private/ULA, public, multicast, reserved, unknown.
- [ ] Inaccessible processes (protected, PPL) become coverage records, not findings.
- [ ] No fabricated values anywhere: tests assert `Unavailable` for forced failures.
- [ ] Defender run recorded in `STATUS.md` (flagged or not).
**Validate:** Windows 11 VM as admin and as standard user (the latter must degrade gracefully with a visible coverage gap).

### M4: Integrity: hashing and signatures
**Build:** SHA-256 with streaming, file-identity cache, change-during-hash detection; signature verifier implementing amendments A1 and A2 (`Embedded`, `Catalog`, `None`, `Invalid`, `Unavailable`), signer/publisher extraction, timestamp-signature handling.
**Acceptance:**
- [ ] `svchost.exe`, `explorer.exe`, `lsass.exe` verify as validly signed via `Catalog` or `Embedded` (path recorded). **This is the key regression test.**
- [ ] A file with a tampered byte yields `Invalid`, not `None`. An unsigned file yields `None`. A failure to read yields `Unavailable`. These are three distinct states.
- [ ] Footprint audit: Procmon shows zero writes by `Canaveral.exe` outside the output path while verifying 500 files; pktmon shows no packets from the process during verification.
- [ ] A file modified mid-hash is reported as `ChangedDuringInspection`.
**Validate:** Windows VM, with the Procmon and pktmon steps from Section 7.

### M5: Baselines, whitelisting, self-recognition
**Build:** embedded `baseline.yaml`, `ruleset.yaml`, `remote_tools.yaml`; versioning; external override; trust-rule evaluator (publisher, path, lineage, hash for third-party only); proposals exporter; self-recognition (own PID + creation time + own exe path + own SHA-256 computed at startup + expected parent chain).
**Acceptance:**
- [ ] Self-recognition test: a *different* process named `Canaveral.exe` in a user path is **not** recognized as self.
- [ ] Self is labeled "authorized investigative tool" but still appears in the inventory and can still be contradicted.
- [ ] Whitelisted Microsoft-signed binary in the wrong path or with wrong lineage is **not** suppressed.
- [ ] Baseline never auto-adds entries (test attempts every code path).
- [ ] External config used = hash in report and `CUSTOM CONFIG IN EFFECT`.
**Validate:** Linux (logic) and Windows VM (self-recognition).

### M6: Detection engine v1 and false-positive suite
**Build:** rule engine implementing the starter catalog (Section 6, process/network/self rules first), dual-layer explanations (plain + technical), per-process, per-connection and per-host assessments, assessment history.
**Acceptance:**
- [ ] Every rule has ID, explanation, evidence requirements, severity, exceptions, follow-up (loader rejects a rule missing any).
- [ ] **False-positive suite passes** (fixtures): verified Microsoft processes, legitimate unsigned program, legitimate AppData app, authorized remote tool, normal cloud connections, system services with outbound connections, Canaveral itself.
- [ ] **Suspicious suite passes:** system-process impersonation, unsigned user-path binary with external connection, invalid signature with odd lineage, one-interval short-lived connection.
- [ ] Each single weak indicator (AppData, unsigned, public IP, startup, unfamiliar publisher, disappeared) alone never exceeds `Info/Low`.
- [ ] Plain-language text never contradicts or exaggerates the technical text (golden-file test for each rule).
**Validate:** Linux.

### M7: Verification, corroboration, verdict
**Build:** re-verification pipeline (spec section 11 steps), corroboration per Section 4.2, contradiction handling, verdict derivation per Section 4.3, **critical-collector list** (process enumeration, socket enumeration, Run keys, services, scheduled tasks, signature verifier).
**Acceptance:**
- [ ] Same observation repeated N times does not become High-Confidence.
- [ ] Two independent classes about the same subject do reach High-Confidence; the same two without subject linkage do not.
- [ ] A matching approved baseline entry (hash + publisher) contradicts and downgrades the finding.
- [ ] A failed ordinary check never creates a finding by itself.
- [ ] Verdict table tests cover all four verdicts and the precedence rules, including "High-Confidence plus critical gap".
- [ ] A vanished process or connection never lowers a finding's retained severity.
**Validate:** Linux.

### M8: Persistence collectors (read-only)
**Build, Tier 1:** Run/RunOnce (HKLM, HKCU, WOW6432Node, Policies\Explorer\Run), Startup folders (all profiles), services (registry `ImagePath`, `ServiceDll`, account, start type; also cross-check against SCM), scheduled tasks (XML in `System32\Tasks` **compared against** registry `TaskCache\Tree` and `Tasks`), Winlogon `Shell`/`Userinit`, IFEO `Debugger` and `SilentProcessExit`, `AppInit_DLLs`.
**Tier 2:** WMI permanent event subscriptions (`root\subscription`: filter, consumer, binding; document the `wmiprvse` side effect), COM hijacks (HKCU CLSID overrides of HKLM), BITS jobs, Active Setup `StubPath`, LSA authentication/security packages, print monitors, time providers, netsh helpers, AppCertDLLs.
**Acceptance:**
- [ ] Each collector returns records plus coverage; each is read-only (footprint-audited).
- [ ] Task XML with no TaskCache entry (or the reverse, or a Tree key missing its SD value) produces a `PER-003` observation.
- [ ] Loaded and unloaded user profiles both covered; unloaded via in-memory hive parse (no `RegLoadKey`, verified by Procmon).
- [ ] Persistence entries are linked to their target `File` node by path and file identity.
**Validate:** Windows VM with seeded lab artifacts (Section 7).

### M9: Artifact discovery and remote-access detection
**Build:** bounded, read-only directory walks of all profiles (AppData Local/Roaming/Temp, `Users\Public`, Downloads, Startup, `ProgramData`); executable and script discovery by PE header or extension; remote-tool family detection driven by `remote_tools.yaml` (names, paths, service patterns, config files, logs, signer expectations); ScreenConnect instance parsing (relay host from service `ImagePath`); tool log parsing as **evidence of sessions**; bounded content scan of scripts (size cap) for download/encoded-command patterns.
**Acceptance:**
- [ ] Software presence alone is `Info`/`Low`; elevation requires another evidence class (persistence, network, log evidence of inbound session, or hash/publisher mismatch).
- [ ] Authorized-tool config (publisher + path + optionally relay host) suppresses `RA-001`/`RA-002` but not `RA-003` for an unexpected relay.
- [ ] Walks are bounded (depth, file count, time) with coverage records on truncation.
- [ ] Log-path hypotheses (AnyDesk `ad.trace`/`ad_svc.trace`/`connection_trace.txt`, TeamViewer `Connections_incoming.txt` and `*_Logfile.log`, RustDesk `config\RustDesk2.toml` and `log\`, UltraViewer logs) are **verified in the VM against current versions** and recorded in `docs/RULES.md`. Treat the paths in this file as starting hypotheses, not facts.
**Validate:** Windows VM with each tool installed benignly.

### M10: Historical execution evidence and event logs
**Build:** `EvtQuery`/`EvtNext`/`EvtRender` reader (read-only, time-windowed, count-capped). Event sources: System 7045 (service installed); Security 4698/4688/4624 (logon type 10)/4625/4720/4732 **when auditing exists**; TerminalServices LocalSessionManager (21, 22, 24, 25) and RemoteConnectionManager 1149; TaskScheduler/Operational (when enabled); Defender Operational 5001/5007; Sysmon Operational if present. Execution artifacts: Prefetch (`.pf`, Win10+ XPRESS-Huffman decompression via `RtlDecompressBufferEx`), BAM/DAM (`bam\State\UserSettings` and legacy `bam\UserSettings`), ShimCache (note: written at shutdown, may be stale), Amcache (`Amcache.hve`: read with backup semantics; on sharing violation mark `Unavailable`, **never create a VSS snapshot**).
**Acceptance:**
- [ ] Every history source reports `Present | Disabled | Empty | Unavailable` so missing auditing is not misread as "nothing happened".
- [ ] Fuzz tests for the Prefetch, hive and event-XML parsers run 60 seconds without panics.
- [ ] History records link to `File` nodes by path or hash where possible, feeding corroboration.
- [ ] No Windows evidence is modified (event logs not cleared, not subscribed to in ways that change settings; footprint-audited).
**Validate:** Windows VM with auditing enabled and disabled.

### M11: Network-integrity and configuration collector
**Build:** DNS servers per adapter (`GetAdaptersAddresses`), DoH config, WinINET/WinHTTP proxy and PAC URL, `hosts` file diff against default, static routes, unexpected VPN/TAP adapters, user-added root certificates (HKCU root store, plus non-default HKLM roots as `Info`), firewall rules allowing inbound for remote tools, RDP (`fDenyTSConnections`, NLA), WinRM, local users and Administrators membership (`NetLocalGroupGetMembers`), Defender state, tamper protection status and exclusions that cover user-writable directories, open shares.
**Acceptance:**
- [ ] Each fact is a `ConfigFact` with source and state; defaults and benign values are recorded but not flagged.
- [ ] Defender exclusion on a user-writable path or `%TEMP%` triggers `CFG-001` as `Medium`; alone it is never `High`.
- [ ] Unreadable settings (for example tamper-protected) become `Unavailable` coverage records.
**Validate:** Windows VM.

### M12: Reporting (JSON, Markdown, checksums, redaction)
**Build:** canonical `report.json` (schema versioned), Markdown renderer from the JSON, `.sha256` companions (no self-referential hash), `--redact`, optional full inventories (`--full-inventory`), footprint-review section, coverage matrix, limitations section, fictional sample report in `docs/sample_report.md`.
**Acceptance:**
- [ ] Markdown contains all 15 per-finding fields from spec section 14 and all host-metadata fields.
- [ ] Golden-file tests for every verdict state.
- [ ] Re-rendering the Markdown from saved JSON is byte-identical.
- [ ] `.sha256` file verifies with `Get-FileHash` on the USB.
- [ ] Redaction test: no real username, hostname or SID appears in redacted output (grep-style test) and tokens are stable within one report.
- [ ] Fixture-mode and custom-config banners render when applicable.
**Validate:** Linux (golden) and Windows VM (checksum verify).

### M13: Headless engine and monitoring loop
**Build:** CLI (`scan`, `monitor`, `report`), snapshot scheduler (default 5 s, floor 2 s, non-overlapping; measures real collection duration and records overruns), bounded worker pools, async enrichment (hash/signature), cancellation, signal handling, event stream for the TUI.
**Acceptance:**
- [ ] Snapshots never overlap; a slow collector delays the next tick and records the overrun.
- [ ] Cancel (Ctrl+C) stops collectors, flushes the report if requested, and runs cleanup within 5 seconds.
- [ ] 30-minute soak in a VM: memory stays under budget and goroutine count is stable.
- [ ] Report states, in plain words, that polling cannot guarantee observing every connection.
**Validate:** Windows VM.

### M14: Game Boy TUI
**Build:** Bubble Tea, Lip Gloss and Bubbles (pin to current stable and verify with `go list -m -versions`; record versions in `go.mod`). Seven views (Overview, Live Network, Processes, Findings, Persistence/Artifacts, Report/Export, Settings/Baselines), help overlay, keyboard-first, drill-down panes with plain and technical layers, `--ascii` and `--no-color` fallbacks (also honor `NO_COLOR`).
**Palette (classic DMG):** `#0f380f`, `#306230`, `#8bac0f`, `#9bbc0f`.
**Severity must not rely on color.** Symbols: Verified Good `✓`, No Anomaly `·`, Needs Review `▲`, High-Confidence `■` (ASCII: `OK . ! #`).
**Acceptance:**
- [ ] UI stays responsive (input handled in under 100 ms) while the engine hashes and scans.
- [ ] `teatest` tests cover navigation, view switching, drill-down and quit-safely (cleanup runs).
- [ ] Renders correctly at 80x24 and degrades gracefully below it.
- [ ] Shortcuts are visible in the footer; `?` opens help.
- [ ] Authorization banner and elevation status shown at launch.
**Validate:** Windows Terminal and legacy conhost.

### M15: Live network observation (ETW)
**Build:** real-time ETW session per amendment A4, in-memory event handling only, correlation of short-lived events into the evidence graph as `NET` observations with `source=ETW`.
**Acceptance:**
- [ ] No ETL file is created (Procmon audit).
- [ ] Session is stopped on every exit path including `recover` and Ctrl+C; stale same-named session is handled at launch.
- [ ] A lab beacon that connects and exits in under the polling interval is caught by ETW and missed by polling (demonstrated, recorded in `STATUS.md`).
- [ ] If ETW cannot start, snapshot mode continues and the report lists a coverage gap. No claim of complete capture is ever made.
**Validate:** Windows VM.

### M16: Hardening and release
**Build:** full footprint audit (Section 7), AV test matrix, code signing, README (installation-free usage), `docs/LIMITATIONS.md`, `docs/ARCHITECTURE.md`, `docs/RULES.md`, reproducible build check (`-trimpath`, pinned toolchain; two builds, same hash).
**Acceptance:**
- [ ] All features at `WINDOWS-VALIDATED` or lower with honest status; footprint-sensitive collectors at `FOOTPRINT-AUDITED`.
- [ ] Test matrix passed on Windows 10 22H2 and Windows 11 (current plus one prior feature release).
- [ ] Final Review document answers spec section 19 step 8: implemented, tested, not tested, limitations, remaining risks, what to improve before regular customer use.
- [ ] Owner sign-off checklist (Section 10) completed.

---

## 6. Starter rule catalog (about 25; add nothing until these are solid)

"Requires" lists what must be true. "Never alone" lists conditions that must not trigger this rule by themselves.

| ID | Trigger (requires) | Exceptions / never alone | Base severity |
|---|---|---|---|
| PROC-001 | Protected system name (`svchost.exe`, `lsass.exe`, `csrss.exe`, ...) with wrong path **or** no valid Microsoft signature | Name match alone | High (needs corroboration for High-Confidence) |
| PROC-002 | Lineage violation against embedded table (`wininit`→`services`/`lsass`; `services`→`svchost`; `smss`→`csrss`/`wininit`; single-instance system processes) | Documented exceptions per build | Medium |
| PROC-003 | Executable in user-writable path **and** no trusted signature **and** outbound public connection | Any one of these alone; baselined apps | Medium |
| PROC-004 | Signature present but **invalid** (tampered or untrusted chain) | Unsigned files (different state) | Medium |
| PROC-005 | Hash differs from approved baseline for the same path/publisher (third-party only) | Auto-updating apps with version-aware baselines | Medium |
| PROC-006 | Document/browser/script host spawns an interpreter (`powershell`, `cmd`, `wscript`, `mshta`, ...) **and** that process has network activity or an encoded command | Interpreter launch alone | Medium |
| PROC-007 | Running image missing on disk or changed during inspection | Transient installers | Low |
| NET-001 | Non-loopback listener owned by an untrusted user-path binary | Trusted/baselined servers | Medium |
| NET-002 | Remote-access tool with external connection and **not** in authorized list | Authorized list match | Medium |
| NET-003 | Single-interval connection, owner gone, owner untrusted (retained, not lowered later) | Trusted owners | Low |
| NET-004 | Periodic same-destination connections (at least N intervals, regular spacing) by untrusted owner | Trusted updaters | Low |
| RA-001 | Unauthorized remote tool present on disk | Presence alone is never above Low | Low |
| RA-002 | Unauthorized remote tool **with persistence** (service/run/task) | Authorized list match | Medium |
| RA-003 | ScreenConnect instance with relay host not in authorized relays | No authorized relay list means `Needs Review`, not High | Medium |
| RA-004 | Tool logs show inbound session in or near the suspected window | Evidence record; elevates linked findings | Info (supports) |
| PER-001 | Autorun target in `%TEMP%`, `Users\Public`, or other user-writable path | Baselined apps | Low |
| PER-002 | Autorun target is untrusted **and** that file has network activity (corroborated across PERSIST+NET+FILE) | Baselined | High |
| PER-003 | Task XML/TaskCache mismatch | None | Medium |
| PER-004 | Service `ImagePath` unquoted with spaces, user-path, or untrusted binary | Vendor services with documented quirks | Low |
| PER-005 | IFEO `Debugger`, modified Winlogon `Shell`/`Userinit`, `AppInit_DLLs` populated | Known accessibility/debug tooling | Medium |
| PER-006 | WMI permanent subscription with command or script consumer | Known vendor subscriptions | Medium |
| ART-001 | Script in temp/public with download-and-execute or encoded-command patterns | Pattern match alone on administrator scripts in `ProgramData` of known tools | Medium |
| ART-002 | Recently created executable in Temp/Public/Downloads | Never alone | Info |
| CFG-001 | Defender disabled or exclusions covering user-writable paths | Enterprise-managed exclusions | Medium |
| CFG-002 | Hosts overrides for security/update domains, unexpected proxy/PAC or DNS | ISP/VPN-managed values | Medium |
| CFG-003 | RDP enabled without NLA, new local admin, user-added root cert | Each alone is Low | Low |
| SELF-001 | **Not a finding.** Labels the tool's own process as authorized | N/A | N/A |

---

## 7. Test lab and footprint audit

### 7.1 Lab setup (step by step)

1. Create two Hyper-V (or VMware/VirtualBox) VMs: **Windows 11** (current) and **Windows 10 22H2**. Take a checkpoint named `clean`.
2. Attach a **virtual USB/removable disk** for `Canaveral.exe` and its reports. Take a checkpoint named `clean+usb`.
3. Install Sysinternals (Procmon, Autoruns) in the VM, **not** on the USB reports path.
4. For scenario VMs, restore `clean+usb` each time, then apply one scenario:
   - **Benign remote tool:** install AnyDesk (or another listed tool) normally and mark it authorized in `config\baseline.yaml`.
   - **Seeded lookalikes** (`scripts/lab/Seed-LabArtifacts.ps1` creates; `scripts/lab/Remove-LabArtifacts.ps1` reverts): copy `notepad.exe` to `%LOCALAPPDATA%\Temp\svchost.exe`, add an HKCU Run entry pointing at it, register a scheduled task for it, drop an inert `.ps1` containing a *non-executing* encoded-string pattern in `Users\Public`.
   - **Lab beacon:** a tiny Go program in `testdata/lab/beacon/` that connects to a server **you control** and exits (for ETW and short-lived tests).
5. **Never** use real malware in any VM that the tests touch.

### 7.2 Footprint audit (step by step)

Run in the VM, from an **elevated PowerShell**:

```powershell
# 1. Start network capture (no packet payload files in the USB path)
pktmon start --capture --comp nics --pkt-size 0

# 2. Start Procmon capture to a file on the analyst's own drive (harness data, not tool output)
& "C:\Tools\Procmon64.exe" /AcceptEula /Quiet /Minimized /BackingFile C:\audit\run.pml

# 3. Run the tool from the removable disk
& "E:\Canaveral.exe" scan --output "E:\Canaveral_Reports"

# 4. Stop captures
& "C:\Tools\Procmon64.exe" /Terminate
pktmon stop
pktmon etl2txt PktMon.etl -o C:\audit\net.txt

# 5. Export Procmon to CSV with the saved filter config, then review
& "C:\Tools\Procmon64.exe" /OpenLog C:\audit\run.pml /LoadConfig C:\audit\canaveral.pmc /SaveAs C:\audit\run.csv /Quiet
```

`canaveral.pmc` filters: `Process Name is Canaveral.exe` **and** operation in `WriteFile, SetEndOfFileInformationFile, SetRenameInformationFile, SetDispositionInformationFile, RegSetValue, RegCreateKey, RegDeleteKey, RegDeleteValue, RegLoadKey` **and** path **not** beginning with `E:\Canaveral_Reports`.

Pass criteria:
- [ ] The filtered CSV is empty (or every row is explained in `docs/LIMITATIONS.md`).
- [ ] `net.txt` has no packets attributable to `Canaveral.exe` (PID).
- [ ] `logman query -ets` shows no leftover `Canaveral-Live` session after exit.
- [ ] USB contains only the report directory contents defined in M2.
- [ ] Footprint section of the report matches what Procmon observed.

### 7.3 Regression matrix

Windows 10 22H2, Windows 11 (current and prior feature release) × admin/standard user × clean / benign-remote-tool / seeded-lookalikes × Defender on/off. Record results in `docs/STATUS.md`.

---

## 8. Build, run, test commands

```powershell
# One-time tools (PowerShell, from the repo root)
go version
go install github.com/akavel/rsrc@latest                      # builds the admin-manifest .syso
rsrc -manifest cmd\canaveral\canaveral.manifest -o cmd\canaveral\rsrc_windows_amd64.syso

# Build (reproducible-oriented; no UPX, no packers; keep symbols until AV testing is done)
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags "-X main.version=0.1.0" -o dist\Canaveral.exe .\cmd\canaveral
# or simply:
.\scripts\build.ps1

# Tests
go vet ./...
go test ./...                                   # all platform-independent tests
go test -tags windows ./internal/platform/...   # on a Windows machine
# Race detector needs cgo, so run it on Linux CI:
#   CGO_ENABLED=1 go test -race ./internal/...
go test -fuzz=Fuzz -fuzztime=60s ./internal/collectors/history/...

# Run (from the USB drive, elevated)
E:\Canaveral.exe                              # TUI
E:\Canaveral.exe scan                         # one-time headless scan
E:\Canaveral.exe monitor --interval 5s --duration 30m
E:\Canaveral.exe scan --full-inventory --redact
E:\Canaveral.exe report --from E:\Canaveral_Reports\<scan>\report.json
Get-FileHash E:\Canaveral_Reports\<scan>\report.md -Algorithm SHA256   # compare to report.md.sha256
```

---

## 9. Milestone Report template

```markdown
## Milestone M<N> Report
**Status of each feature:** (SCAFFOLD / COMPILES / FIXTURE-TESTED / WINDOWS-VALIDATED / FOOTPRINT-AUDITED)
**Implemented:** ...
**Acceptance checklist:** (paste the list, ticked honestly; unticked items explained)
**Tests run:** commands + pass/fail counts
**Not tested / cannot be tested here:** ...
**Deviations from CLAUDE.md or SPEC.md:** ...
**New risks or limitations (also added to docs/LIMITATIONS.md):** ...
**What the owner must validate on a Windows VM:** step-by-step commands
```

---

## 10. Open decisions for the owner (answer before M3 and M16)

1. **Code signing:** certificate type and where it lives (needed for M16; unsigned builds will get flagged).
2. **Config format:** YAML (default in this file) or TOML.
3. **Reputation lookups:** recommended **not in v1**; keep offline-only. Revisit after M16.
4. **ARM64:** deferred; x64 only for now.
5. **Report retention policy:** how long reports stay on the USB and how they are wiped (BitLocker To Go on the USB is strongly recommended).
6. **Employer approval and consent wording:** confirm company policy on third-party tools and customer machines, and finalize the authorization-banner text.
7. **Authorized-tool list for the bench:** which remote tools and relay hosts your shop legitimately uses.

---

## 11. Non-negotiables (restated, short)

- Accuracy over speed. Evidence over scores. No guessed data.
- Signed is not safe; unsigned is not malicious; public IP is not malicious; absence is not safety.
- Whitelists reduce priority; they never bypass contradictory evidence.
- Zero **intentional** host writes by the tool, with honest disclosure of Windows-generated artifacts. Never claim a guaranteed zero footprint.
- Never delete, kill, modify, or "fix" anything on the customer machine.
- Never claim Windows functionality was tested unless it was run on Windows.
