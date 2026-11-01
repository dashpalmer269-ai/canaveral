# CANAVERAL — MASTER DEVELOPMENT & IMPLEMENTATION PROMPT

## 1. Your Role & Primary Objective

You are acting as a senior Go software engineer, Windows internals specialist, digital forensics and incident response (DFIR) engineer, cybersecurity detection engineer, and terminal interface designer.

Your task is to **design, implement, test, and deliver Canaveral**, a standalone, portable Windows forensic triage and network integrity utility for my internal computer repair and technical support workflow.

This is a real application intended for use on customer computers, particularly during investigations involving suspected scams, unauthorized remote access, suspicious software, persistence mechanisms, and unusual network activity.

**Do not simply write an architectural proposal or pseudocode. Build the actual modular Go application.**

The fundamental objective is to transform scattered Windows system evidence into a technically defensible, clearly explained security assessment.

Canaveral is an **evidence correlation and verification engine**, not merely a security score generator, antivirus replacement, or simplistic process scanner.

The final security verdict must be a consequence of the collected and corroborated evidence.

### Primary Engineering Priorities

In descending order:

1. Forensic accuracy and defensible conclusions.
2. Read-only investigation and minimal host modification.
3. Accurate process-to-network correlation.
4. Independent verification and re-verification.
5. Minimization and identification of false positives.
6. Thorough collection of relevant security evidence.
7. Transparent limitations and uncertainty handling.
8. Clear, actionable reporting.
9. Reliable operation on customer computers.
10. Performance optimization without sacrificing accuracy.
11. Responsive Game Boy/pixel-art-inspired terminal interface.

**Accuracy takes priority over speed. Never sacrifice correctness simply to make scans complete faster.**

---

## 2. Technology Stack — Go Only

Build the entire application using native Go (Golang).

Do not use Python, PyInstaller, Electron, Node.js, JavaScript frontends, web servers, browsers, or external language runtimes.

### Core Requirements

- Native Go implementation.
- Windows 10 and Windows 11 support.
- Initial target: Windows x64.
- Single portable executable: `Canaveral.exe`.
- No installation required.
- No persistent Windows services or drivers.
- No dependency on Python or other interpreters.
- Prefer native Windows APIs and well-maintained Go packages.
- Prefer `CGO_ENABLED=0` where technically feasible.
- All required dependencies bundled into the compiled binary.
- Support offline operation by default.
- Do not initiate network connections for reputation lookups unless explicitly enabled by the operator.

### Recommended TUI Libraries

Use the Charm ecosystem:

- **Bubble Tea:** Terminal UI, state management, keyboard navigation, event handling.
- **Lip Gloss:** Layout, colors, borders, visual styling.
- **Bubbles:** Tables, progress bars, lists, scrolling, and interactive components.

Choose compatible, stable versions of these libraries.

Implement collectors, detection logic, reporting, and UI as separate modules.

The forensic engine must be able to operate without the TUI through a command-line/headless mode.

---

## 3. Portable Execution & Minimal Host Modification

This requirement is foundational.

Canaveral is intended to execute directly from an external USB storage device during repair-bench investigations.

Its operational design must prioritize memory-only processing and avoid altering the customer's computer.

### Strict Application-Controlled Write Policy

The application must:

- Avoid intentionally creating files on the host's internal drives.
- Avoid writing application logs to host storage.
- Avoid creating temporary files or caches on host drives.
- Avoid creating or modifying registry keys.
- Avoid installing software, services, drivers, or scheduled tasks.
- Avoid changing Windows security settings.
- Avoid modifying the files, processes, or persistence entries being investigated.
- Avoid terminating suspicious processes automatically.
- Avoid clearing Windows event logs or altering security monitoring.
- Keep intermediate findings, evidence models, correlation records, and temporary analysis results in RAM wherever possible.
- Direct generated reports and permitted configuration output exclusively to the selected USB storage path.

### Output Location

By default, identify the executable's own drive and use a dedicated report directory on that drive.

Validate the output path before writing. Do not silently fall back to the host's system drive.

If the USB becomes unavailable, retain results in memory where feasible, display a clear warning, and allow another explicitly approved external destination.

Do not scatter report files throughout the USB drive.

### Cleanup and Footprint Review

Implement an internal resource-management and cleanup mechanism.

- Track every temporary resource created by Canaveral.
- Avoid creating host-side temporary files in the first place.
- Automatically remove any application-owned temporary file or resource accidentally created outside the approved output path, where safe and precisely attributable.
- Do not delete unrelated files or artifacts merely because they appear near the scan timestamp.
- Provide a final footprint-review status to the operator.

Windows may independently produce execution artifacts such as Prefetch records, security events, or paging data. A user-mode program cannot guarantee their absence.

**Do not erase, suppress, or tamper with Windows-generated forensic evidence.**

Where Canaveral can identify possible Windows-generated execution artifacts, flag them for informational operator review only.

Do not promise a mathematically guaranteed zero-footprint execution.

The implementation target is **zero intentional host-disk writes by Canaveral, with transparent disclosure of operating-system limitations**.

---

## 4. Privilege Management & Operational Safety

Canaveral is designed to run with Windows Administrator privileges for maximum visibility.

Implement:

- Privilege detection on launch.
- Clear elevation-status display.
- Administrator privilege requirements for restricted collectors.
- User-friendly warnings if privileges are insufficient.
- Graceful error handling for inaccessible processes, files, or Windows APIs.
- No fabricated values when information cannot be retrieved.

Prefer requesting elevation through an appropriate Windows executable manifest.

Do not use UAC bypasses or attempt to circumvent operating-system security protections.

Canaveral should remain read-only with respect to customer system configuration and investigated artifacts.

---

## 5. Core Architecture — Concurrent Investigative Subsystems

Structure the application around two primary investigative subsystems, with an optional third.

These are logical components that can run concurrently using Go goroutines and controlled worker pools; they do not need to be separate operating-system processes.

### Subsystem A — Snapshot Analysis

Inspect currently running processes and active network connections.

Responsibilities:

- Enumerate current network endpoints.
- Resolve owning processes.
- Collect process metadata.
- Inspect executable integrity.
- Verify trust information.
- Correlate processes and network connections.
- Apply detection rules.
- Repeat relevant observations for verification.

Run repeated snapshots during a monitoring session.

### Subsystem B — Historical Artifact & Persistence Analysis

Examine existing evidence of earlier execution, persistence, and potentially unwanted software.

Responsibilities:

- Suspicious executable discovery.
- Remote-access tool artifacts.
- Windows autorun mechanisms.
- Scheduled tasks.
- Windows services.
- Startup folders.
- PowerShell/script artifacts.
- Browser extension and policy indicators.
- Existing Windows execution artifacts where accessible.

Use read-only collection methods.

### Optional Subsystem C — Live Network Observation

Investigate whether Windows-native event-based monitoring, including appropriate ETW facilities, can improve visibility beyond polling.

The goal is to identify short-lived network events that might occur between snapshots.

Important requirements:

- No persistent driver installation.
- No ETL trace files on host storage.
- Prefer in-memory real-time event handling.
- Explicitly document privilege requirements and blind spots.
- Do not claim that all network activity is captured unless that guarantee is technically established.

If reliable event-based monitoring cannot be implemented without violating host-modification constraints, keep it optional and preserve the snapshot engine.

### Snapshot vs. Live Monitoring

Short-lived malicious processes may connect to a network and terminate before the next polling interval.

Therefore:

- Use configurable snapshot intervals.
- Begin with an appropriate default and permit operator adjustment.
- Measure actual collection duration.
- Avoid overlapping collectors that create inconsistent evidence.
- Track observations across snapshots.
- Correlate processes using PID plus process creation identity, not PID alone.
- Preserve previously observed suspicious activity even after a process or connection disappears.
- Do not automatically reduce risk simply because suspicious activity is absent from a later snapshot.

A disappearing process is not automatically evidence of safety.

---

## 6. Network Socket & Connection Collection

Enumerate available IPv4 and IPv6 TCP/UDP endpoints.

Collect:

- Protocol.
- Local address.
- Local port.
- Remote address, where applicable.
- Remote port, where applicable.
- TCP connection state.
- Owning PID, where supplied by Windows.
- Observation timestamp.
- Correlation confidence and collection limitations.

Include TCP states such as:

- LISTENING
- ESTABLISHED
- TIME_WAIT
- CLOSE_WAIT
- Other available states.

Do not invent TCP-like connection states for UDP.

Handle sockets without identifiable ownership and document cases where Windows does not expose a reliable owning PID.

### Network Classification

Categorize endpoints appropriately:

- Loopback.
- Link-local.
- Private network.
- Public/external IP.
- Multicast, reserved, or other special-purpose addresses.
- Unknown.

Support both IPv4 and IPv6.

Do not treat every public IP connection as suspicious.

Do not assume that a public IP or port number proves malicious behavior.

Evaluate network observations in the context of the associated process, executable trust, observed behavior, and available history.

### Accurate Process Correlation

Use Windows-native network and process APIs where appropriate.

Consider race conditions involving:

- Process termination.
- PID reuse.
- Socket closure.
- Short-lived processes.
- Connection state changes.
- Unavailable owner information.

A connection should not be assigned to a process with greater confidence than the evidence supports.

When attribution is uncertain, show it as uncertain.

---

## 7. Deep Process Metadata Collection

For relevant running processes, gather as much of the following information as Windows permits.

### Identity

- Process name.
- PID.
- Parent PID.
- Parent process name.
- Process creation time.
- Available parent/ancestor lineage.

### Execution Context

- Full executable path.
- Full command line.
- User account/security context.
- Executable location classification.
- Whether the location is expected or user-writable.

### Integrity

- SHA-256 executable hash.
- File accessibility.
- File metadata relevant to verification.
- Signature verification status.
- Signer/publisher identity.
- Trust-check limitations.

### Signature Validation

Use Windows Authenticode and appropriate native Windows trust APIs.

Distinguish:

- Valid signature.
- Invalid signature.
- Unsigned file.
- Verification unavailable or indeterminate.

A valid signature must not automatically imply that a program is safe.

Evaluate expected publisher identity, execution location, process lineage, baseline rules, and contradictory evidence.

Avoid automatically trusting files merely because their filename resembles a legitimate Windows executable.

### Hashing Reliability

- Hash executable bytes, not the filename.
- Cache hashes only where identity and file metadata make reuse defensible.
- Detect and report files that change during inspection when possible.
- Do not fabricate hashes for inaccessible files.
- Distinguish verified disk-file identity from assumptions about what a process has loaded into memory.

---

## 8. Scam-Specific Artifact Detection

Canaveral must be particularly useful when inspecting computers after suspected tech-support scams or unauthorized remote-access sessions.

### Priority Software Families

Detect relevant artifacts associated with:

- AnyDesk.
- RustDesk.
- ScreenConnect / ConnectWise Control.
- TeamViewer.
- UltraViewer.
- Other configurable remote-support and remote-administration tools.

Software presence alone must not automatically be labeled malicious.

Distinguish between authorized installations, unexpected portable executables, suspicious persistence, and evidence requiring additional review.

### High-Risk Locations

Inspect relevant user-accessible directories, including:

- AppData\Local.
- AppData\Roaming.
- AppData\Local\Temp.
- Users\Public.
- Downloads.
- Startup directories.
- Other configurable locations.

Cover applicable user profiles, not only the currently signed-in account.

Avoid treating all files under these directories as suspicious.

### Suspicious Artifact Types

Investigate:

- Unexpected executable binaries.
- Portable remote-access applications.
- Recently created or modified executable files.
- Suspicious PowerShell scripts.
- Batch and command scripts.
- JavaScript and VBScript artifacts.
- Executables with system-process-impersonating filenames.
- Unusual file paths and unexpected launch locations.

Use contextual detection rather than simplistic filename matching alone.

### Persistence Checks

Implement read-only collection for:

- Scheduled tasks.
- Windows services.
- Registry Run/RunOnce entries.
- Startup folders.
- Other high-value autorun locations where supported.
- Browser extension and policy abnormalities.

Do not delete or modify discovered persistence entries.

---

## 9. Trust Baselines, Whitelisting & False-Positive Reduction

This is one of the most important components.

### Hard Whitelist Philosophy

Trusted software should receive reduced investigative priority when strong trust criteria are satisfied.

However, whitelisting must never completely bypass the baseline inspection of suspicious behavior.

Trust criteria can include:

- Verified executable signature.
- Expected publisher identity.
- Canonical execution location.
- Expected process lineage.
- Approved SHA-256 baseline.
- Absence of contradictory high-confidence evidence.

Not every criterion must apply identically to every software family. Trust rules should be explicit and software-appropriate.

A Microsoft-signed binary behaving unexpectedly must remain eligible for investigation.

### Avoid False Positives

The goal is to aggressively minimize false positives through evidence correlation, independent verification, and appropriate rule thresholds.

Do not promise a literal zero false-positive rate.

Examples of conditions that are individually insufficient to prove maliciousness:

- Running from AppData.
- Being unsigned.
- Connecting to a public IP.
- Running automatically at startup.
- Using a remote-access software family.
- Having an unfamiliar publisher.
- Disappearing between snapshots.

These may still be important indicators when combined.

### Canaveral Self-Recognition

Ensure the application recognizes its own process and associated activity.

Identify Canaveral using reliable runtime identity, executable path, and relevant metadata rather than process name alone.

Clearly label its own process as an authorized investigative tool.

Avoid treating expected Canaveral behavior as a security incident.

Do not conceal its presence from the complete process inventory, and do not automatically exclude genuinely contradictory evidence.

### Baseline Management

Support configurable, versioned:

- Trusted publishers.
- Approved executable hashes.
- Approved execution paths.
- Expected system-process identities.
- Authorized remote-support applications.
- Heuristic rules and weights.
- Known-benign exceptions.

Store configuration alongside the executable on the USB drive where practical, with embedded safe defaults.

Never silently add newly encountered binaries to a trusted baseline.

---

## 10. Heuristic Detection Engine

Build an explainable, modular rule engine.

Flag and investigate relevant combinations of:

- Unsigned executables maintaining external connections.
- Executables running from unexpected user-writable paths.
- System-process name impersonation.
- Suspicious parent-child relationships.
- Unexpected outbound connections during bench sessions.
- Unusual persistent network activity.
- Unexpected remote-access tools.
- Suspicious autorun entries.
- Executables associated with questionable persistence.
- Hash mismatches.
- Invalid or unexpected signatures.
- Other supported, technically defensible indicators.

### Scoring Philosophy

Do not construct arbitrary scores without documented reasoning.

Each rule must have:

- A unique rule ID.
- A clear explanation.
- Supporting evidence requirements.
- Severity or risk contribution.
- Confidence/verification status.
- Relevant exceptions.
- A recommended technician follow-up.

Correlate related evidence rather than blindly adding duplicate alerts.

A single underlying behavior observed repeatedly must not automatically become a critical finding merely because it was counted many times.

Do not confuse numerical risk score with proof of compromise.

### Per-Process and Per-Connection Assessment

Maintain a current assessment for:

- Each observed process.
- Each network connection, where meaningful.
- Relevant artifact and persistence findings.
- The overall host.

A port number alone is not independently malicious.

The UI should display changing process/connection assessments as new evidence arrives.

Preserve the original observations and reasons for any assessment changes.

Do not calculate a simple average of past snapshots if that would conceal short-lived high-confidence suspicious behavior.

---

## 11. Verification & Re-Verification Engine

Before escalating a finding to high confidence, independently corroborate it wherever possible.

For example, when detecting an unsigned executable communicating with a public IP:

1. Verify the owning process identity.
2. Confirm the process creation identity to reduce PID-reuse errors.
3. Resolve the executable's actual path.
4. Calculate its SHA-256 hash.
5. Validate its digital signature.
6. Check publisher and baseline rules.
7. Evaluate parent-process lineage.
8. Recheck available network observations.
9. Search for related persistence or suspicious artifacts.
10. Correlate the findings and assess confidence.

Do not require the same short-lived connection to remain active for the finding to be considered valid.

A historical observation may remain significant even if it cannot be reproduced.

### Evidence States

Distinguish:

- Observed.
- Verified.
- Corroborated.
- Contradicted.
- Unavailable.
- Inconclusive.

A failure to access a process, file, or artifact must not be treated as evidence that it is malicious.

Conversely, inaccessible evidence must not be treated as proof that the host is safe.

### Handling Failed Checks

When a collection method fails:

- Skip the unavailable data from rules that require it.
- Do not substitute guessed results.
- Avoid creating a suspicious finding solely because an ordinary check failed.
- Record important coverage gaps and collection errors.
- Surface critical gaps in the overall assessment.

Do not overwhelm the TUI with repetitive error messages.

Detailed coverage information should remain available in the report.

---

## 12. Security Classifications & Verdict Logic

Implement separate trust, anomaly, and confidence assessments.

### Finding Classification

**Verified Good**

Explicit trust criteria have been satisfied, and no disqualifying contradictory indicators were observed.

**No Anomaly Detected**

No relevant suspicious characteristics were observed, but the item has not been positively established as trusted.

**Needs Review**

One or more suspicious characteristics warrant technician investigation.

**High-Confidence Indicator**

Independent, corroborated evidence strongly supports malicious or unauthorized activity.

### Overall Host Verdict

Use the following states:

**NO INDICATORS IDENTIFIED**

The completed checks did not detect meaningful suspicious evidence.

This is not proof that the system is uncompromised.

**FURTHER REVIEW REQUIRED**

Potentially suspicious findings exist but have not been confirmed malicious.

**HIGH-CONFIDENCE COMPROMISE INDICATORS**

Corroborated evidence strongly suggests malicious or unauthorized activity.

Do not automatically assert the full extent of a compromise.

**ASSESSMENT INCOMPLETE**

Critical collections failed or coverage is insufficient for a defensible overall verdict.

### Verdict Requirements

- Every verdict must be explainable.
- High-confidence classifications require strong supporting evidence.
- Do not equate a known malicious artifact with proof of what an attacker accomplished.
- Preserve uncertainty where appropriate.
- Do not issue a clean verdict when critical required checks could not be completed.

---

## 13. Game Boy / Pixel-Art Terminal Interface

Create a clean, distinctive, retro-inspired TUI using Go.

The aesthetic should resemble a professional diagnostic instrument influenced by an original Game Boy interface.

### Visual Direction

- Muted monochrome green palette.
- Dark green or dark charcoal background.
- Pixel-inspired borders and Unicode block symbols.
- Compact retro terminal headers.
- Simple, readable severity indicators.
- Keyboard-driven navigation.
- Minimal unnecessary animation.
- No overwhelming decorative elements.

Use terminal text and Unicode art rather than requiring external graphical assets.

Provide ASCII-compatible and reduced-color fallbacks where needed.

### Main Navigation

Include dedicated screens or views for:

1. Overview.
2. Live Network.
3. Processes.
4. Findings.
5. Persistence / Artifacts.
6. Report / Export.
7. Settings / Baselines.

### Live Monitoring Presentation

Display:

- Current monitoring status.
- Active process count.
- Network endpoint count.
- Findings grouped by severity.
- Current collection phase.
- Last completed snapshot.
- Dynamic risk indicators.
- Newly observed or disappeared connections.

Allow selecting an individual process or connection to expand its technical details.

The TUI must remain responsive during collectors and hashing operations.

### Dual-Layer Finding Explanations

Every finding should have two explanatory layers.

**Layer One — Simple Language**

Immediately understandable to a repair technician.

Example:

"Unverified program in a user folder is talking to another computer. Check what it is."

**Layer Two — Technical Evidence**

Example:

"Unsigned executable under %APPDATA% maintaining an outbound TCP connection. Associated PID, full executable path, SHA-256 hash, destination IP, port, signature status, timestamp, and triggered detection rule recorded."

The simple explanation must never contradict or exaggerate the technical evidence.

### Keyboard Navigation

Provide intuitive shortcuts for:

- Starting a scan.
- Switching views.
- Inspecting findings.
- Viewing technical evidence.
- Changing monitoring settings.
- Exporting a report.
- Quitting safely.

Display shortcuts visibly and provide help.

---

## 14. Evidentiary Markdown Reporting

The TUI is the interactive operator-facing interface.

**The Markdown report is the detailed forensic record.**

All reports must be saved directly to the approved USB output location.

Generate a readable `.md` file containing:

### Host Metadata

- Hostname.
- OS version and architecture.
- Scan date and timestamps.
- Tool version.
- Ruleset version.
- Privilege status.
- Scan duration.
- Collection coverage and limitations.

### Executive Summary

- Overall security verdict.
- Plain-language interpretation.
- Processes inspected.
- Network endpoints observed.
- Persistence mechanisms inspected.
- Suspicious artifacts discovered.
- Findings by severity.
- Critical limitations.

### Detailed Findings

For each flagged item:

1. Plain-language description.
2. Technical description.
3. Triggered detection rule.
4. Why the rule triggered.
5. Evidence supporting the finding.
6. Process metadata and lineage, if applicable.
7. Executable path.
8. SHA-256 hash.
9. Signature and publisher status.
10. Associated network endpoints.
11. Related persistence evidence.
12. Observation timestamps.
13. Corroboration status.
14. Severity and confidence explanation.
15. Recommended technician verification steps.

### Complete Inventories

Allow optional inclusion of:

- Full process table.
- Full network connection table.
- Artifact inventory.
- Persistence inventory.
- Relevant collection and verification errors.

### Integrity & Traceability

Include:

- Canaveral application version.
- Ruleset/baseline version.
- Scan timestamps.
- Evidence identifiers.
- Consistent timestamps and identifiers across linked findings.

Generate a SHA-256 checksum of the completed report in a separate `.sha256` companion file on the USB.

Do not attempt to embed a self-referential checksum inside the report itself.

The report must be useful both as a technical record and as a practical repair-bench investigation summary.

---

## 15. Performance, Stability & Reliability

Accuracy is more important than speed, but the application should still operate efficiently.

Implement:

- Bounded concurrency.
- Controlled worker pools.
- Cancellable scans.
- Configurable snapshot intervals.
- Deduplicated evidence.
- Sensible hashing caches.
- In-memory evidence storage.
- Graceful process termination.
- Reliable cancellation and cleanup.
- Clear status messages.
- Explicit error handling.

Avoid unnecessary resource consumption on already unstable customer computers.

Do not automatically sacrifice forensic completeness to achieve arbitrary speed targets.

---

## 16. Suggested Project Structure

Use a modular Go repository organized approximately as follows.

- `cmd/canaveral/` — Application entry point and CLI.
- `internal/tui/` — Bubble Tea models, views, components, and styles.
- `internal/collectors/network/` — Network endpoint collection.
- `internal/collectors/process/` — Process metadata and lineage.
- `internal/collectors/artifacts/` — Suspicious file discovery.
- `internal/collectors/persistence/` — Windows persistence checks.
- `internal/collectors/history/` — Historical evidence.
- `internal/integrity/` — SHA-256 and signature verification.
- `internal/baseline/` — Trust rules and configurations.
- `internal/detection/` — Heuristic rule engine.
- `internal/correlation/` — Process, connection, and evidence correlation.
- `internal/verification/` — Corroboration and re-verification.
- `internal/scoring/` — Severity and confidence assessment.
- `internal/report/` — Markdown output.
- `internal/platform/windows/` — Windows-native API implementations.
- `internal/models/` — Shared typed data models.
- `internal/runtime/` — USB path validation, resources, and cleanup.
- `configs/` — Example ruleset and baseline configurations.
- `scripts/` — Build and validation scripts.
- `testdata/` — Deterministic test fixtures.
- `docs/` — Architecture and operational documentation.

Adjust the structure if necessary for clean Go conventions, but preserve modular separation.

---

## 17. Testing & Quality Assurance

Do not consider a module complete merely because it compiles.

Implement unit tests and representative test fixtures.

### Required Test Areas

- Process and socket correlation.
- PID reuse and process termination races.
- IPv4 and IPv6 endpoint classification.
- Signature verification status handling.
- Hash calculation.
- Baseline matching.
- False-positive suppression.
- Suspicious executable path detection.
- Process lineage evaluation.
- Repeated-observation correlation.
- Findings deduplication.
- Risk classification.
- Contradictory evidence.
- Incomplete collection handling.
- Markdown report generation.
- USB output-path validation.
- Resource cleanup.

### False-Positive Test Scenarios

Include legitimate scenarios such as:

- Verified Microsoft OS processes.
- Legitimate unsigned programs.
- Legitimate applications installed in AppData.
- Authorized remote-support software.
- Normal cloud application connections.
- Normal system services maintaining outbound connections.
- Canaveral's own running process.

### Suspicious Test Scenarios

Include synthetic examples such as:

- System-process impersonation.
- Unexpected remote-access persistence.
- Unsigned executable with suspicious external connectivity.
- Unknown executable in a temporary directory with an autorun entry.
- Invalid signature and unexpected parent-process lineage.
- Short-lived suspicious network activity observed in only one collection interval.

Tests must demonstrate that legitimate and suspicious scenarios are distinguished based on evidence rather than arbitrary assumptions.

Never execute real malicious samples as part of the default test suite.

---

## 18. Build & Deliverables

Provide a complete, compilable project with:

1. All Go source files.
2. `go.mod`.
3. `go.sum`.
4. Windows build script (`build.ps1`).
5. Single standalone Windows executable build target.
6. Embedded default detection rules.
7. Example configurable baselines.
8. Complete Markdown reporting engine.
9. Sample fictional forensic report.
10. Unit tests.
11. README with installation-free usage instructions.
12. Documentation of limitations and required privileges.

The build system must support producing:

`Canaveral.exe`

Provide example commands for:

- Compiling.
- Running the TUI.
- Running a one-time scan.
- Running a longer monitoring session.
- Generating a full Markdown report.
- Running tests.

Do not claim Windows-specific functionality has been tested unless it actually has been tested on Windows.

---

## 19. Development Execution Instructions

Follow these instructions during implementation.

### Step 1 — Inspect and Plan

If a repository already exists, inspect it before changing files.

Identify:

- Existing implementation.
- Relevant dependencies.
- Missing functionality.
- Platform-specific constraints.
- Potential problems with assumptions in this specification.

Prepare a concise implementation plan, then begin development.

Do not stop after producing a plan.

### Step 2 — Implement the Forensic Foundation

Prioritize:

1. Windows process collection.
2. Network endpoint enumeration.
3. Accurate PID/process correlation.
4. Executable hashing.
5. Signature verification.
6. Shared evidence models.

Validate these before building advanced scoring or decorative UI elements.

### Step 3 — Implement Historical and Scam-Specific Analysis

Develop:

- Artifact discovery.
- Remote-access software detection.
- Persistence collection.
- Historical evidence inspection.

Use read-only access.

### Step 4 — Implement Detection and Verification

Build:

- Trust baselines.
- Heuristic rule engine.
- Corroboration logic.
- False-positive reduction.
- Severity classification.
- Evidence-driven verdict generation.

### Step 5 — Implement Monitoring and TUI

Integrate the collectors into the interactive Game Boy-inspired terminal interface.

Ensure long-running operations do not block the UI.

### Step 6 — Implement Reporting

Generate USB-directed Markdown reports containing complete evidence, explanations, and limitations.

### Step 7 — Validate and Harden

Run available tests, inspect results, fix defects, and check:

- Host-write avoidance.
- Output destination restrictions.
- Collector reliability.
- False-positive scenarios.
- Error handling.
- Resource cleanup.
- Build reproducibility.

Do not silently substitute mock results for real Windows collector results.

### Step 8 — Final Review

At the end, provide:

- What was implemented.
- What was tested.
- What could not be tested.
- Known limitations.
- Remaining risks.
- Build and execution instructions.
- What should be improved before regular use on customer computers.

Do not claim a feature is complete when it is only scaffolding or pseudocode.

---

## 20. Non-Negotiable Engineering Standards

Throughout development:

- Prioritize accuracy over speed.
- Verify evidence instead of trusting single observations.
- Never invent missing forensic data.
- Never assume a signed executable is automatically safe.
- Never assume an unsigned executable is automatically malicious.
- Never assume an external network connection is malicious.
- Never classify missing evidence as proof of safety.
- Never silently hide critical collection failures.
- Never automatically delete suspicious customer files.
- Never tamper with operating-system forensic logs.
- Never modify customer security settings.
- Never intentionally write application data to host drives.
- Never allow a whitelist to completely bypass contradictory high-confidence evidence.
- Never claim that snapshot polling guarantees observing every network event.
- Never call a system uncompromised solely because the scan found no indicators.

Every finding must be understandable, technically traceable, and supported by evidence.

---

## 21. Final Product Vision

Canaveral should feel like a professional, portable diagnostic instrument designed specifically for a repair technician.

The technician inserts a USB drive, launches the Go executable with the necessary permissions, and investigates the computer through a clean, responsive Game Boy-inspired TUI.

The application examines active processes, network connections, executable integrity, persistence mechanisms, and historical artifacts.

It correlates evidence, verifies suspicious observations, minimizes false positives, and explains exactly why findings deserve attention.

The technician can monitor activity, inspect individual processes and connections, and export a detailed Markdown forensic report back to the USB drive.

The final application must provide both:

**Immediate understanding:** Simple, easily digestible descriptions and symbols.

**Technical accountability:** Precise evidence, verification records, rule explanations, and documented uncertainty.

The ultimate goal is not to assign an impressive-looking numerical security score.

**The goal is to build a reliable investigative tool that helps me determine what is happening on a customer's computer, why it matters, what evidence supports the assessment, and what I should investigate next.**

Begin implementation using these requirements. Make sound technical decisions, document unavoidable limitations, and prioritize a working, well-tested forensic foundation over superficial feature completeness.