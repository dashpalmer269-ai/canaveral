# Canaveral

**An evidence correlation and verification engine that turns scattered Windows system evidence into a technically defensible, understandable assessment.**

Canaveral is a portable, read-only Windows forensic triage and network-integrity tool for repair-bench investigations, especially after suspected tech-support scams or unauthorized remote access. It is written in Go, ships as a single `Canaveral.exe`, and runs from a USB drive with no installation.

> **Project status: pre-implementation.** The product spec and the milestone-driven build contract are written. No application code exists yet, and nothing below should be read as a shipped feature. See [Status](#status).

---

## Why it exists

A repair technician looking at a possibly compromised machine has to answer: *what is running, what is it talking to, how did it get there, and how sure am I?* Antivirus scores and one-shot process scanners don't answer that defensibly. Canaveral is built around evidence instead of scores:

- Every verdict is a consequence of collected, **corroborated** evidence, and the report shows the chain.
- Every finding has two layers: a plain-language explanation for the technician and the technical evidence behind it. The plain text must never exaggerate the technical text.
- Missing data is reported as missing. It is never guessed, never treated as malicious, and never treated as proof of safety.

## Core principles

- Signed is not automatically safe. Unsigned is not automatically malicious. A public IP is not automatically malicious. Absence of evidence is not proof of a clean system.
- Whitelists reduce priority but never bypass contradictory evidence.
- Zero **intentional** host writes by the tool. Reports go only to the approved USB path. Windows-generated artifacts (Prefetch, event log entries, and so on) can't be fully prevented, so they're disclosed in every report rather than hidden.
- Never delete, terminate, modify or "fix" anything on the customer's machine.
- Accuracy over speed. High-confidence findings need corroboration across independent evidence classes, not the same observation counted twice.

## Planned capabilities

- **Snapshot analysis:** processes and TCP/UDP sockets (IPv4 and IPv6), correlated by PID plus process creation time to survive PID reuse, with honest attribution confidence.
- **Integrity checks:** SHA-256 hashing and catalog-aware Authenticode verification, offline and write-free, so normal Windows binaries aren't misreported as unsigned.
- **Persistence and artifacts:** Run keys, services, scheduled tasks (XML compared against the registry task cache), WMI subscriptions, IFEO, Winlogon, startup folders, plus bounded artifact discovery across user profiles.
- **Remote-access tool detection:** AnyDesk, TeamViewer, ScreenConnect, RustDesk, UltraViewer, Quick Assist and others, including tool logs as evidence of sessions. Presence alone is never treated as malicious.
- **History and configuration:** event logs, execution artifacts, and network-integrity facts such as DNS, proxy, hosts file, RDP, local admins and Defender exclusions.
- **Explainable rules:** about 25 starter rules, each with an ID, required evidence, exceptions and a recommended technician follow-up.
- **Reports:** canonical JSON plus a Markdown rendering, each with a `.sha256` companion, with an optional redaction mode for customer data.
- **Interface:** a headless CLI engine, then a Game Boy-inspired terminal UI (Bubble Tea) on top of it.
- **Optional live observation:** ETW-based capture of short-lived connections that polling can miss.

## Planned usage (not yet available)

The commands below are the intended interface and will not work until the relevant milestones are done.

Two read-only diagnostic commands work today (Windows only). They write nothing:

```powershell
E:\Canaveral.exe diag-output                      # where reports would be written, and why
E:\Canaveral.exe diag-output --output F:\Reports  # check an explicit destination
E:\Canaveral.exe diag-snapshot                    # privileges, process coverage, every socket with its owner and confidence
```

```powershell
# Build (from the repo root, once the code exists)
.\scripts\build.ps1

# Run from the USB drive in an elevated terminal
E:\Canaveral.exe                                   # interactive TUI
E:\Canaveral.exe scan                              # one-time headless scan
E:\Canaveral.exe monitor --interval 5s --duration 30m
E:\Canaveral.exe scan --full-inventory --redact    # full report, customer data redacted
```

Every launch will show a UAC prompt, since the tool requests Administrator rights through its manifest for maximum visibility. It does not bypass UAC or any other protection.

## How it's being built

Development is driven by two documents:

| File | Role |
|---|---|
| [`docs/SPEC.md`](docs/SPEC.md) | The product vision and requirements. |
| [`CLAUDE.md`](CLAUDE.md) | The build contract: spec amendments, evidence model, rule catalog, 17 milestones with acceptance criteria, and the lab and footprint-audit protocol. **Where it conflicts with the spec, it wins.** |

Work proceeds **one milestone at a time**. A milestone isn't done until every acceptance box is checked, and each ends with a milestone report. Features carry an honest maturity level, tracked in `docs/STATUS.md` once it exists:

`SCAFFOLD` → `COMPILES` → `FIXTURE-TESTED` → `WINDOWS-VALIDATED` → `FOOTPRINT-AUDITED`

Nothing is marked `WINDOWS-VALIDATED` unless it was actually run on Windows, and the footprint claims are verified with Procmon and pktmon rather than asserted.

## Status

| Phase | Milestones | State |
|---|---|---|
| Foundation | M0 bootstrap and CI, M1 models and evidence graph, M2 USB output safety | M0, M1, M2 done |
| Windows core | M3 processes and sockets, M4 hashing and signatures, M5 baselines and self-recognition | M3 done; M4 in progress |
| Detection | M6 rule engine and false-positive suite, M7 verification and verdict | Not started |
| Collectors | M8 persistence, M9 artifacts and remote tools, M10 history, M11 network integrity | Not started |
| Output | M12 reporting, M13 headless engine and monitoring | Not started |
| Interface and live | M14 terminal UI, M15 ETW live observation | Not started |
| Release | M16 hardening, AV testing, code signing | Not started |

## Responsible use and limitations

- **Authorized use only.** Run Canaveral only on systems you are permitted to examine, with the owner's consent. The tool is designed to record an authorization acknowledgement in each report.
- **Not an antivirus replacement.** It collects and correlates evidence to help a technician investigate. It doesn't remove threats.
- **A clean result is not proof of a clean system.** The strongest "good" verdict is *No indicators identified*, and it comes with the coverage gaps that applied.
- **Polling can't see everything.** Snapshot monitoring can miss short-lived connections between intervals. Optional ETW observation narrows that gap but is not a guarantee of complete capture.
- **Reports contain customer data** (usernames, paths, command lines). Treat the USB as sensitive. BitLocker To Go on the drive is strongly recommended.
- **Expect antivirus friction.** A Go binary that inspects every process can trigger heuristic detections. The plan is code signing and transparent handling, with no evasion techniques.

## Repository layout

Present now:

```text
CLAUDE.md                  build contract and milestones
.golangci.yml              lint rules enforcing the no-exec, no-host-write, no-network policy
.github/workflows/ci.yml   CI: lint, test, race, cross-build (ubuntu); build and test (windows)
cmd/canaveral/             entry point (skeleton: prints version and a pre-implementation notice)
internal/                  package skeleton (empty doc.go stubs)
scripts/build.ps1          Windows build script (-NoManifest for a standard-user test build)
tools/gensyso/             generates the requireAdministrator manifest resource at build time
docs/                      SPEC, STATUS ledger, ARCHITECTURE, LIMITATIONS, RULES
```

Planned (created by later milestones):

```text
configs/           embedded default rules and baselines
scripts/lab/       lab seeding scripts
testdata/          deterministic fixtures
```

## License

Not yet chosen. Until a license is added, all rights are reserved by the author.
