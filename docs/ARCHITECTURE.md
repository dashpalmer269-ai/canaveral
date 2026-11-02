# Architecture

Status: skeleton (M0). The authoritative design is CLAUDE.md sections 3 and 4. This document will describe the implemented system as milestones land.

## Package layout

Each package below exists as an empty `doc.go` stub.

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

## Enforced boundaries

`.golangci.yml` enforces CLAUDE.md 1.2 in CI, on both the host OS and `GOOS=windows`:

- No process creation anywhere (`os/exec`, `os.StartProcess`, `syscall`/`x/sys/windows` process APIs).
- Host writes (file, directory and registry) only in `internal/runtime/output`. `_test.go` files are also exempt, since tests run on dev and CI machines, never on a customer host.
- Network code only in `internal/reputation`, which is not built in v1.
- `internal/platform/fake` is importable only from `_test.go` files and `fixture`-tagged files.

See `docs/LIMITATIONS.md` for what lint cannot catch.
