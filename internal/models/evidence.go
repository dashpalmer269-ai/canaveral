package models

import (
	"fmt"
	"time"
)

// EvidenceState is the verification state of an evidence node (CLAUDE.md 4.1).
type EvidenceState string

// Evidence states.
const (
	StateObserved     EvidenceState = "Observed"
	StateVerified     EvidenceState = "Verified"
	StateCorroborated EvidenceState = "Corroborated"
	StateContradicted EvidenceState = "Contradicted"
	StateUnavailable  EvidenceState = "Unavailable"
	StateInconclusive EvidenceState = "Inconclusive"
)

// AllEvidenceStates lists every evidence state.
var AllEvidenceStates = []EvidenceState{
	StateObserved, StateVerified, StateCorroborated,
	StateContradicted, StateUnavailable, StateInconclusive,
}

// EvidenceClass groups evidence by independent source (CLAUDE.md 4.2).
// Corroboration requires at least two different classes.
type EvidenceClass string

// Evidence classes.
const (
	ClassProcess     EvidenceClass = "PROC"
	ClassNetwork     EvidenceClass = "NET"
	ClassFile        EvidenceClass = "FILE"
	ClassPersistence EvidenceClass = "PERSIST"
	ClassHistory     EvidenceClass = "HISTORY"
	ClassConfig      EvidenceClass = "CONFIG"
)

// NodeKind is the type of an evidence graph node.
type NodeKind string

// Node kinds.
const (
	KindProcess     NodeKind = "Process"
	KindFile        NodeKind = "File"
	KindSocket      NodeKind = "Socket"
	KindPersistence NodeKind = "PersistenceEntry"
	KindHistory     NodeKind = "HistoryRecord"
	KindConfig      NodeKind = "ConfigFact"
	KindFinding     NodeKind = "Finding"
)

// AllNodeKinds lists every node kind.
var AllNodeKinds = []NodeKind{
	KindProcess, KindFile, KindSocket, KindPersistence,
	KindHistory, KindConfig, KindFinding,
}

// EdgeKind is the type of a directed evidence graph edge.
type EdgeKind string

// Edge kinds. The direction is From -> To as named, for example a File is the
// ImageOf a Process, and a parent Process is ParentOf its child.
const (
	EdgeImageOf             EdgeKind = "ImageOf"             // File -> Process
	EdgeParentOf            EdgeKind = "ParentOf"            // Process -> Process
	EdgeOwnsSocket          EdgeKind = "OwnsSocket"          // Process -> Socket
	EdgeLaunchesFile        EdgeKind = "LaunchesFile"        // PersistenceEntry -> File
	EdgeRecordedExecutionOf EdgeKind = "RecordedExecutionOf" // HistoryRecord -> File
	EdgeSupportsFinding     EdgeKind = "SupportsFinding"     // any non-Finding -> Finding
	EdgeContradictsFinding  EdgeKind = "ContradictsFinding"  // any non-Finding -> Finding
)

// Severity is an ordered severity level. Higher values are more severe.
type Severity uint8

// Severity levels.
const (
	SeverityNone Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
)

var severityNames = [...]string{"None", "Info", "Low", "Medium", "High"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprintf("Severity(%d)", uint8(s))
}

// MarshalText encodes the severity by name.
func (s Severity) MarshalText() ([]byte, error) {
	if int(s) >= len(severityNames) {
		return nil, fmt.Errorf("invalid severity %d", uint8(s))
	}
	return []byte(severityNames[s]), nil
}

// UnmarshalText decodes a severity name.
func (s *Severity) UnmarshalText(b []byte) error {
	for i, name := range severityNames {
		if string(b) == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", b)
}

// CoverageStatus describes how completely something was collected or retained.
type CoverageStatus string

// Coverage statuses.
const (
	CoverageComplete    CoverageStatus = "Complete"
	CoveragePartial     CoverageStatus = "Partial"
	CoverageTruncated   CoverageStatus = "Truncated"
	CoverageUnavailable CoverageStatus = "Unavailable"
	// CoverageBudgetExceeded means retained evidence exceeds the memory budget
	// and was kept anyway because it is protected from eviction.
	CoverageBudgetExceeded CoverageStatus = "BudgetExceeded"
)

// CoverageNote records what was attempted, what was incomplete and why.
type CoverageNote struct {
	Source string
	Item   string
	Status CoverageStatus
	Reason string
	At     time.Time
}
