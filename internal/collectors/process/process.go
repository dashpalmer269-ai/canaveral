package process

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

// Source is the coverage source name for this collector.
const Source = "collectors/process"

// Process is one process with its identity and resolved parent.
type Process struct {
	models.ProcessRecord
	// Key is PID + creation time. It is only meaningful when KeyComplete is
	// true; without a creation time, PID reuse cannot be ruled out.
	Key         models.ProcessKey
	KeyComplete bool
	// Parent is the parent's identity, known only when the parent is still
	// running and was created no later than this process.
	Parent models.Value[models.ProcessKey]
}

// Snapshot is one process enumeration.
type Snapshot struct {
	At        time.Time
	Processes []Process // sorted by PID
	Coverage  []models.CoverageNote
	byPID     map[uint32]int
}

// ByPID returns the process with pid in this snapshot.
func (s Snapshot) ByPID(pid uint32) (Process, bool) {
	i, ok := s.byPID[pid]
	if !ok {
		return Process{}, false
	}
	return s.Processes[i], true
}

// Collect enumerates processes. If enumeration fails, the snapshot holds a
// single Unavailable coverage note and the error is returned; process
// enumeration is a critical collector.
func Collect(ctx context.Context, src platform.ProcessSource, clock platform.Clock) (Snapshot, error) {
	at := clock.Now().UTC()
	recs, err := src.Processes(ctx)
	if err != nil {
		return Snapshot{At: at, byPID: map[uint32]int{}, Coverage: []models.CoverageNote{{
			Source: Source, Item: "process enumeration", Status: models.CoverageUnavailable,
			Reason: "process enumeration failed: " + err.Error(), At: at,
		}}}, err
	}
	return Build(at, recs), nil
}

// Build turns raw records into a snapshot: identities, parents and coverage.
func Build(at time.Time, recs []models.ProcessRecord) Snapshot {
	s := Snapshot{At: at, byPID: map[uint32]int{}}
	for _, r := range recs {
		if _, dup := s.byPID[r.PID]; dup {
			s.Coverage = append(s.Coverage, models.CoverageNote{
				Source: Source, Item: fmt.Sprintf("PID %d", r.PID), Status: models.CoveragePartial,
				Reason: "the process list reported this PID twice; only the first entry was kept", At: at,
			})
			continue
		}
		p := Process{ProcessRecord: r, Key: models.ProcessKey{PID: r.PID}}
		if ct, ok := r.CreateTime.Get(); ok {
			p.Key.CreateTime, p.KeyComplete = ct, true
		}
		s.byPID[r.PID] = len(s.Processes)
		s.Processes = append(s.Processes, p)
	}
	sort.Slice(s.Processes, func(i, j int) bool { return s.Processes[i].PID < s.Processes[j].PID })
	for i, p := range s.Processes {
		s.byPID[p.PID] = i
	}
	for i := range s.Processes {
		s.Processes[i].Parent = s.resolveParent(s.Processes[i])
	}
	s.Coverage = append(s.Coverage, s.coverage(at)...)
	return s
}

func (s Snapshot) resolveParent(p Process) models.Value[models.ProcessKey] {
	switch {
	case p.PID == 0:
		return models.Unavailable[models.ProcessKey]("the System Idle Process has no parent")
	case p.ParentPID == p.PID:
		return models.Unavailable[models.ProcessKey](fmt.Sprintf("PID %d reports itself as its own parent", p.PID))
	}
	parent, ok := s.ByPID(p.ParentPID)
	switch {
	case !ok:
		return models.Unavailable[models.ProcessKey](fmt.Sprintf("parent PID %d is no longer running", p.ParentPID))
	case !p.KeyComplete || !parent.KeyComplete:
		return models.Unavailable[models.ProcessKey](fmt.Sprintf("parent PID %d is running, but a creation time is unknown, so PID reuse cannot be ruled out", p.ParentPID))
	case parent.Key.CreateTime > p.Key.CreateTime:
		return models.Unavailable[models.ProcessKey](fmt.Sprintf("PID %d now belongs to a process started after this one; the original parent exited and its PID was reused", p.ParentPID))
	}
	return models.Known(parent.Key)
}

// Lineage returns the ancestors of key, nearest first, following only known
// parents. It stops at an unknown parent, after max steps, or on a cycle.
func (s Snapshot) Lineage(key models.ProcessKey, max int) []Process {
	var out []Process
	seen := map[models.ProcessKey]bool{key: true}
	cur, ok := s.ByPID(key.PID)
	if !ok || !cur.KeyComplete || cur.Key != key {
		return nil
	}
	for len(out) < max {
		pk, ok := cur.Parent.Get()
		if !ok || seen[pk] {
			break
		}
		parent, ok := s.ByPID(pk.PID)
		if !ok || parent.Key != pk {
			break
		}
		seen[pk] = true
		out = append(out, parent)
		cur = parent
	}
	return out
}

// coverage reports processes that could not be fully read. These are
// coverage records, never findings: an unreadable process is not evidence of
// anything.
func (s Snapshot) coverage(at time.Time) []models.CoverageNote {
	var notes []models.CoverageNote
	partial, unnamed := 0, 0
	for _, p := range s.Processes {
		if p.PID == 0 {
			continue // the Idle pseudo-process has nothing to read
		}
		if !p.UserName.IsKnown() && p.UserSID.IsKnown() {
			unnamed++
		}
		fields := []struct {
			name string
			ok   bool
			why  string
		}{
			{"creation time", p.CreateTime.IsKnown(), p.CreateTime.Reason()},
			{"image path", p.ImagePath.IsKnown(), p.ImagePath.Reason()},
			{"command line", p.CommandLine.IsKnown(), p.CommandLine.Reason()},
			{"user", p.UserSID.IsKnown(), p.UserSID.Reason()},
			{"protection level", p.Protection.IsKnown(), p.Protection.Reason()},
		}
		var missing []string
		for _, f := range fields {
			if !f.ok {
				missing = append(missing, f.name+" ("+f.why+")")
			}
		}
		if len(missing) == 0 {
			continue
		}
		partial++
		status := models.CoveragePartial
		if len(missing) == len(fields) {
			status = models.CoverageUnavailable
		}
		reason := "not readable: " + strings.Join(missing, "; ")
		if prot, ok := p.Protection.Get(); ok && prot != "None" {
			reason = fmt.Sprintf("protected process (%s); Windows restricts what can be read. %s", prot, reason)
		}
		notes = append(notes, models.CoverageNote{
			Source: Source, Item: fmt.Sprintf("PID %d (%s)", p.PID, p.Name), Status: status, Reason: reason, At: at,
		})
	}
	summary := models.CoverageNote{Source: Source, Item: "process inventory", Status: models.CoverageComplete, At: at,
		Reason: fmt.Sprintf("%d processes enumerated; all fields read", len(s.Processes))}
	if partial > 0 {
		summary.Status = models.CoveragePartial
		summary.Reason = fmt.Sprintf("%d processes enumerated; %d could not be fully read (listed separately). Unreadable processes are coverage gaps, not findings", len(s.Processes), partial)
	}
	notes = append(notes, summary)
	if unnamed > 0 {
		notes = append(notes, models.CoverageNote{Source: Source, Item: "account names", Status: models.CoveragePartial, At: at,
			Reason: fmt.Sprintf("%d processes have a user SID but no resolved account name", unnamed)})
	}
	return notes
}
