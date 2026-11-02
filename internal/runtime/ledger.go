package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

// ResourceKind is the kind of host resource the tool created.
type ResourceKind string

// Resource kinds.
const (
	ResourceDirectory ResourceKind = "Directory"
	ResourceFile      ResourceKind = "File"
)

// ResourceState is the lifecycle state of a created resource.
type ResourceState string

// Resource states.
const (
	// StateCreated is a directory the tool created.
	StateCreated ResourceState = "Created"
	// StateTemporary is a file that must not outlive the scan, such as a
	// .partial file before its rename.
	StateTemporary ResourceState = "Temporary"
	// StateFinal is a report artifact that is meant to stay.
	StateFinal ResourceState = "Final"
	// StateReplaced is a final artifact overwritten by a newer version.
	StateReplaced ResourceState = "Replaced"
	// StateRemoved means the tool removed its own resource.
	StateRemoved ResourceState = "Removed"
	// StateRemoveFailed means removal was attempted and failed.
	StateRemoveFailed ResourceState = "RemoveFailed"
	// StateNotRemoved means the tool chose not to remove it, for example
	// because the file at that path is no longer the one it created.
	StateNotRemoved ResourceState = "NotRemoved"
	// StateLost means the device holding it became unavailable.
	StateLost ResourceState = "Lost"
)

// Resource is one host resource the tool created.
type Resource struct {
	ID        int
	Kind      ResourceKind
	Path      string
	CreatedAt time.Time
	State     ResourceState
	Note      string
	// Identity is the file information captured from the tool's own handle
	// at creation, used with os.SameFile so cleanup only ever touches the
	// exact object the tool created.
	Identity os.FileInfo
}

// Ledger records every host resource the tool creates. It is the only source
// cleanup uses, so nothing is ever removed just because its name or
// timestamp looks like the tool's.
type Ledger struct {
	mu        sync.Mutex
	clock     platform.Clock
	resources []*Resource
	approved  []string
}

// NewLedger returns an empty ledger using clock for timestamps.
func NewLedger(clock platform.Clock) *Ledger {
	return &Ledger{clock: clock}
}

// Approve records root as an approved output location.
func (l *Ledger) Approve(root string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.approved {
		if r == root {
			return
		}
	}
	l.approved = append(l.approved, root)
}

// Record adds a created resource and returns its ID.
func (l *Ledger) Record(kind ResourceKind, path string, state ResourceState, identity os.FileInfo) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := &Resource{
		ID: len(l.resources) + 1, Kind: kind, Path: path,
		CreatedAt: l.clock.Now().UTC(), State: state, Identity: identity,
	}
	l.resources = append(l.resources, r)
	return r.ID
}

// SetIdentity stores the identity for a resource.
func (l *Ledger) SetIdentity(id int, identity os.FileInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.get(id); r != nil {
		r.Identity = identity
	}
}

// Update changes a resource's state and note.
func (l *Ledger) Update(id int, state ResourceState, note string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.get(id); r != nil {
		r.State, r.Note = state, note
	}
}

// Renamed records that a resource now lives at newPath with a new state.
// Any earlier Final resource at newPath becomes Replaced.
func (l *Ledger) Renamed(id int, newPath string, state ResourceState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.resources {
		if r.ID != id && r.Path == newPath && r.State == StateFinal {
			r.State, r.Note = StateReplaced, fmt.Sprintf("overwritten by resource %d", id)
		}
	}
	if r := l.get(id); r != nil {
		r.Path, r.State = newPath, state
	}
}

// MarkLostUnder marks every live resource under root as Lost, for when the
// device holding root disappears.
func (l *Ledger) MarkLostUnder(root, note string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.resources {
		if within(root, r.Path) && (r.State == StateCreated || r.State == StateTemporary || r.State == StateFinal) {
			r.State, r.Note = StateLost, note
		}
	}
}

func (l *Ledger) get(id int) *Resource {
	if id < 1 || id > len(l.resources) {
		return nil
	}
	return l.resources[id-1]
}

// Resources returns copies of all recorded resources in creation order.
func (l *Ledger) Resources() []Resource {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Resource, len(l.resources))
	for i, r := range l.resources {
		out[i] = *r
	}
	return out
}

// Approved returns the approved output roots.
func (l *Ledger) Approved() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.approved...)
}

// within reports whether path is root or inside it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
