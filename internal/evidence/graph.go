package evidence

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// Errors returned by the graph.
var (
	ErrInvalidObservation        = errors.New("evidence: invalid observation")
	ErrUnknownNode               = errors.New("evidence: unknown node")
	ErrIDCollision               = errors.New("evidence: node ID collision")
	ErrInvalidEdge               = errors.New("evidence: invalid edge")
	ErrIllegalTransition         = errors.New("evidence: illegal state transition")
	ErrInsufficientCorroboration = errors.New("evidence: corroboration needs at least two distinct evidence classes")
	ErrEvidenceRequired          = errors.New("evidence: transition requires supporting evidence")
	ErrReasonRequired            = errors.New("evidence: a reason is required")
)

// NodeID is a stable evidence identifier: a kind prefix plus 64 bits of
// SHA-256 over the node's kind and key, for example "SOC-1a2b3c4d5e6f7a8b".
// The same fact gets the same ID in every scan.
type NodeID string

var kindPrefix = map[models.NodeKind]string{
	models.KindProcess:     "PRC",
	models.KindFile:        "FIL",
	models.KindSocket:      "SOC",
	models.KindPersistence: "PER",
	models.KindHistory:     "HIS",
	models.KindConfig:      "CFG",
	models.KindFinding:     "FND",
}

var kindClass = map[models.NodeKind]models.EvidenceClass{
	models.KindProcess:     models.ClassProcess,
	models.KindFile:        models.ClassFile,
	models.KindSocket:      models.ClassNetwork,
	models.KindPersistence: models.ClassPersistence,
	models.KindHistory:     models.ClassHistory,
	models.KindConfig:      models.ClassConfig,
}

// ClassOf returns the evidence class of a node kind. Findings have no class.
func ClassOf(k models.NodeKind) (models.EvidenceClass, bool) {
	c, ok := kindClass[k]
	return c, ok
}

// makeID is a variable so tests can force a collision.
var makeID = func(kind models.NodeKind, key string) NodeID {
	sum := sha256.Sum256([]byte(string(kind) + "\x00" + key))
	return NodeID(kindPrefix[kind] + "-" + hex.EncodeToString(sum[:8]))
}

// Sizer lets a payload report its approximate in-memory size for the budget.
type Sizer interface {
	ApproxBytes() int
}

// Observation is one collected fact to add to the graph.
type Observation struct {
	Kind models.NodeKind
	// Key identifies the subject within its kind and must capture everything
	// that makes two observations the same fact. Equal kind and key are
	// deduplicated into one node.
	Key string
	// At is when the fact was observed, from the single platform clock.
	At        time.Time
	Collector string
	Method    string
	// State is StateObserved (the default when empty) or StateUnavailable.
	State models.EvidenceState
	// Reason is required when State is StateUnavailable.
	Reason   string
	Severity models.Severity
	// Payload is the collected record. It is treated as immutable once added.
	Payload any
}

// StateChange is one entry in a node's state history.
type StateChange struct {
	At       time.Time
	From, To models.EvidenceState
	Reason   string
	Evidence []NodeID
}

// SeverityChange is one entry in a node's severity history.
type SeverityChange struct {
	At       time.Time
	From, To models.Severity
	Reason   string
	Evidence []NodeID
}

// Node is a snapshot of one evidence node. Values returned by the graph are
// copies; changing them does not change the graph.
type Node struct {
	ID    NodeID
	Kind  models.NodeKind
	Class models.EvidenceClass // empty for findings
	Key   string
	State models.EvidenceState

	// FirstObserved, LastObserved and Count cover successful observations
	// only. They are zero for a node that has only ever been Unavailable.
	FirstObserved time.Time
	LastObserved  time.Time
	Count         uint64

	// UnavailableAttempts counts collection attempts that failed. A failure
	// never erases or downgrades an earlier successful observation.
	UnavailableAttempts uint64
	UnavailableReason   string
	LastUnavailableAt   time.Time

	Collector string
	Method    string

	Severity    models.Severity
	MaxSeverity models.Severity

	Payload         any
	StateHistory    []StateChange
	SeverityHistory []SeverityChange
}

// Edge is a directed, typed link between two nodes.
type Edge struct {
	From, To NodeID
	Kind     models.EdgeKind
}

// edgeEndpoints defines which node kinds each edge kind may connect.
var edgeEndpoints = map[models.EdgeKind]func(from, to models.NodeKind) bool{
	models.EdgeImageOf: func(f, t models.NodeKind) bool {
		return f == models.KindFile && t == models.KindProcess
	},
	models.EdgeParentOf: func(f, t models.NodeKind) bool {
		return f == models.KindProcess && t == models.KindProcess
	},
	models.EdgeOwnsSocket: func(f, t models.NodeKind) bool {
		return f == models.KindProcess && t == models.KindSocket
	},
	models.EdgeLaunchesFile: func(f, t models.NodeKind) bool {
		return f == models.KindPersistence && t == models.KindFile
	},
	models.EdgeRecordedExecutionOf: func(f, t models.NodeKind) bool {
		return f == models.KindHistory && t == models.KindFile
	},
	models.EdgeSupportsFinding: func(f, t models.NodeKind) bool {
		return f != models.KindFinding && t == models.KindFinding
	},
	models.EdgeContradictsFinding: func(f, t models.NodeKind) bool {
		return f != models.KindFinding && t == models.KindFinding
	},
}

// Approximate per-item costs for the memory budget. These are estimates of
// heap usage, not exact measurements.
const (
	nodeOverheadBytes   = 256
	defaultPayloadBytes = 128
	historyEntryBytes   = 96
	evidenceRefBytes    = 24
	edgeBytes           = 128
)

type entry struct {
	node  Node
	bytes int64
	elem  *list.Element // position in the recency list
}

// Graph is the in-memory evidence graph. It is safe for concurrent use.
type Graph struct {
	mu sync.RWMutex

	nodes map[NodeID]*entry
	edges map[Edge]struct{}
	out   map[NodeID]map[Edge]struct{}
	in    map[NodeID]map[Edge]struct{}
	// recency orders nodes from least to most recently observed.
	recency *list.List

	budget    int64
	protectAt models.Severity
	used      int64

	rollups    map[rollupKey]*Rollup
	overBudget *overBudgetRecord
}

// DefaultBudgetBytes is the default memory budget (CLAUDE.md A13).
const DefaultBudgetBytes int64 = 256 << 20

// Options configures a Graph. Zero fields take defaults.
type Options struct {
	// BudgetBytes is the memory budget for retained evidence.
	// Default DefaultBudgetBytes.
	BudgetBytes int64
	// ProtectAtOrAbove is the lowest severity that is never evicted.
	// Default SeverityMedium, so only None, Info and Low raw observations are
	// ever evicted.
	ProtectAtOrAbove models.Severity
}

// New returns an empty graph.
func New(opts Options) *Graph {
	if opts.BudgetBytes <= 0 {
		opts.BudgetBytes = DefaultBudgetBytes
	}
	if opts.ProtectAtOrAbove == models.SeverityNone {
		opts.ProtectAtOrAbove = models.SeverityMedium
	}
	return &Graph{
		nodes:     map[NodeID]*entry{},
		edges:     map[Edge]struct{}{},
		out:       map[NodeID]map[Edge]struct{}{},
		in:        map[NodeID]map[Edge]struct{}{},
		recency:   list.New(),
		budget:    opts.BudgetBytes,
		protectAt: opts.ProtectAtOrAbove,
		rollups:   map[rollupKey]*Rollup{},
	}
}

func validateObservation(o *Observation) error {
	if _, ok := kindPrefix[o.Kind]; !ok {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidObservation, o.Kind)
	}
	if o.Key == "" {
		return fmt.Errorf("%w: empty key", ErrInvalidObservation)
	}
	if o.At.IsZero() {
		return fmt.Errorf("%w: zero observation time", ErrInvalidObservation)
	}
	if o.Collector == "" || o.Method == "" {
		return fmt.Errorf("%w: collector and method are required", ErrInvalidObservation)
	}
	if o.Severity > models.SeverityHigh {
		return fmt.Errorf("%w: invalid severity %d", ErrInvalidObservation, o.Severity)
	}
	switch o.State {
	case "":
		o.State = models.StateObserved
	case models.StateObserved:
	case models.StateUnavailable:
		if o.Reason == "" {
			return fmt.Errorf("%w: unavailable observation needs a reason", ErrInvalidObservation)
		}
	default:
		return fmt.Errorf("%w: a node cannot start as %s", ErrInvalidObservation, o.State)
	}
	return nil
}

// Observe adds an observation, merging it into an existing node with the same
// kind and key. It returns the node's ID.
func (g *Graph) Observe(o Observation) (NodeID, error) {
	if err := validateObservation(&o); err != nil {
		return "", err
	}
	at := o.At.UTC()
	id := makeID(o.Kind, o.Key)

	g.mu.Lock()
	defer g.mu.Unlock()

	if e, ok := g.nodes[id]; ok {
		if e.node.Kind != o.Kind || e.node.Key != o.Key {
			return "", fmt.Errorf("%w: %s already holds %s %q", ErrIDCollision, id, e.node.Kind, e.node.Key)
		}
		g.merge(e, o, at)
		g.recency.MoveToBack(e.elem)
		g.resize(e)
		return id, nil
	}

	class, _ := ClassOf(o.Kind)
	n := Node{
		ID: id, Kind: o.Kind, Class: class, Key: o.Key, State: o.State,
		Collector: o.Collector, Method: o.Method,
		Severity: o.Severity, MaxSeverity: o.Severity,
	}
	if o.State == models.StateUnavailable {
		n.UnavailableAttempts = 1
		n.UnavailableReason = o.Reason
		n.LastUnavailableAt = at
	} else {
		n.FirstObserved, n.LastObserved, n.Count = at, at, 1
		n.Payload = o.Payload
	}
	e := &entry{node: n}
	e.elem = g.recency.PushBack(id)
	g.nodes[id] = e
	g.resize(e)
	return id, nil
}

func (g *Graph) merge(e *entry, o Observation, at time.Time) {
	n := &e.node
	switch {
	case o.State == models.StateUnavailable:
		n.UnavailableAttempts++
		n.UnavailableReason = o.Reason
		if at.After(n.LastUnavailableAt) {
			n.LastUnavailableAt = at
		}
	case n.State == models.StateUnavailable:
		n.StateHistory = append(n.StateHistory, StateChange{
			At: at, From: models.StateUnavailable, To: models.StateObserved,
			Reason: fmt.Sprintf("collected on a later attempt by %s/%s", o.Collector, o.Method),
		})
		n.State = models.StateObserved
		n.FirstObserved, n.LastObserved, n.Count = at, at, 1
		n.Payload = o.Payload
	default:
		n.Count++
		if at.Before(n.FirstObserved) {
			n.FirstObserved = at
		}
		if at.After(n.LastObserved) {
			n.LastObserved = at
		}
		if n.Payload == nil {
			n.Payload = o.Payload
		}
	}
	if o.Severity > n.Severity {
		n.SeverityHistory = append(n.SeverityHistory, SeverityChange{
			At: at, From: n.Severity, To: o.Severity,
			Reason: fmt.Sprintf("observed at %s by %s/%s", o.Severity, o.Collector, o.Method),
		})
		n.Severity = o.Severity
	}
	if n.Severity > n.MaxSeverity {
		n.MaxSeverity = n.Severity
	}
}

// Link adds a typed edge. Adding an existing edge again is a no-op.
func (g *Graph) Link(from, to NodeID, kind models.EdgeKind) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	fe, ok := g.nodes[from]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownNode, from)
	}
	te, ok := g.nodes[to]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownNode, to)
	}
	allowed, ok := edgeEndpoints[kind]
	if !ok {
		return fmt.Errorf("%w: unknown edge kind %q", ErrInvalidEdge, kind)
	}
	if from == to {
		return fmt.Errorf("%w: %s cannot link to itself", ErrInvalidEdge, from)
	}
	if !allowed(fe.node.Kind, te.node.Kind) {
		return fmt.Errorf("%w: %s cannot go from %s to %s", ErrInvalidEdge, kind, fe.node.Kind, te.node.Kind)
	}
	ed := Edge{From: from, To: to, Kind: kind}
	if _, dup := g.edges[ed]; dup {
		return nil
	}
	g.edges[ed] = struct{}{}
	addEdgeIndex(g.out, from, ed)
	addEdgeIndex(g.in, to, ed)
	g.used += edgeBytes
	return nil
}

func addEdgeIndex(idx map[NodeID]map[Edge]struct{}, id NodeID, ed Edge) {
	m, ok := idx[id]
	if !ok {
		m = map[Edge]struct{}{}
		idx[id] = m
	}
	m[ed] = struct{}{}
}

// Node returns a copy of the node with the given ID.
func (g *Graph) Node(id NodeID) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e, ok := g.nodes[id]
	if !ok {
		return Node{}, false
	}
	return copyNode(e.node), true
}

// Nodes returns copies of all nodes, sorted by ID.
func (g *Graph) Nodes() []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Node, 0, len(g.nodes))
	for _, e := range g.nodes {
		out = append(out, copyNode(e.node))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Edges returns every edge that starts or ends at id, sorted.
func (g *Graph) Edges(id NodeID) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []Edge
	for ed := range g.out[id] {
		out = append(out, ed)
	}
	for ed := range g.in[id] {
		out = append(out, ed)
	}
	sortEdges(out)
	return out
}

// AllEdges returns every edge in the graph, sorted.
func (g *Graph) AllEdges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Edge, 0, len(g.edges))
	for ed := range g.edges {
		out = append(out, ed)
	}
	sortEdges(out)
	return out
}

func sortEdges(es []Edge) {
	sort.Slice(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
}

// Len returns the number of nodes.
func (g *Graph) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

func copyNode(n Node) Node {
	n.StateHistory = append([]StateChange(nil), n.StateHistory...)
	for i := range n.StateHistory {
		n.StateHistory[i].Evidence = append([]NodeID(nil), n.StateHistory[i].Evidence...)
	}
	n.SeverityHistory = append([]SeverityChange(nil), n.SeverityHistory...)
	for i := range n.SeverityHistory {
		n.SeverityHistory[i].Evidence = append([]NodeID(nil), n.SeverityHistory[i].Evidence...)
	}
	return n
}

// resize recomputes an entry's estimated size and adjusts the total.
func (g *Graph) resize(e *entry) {
	n := &e.node
	size := int64(nodeOverheadBytes + len(n.Key) + len(n.Collector) + len(n.Method) + len(n.UnavailableReason))
	switch p := n.Payload.(type) {
	case nil:
	case Sizer:
		size += int64(p.ApproxBytes())
	default:
		size += defaultPayloadBytes
	}
	for _, h := range n.StateHistory {
		size += historyEntryBytes + int64(len(h.Reason)) + int64(len(h.Evidence))*evidenceRefBytes
	}
	for _, h := range n.SeverityHistory {
		size += historyEntryBytes + int64(len(h.Reason)) + int64(len(h.Evidence))*evidenceRefBytes
	}
	g.used += size - e.bytes
	e.bytes = size
}
