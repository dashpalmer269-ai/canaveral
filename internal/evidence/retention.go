package evidence

import (
	"fmt"
	"sort"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// protectionFlow says how protection spreads along an edge kind so that a
// protected node keeps the evidence that explains it.
//   - backward: if To is protected, From is protected.
//   - forward:  if From is protected, To is protected.
//
// A finding keeps its supporting and contradicting evidence; a socket keeps
// its owning process; a process keeps its image file and its ancestors (but
// not its children); persistence entries and history records keep their
// files, and a protected file keeps the persistence and history that point
// at it.
var protectionFlow = map[models.EdgeKind]struct{ backward, forward bool }{
	models.EdgeImageOf:             {backward: true},
	models.EdgeParentOf:            {backward: true},
	models.EdgeOwnsSocket:          {backward: true},
	models.EdgeLaunchesFile:        {backward: true, forward: true},
	models.EdgeRecordedExecutionOf: {backward: true, forward: true},
	models.EdgeSupportsFinding:     {backward: true},
	models.EdgeContradictsFinding:  {backward: true},
}

type rollupKey struct {
	kind      models.NodeKind
	collector string
}

// Rollup summarizes nodes evicted under the memory budget, grouped by node
// kind and collector.
type Rollup struct {
	Kind                models.NodeKind
	Collector           string
	Nodes               int
	Observations        uint64
	UnavailableAttempts uint64
	FirstObserved       time.Time
	LastObserved        time.Time
	MaxSeverity         models.Severity
	LastEvictedAt       time.Time
}

type overBudgetRecord struct {
	at     time.Time
	used   int64
	budget int64
}

// EvictionResult reports what one EnforceBudget call did.
type EvictionResult struct {
	Evicted     int
	FreedBytes  int64
	UsedBytes   int64
	BudgetBytes int64
	// OverBudget is true when protected evidence alone exceeds the budget.
	// It is kept anyway and a coverage note is recorded.
	OverBudget bool
}

// UsedBytes returns the estimated memory used by retained evidence.
func (g *Graph) UsedBytes() int64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.used
}

// SetBudget changes the memory budget. It takes effect at the next
// EnforceBudget call.
func (g *Graph) SetBudget(bytes int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if bytes <= 0 {
		bytes = DefaultBudgetBytes
	}
	g.budget = bytes
}

// EnforceBudget evicts unprotected nodes, least recently observed first, until
// estimated usage is within budget. It is called explicitly (for example after
// each snapshot has been fully linked) rather than on every insert, so a
// snapshot is never evicted halfway through correlation.
//
// Never evicted: findings, nodes whose MaxSeverity is at or above the
// protection threshold, and the linked evidence of either (see
// protectionFlow). Every eviction is summarized in a Rollup and reported
// through Coverage.
func (g *Graph) EnforceBudget(at time.Time) EvictionResult {
	g.mu.Lock()
	defer g.mu.Unlock()

	res := EvictionResult{BudgetBytes: g.budget}
	before := g.used
	if g.used > g.budget {
		protected := g.protectedSet()
		for el := g.recency.Front(); el != nil && g.used > g.budget; {
			next := el.Next()
			id := el.Value.(NodeID)
			if !protected[id] {
				g.evict(id, at.UTC())
				res.Evicted++
			}
			el = next
		}
		if g.used > g.budget {
			res.OverBudget = true
			g.overBudget = &overBudgetRecord{at: at.UTC(), used: g.used, budget: g.budget}
		}
	}
	res.FreedBytes = before - g.used
	res.UsedBytes = g.used
	return res
}

// protectedSet returns the nodes that must never be evicted.
func (g *Graph) protectedSet() map[NodeID]bool {
	protected := map[NodeID]bool{}
	var queue []NodeID
	mark := func(id NodeID) {
		if !protected[id] {
			protected[id] = true
			queue = append(queue, id)
		}
	}
	for id, e := range g.nodes {
		if e.node.Kind == models.KindFinding || e.node.MaxSeverity >= g.protectAt {
			mark(id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for ed := range g.in[id] {
			if protectionFlow[ed.Kind].backward {
				mark(ed.From)
			}
		}
		for ed := range g.out[id] {
			if protectionFlow[ed.Kind].forward {
				mark(ed.To)
			}
		}
	}
	return protected
}

func (g *Graph) evict(id NodeID, at time.Time) {
	e := g.nodes[id]
	n := e.node

	k := rollupKey{kind: n.Kind, collector: n.Collector}
	r, ok := g.rollups[k]
	if !ok {
		r = &Rollup{Kind: n.Kind, Collector: n.Collector}
		g.rollups[k] = r
	}
	r.Nodes++
	r.Observations += n.Count
	r.UnavailableAttempts += n.UnavailableAttempts
	if !n.FirstObserved.IsZero() && (r.FirstObserved.IsZero() || n.FirstObserved.Before(r.FirstObserved)) {
		r.FirstObserved = n.FirstObserved
	}
	if n.LastObserved.After(r.LastObserved) {
		r.LastObserved = n.LastObserved
	}
	if n.MaxSeverity > r.MaxSeverity {
		r.MaxSeverity = n.MaxSeverity
	}
	r.LastEvictedAt = at

	for ed := range g.out[id] {
		g.removeEdge(ed)
	}
	for ed := range g.in[id] {
		g.removeEdge(ed)
	}
	delete(g.out, id)
	delete(g.in, id)
	g.recency.Remove(e.elem)
	delete(g.nodes, id)
	g.used -= e.bytes
}

func (g *Graph) removeEdge(ed Edge) {
	if _, ok := g.edges[ed]; !ok {
		return
	}
	delete(g.edges, ed)
	delete(g.out[ed.From], ed)
	delete(g.in[ed.To], ed)
	g.used -= edgeBytes
}

// Rollups returns summaries of evicted evidence, sorted by kind and collector.
func (g *Graph) Rollups() []Rollup {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Rollup, 0, len(g.rollups))
	for _, r := range g.rollups {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Collector < out[j].Collector
	})
	return out
}

// Coverage returns coverage notes describing evidence that was evicted, and
// whether protected evidence exceeded the budget.
func (g *Graph) Coverage() []models.CoverageNote {
	rollups := g.Rollups()

	g.mu.RLock()
	defer g.mu.RUnlock()

	var notes []models.CoverageNote
	for _, r := range rollups {
		window := "no successful observations"
		if !r.FirstObserved.IsZero() {
			window = fmt.Sprintf("observed %s to %s", r.FirstObserved.Format(time.RFC3339), r.LastObserved.Format(time.RFC3339))
		}
		notes = append(notes, models.CoverageNote{
			Source: "evidence.retention",
			Item:   fmt.Sprintf("%s nodes from %s", r.Kind, r.Collector),
			Status: models.CoverageTruncated,
			Reason: fmt.Sprintf("%d nodes (%d observations, %d failed attempts, %s, max severity %s) were evicted under the %d-byte memory budget and are kept only as this summary",
				r.Nodes, r.Observations, r.UnavailableAttempts, window, r.MaxSeverity, g.budget),
			At: r.LastEvictedAt,
		})
	}
	if ob := g.overBudget; ob != nil {
		notes = append(notes, models.CoverageNote{
			Source: "evidence.retention",
			Item:   "memory budget",
			Status: models.CoverageBudgetExceeded,
			Reason: fmt.Sprintf("protected evidence (findings, severity %s or above, and their linked evidence) used about %d bytes against a %d-byte budget; it was kept, not evicted",
				g.protectAt, ob.used, ob.budget),
			At: ob.at,
		})
	}
	return notes
}
