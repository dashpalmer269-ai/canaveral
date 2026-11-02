package evidence

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

type budgetScenario struct {
	g         *Graph
	protected map[string]NodeID
	child     NodeID   // unprotected child of a protected process
	noise     []NodeID // unprotected, observed oldest first
	noiseObs  map[NodeID]uint64
}

// buildBudgetScenario observes every protected node first, so they are the
// least recently observed. If protection were broken they would be the first
// evicted.
func buildBudgetScenario(t *testing.T, noise int) *budgetScenario {
	t.Helper()
	g := New(Options{BudgetBytes: 1 << 40})
	s := &budgetScenario{g: g, protected: map[string]NodeID{}, noiseObs: map[NodeID]uint64{}}
	at := t0
	next := func(kind models.NodeKind, key string, sev models.Severity) NodeID {
		o := obs(kind, key)
		o.At, o.Severity = at, sev
		at = at.Add(time.Second)
		return mustObserve(t, g, o)
	}
	p := s.protected

	// A finding and its context.
	p["finding"] = next(models.KindFinding, "PROC-003|beacon", models.SeverityMedium)
	p["socket"] = next(models.KindSocket, "beacon socket", models.SeverityInfo)
	p["proc"] = next(models.KindProcess, "beacon proc", models.SeverityNone)
	p["parent"] = next(models.KindProcess, "explorer", models.SeverityNone)
	p["grandparent"] = next(models.KindProcess, "userinit", models.SeverityNone)
	p["image"] = next(models.KindFile, `C:\Users\u\AppData\Local\Temp\svchost.exe`, models.SeverityNone)
	p["runkey"] = next(models.KindPersistence, `HKU\S-1\...\Run\svc`, models.SeverityLow)
	p["prefetch"] = next(models.KindHistory, "SVCHOST.EXE-1234.pf", models.SeverityNone)
	p["baseline"] = next(models.KindConfig, "baseline: not listed", models.SeverityInfo)
	s.child = next(models.KindProcess, "child of beacon", models.SeverityNone)

	mustLink(t, g, p["socket"], p["finding"], models.EdgeSupportsFinding)
	mustLink(t, g, p["baseline"], p["finding"], models.EdgeContradictsFinding)
	mustLink(t, g, p["proc"], p["socket"], models.EdgeOwnsSocket)
	mustLink(t, g, p["parent"], p["proc"], models.EdgeParentOf)
	mustLink(t, g, p["grandparent"], p["parent"], models.EdgeParentOf)
	mustLink(t, g, p["image"], p["proc"], models.EdgeImageOf)
	mustLink(t, g, p["runkey"], p["image"], models.EdgeLaunchesFile)
	mustLink(t, g, p["prefetch"], p["image"], models.EdgeRecordedExecutionOf)
	mustLink(t, g, p["proc"], s.child, models.EdgeParentOf)

	// A finding below the severity threshold is still never evicted, and
	// neither is its evidence.
	p["infoFinding"] = next(models.KindFinding, "ART-002|download.exe", models.SeverityInfo)
	p["infoEvidence"] = next(models.KindFile, `C:\Users\u\Downloads\download.exe`, models.SeverityNone)
	mustLink(t, g, p["infoEvidence"], p["infoFinding"], models.EdgeSupportsFinding)

	// Severity-protected observations with no finding.
	p["medium"] = next(models.KindConfig, "proxy set", models.SeverityMedium)
	p["high"] = next(models.KindProcess, "fake lsass", models.SeverityHigh)
	p["highImage"] = next(models.KindFile, `C:\Users\Public\lsass.exe`, models.SeverityNone)
	mustLink(t, g, p["highImage"], p["high"], models.EdgeImageOf)
	p["downgraded"] = next(models.KindSocket, "was high", models.SeverityHigh)
	if err := g.SetSeverity(p["downgraded"], models.SeverityInfo, at, "contradicted by baseline"); err != nil {
		t.Fatal(err)
	}

	// Unprotected raw observations. Every third one is seen three times.
	for i := range noise {
		sev := []models.Severity{models.SeverityNone, models.SeverityInfo, models.SeverityLow}[i%3]
		id := next(models.KindSocket, fmt.Sprintf("benign socket %d", i), sev)
		s.noiseObs[id] = 1
		if i%3 == 0 {
			o := obs(models.KindSocket, fmt.Sprintf("benign socket %d", i))
			o.At, o.Severity = at, sev
			mustObserve(t, g, o)
			mustObserve(t, g, o)
			s.noiseObs[id] = 3
		}
		s.noise = append(s.noise, id)
	}
	return s
}

// Acceptance (M1): exceeding the budget evicts low-severity raw observations
// only, never findings or high-severity evidence, and records a coverage note.
func TestBudgetEvictsOnlyUnprotectedLowSeverity(t *testing.T) {
	s := buildBudgetScenario(t, 300)
	g := s.g

	full := g.UsedBytes()
	perNoise := full / int64(g.Len()) // rough, only used to size the budget
	g.SetBudget(full - 100*perNoise)
	evictAt := t0.Add(time.Hour)
	res := g.EnforceBudget(evictAt)

	if res.Evicted == 0 || res.OverBudget {
		t.Fatalf("result %+v", res)
	}
	if res.UsedBytes > res.BudgetBytes || g.UsedBytes() != res.UsedBytes {
		t.Fatalf("still over budget: %+v (graph reports %d)", res, g.UsedBytes())
	}
	if res.FreedBytes != full-res.UsedBytes {
		t.Fatalf("freed %d, want %d", res.FreedBytes, full-res.UsedBytes)
	}

	for name, id := range s.protected {
		if _, ok := g.Node(id); !ok {
			t.Errorf("protected node %q (%s) was evicted", name, id)
		}
	}

	// The unprotected child is the oldest unprotected node, so it goes first.
	if _, ok := g.Node(s.child); ok {
		t.Error("unprotected child process survived while newer nodes were evicted")
	}
	for _, e := range g.Edges(s.protected["proc"]) {
		if e.To == s.child || e.From == s.child {
			t.Errorf("edge to evicted child remains: %v", e)
		}
	}

	// Eviction is least-recently-observed first: a prefix of the noise is
	// gone and the rest remains.
	evictedNoise := res.Evicted - 1 // minus the child
	var wantObs uint64 = 0
	for i, id := range s.noise {
		_, present := g.Node(id)
		if i < evictedNoise && present {
			t.Fatalf("noise %d should have been evicted before newer noise", i)
		}
		if i >= evictedNoise && !present {
			t.Fatalf("noise %d evicted out of order", i)
		}
		if i < evictedNoise {
			wantObs += s.noiseObs[id]
		}
	}

	// Rollups summarize exactly what was evicted.
	var gotSockets, gotProcs Rollup
	for _, r := range g.Rollups() {
		switch r.Kind {
		case models.KindSocket:
			gotSockets = r
		case models.KindProcess:
			gotProcs = r
		default:
			t.Errorf("unexpected rollup %+v", r)
		}
	}
	if gotSockets.Nodes != evictedNoise || gotSockets.Observations != wantObs || gotSockets.MaxSeverity > models.SeverityLow {
		t.Errorf("socket rollup %+v, want %d nodes / %d observations", gotSockets, evictedNoise, wantObs)
	}
	if gotProcs.Nodes != 1 || gotProcs.Observations != 1 {
		t.Errorf("process rollup %+v", gotProcs)
	}

	notes := g.Coverage()
	if len(notes) != 2 {
		t.Fatalf("coverage notes %+v", notes)
	}
	for _, n := range notes {
		if n.Source != "evidence.retention" || n.Status != models.CoverageTruncated || !n.At.Equal(evictAt) ||
			!strings.Contains(n.Reason, "evicted under the") {
			t.Errorf("note %+v", n)
		}
	}
	if !strings.Contains(notes[1].Reason, fmt.Sprintf("%d nodes (%d observations", evictedNoise, wantObs)) {
		t.Errorf("socket note does not state the counts: %q", notes[1].Reason)
	}
}

func TestBudgetUnderLimitDoesNothing(t *testing.T) {
	s := buildBudgetScenario(t, 50)
	before := s.g.Len()
	res := s.g.EnforceBudget(t0)
	if res.Evicted != 0 || res.OverBudget || s.g.Len() != before || len(s.g.Coverage()) != 0 {
		t.Fatalf("result %+v, notes %v", res, s.g.Coverage())
	}
}

func TestBudgetSmallerThanProtectedEvidence(t *testing.T) {
	s := buildBudgetScenario(t, 60)
	g := s.g
	g.SetBudget(1)
	res := g.EnforceBudget(t0.Add(time.Hour))

	if !res.OverBudget {
		t.Fatalf("result %+v", res)
	}
	if want := len(s.noise) + 1; res.Evicted != want {
		t.Fatalf("evicted %d, want every unprotected node (%d)", res.Evicted, want)
	}
	if g.Len() != len(s.protected) {
		t.Fatalf("%d nodes remain, want the %d protected ones", g.Len(), len(s.protected))
	}
	for name, id := range s.protected {
		if _, ok := g.Node(id); !ok {
			t.Errorf("protected node %q evicted under extreme pressure", name)
		}
	}
	var exceeded bool
	for _, n := range g.Coverage() {
		if n.Status == models.CoverageBudgetExceeded {
			exceeded = true
			if !strings.Contains(n.Reason, "kept, not evicted") {
				t.Errorf("note %q", n.Reason)
			}
		}
	}
	if !exceeded {
		t.Fatal("no BudgetExceeded coverage note")
	}
}

func TestProtectionThresholdConfigurable(t *testing.T) {
	g := New(Options{ProtectAtOrAbove: models.SeverityHigh})
	o := obs(models.KindConfig, "medium fact")
	o.Severity = models.SeverityMedium
	med := mustObserve(t, g, o)
	o = obs(models.KindConfig, "high fact")
	o.Severity = models.SeverityHigh
	high := mustObserve(t, g, o)

	g.SetBudget(1)
	g.EnforceBudget(t0)
	if _, ok := g.Node(med); ok {
		t.Error("Medium survived with threshold High")
	}
	if _, ok := g.Node(high); !ok {
		t.Error("High evicted")
	}
}

func TestReobservingMovesNodeToBack(t *testing.T) {
	g := New(Options{})
	old := obs(models.KindSocket, "old but refreshed")
	oldID := mustObserve(t, g, old)
	var mid []NodeID
	for i := range 10 {
		o := obs(models.KindSocket, fmt.Sprintf("mid %d", i))
		o.At = t0.Add(time.Duration(i+1) * time.Second)
		mid = append(mid, mustObserve(t, g, o))
	}
	old.At = t0.Add(time.Minute)
	mustObserve(t, g, old)

	n := mustNode(t, g, oldID)
	g.SetBudget(g.UsedBytes() - 1)
	g.EnforceBudget(t0.Add(time.Hour))
	if _, ok := g.Node(mid[0]); ok {
		t.Error("least recently observed node survived")
	}
	if _, ok := g.Node(oldID); !ok {
		t.Errorf("recently re-observed node evicted (count %d)", n.Count)
	}
}

func TestEnforceBudgetConcurrentWithObserve(t *testing.T) {
	g := New(Options{BudgetBytes: 64 << 10})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 2000 {
			o := obs(models.KindSocket, fmt.Sprintf("s%d", i))
			if _, err := g.Observe(o); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 50 {
		g.EnforceBudget(t0)
		_ = g.Coverage()
	}
	<-done
	g.EnforceBudget(t0)
	if g.UsedBytes() > 64<<10 {
		t.Fatalf("used %d over budget after final enforcement", g.UsedBytes())
	}
}
