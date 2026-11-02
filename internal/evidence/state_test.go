package evidence

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// expectedLegal is written out independently of legalTransitions so that an
// accidental change to the state machine fails this test.
var expectedLegal = map[models.EvidenceState][]models.EvidenceState{
	models.StateObserved:     {models.StateVerified, models.StateCorroborated, models.StateContradicted, models.StateInconclusive},
	models.StateVerified:     {models.StateCorroborated, models.StateContradicted, models.StateInconclusive},
	models.StateCorroborated: {models.StateContradicted, models.StateInconclusive},
	models.StateContradicted: {models.StateInconclusive},
	models.StateInconclusive: {models.StateVerified, models.StateCorroborated, models.StateContradicted},
	models.StateUnavailable:  {models.StateObserved},
}

func isExpectedLegal(from, to models.EvidenceState) bool {
	for _, s := range expectedLegal[from] {
		if s == to {
			return true
		}
	}
	return false
}

// nodeIn returns a Process node that has reached state s through legal steps,
// plus a Socket and a File node usable as cross-class evidence.
func nodeIn(t *testing.T, s models.EvidenceState, tag string) (g *Graph, id, sock, file NodeID) {
	t.Helper()
	g = New(Options{})
	sock = mustObserve(t, g, obs(models.KindSocket, "sock-"+tag))
	file = mustObserve(t, g, obs(models.KindFile, "file-"+tag))
	o := obs(models.KindProcess, "proc-"+tag)
	if s == models.StateUnavailable {
		o.State, o.Reason = models.StateUnavailable, "access denied"
	}
	id = mustObserve(t, g, o)
	switch s {
	case models.StateObserved, models.StateUnavailable:
	case models.StateVerified, models.StateInconclusive:
		if err := g.Transition(id, s, t0, "setup"); err != nil {
			t.Fatal(err)
		}
	case models.StateCorroborated, models.StateContradicted:
		if err := g.Transition(id, s, t0, "setup", sock); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("no setup for %s", s)
	}
	if got := mustNode(t, g, id).State; got != s {
		t.Fatalf("setup reached %s, want %s", got, s)
	}
	return g, id, sock, file
}

func TestTransitionMatrix(t *testing.T) {
	for _, from := range models.AllEvidenceStates {
		for _, to := range models.AllEvidenceStates {
			if from == to {
				continue
			}
			t.Run(fmt.Sprintf("%s->%s", from, to), func(t *testing.T) {
				g, id, sock, file := nodeIn(t, from, "m")
				err := g.Transition(id, to, t0.Add(1), "matrix", sock, file)
				legal := isExpectedLegal(from, to)
				if legal != CanTransition(from, to) {
					t.Fatalf("CanTransition = %v, expected %v", CanTransition(from, to), legal)
				}
				switch {
				case legal && err != nil:
					t.Fatalf("legal transition rejected: %v", err)
				case !legal && !errors.Is(err, ErrIllegalTransition):
					t.Fatalf("illegal transition: err = %v, want ErrIllegalTransition", err)
				}
				n := mustNode(t, g, id)
				if legal && n.State != to {
					t.Fatalf("state = %s, want %s", n.State, to)
				}
				if !legal && n.State != from {
					t.Fatalf("illegal transition changed state to %s", n.State)
				}
			})
		}
	}
}

func TestNoStepBackDown(t *testing.T) {
	// Spot checks of the most important illegal moves, named explicitly.
	cases := [][2]models.EvidenceState{
		{models.StateVerified, models.StateObserved},
		{models.StateCorroborated, models.StateVerified},
		{models.StateCorroborated, models.StateObserved},
		{models.StateContradicted, models.StateCorroborated},
		{models.StateObserved, models.StateUnavailable},
		{models.StateVerified, models.StateUnavailable},
		{models.StateUnavailable, models.StateCorroborated},
	}
	for _, c := range cases {
		if CanTransition(c[0], c[1]) {
			t.Errorf("%s -> %s must be illegal", c[0], c[1])
		}
	}
}

func TestSameStateIsNoOp(t *testing.T) {
	g, id, _, _ := nodeIn(t, models.StateVerified, "noop")
	before := len(mustNode(t, g, id).StateHistory)
	if err := g.Transition(id, models.StateVerified, t0, "again"); err != nil {
		t.Fatal(err)
	}
	if after := len(mustNode(t, g, id).StateHistory); after != before {
		t.Fatalf("history grew from %d to %d on a no-op", before, after)
	}
}

func TestInitialStateRestricted(t *testing.T) {
	g := New(Options{})
	for _, s := range []models.EvidenceState{models.StateVerified, models.StateCorroborated, models.StateContradicted, models.StateInconclusive} {
		o := obs(models.KindProcess, "p-"+string(s))
		o.State = s
		if _, err := g.Observe(o); !errors.Is(err, ErrInvalidObservation) {
			t.Errorf("starting as %s: err = %v", s, err)
		}
	}
	o := obs(models.KindProcess, "p-unavail")
	o.State = models.StateUnavailable
	if _, err := g.Observe(o); !errors.Is(err, ErrInvalidObservation) {
		t.Errorf("Unavailable without a reason: err = %v", err)
	}
	if g.Len() != 0 {
		t.Fatalf("rejected observations created %d nodes", g.Len())
	}
}

func TestCorroborationNeedsTwoClasses(t *testing.T) {
	g := New(Options{})
	proc := mustObserve(t, g, obs(models.KindProcess, "p1"))
	proc2 := mustObserve(t, g, obs(models.KindProcess, "p2"))
	sock := mustObserve(t, g, obs(models.KindSocket, "s1"))
	sock2 := mustObserve(t, g, obs(models.KindSocket, "s2"))
	file := mustObserve(t, g, obs(models.KindFile, "f1"))
	finding := mustObserve(t, g, obs(models.KindFinding, "PROC-003|p1"))

	// Same class as the subject: PROC + PROC.
	if err := g.Transition(proc, models.StateCorroborated, t0, "same class", proc2); !errors.Is(err, ErrInsufficientCorroboration) {
		t.Errorf("PROC corroborated by PROC: err = %v", err)
	}
	// No evidence at all.
	if err := g.Transition(proc, models.StateCorroborated, t0, "nothing"); !errors.Is(err, ErrInsufficientCorroboration) {
		t.Errorf("no evidence: err = %v", err)
	}
	// A finding has no class, so two NET observations are still one class.
	if err := g.Transition(finding, models.StateCorroborated, t0, "one class twice", sock, sock2); !errors.Is(err, ErrInsufficientCorroboration) {
		t.Errorf("finding with NET+NET: err = %v", err)
	}
	if got := mustNode(t, g, finding).State; got != models.StateObserved {
		t.Fatalf("rejected corroboration changed state to %s", got)
	}

	// Two classes: allowed.
	if err := g.Transition(finding, models.StateCorroborated, t0, "PROC+NET+FILE", proc, sock, file); err != nil {
		t.Errorf("finding with three classes: %v", err)
	}
	if err := g.Transition(proc, models.StateCorroborated, t0, "PROC+NET", sock); err != nil {
		t.Errorf("PROC corroborated by NET: %v", err)
	}
}

func TestContradictionNeedsEvidence(t *testing.T) {
	g := New(Options{})
	f := mustObserve(t, g, obs(models.KindFinding, "x"))
	if err := g.Transition(f, models.StateContradicted, t0, "no evidence"); !errors.Is(err, ErrEvidenceRequired) {
		t.Fatalf("err = %v", err)
	}
	cfg := mustObserve(t, g, obs(models.KindConfig, "baseline match"))
	if err := g.Transition(f, models.StateContradicted, t0, "baseline", cfg); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInputValidation(t *testing.T) {
	g := New(Options{})
	p := mustObserve(t, g, obs(models.KindProcess, "p"))
	if err := g.Transition(p, models.StateVerified, t0, ""); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("empty reason: %v", err)
	}
	if err := g.Transition("PRC-missing", models.StateVerified, t0, "x"); !errors.Is(err, ErrUnknownNode) {
		t.Errorf("unknown node: %v", err)
	}
	if err := g.Transition(p, models.StateContradicted, t0, "x", "CFG-missing"); !errors.Is(err, ErrUnknownNode) {
		t.Errorf("unknown evidence: %v", err)
	}
	if err := g.Transition(p, models.StateContradicted, t0, "x", p); !errors.Is(err, ErrInvalidEdge) {
		t.Errorf("self as evidence: %v", err)
	}
	if got := mustNode(t, g, p).State; got != models.StateObserved {
		t.Fatalf("failed transitions changed state to %s", got)
	}
}

func TestTransitionHistoryRecorded(t *testing.T) {
	g := New(Options{})
	p := mustObserve(t, g, obs(models.KindProcess, "p"))
	s := mustObserve(t, g, obs(models.KindSocket, "s"))
	if err := g.Transition(p, models.StateVerified, t0.Add(1), "image path re-read via PEB"); err != nil {
		t.Fatal(err)
	}
	if err := g.Transition(p, models.StateCorroborated, t0.Add(2), "network evidence", s, s); err != nil {
		t.Fatal(err)
	}
	h := mustNode(t, g, p).StateHistory
	if len(h) != 2 {
		t.Fatalf("history len %d", len(h))
	}
	if h[0].From != models.StateObserved || h[0].To != models.StateVerified || h[0].Reason != "image path re-read via PEB" || !h[0].At.Equal(t0.Add(1)) {
		t.Errorf("entry 0 = %+v", h[0])
	}
	if h[1].From != models.StateVerified || h[1].To != models.StateCorroborated || len(h[1].Evidence) != 1 || h[1].Evidence[0] != s {
		t.Errorf("entry 1 = %+v (evidence should be deduplicated)", h[1])
	}
}

func TestSeverityHistoryAndMax(t *testing.T) {
	g := New(Options{})
	f := mustObserve(t, g, obs(models.KindFinding, "PROC-001|x"))
	cfg := mustObserve(t, g, obs(models.KindConfig, "baseline"))

	if err := g.SetSeverity(f, models.SeverityHigh, t0, "rule PROC-001"); err != nil {
		t.Fatal(err)
	}
	if err := g.SetSeverity(f, models.SeverityLow, t0.Add(1), "baseline contradicts", cfg); err != nil {
		t.Fatal(err)
	}
	if err := g.SetSeverity(f, models.SeverityLow, t0.Add(2), "no change"); err != nil {
		t.Fatal(err)
	}
	n := mustNode(t, g, f)
	if n.Severity != models.SeverityLow || n.MaxSeverity != models.SeverityHigh {
		t.Fatalf("severity %s max %s", n.Severity, n.MaxSeverity)
	}
	if len(n.SeverityHistory) != 2 || n.SeverityHistory[1].From != models.SeverityHigh || n.SeverityHistory[1].Evidence[0] != cfg {
		t.Fatalf("history %+v", n.SeverityHistory)
	}
	if err := g.SetSeverity(f, models.SeverityMedium, t0, ""); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("empty reason: %v", err)
	}
	if err := g.SetSeverity(f, models.Severity(9), t0, "x"); !errors.Is(err, ErrInvalidObservation) {
		t.Errorf("invalid severity: %v", err)
	}
}

func TestObserveNeverLowersSeverity(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindSocket, "s")
	o.Severity = models.SeverityMedium
	id := mustObserve(t, g, o)
	o.Severity = models.SeverityInfo
	mustObserve(t, g, o)
	n := mustNode(t, g, id)
	if n.Severity != models.SeverityMedium || len(n.SeverityHistory) != 0 {
		t.Fatalf("severity %s history %v", n.Severity, n.SeverityHistory)
	}
	o.Severity = models.SeverityHigh
	mustObserve(t, g, o)
	n = mustNode(t, g, id)
	if n.Severity != models.SeverityHigh || n.MaxSeverity != models.SeverityHigh || len(n.SeverityHistory) != 1 {
		t.Fatalf("raise: severity %s max %s history %v", n.Severity, n.MaxSeverity, n.SeverityHistory)
	}
}
