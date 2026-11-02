package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// Acceptance (M1): 500 identical observations produce 1 node with count 500.
func TestDedup500IdenticalObservations(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindSocket, "TCPv4|10.0.0.5:51000|203.0.113.7:443|PRC-owner")
	var id NodeID
	for i := range 500 {
		o.At = t0.Add(time.Duration(i) * time.Second)
		got := mustObserve(t, g, o)
		if i > 0 && got != id {
			t.Fatalf("observation %d got ID %s, want %s", i, got, id)
		}
		id = got
	}
	if g.Len() != 1 {
		t.Fatalf("Len = %d, want 1", g.Len())
	}
	n := mustNode(t, g, id)
	if n.Count != 500 {
		t.Fatalf("Count = %d, want 500", n.Count)
	}
	if !n.FirstObserved.Equal(t0) || !n.LastObserved.Equal(t0.Add(499*time.Second)) {
		t.Fatalf("window %v .. %v", n.FirstObserved, n.LastObserved)
	}
}

func TestDedupConcurrent(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindProcess, "PID 4120 created 133000000000000000")
	var wg sync.WaitGroup
	for w := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				oo := o
				oo.At = t0.Add(time.Duration(w*25+i) * time.Millisecond)
				if _, err := g.Observe(oo); err != nil {
					t.Error(err)
				}
				_ = g.Nodes()
			}
		}()
	}
	wg.Wait()
	if g.Len() != 1 {
		t.Fatalf("Len = %d", g.Len())
	}
	if n := g.Nodes()[0]; n.Count != 500 {
		t.Fatalf("Count = %d, want 500", n.Count)
	}
}

func TestDistinctKeysAndKindsAreDistinctNodes(t *testing.T) {
	g := New(Options{})
	a := mustObserve(t, g, obs(models.KindFile, "x"))
	b := mustObserve(t, g, obs(models.KindFile, "y"))
	c := mustObserve(t, g, obs(models.KindProcess, "x"))
	if a == b || a == c || b == c || g.Len() != 3 {
		t.Fatalf("ids %s %s %s len %d", a, b, c, g.Len())
	}
}

func TestOutOfOrderObservationsWidenWindow(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindSocket, "s")
	o.At = t0.Add(10 * time.Second)
	id := mustObserve(t, g, o)
	o.At = t0
	mustObserve(t, g, o)
	o.At = t0.Add(5 * time.Second)
	mustObserve(t, g, o)
	n := mustNode(t, g, id)
	if !n.FirstObserved.Equal(t0) || !n.LastObserved.Equal(t0.Add(10*time.Second)) || n.Count != 3 {
		t.Fatalf("%v .. %v count %d", n.FirstObserved, n.LastObserved, n.Count)
	}
}

func TestStableIDs(t *testing.T) {
	id1 := mustObserve(t, New(Options{}), obs(models.KindSocket, "same fact"))
	id2 := mustObserve(t, New(Options{}), obs(models.KindSocket, "same fact"))
	if id1 != id2 {
		t.Fatalf("same fact in two graphs: %s vs %s", id1, id2)
	}
	want := map[models.NodeKind]string{
		models.KindProcess: "PRC", models.KindFile: "FIL", models.KindSocket: "SOC",
		models.KindPersistence: "PER", models.KindHistory: "HIS", models.KindConfig: "CFG",
		models.KindFinding: "FND",
	}
	g := New(Options{})
	for _, k := range models.AllNodeKinds {
		id := mustObserve(t, g, obs(k, "k"))
		if !regexp.MustCompile(`^` + want[k] + `-[0-9a-f]{16}$`).MatchString(string(id)) {
			t.Errorf("%s id %q has wrong format", k, id)
		}
	}
}

func TestIDCollisionDetected(t *testing.T) {
	orig := makeID
	t.Cleanup(func() { makeID = orig })
	makeID = func(models.NodeKind, string) NodeID { return "SOC-0000000000000000" }

	g := New(Options{})
	mustObserve(t, g, obs(models.KindSocket, "first"))
	if _, err := g.Observe(obs(models.KindSocket, "second")); !errors.Is(err, ErrIDCollision) {
		t.Fatalf("err = %v, want ErrIDCollision", err)
	}
	if n := g.Nodes()[0]; n.Key != "first" || n.Count != 1 {
		t.Fatalf("colliding observation merged into %+v", n)
	}
}

func TestObservationValidation(t *testing.T) {
	g := New(Options{})
	bad := map[string]func(*Observation){
		"unknown kind": func(o *Observation) { o.Kind = "Registry" },
		"empty key":    func(o *Observation) { o.Key = "" },
		"zero time":    func(o *Observation) { o.At = time.Time{} },
		"no collector": func(o *Observation) { o.Collector = "" },
		"no method":    func(o *Observation) { o.Method = "" },
		"bad severity": func(o *Observation) { o.Severity = 7 },
	}
	for name, mut := range bad {
		o := obs(models.KindProcess, "p")
		mut(&o)
		if _, err := g.Observe(o); !errors.Is(err, ErrInvalidObservation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if g.Len() != 0 {
		t.Fatalf("invalid observations created %d nodes", g.Len())
	}
}

func TestObservationTimesAreUTC(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindProcess, "p")
	o.At = t0.In(time.FixedZone("UTC+5", 5*3600))
	n := mustNode(t, g, mustObserve(t, g, o))
	if n.FirstObserved.Location() != time.UTC || !n.FirstObserved.Equal(t0) {
		t.Fatalf("FirstObserved = %v", n.FirstObserved)
	}
}

func TestLaterFailureNeverErasesObservation(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindProcess, "p")
	o.Payload = "first payload"
	id := mustObserve(t, g, o)

	fail := obs(models.KindProcess, "p")
	fail.At = t0.Add(time.Minute)
	fail.State, fail.Reason = models.StateUnavailable, "process exited"
	mustObserve(t, g, fail)

	n := mustNode(t, g, id)
	if n.State != models.StateObserved || n.Count != 1 || n.Payload != "first payload" {
		t.Fatalf("failure changed the observation: %+v", n)
	}
	if n.UnavailableAttempts != 1 || n.UnavailableReason != "process exited" || !n.LastObserved.Equal(t0) {
		t.Fatalf("failure not recorded honestly: %+v", n)
	}
}

func TestLaterSuccessUpgradesUnavailable(t *testing.T) {
	g := New(Options{})
	fail := obs(models.KindFile, `C:\x.exe`)
	fail.State, fail.Reason = models.StateUnavailable, "sharing violation"
	id := mustObserve(t, g, fail)
	n := mustNode(t, g, id)
	if n.State != models.StateUnavailable || n.Count != 0 || !n.FirstObserved.IsZero() || n.Payload != nil {
		t.Fatalf("unavailable node invented data: %+v", n)
	}

	ok := obs(models.KindFile, `C:\x.exe`)
	ok.At = t0.Add(time.Minute)
	ok.Payload = "hash"
	mustObserve(t, g, ok)
	n = mustNode(t, g, id)
	if n.State != models.StateObserved || n.Count != 1 || !n.FirstObserved.Equal(t0.Add(time.Minute)) || n.Payload != "hash" {
		t.Fatalf("upgrade: %+v", n)
	}
	if len(n.StateHistory) != 1 || n.StateHistory[0].From != models.StateUnavailable || n.UnavailableAttempts != 1 {
		t.Fatalf("upgrade history: %+v", n)
	}
}

func TestFirstPayloadKept(t *testing.T) {
	g := New(Options{})
	o := obs(models.KindSocket, "s")
	o.Payload = "original"
	id := mustObserve(t, g, o)
	o.Payload = "later"
	mustObserve(t, g, o)
	if p := mustNode(t, g, id).Payload; p != "original" {
		t.Fatalf("payload = %v", p)
	}
}

func TestReturnedNodesAreCopies(t *testing.T) {
	g := New(Options{})
	p := mustObserve(t, g, obs(models.KindProcess, "p"))
	s := mustObserve(t, g, obs(models.KindSocket, "s"))
	if err := g.Transition(p, models.StateCorroborated, t0, "x", s); err != nil {
		t.Fatal(err)
	}
	n := mustNode(t, g, p)
	n.StateHistory[0].Evidence[0] = "tampered"
	n.State = models.StateObserved
	again := mustNode(t, g, p)
	if again.State != models.StateCorroborated || again.StateHistory[0].Evidence[0] != s {
		t.Fatal("caller mutated graph through a returned node")
	}
}

func TestEdgeValidation(t *testing.T) {
	g := New(Options{})
	proc := mustObserve(t, g, obs(models.KindProcess, "child"))
	parent := mustObserve(t, g, obs(models.KindProcess, "parent"))
	file := mustObserve(t, g, obs(models.KindFile, "f"))
	sock := mustObserve(t, g, obs(models.KindSocket, "s"))
	per := mustObserve(t, g, obs(models.KindPersistence, "run"))
	his := mustObserve(t, g, obs(models.KindHistory, "prefetch"))
	cfg := mustObserve(t, g, obs(models.KindConfig, "c"))
	fnd := mustObserve(t, g, obs(models.KindFinding, "f1"))
	fnd2 := mustObserve(t, g, obs(models.KindFinding, "f2"))

	valid := []Edge{
		{file, proc, models.EdgeImageOf},
		{parent, proc, models.EdgeParentOf},
		{proc, sock, models.EdgeOwnsSocket},
		{per, file, models.EdgeLaunchesFile},
		{his, file, models.EdgeRecordedExecutionOf},
		{sock, fnd, models.EdgeSupportsFinding},
		{cfg, fnd, models.EdgeContradictsFinding},
	}
	for _, e := range valid {
		mustLink(t, g, e.From, e.To, e.Kind)
	}

	invalid := []Edge{
		{proc, file, models.EdgeImageOf},        // reversed
		{sock, proc, models.EdgeOwnsSocket},     // reversed
		{file, proc, models.EdgeParentOf},       // wrong kinds
		{fnd2, fnd, models.EdgeSupportsFinding}, // finding cannot support a finding
		{sock, cfg, models.EdgeSupportsFinding}, // target is not a finding
		{proc, proc, models.EdgeParentOf},       // self loop
		{proc, sock, "Talks"},                   // unknown kind
	}
	for _, e := range invalid {
		if err := g.Link(e.From, e.To, e.Kind); !errors.Is(err, ErrInvalidEdge) {
			t.Errorf("%v: err = %v, want ErrInvalidEdge", e, err)
		}
	}
	if err := g.Link(proc, "SOC-missing", models.EdgeOwnsSocket); !errors.Is(err, ErrUnknownNode) {
		t.Errorf("unknown target: %v", err)
	}
	if got := len(g.AllEdges()); got != len(valid) {
		t.Fatalf("%d edges, want %d", got, len(valid))
	}

	used := g.UsedBytes()
	mustLink(t, g, proc, sock, models.EdgeOwnsSocket)
	if len(g.AllEdges()) != len(valid) || g.UsedBytes() != used {
		t.Fatal("duplicate edge was added again")
	}
	if es := g.Edges(proc); len(es) != 3 {
		t.Fatalf("Edges(proc) = %v", es)
	}
}

func ExampleGraph_Observe() {
	g := New(Options{})
	o := Observation{
		Kind: models.KindSocket, Key: "TCPv4|192.0.2.10:49822|198.51.100.4:443",
		At: t0, Collector: "network", Method: "GetExtendedTcpTable",
	}
	for range 3 {
		_, _ = g.Observe(o)
	}
	n := g.Nodes()[0]
	fmt.Println(n.ID, n.Count)
	// The ID is sha256("Socket\x00" + key)[:8] in hex, checked with sha256sum.
	// Output: SOC-6d32170cd6ec1b0b 3
}
