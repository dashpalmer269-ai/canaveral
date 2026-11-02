package evidence

import (
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func obs(kind models.NodeKind, key string) Observation {
	return Observation{Kind: kind, Key: key, At: t0, Collector: "test", Method: "fixture"}
}

func mustObserve(t *testing.T, g *Graph, o Observation) NodeID {
	t.Helper()
	id, err := g.Observe(o)
	if err != nil {
		t.Fatalf("Observe(%s %q): %v", o.Kind, o.Key, err)
	}
	return id
}

func mustLink(t *testing.T, g *Graph, from, to NodeID, kind models.EdgeKind) {
	t.Helper()
	if err := g.Link(from, to, kind); err != nil {
		t.Fatalf("Link(%s -%s-> %s): %v", from, kind, to, err)
	}
}

func mustNode(t *testing.T, g *Graph, id NodeID) Node {
	t.Helper()
	n, ok := g.Node(id)
	if !ok {
		t.Fatalf("node %s missing", id)
	}
	return n
}
