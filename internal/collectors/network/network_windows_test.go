//go:build windows

package network

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/windows"
)

// End to end on real Windows data: this test's own listener must be
// attributed to this process with high confidence.
func TestCollectAttributesOwnListener(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	want := netip.MustParseAddrPort(l.Addr().String())

	res, err := Collect(context.Background(), windows.ProcessSource{}, windows.SocketSource{}, platform.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[Confidence]int{}
	var found bool
	for _, s := range res.Sockets.Sockets {
		counts[s.Confidence]++
		if s.Local != want || s.State != models.TCPStateListen {
			continue
		}
		found = true
		k, ok := s.Owner.Get()
		if !ok || k.PID != uint32(os.Getpid()) || s.Confidence != ConfidenceHigh || s.LocalClass != ClassLoopback {
			t.Fatalf("own listener: owner=%+v (%s) confidence=%s (%s) class=%s", k, s.Owner.Reason(), s.Confidence, s.ConfidenceReason, s.LocalClass)
		}
	}
	if !found {
		t.Fatalf("own listener %v not collected", want)
	}
	t.Logf("%d sockets: %v; processes before=%d after=%d", len(res.Sockets.Sockets), counts, len(res.Before.Processes), len(res.After.Processes))
	for _, n := range res.Sockets.Coverage {
		t.Logf("coverage: [%s] %s: %s", n.Status, n.Item, n.Reason)
	}
}
