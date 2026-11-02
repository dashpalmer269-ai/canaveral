package runtime

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

func TestReviewClassifiesResources(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC))
	l := NewLedger(clock)
	root := filepath.Join(string(filepath.Separator), "usb", "Canaveral_Reports")
	l.Approve(root)
	l.Approve(root) // idempotent

	scan := filepath.Join(root, "scan_1")
	dir := l.Record(ResourceDirectory, scan, StateCreated, nil)
	tmp := l.Record(ResourceFile, filepath.Join(scan, "report.json.partial"), StateTemporary, nil)
	l.Renamed(tmp, filepath.Join(scan, "report.json"), StateFinal)
	left := l.Record(ResourceFile, filepath.Join(scan, "report.md.partial"), StateTemporary, nil)

	rv := l.Review()
	if len(rv.Approved) != 1 || len(rv.Inside) != 3 || len(rv.Outside) != 0 || len(rv.Leftovers) != 1 || rv.Leftovers[0].ID != left {
		t.Fatalf("review %+v", rv)
	}
	if !strings.Contains(rv.Summary, "all inside the approved output location") || !strings.Contains(rv.Summary, "may remain") {
		t.Fatalf("summary %q", rv.Summary)
	}
	if len(rv.WindowsGenerated) == 0 || !strings.Contains(strings.Join(rv.WindowsGenerated, "\n"), "Prefetch") {
		t.Fatal("Windows-generated artifacts not disclosed")
	}
	if r := l.Resources()[dir-1]; !r.CreatedAt.Equal(clock.Now()) {
		t.Fatalf("CreatedAt %v", r.CreatedAt)
	}

	l.Record(ResourceFile, filepath.Join(string(filepath.Separator), "Windows", "Temp", "oops"), StateTemporary, nil)
	rv = l.Review()
	if len(rv.Outside) != 1 || !strings.HasPrefix(rv.Summary, "WARNING") {
		t.Fatalf("outside resource not flagged: %+v", rv)
	}
}

func TestRenamedMarksOverwrittenFinalReplaced(t *testing.T) {
	l := NewLedger(fake.NewClock(time.Now()))
	a := l.Record(ResourceFile, "/r/report.json.partial", StateTemporary, nil)
	l.Renamed(a, "/r/report.json", StateFinal)
	b := l.Record(ResourceFile, "/r/report.json.partial", StateTemporary, nil)
	l.Renamed(b, "/r/report.json", StateFinal)
	res := l.Resources()
	if res[a-1].State != StateReplaced || res[b-1].State != StateFinal {
		t.Fatalf("states %s %s", res[a-1].State, res[b-1].State)
	}
}

func TestMarkLostUnder(t *testing.T) {
	l := NewLedger(fake.NewClock(time.Now()))
	in := l.Record(ResourceFile, "/usb/r/scan/report.json", StateFinal, nil)
	removed := l.Record(ResourceFile, "/usb/r/scan/x.partial", StateRemoved, nil)
	other := l.Record(ResourceFile, "/usb2/r/scan/report.json", StateFinal, nil)
	sibling := l.Record(ResourceFile, "/usb/r-other/report.json", StateFinal, nil)
	l.MarkLostUnder("/usb/r", "gone")
	res := l.Resources()
	if res[in-1].State != StateLost || res[removed-1].State != StateRemoved || res[other-1].State != StateFinal || res[sibling-1].State != StateFinal {
		t.Fatalf("states %v", res)
	}
}
