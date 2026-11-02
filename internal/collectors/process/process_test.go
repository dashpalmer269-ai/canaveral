package process

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

var at = time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)

// Proc builds a fully readable process record.
func Proc(pid, ppid uint32, name string, created models.FileTime) models.ProcessRecord {
	return models.ProcessRecord{
		PID: pid, ParentPID: ppid, Name: name,
		CreateTime:  models.Known(created),
		ImagePath:   models.Known(`C:\Windows\System32\` + name),
		CommandLine: models.Known(name),
		UserSID:     models.Known("S-1-5-18"),
		UserName:    models.Known(`NT AUTHORITY\SYSTEM`),
		SessionID:   models.Known[uint32](0),
		Protection:  models.Known("None"),
	}
}

func TestIdentityIsPIDPlusCreationTime(t *testing.T) {
	s1 := Build(at, []models.ProcessRecord{Proc(500, 4, "a.exe", 1000)})
	s2 := Build(at, []models.ProcessRecord{Proc(500, 4, "b.exe", 2000)})
	p1, _ := s1.ByPID(500)
	p2, _ := s2.ByPID(500)
	if !p1.KeyComplete || !p2.KeyComplete || p1.Key == p2.Key {
		t.Fatalf("same PID with different creation times must be distinct identities: %+v %+v", p1.Key, p2.Key)
	}
	if p1.Key != (models.ProcessKey{PID: 500, CreateTime: 1000}) {
		t.Fatalf("key %+v", p1.Key)
	}
}

func TestParentResolution(t *testing.T) {
	recs := []models.ProcessRecord{
		Proc(4, 0, "System", 100),
		Proc(600, 4, "smss.exe", 200),
		Proc(700, 600, "csrss.exe", 300),
		Proc(800, 999, "orphan.exe", 400),   // parent gone
		Proc(900, 1000, "reused.exe", 500),  // parent PID reused by a newer process
		Proc(1000, 4, "newer.exe", 600),     //
		Proc(1100, 1100, "selfish.exe", 50), // claims itself
		{PID: 1200, ParentPID: 600, Name: "unreadable.exe", CreateTime: models.Unavailable[models.FileTime]("access denied")},
		Proc(1300, 1200, "child-of-unreadable.exe", 700),
	}
	s := Build(at, recs)
	want := map[uint32]string{
		600:  "known:4",
		700:  "known:600",
		800:  "no longer running",
		900:  "PID was reused",
		1100: "its own parent",
		1200: "PID reuse cannot be ruled out",
		1300: "PID reuse cannot be ruled out",
	}
	for pid, w := range want {
		p, _ := s.ByPID(pid)
		pk, ok := p.Parent.Get()
		if strings.HasPrefix(w, "known:") {
			if !ok || pk.PID != map[string]uint32{"known:4": 4, "known:600": 600}[w] {
				t.Errorf("PID %d parent = %+v (%s), want %s", pid, pk, p.Parent.Reason(), w)
			}
			continue
		}
		if ok || !strings.Contains(p.Parent.Reason(), w) {
			t.Errorf("PID %d parent = %+v reason %q, want unavailable containing %q", pid, pk, p.Parent.Reason(), w)
		}
	}
}

func TestLineage(t *testing.T) {
	s := Build(at, []models.ProcessRecord{
		Proc(4, 0, "System", 100), Proc(600, 4, "smss.exe", 200), Proc(700, 600, "wininit.exe", 300), Proc(800, 700, "services.exe", 400),
	})
	got := s.Lineage(models.ProcessKey{PID: 800, CreateTime: 400}, 10)
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if strings.Join(names, ">") != "wininit.exe>smss.exe>System" {
		t.Fatalf("lineage %v", names)
	}
	if len(s.Lineage(models.ProcessKey{PID: 800, CreateTime: 400}, 1)) != 1 {
		t.Fatal("max not honored")
	}
	if s.Lineage(models.ProcessKey{PID: 800, CreateTime: 999}, 10) != nil {
		t.Fatal("lineage returned for a stale identity")
	}
}

func TestLineageStopsOnCycle(t *testing.T) {
	// Two processes that name each other as parent, with equal creation
	// times so both links look valid. Malformed data must not loop forever.
	s := Build(at, []models.ProcessRecord{Proc(10, 20, "a.exe", 100), Proc(20, 10, "b.exe", 100)})
	if n := len(s.Lineage(models.ProcessKey{PID: 10, CreateTime: 100}, 1000)); n != 1 {
		t.Fatalf("cycle produced lineage of %d", n)
	}
}

// Acceptance (M3): inaccessible processes become coverage records, never
// findings, and nothing is fabricated for them.
func TestInaccessibleProcessesBecomeCoverage(t *testing.T) {
	denied := "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION): Access is denied."
	ppl := Proc(3000, 4, "MsMpEng.exe", 900)
	ppl.CommandLine = models.Unavailable[string]("NtQueryInformationProcess: STATUS_ACCESS_DENIED")
	ppl.Protection = models.Known("PsProtectedSignerAntimalware-Light")
	recs := []models.ProcessRecord{
		{PID: 0, Name: "[System Process]", CreateTime: models.Unavailable[models.FileTime]("x")},
		Proc(4, 0, "System", 100),
		{PID: 2000, ParentPID: 4, Name: "secret.exe",
			CreateTime: models.Unavailable[models.FileTime](denied), ImagePath: models.Unavailable[string](denied),
			CommandLine: models.Unavailable[string](denied), UserSID: models.Unavailable[string](denied),
			UserName: models.Unavailable[string](denied), Protection: models.Unavailable[string](denied)},
		ppl,
	}
	s := Build(at, recs)
	p, _ := s.ByPID(2000)
	if p.KeyComplete || p.ImagePath.IsKnown() || p.CommandLine.IsKnown() {
		t.Fatalf("values fabricated for an inaccessible process: %+v", p)
	}
	var full, partial, summary *models.CoverageNote
	for i, n := range s.Coverage {
		switch n.Item {
		case "PID 2000 (secret.exe)":
			full = &s.Coverage[i]
		case "PID 3000 (MsMpEng.exe)":
			partial = &s.Coverage[i]
		case "process inventory":
			summary = &s.Coverage[i]
		case "PID 0 ([System Process])":
			t.Error("the Idle pseudo-process should not produce a coverage gap")
		}
	}
	if full == nil || full.Status != models.CoverageUnavailable || !strings.Contains(full.Reason, "Access is denied") {
		t.Fatalf("fully inaccessible process: %+v", full)
	}
	if partial == nil || partial.Status != models.CoveragePartial || !strings.Contains(partial.Reason, "protected process (PsProtectedSignerAntimalware-Light)") ||
		!strings.Contains(partial.Reason, "command line") {
		t.Fatalf("protected process: %+v", partial)
	}
	if summary == nil || summary.Status != models.CoveragePartial || !strings.Contains(summary.Reason, "not findings") || !strings.Contains(summary.Reason, "2 could not be fully read") {
		t.Fatalf("summary: %+v", summary)
	}
}

func TestFullyReadableInventory(t *testing.T) {
	s := Build(at, []models.ProcessRecord{Proc(4, 0, "System", 100)})
	if len(s.Coverage) != 1 || s.Coverage[0].Status != models.CoverageComplete {
		t.Fatalf("coverage %+v", s.Coverage)
	}
}

func TestDuplicatePIDKeepsFirst(t *testing.T) {
	s := Build(at, []models.ProcessRecord{Proc(5, 4, "first.exe", 1), Proc(5, 4, "second.exe", 2)})
	p, _ := s.ByPID(5)
	if len(s.Processes) != 1 || p.Name != "first.exe" || s.Coverage[0].Status != models.CoveragePartial {
		t.Fatalf("processes %+v coverage %+v", s.Processes, s.Coverage)
	}
}

func TestCollectFailureIsCoverageNotGuess(t *testing.T) {
	src := &fake.ProcessSource{Err: platform.ErrAccessDenied}
	s, err := Collect(context.Background(), src, fake.NewClock(at))
	if !errors.Is(err, platform.ErrAccessDenied) || len(s.Processes) != 0 {
		t.Fatalf("err %v processes %d", err, len(s.Processes))
	}
	if len(s.Coverage) != 1 || s.Coverage[0].Status != models.CoverageUnavailable {
		t.Fatalf("coverage %+v", s.Coverage)
	}
	if _, ok := s.ByPID(4); ok {
		t.Fatal("lookup on a failed snapshot returned a process")
	}
}

func TestUnresolvedAccountNamesAreReported(t *testing.T) {
	p := Proc(1234, 4, "user.exe", 10)
	p.UserSID = models.Known("S-1-5-21-9-9-9-1104")
	p.UserName = models.Unavailable[string]("not resolved: domain account")
	s := Build(at, []models.ProcessRecord{p})
	for _, n := range s.Coverage {
		if n.Item == "account names" && strings.Contains(n.Reason, "1 processes") {
			return
		}
	}
	t.Fatalf("coverage %+v", s.Coverage)
}
