//go:build windows

package windows

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

var ctx = context.Background()

func processes(t *testing.T) map[uint32]models.ProcessRecord {
	t.Helper()
	recs, err := ProcessSource{}.Processes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) < 10 {
		t.Fatalf("only %d processes", len(recs))
	}
	m := map[uint32]models.ProcessRecord{}
	for _, r := range recs {
		m[r.PID] = r
	}
	return m
}

func TestOwnProcessIsFullyDescribed(t *testing.T) {
	procs := processes(t)
	self, ok := procs[uint32(os.Getpid())]
	if !ok {
		t.Fatal("own process not enumerated")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	img, ok := self.ImagePath.Get()
	if !ok || !strings.EqualFold(filepath.Base(img), filepath.Base(exe)) {
		t.Errorf("image path %q (%s), executable %q", img, self.ImagePath.Reason(), exe)
	}
	if cl, ok := self.CommandLine.Get(); !ok || !strings.Contains(strings.ToLower(cl), strings.ToLower(strings.TrimSuffix(filepath.Base(exe), ".exe"))) {
		t.Errorf("command line %q (%s)", cl, self.CommandLine.Reason())
	}
	if !self.CreateTime.IsKnown() || !self.SessionID.IsKnown() {
		t.Errorf("creation time %s / session %s", self.CreateTime.Reason(), self.SessionID.Reason())
	}
	if sid, ok := self.UserSID.Get(); !ok || !strings.HasPrefix(sid, "S-1-") {
		t.Errorf("user SID %q (%s)", sid, self.UserSID.Reason())
	}
	if prot, ok := self.Protection.Get(); !ok || prot != "None" {
		t.Errorf("protection %q (%s)", prot, self.Protection.Reason())
	}
	if self.ParentPID != uint32(os.Getppid()) {
		t.Errorf("parent PID %d, os.Getppid %d", self.ParentPID, os.Getppid())
	}
	t.Logf("self: pid=%d user=%v name=%v", self.PID, self.UserSID, self.UserName)
}

// Nothing may be invented for processes that cannot be opened.
func TestIdleProcessHasNoInventedValues(t *testing.T) {
	procs := processes(t)
	idle, ok := procs[0]
	if !ok {
		t.Fatal("PID 0 not enumerated")
	}
	if idle.CreateTime.IsKnown() || idle.ImagePath.IsKnown() || idle.CommandLine.IsKnown() || idle.UserSID.IsKnown() {
		t.Fatalf("values reported for the Idle pseudo-process: %+v", idle)
	}
	if sys, ok := procs[4]; !ok || sys.Name != "System" {
		t.Fatalf("System process: %+v", sys)
	}
}

func TestProcessCoverageSummary(t *testing.T) {
	procs := processes(t)
	unreadable, protected := 0, 0
	for _, p := range procs {
		if !p.ImagePath.IsKnown() {
			unreadable++
		}
		if prot, ok := p.Protection.Get(); ok && prot != "None" {
			protected++
			t.Logf("protected: pid=%d %s %s cmdline-known=%v", p.PID, p.Name, prot, p.CommandLine.IsKnown())
		}
	}
	t.Logf("%d processes, %d without an image path, %d protected", len(procs), unreadable, protected)
}

func TestElevation(t *testing.T) {
	info, err := Privileges{}.Elevation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Elevated.IsKnown() || !info.IntegrityLevel.IsKnown() || !info.AdminMember.IsKnown() {
		t.Fatalf("elevation info incomplete: %+v", info)
	}
	t.Logf("elevated=%v integrity=%v admins=%v", info.Elevated, info.IntegrityLevel, info.AdminMember)
}
