//go:build windows

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	winplat "github.com/dashpalmer269-ai/canaveral/internal/platform/windows"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

// requireEnv returns the variable's value. When CANAVERAL_REQUIRE_OUTPUT=1
// (set by the CI step that provides a test volume) a missing value fails
// instead of skipping.
func requireEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		if os.Getenv("CANAVERAL_REQUIRE_OUTPUT") == "1" {
			t.Fatalf("%s must be set when CANAVERAL_REQUIRE_OUTPUT=1", name)
		}
		t.Skipf("%s not set", name)
	}
	return v
}

// The real writer, real volume inspector and real NTFS: an explicit output
// root on a non-system volume gets exactly the report layout. The files are
// left in place so CI can check the companions with Get-FileHash.
func TestRealWriterOnNonSystemVolume(t *testing.T) {
	root := requireEnv(t, "CANAVERAL_TEST_OUTPUT")
	if _, err := os.Stat(root); err == nil {
		t.Fatalf("%s already exists; the test needs a fresh path", root)
	}
	insp := winplat.VolumeInspector{}
	dest, err := runtime.ValidateOutput(ctx, insp, runtime.OutputRequest{Override: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("destination %s basis %v volume %s", dest.Root, dest.Basis, show(dest.Volume.VolumeID.Get()))

	ledger := runtime.NewLedger(platform.SystemClock{})
	w, err := Open(ctx, dest, Options{Inspector: insp, Ledger: ledger, Clock: platform.SystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	must(t, w.Stage("report.md", mdV1))
	res, err := w.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scan := filepath.Base(res.ScanDir)
	var want []string
	for _, p := range scanLayout(scan) {
		want = append(want, strings.TrimPrefix(p, "Canaveral_Reports/"))
	}
	wantTree(t, root, want[1:]...)
	verifyCompanion(t, filepath.Join(res.ScanDir, "report.json"))
	verifyCompanion(t, filepath.Join(res.ScanDir, "report.md"))

	Cleanup(ledger)
	wantTree(t, root, want[1:]...)
	if rv := ledger.Review(); len(rv.Outside) != 0 || len(rv.Leftovers) != 0 {
		t.Fatalf("footprint review: outside=%v leftovers=%v", rv.Outside, rv.Leftovers)
	}
	t.Logf("wrote %v", res.Files)
}

// The real inspector refuses the system volume, and a hand-forged
// destination there is refused before anything is created.
func TestRealSystemVolumeIsRefused(t *testing.T) {
	sysPath := requireEnv(t, "CANAVERAL_TEST_SYSTEM_PATH")
	insp := winplat.VolumeInspector{}
	if _, err := runtime.ValidateOutput(ctx, insp, runtime.OutputRequest{Override: sysPath}); err == nil {
		t.Fatalf("%s accepted", sysPath)
	}
	vol, err := insp.Volume(ctx, sysPath)
	if err != nil {
		t.Fatal(err)
	}
	forged := runtime.Destination{Root: sysPath, Volume: vol}
	ledger := runtime.NewLedger(platform.SystemClock{})
	if _, err := Open(ctx, forged, Options{Inspector: insp, Ledger: ledger, Clock: platform.SystemClock{}}); err == nil {
		t.Fatal("forged system destination accepted by the writer")
	}
	if _, err := os.Stat(sysPath); err == nil {
		t.Fatalf("%s was created on the system volume", sysPath)
	}
	if n := len(ledger.Resources()); n != 0 {
		t.Fatalf("%d resources created", n)
	}
}

func show(v string, ok bool) string {
	if !ok {
		return "unknown"
	}
	return v
}
