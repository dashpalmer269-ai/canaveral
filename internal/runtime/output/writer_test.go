package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

var (
	ctx     = context.Background()
	scanAt  = time.Date(2026, 11, 2, 14, 30, 5, 0, time.UTC)
	jsonV1  = []byte(`{"verdict":"NO INDICATORS IDENTIFIED"}` + "\n")
	mdV1    = []byte("# Canaveral report\n\nNo indicators identified. This is not proof of a clean system.\n")
	errGone = errors.New("simulated: the device is not ready")
)

type env struct {
	sys, usb, usb2 string
	vols           *fake.Volumes
	clock          *fake.Clock
	ledger         *runtime.Ledger
	warnings       []string
}

func vol(root string, dt models.DriveType, bus models.BusType, isSys bool) models.VolumeInfo {
	return models.VolumeInfo{
		Root: root, VolumeID: models.Known("vol:" + filepath.Base(root)), DriveType: dt,
		BusType: models.Known(bus), RemovableMedia: models.Known(dt == models.DriveRemovable),
		ReadOnly: models.Known(false), FreeBytes: models.Known[uint64](4 << 30), IsSystem: models.Known(isSys),
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	e := &env{sys: filepath.Join(base, "sys"), usb: filepath.Join(base, "usb"), usb2: filepath.Join(base, "usb2")}
	for _, d := range []string{e.sys, e.usb, e.usb2} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.vols = fake.NewVolumes(
		vol(e.sys, models.DriveFixed, models.BusNVMe, true),
		vol(e.usb, models.DriveRemovable, models.BusUSB, false),
		vol(e.usb2, models.DriveRemovable, models.BusUSB, false),
	)
	e.clock = fake.NewClock(scanAt)
	e.ledger = runtime.NewLedger(e.clock)
	return e
}

func (e *env) opts(p AlternatePrompter) Options {
	return Options{
		Inspector: e.vols, Ledger: e.ledger, Clock: e.clock, Prompter: p,
		Warn: func(s string) { e.warnings = append(e.warnings, s) },
	}
}

func (e *env) destination(t *testing.T) runtime.Destination {
	t.Helper()
	d, err := runtime.ValidateOutput(ctx, e.vols, runtime.OutputRequest{ExePath: filepath.Join(e.usb, "Canaveral.exe")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// tree lists every file and directory under root, relative to it.
func tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			rel += "/"
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func wantTree(t *testing.T, root string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := tree(t, root); !slices.Equal(got, want) {
		t.Fatalf("contents of %s:\n got  %q\n want %q", root, got, want)
	}
}

func scanLayout(scan string) []string {
	return []string{
		"Canaveral_Reports/", "Canaveral_Reports/" + scan + "/",
		"Canaveral_Reports/" + scan + "/report.json", "Canaveral_Reports/" + scan + "/report.json.sha256",
		"Canaveral_Reports/" + scan + "/report.md", "Canaveral_Reports/" + scan + "/report.md.sha256",
	}
}

// verifyCompanion checks a .sha256 file the way an operator would with
// Get-FileHash: hash the artifact and compare, ignoring case.
func verifyCompanion(t *testing.T, artifact string) {
	t.Helper()
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	comp, err := os.ReadFile(artifact + CompanionSuffix)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:]) + "  " + filepath.Base(artifact) + "\n"
	if !strings.EqualFold(string(comp), want) {
		t.Fatalf("%s companion %q, want %q", artifact, comp, want)
	}
}

// Acceptance (M2): one directory per scan holding report.md, report.json and
// their .sha256 companions, and nothing else on the USB.
func TestLayoutIsOneDirectoryPerScan(t *testing.T) {
	e := newEnv(t)
	w, err := Open(ctx, e.destination(t), e.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	must(t, w.Stage("report.md", mdV1))
	res, err := w.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scan := "scan_20261102T143005Z"
	wantTree(t, e.usb, scanLayout(scan)...)
	verifyCompanion(t, filepath.Join(e.usb, "Canaveral_Reports", scan, "report.json"))
	verifyCompanion(t, filepath.Join(e.usb, "Canaveral_Reports", scan, "report.md"))
	if len(res.Files) != 4 || res.Relocated || len(res.Warnings) != 0 || len(w.Pending()) != 0 {
		t.Fatalf("result %+v pending %v", res, w.Pending())
	}

	Cleanup(e.ledger) // must not remove anything that belongs in the layout
	wantTree(t, e.usb, scanLayout(scan)...)

	rv := e.ledger.Review()
	if len(rv.Outside) != 0 || len(rv.Leftovers) != 0 || len(rv.Inside) != 6 {
		t.Fatalf("review: inside=%d outside=%d leftovers=%d", len(rv.Inside), len(rv.Outside), len(rv.Leftovers))
	}
	wantTree(t, e.sys)
	wantTree(t, e.usb2)
}

func TestSecondScanGetsItsOwnDirectory(t *testing.T) {
	e := newEnv(t)
	for range 2 { // same second: the second scan gets a suffix
		w, err := Open(ctx, e.destination(t), e.opts(nil))
		if err != nil {
			t.Fatal(err)
		}
		must(t, w.Stage("report.json", jsonV1))
		if _, err := w.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	e.clock.Advance(time.Minute)
	w, err := Open(ctx, e.destination(t), e.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(w.ScanDir()); got != "scan_20261102T143105Z" {
		t.Fatalf("scan dir %s", got)
	}
	if got := filepath.Base(filepath.Dir(w.ScanDir())); got != "Canaveral_Reports" {
		t.Fatalf("parent %s", got)
	}
	entries, _ := os.ReadDir(filepath.Join(e.usb, "Canaveral_Reports"))
	var names []string
	for _, d := range entries {
		names = append(names, d.Name())
	}
	if !slices.Equal(names, []string{"scan_20261102T143005Z", "scan_20261102T143005Z_2", "scan_20261102T143105Z"}) {
		t.Fatalf("scan dirs %v", names)
	}
}

// Acceptance (M2): paths outside the approved root are refused.
func TestStageRefusesNamesOutsideTheLayout(t *testing.T) {
	e := newEnv(t)
	w, err := Open(ctx, e.destination(t), e.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"", "notes.txt", "report.JSON", "report.json.sha256", "report.json.partial",
		"../report.json", "../../evil.json", "report.json/../../x", `..\report.json`,
		filepath.Join(e.sys, "report.json"), "sub/report.json",
	} {
		if err := w.Stage(name, []byte("x")); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Stage(%q) err = %v", name, err)
		}
	}
	if _, err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	wantTree(t, e.usb, "Canaveral_Reports/", "Canaveral_Reports/scan_20261102T143005Z/")
	wantTree(t, e.sys)
}

func TestRestagedArtifactReplacesFileAndCompanion(t *testing.T) {
	e := newEnv(t)
	w, err := Open(ctx, e.destination(t), e.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	if _, err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	v2 := []byte(`{"verdict":"FURTHER REVIEW REQUIRED"}` + "\n")
	must(t, w.Stage("report.json", v2))
	if _, err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(w.ScanDir(), "report.json"))
	if string(got) != string(v2) {
		t.Fatalf("content %q", got)
	}
	verifyCompanion(t, filepath.Join(w.ScanDir(), "report.json"))
	var replaced int
	for _, r := range e.ledger.Resources() {
		if r.State == runtime.StateReplaced {
			replaced++
		}
	}
	if replaced != 2 {
		t.Fatalf("%d replaced ledger entries, want 2 (artifact and companion)", replaced)
	}
	wantTree(t, e.usb, "Canaveral_Reports/", "Canaveral_Reports/scan_20261102T143005Z/",
		"Canaveral_Reports/scan_20261102T143005Z/report.json", "Canaveral_Reports/scan_20261102T143005Z/report.json.sha256")
}

// flakyOps behaves like the real filesystem until it is tripped, then fails
// every operation under failRoot, as if the device had been unplugged.
type flakyOps struct {
	osOps
	mu         sync.Mutex
	failRoot   string
	failCreate int // trip on this Create call under failRoot (1-based); 0 = never
	creates    int
	tripped    bool
	onTrip     func()
	// failRename makes Rename fail under failRoot without tripping, and runs
	// beforeRenameFail first.
	failRename       bool
	beforeRenameFail func(tmp string)
	// corruptReads makes reads under failRoot return altered bytes, like a
	// failing flash device that accepted the write.
	corruptReads bool
}

func (f *flakyOps) under(p string) bool { return within(f.failRoot, p) }

func (f *flakyOps) gone(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tripped && f.under(p)
}

func (f *flakyOps) Mkdir(p string) error {
	if f.gone(p) {
		return errGone
	}
	return f.osOps.Mkdir(p)
}

func (f *flakyOps) Create(p string) (writableFile, error) {
	f.mu.Lock()
	if f.under(p) {
		f.creates++
		if f.failCreate > 0 && f.creates == f.failCreate {
			f.tripped = true
		}
	}
	tripped, onTrip := f.tripped && f.under(p), f.onTrip
	f.mu.Unlock()
	if tripped {
		if onTrip != nil {
			onTrip()
		}
		return nil, errGone
	}
	return f.osOps.Create(p)
}

func (f *flakyOps) Rename(o, n string) error {
	if f.gone(o) {
		return errGone
	}
	if f.failRename && f.under(o) {
		if f.beforeRenameFail != nil {
			f.beforeRenameFail(o)
		}
		return errors.New("simulated: rename failed")
	}
	return f.osOps.Rename(o, n)
}

func (f *flakyOps) Remove(p string) error {
	if f.gone(p) {
		return errGone
	}
	return f.osOps.Remove(p)
}

func (f *flakyOps) ReadFile(p string) ([]byte, error) {
	if f.gone(p) {
		return nil, errGone
	}
	b, err := f.osOps.ReadFile(p)
	if err == nil && f.corruptReads && f.under(p) && len(b) > 0 {
		b[0] ^= 0xff
	}
	return b, err
}

func (f *flakyOps) Lstat(p string) (os.FileInfo, error) {
	if f.gone(p) {
		return nil, errGone
	}
	return f.osOps.Lstat(p)
}

func (f *flakyOps) IsEmptyDir(p string) (bool, error) {
	if f.gone(p) {
		return false, errGone
	}
	return f.osOps.IsEmptyDir(p)
}

type scriptedPrompter struct {
	answers []string // "" ends the script with a decline
	calls   []error
}

func (s *scriptedPrompter) Alternate(_ context.Context, lost error, attempt int) (string, bool) {
	s.calls = append(s.calls, lost)
	if attempt > len(s.answers) || s.answers[attempt-1] == "" {
		return "", false
	}
	return s.answers[attempt-1], true
}

func hasWarning(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// Acceptance (M2): USB removed mid-run. Results stay in memory, the operator
// gets a clear warning, and the alternate-destination path works. The system
// drive and a relative path are refused when offered as alternates.
func TestUSBRemovedMidRunRelocatesToAlternate(t *testing.T) {
	e := newEnv(t)
	ops := &flakyOps{failRoot: e.usb, failCreate: 3, onTrip: func() { e.vols.Unmount(e.usb) }}
	prompt := &scriptedPrompter{answers: []string{
		filepath.Join(e.sys, "Canaveral_Reports"),
		"reports",
		filepath.Join(e.usb2, "Saved"),
	}}
	w, err := open(ctx, e.destination(t), e.opts(prompt), ops)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	must(t, w.Stage("report.md", mdV1))

	res, err := w.Flush(ctx)
	if err != nil {
		t.Fatalf("flush after relocation: %v (warnings %q)", err, res.Warnings)
	}
	if !res.Relocated || len(prompt.calls) != 3 || len(w.Pending()) != 0 {
		t.Fatalf("relocated=%v prompts=%d pending=%d", res.Relocated, len(prompt.calls), len(w.Pending()))
	}
	if !errors.Is(prompt.calls[0], errGone) {
		t.Fatalf("operator was not told what went wrong: %v", prompt.calls[0])
	}
	for _, want := range []string{
		"is no longer usable", "still held in memory and has not been lost",
		"system volume", "must be absolute", "Saving the report to the alternate destination",
	} {
		if !hasWarning(res.Warnings, want) {
			t.Errorf("no warning containing %q in %q", want, res.Warnings)
		}
	}
	if !slices.Equal(res.Warnings, e.warnings) {
		t.Fatal("warnings were not delivered to the Warn callback as they happened")
	}

	// The full report landed on the alternate device, in the same layout.
	got := tree(t, e.usb2)
	if len(got) != 6 || got[0] != "Saved/" {
		t.Fatalf("alternate contents %q", got)
	}
	verifyCompanion(t, filepath.Join(res.ScanDir, "report.json"))
	verifyCompanion(t, filepath.Join(res.ScanDir, "report.md"))
	if b, _ := os.ReadFile(filepath.Join(res.ScanDir, "report.md")); string(b) != string(mdV1) {
		t.Fatal("alternate report content differs")
	}

	// The refused system path was never created.
	wantTree(t, e.sys)

	// The footprint review is honest about what may remain on the lost device.
	rv := e.ledger.Review()
	if len(rv.Outside) != 0 || len(rv.Leftovers) == 0 || !strings.Contains(rv.Summary, "may remain") {
		t.Fatalf("review outside=%v leftovers=%d summary=%q", rv.Outside, len(rv.Leftovers), rv.Summary)
	}
}

func TestUSBRemovedOperatorDeclinesKeepsDataInMemory(t *testing.T) {
	e := newEnv(t)
	ops := &flakyOps{failRoot: e.usb, failCreate: 1, onTrip: func() { e.vols.Unmount(e.usb) }}
	w, err := open(ctx, e.destination(t), e.opts(&scriptedPrompter{}), ops)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	must(t, w.Stage("report.md", mdV1))
	res, err := w.Flush(ctx)
	if !errors.Is(err, ErrNotSaved) || !errors.Is(err, errGone) {
		t.Fatalf("err = %v", err)
	}
	p := w.Pending()
	if string(p["report.json"]) != string(jsonV1) || string(p["report.md"]) != string(mdV1) {
		t.Fatalf("pending %v", p)
	}
	if !hasWarning(res.Warnings, "has not been saved") || len(res.Files) != 0 {
		t.Fatalf("result %+v", res)
	}
}

func TestNoPrompterKeepsDataInMemory(t *testing.T) {
	e := newEnv(t)
	ops := &flakyOps{failRoot: e.usb, failCreate: 2}
	w, err := open(ctx, e.destination(t), e.opts(nil), ops)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	if _, err := w.Flush(ctx); !errors.Is(err, ErrNotSaved) {
		t.Fatalf("err = %v", err)
	}
	if len(w.Pending()) != 1 {
		t.Fatalf("pending %v", w.Pending())
	}
}

// A different stick plugged in at the same mount point must not receive the
// report.
func TestSwappedVolumeIsDetected(t *testing.T) {
	e := newEnv(t)
	w, err := Open(ctx, e.destination(t), e.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	swapped := vol(e.usb, models.DriveRemovable, models.BusUSB, false)
	swapped.VolumeID = models.Known("vol:another-stick")
	e.vols.Mount(swapped)
	must(t, w.Stage("report.json", jsonV1))
	_, err = w.Flush(ctx)
	if !errors.Is(err, ErrNotSaved) || !errors.Is(err, ErrDestinationLost) || !strings.Contains(err.Error(), "different volume") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.ScanDir(), "report.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("report written to the swapped volume: %v", err)
	}
}

// If the new scan directory turns out to be on another volume (for example a
// junction or mount point created between validation and creation), the
// writer notices after creating it, removes what it created, and refuses.
func TestRedirectAfterValidationIsCaught(t *testing.T) {
	e := newEnv(t)
	dest := e.destination(t)
	e.vols.Mount(vol(filepath.Join(e.usb, "Canaveral_Reports", "scan_20261102T143005Z"), models.DriveFixed, models.BusNVMe, true))
	_, err := Open(ctx, dest, e.opts(nil))
	if !errors.Is(err, ErrDestinationLost) {
		t.Fatalf("err = %v", err)
	}
	wantTree(t, e.usb)
}

// A destination whose root is already on another volume is refused before
// anything is created.
func TestRedirectedRootIsRefusedBeforeCreating(t *testing.T) {
	e := newEnv(t)
	dest := e.destination(t)
	e.vols.Mount(vol(filepath.Join(e.usb, "Canaveral_Reports"), models.DriveFixed, models.BusNVMe, true))
	if _, err := Open(ctx, dest, e.opts(nil)); !errors.Is(err, ErrDestinationLost) {
		t.Fatalf("err = %v", err)
	}
	if n := len(e.ledger.Resources()); n != 0 {
		t.Fatalf("%d resources created for a refused destination", n)
	}
}

// Defense in depth: even a Destination built by hand for the system volume,
// bypassing validation, is refused at Open before anything is created.
func TestForgedSystemDestinationIsRefused(t *testing.T) {
	e := newEnv(t)
	forged := runtime.Destination{Root: filepath.Join(e.sys, "Canaveral_Reports"), Volume: vol(e.sys, models.DriveRemovable, models.BusUSB, false)}
	if _, err := Open(ctx, forged, e.opts(nil)); !errors.Is(err, ErrDestinationLost) {
		t.Fatalf("forged system destination: err = %v", err)
	}
	wantTree(t, e.sys)
	if n := len(e.ledger.Resources()); n != 0 {
		t.Fatalf("%d resources created on the system volume", n)
	}
}

func TestNonWritableDestination(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("Unix permission bits do not block writes on Windows; read-only volumes are covered by validation")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e := newEnv(t)
	dest := e.destination(t)
	if err := os.Chmod(e.usb, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.usb, 0o700) })
	_, err := Open(ctx, dest, e.opts(nil))
	if !errors.Is(err, runtime.ErrRejected) || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("err = %v", err)
	}
	if n := len(e.ledger.Resources()); n != 0 {
		t.Fatalf("ledger recorded %d resources for a failed open", n)
	}
}

func TestOpenWithNothingWrittenLeavesNothingAfterCleanup(t *testing.T) {
	e := newEnv(t)
	if _, err := Open(ctx, e.destination(t), e.opts(nil)); err != nil {
		t.Fatal(err)
	}
	Cleanup(e.ledger)
	wantTree(t, e.usb)
	for _, r := range e.ledger.Resources() {
		if r.State != runtime.StateRemoved {
			t.Errorf("%s is %s", r.Path, r.State)
		}
	}
}

// Acceptance (M2): cleanup touches only resources the tool created. Unrelated
// files with the same timestamp, look-alike names in other directories, and
// a file that replaced the tool's own temp file are all left alone.
func TestCleanupNeverTouchesUnrelatedFiles(t *testing.T) {
	e := newEnv(t)
	reports := filepath.Join(e.usb, "Canaveral_Reports") // pre-existing, so not ours
	foreignScan := filepath.Join(reports, "scan_20261102T143005Z")
	must(t, os.MkdirAll(foreignScan, 0o700))
	unrelated := map[string]string{
		filepath.Join(e.usb, "unrelated.txt"):                 "customer file",
		filepath.Join(e.usb, "report.json.partial"):           "look-alike at the USB root",
		filepath.Join(foreignScan, "report.json.partial"):     "look-alike in another tool's scan dir",
		filepath.Join(foreignScan, "report.json"):             "someone else's report",
		filepath.Join(e.usb, "scan_20261102T143005Z_2.txt"):   "name collision",
		filepath.Join(e.sys, "Windows", "Temp", "x.partial"):  "host temp file",
		filepath.Join(e.usb2, "Canaveral_Reports", "keep.md"): "other device",
	}
	for p, content := range unrelated {
		must(t, os.MkdirAll(filepath.Dir(p), 0o700))
		must(t, os.WriteFile(p, []byte(content), 0o600))
		must(t, os.Chtimes(p, scanAt, scanAt))
	}

	var replacedTmp string
	ops := &flakyOps{failRoot: e.usb, failRename: true, beforeRenameFail: func(tmp string) {
		// Something else replaces the tool's temp file before cleanup runs.
		if replacedTmp == "" {
			replacedTmp = tmp
			must(t, os.Remove(tmp))
			must(t, os.WriteFile(tmp, []byte("not Canaveral's file, different size"), 0o600))
			must(t, os.Chtimes(tmp, scanAt, scanAt))
		}
	}}
	w, err := open(ctx, e.destination(t), e.opts(nil), ops)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(w.ScanDir()) != "scan_20261102T143005Z_2" {
		t.Fatalf("scan dir %s; the foreign one must not be reused", w.ScanDir())
	}
	// A file someone else drops into our scan directory keeps it from being
	// removed as empty.
	dropped := filepath.Join(w.ScanDir(), "dropped-by-user.txt")
	must(t, os.WriteFile(dropped, []byte("user file"), 0o600))
	unrelated[dropped] = "user file"

	must(t, w.Stage("report.json", jsonV1))
	if _, err := w.Flush(ctx); !errors.Is(err, ErrNotSaved) {
		t.Fatalf("err = %v", err)
	}
	Cleanup(e.ledger)
	Cleanup(e.ledger) // idempotent

	for p, content := range unrelated {
		b, err := os.ReadFile(p)
		if err != nil || string(b) != content {
			t.Errorf("unrelated %s changed: %q, %v", p, b, err)
		}
	}
	if b, err := os.ReadFile(replacedTmp); err != nil || !strings.HasPrefix(string(b), "not Canaveral's") {
		t.Errorf("replaced temp file was removed or changed: %q %v", b, err)
	}
	var notRemoved bool
	for _, r := range e.ledger.Resources() {
		if r.Path == replacedTmp && r.State == runtime.StateNotRemoved {
			notRemoved = true
		}
		if r.Path == reports || r.Path == foreignScan {
			t.Errorf("pre-existing %s appears in the ledger", r.Path)
		}
	}
	if !notRemoved {
		t.Error("ledger does not record that the replaced temp file was left alone")
	}
}

// When the tool's own temp file is still its own, cleanup removes it.
func TestCleanupRemovesOwnTempFile(t *testing.T) {
	e := newEnv(t)
	ops := &flakyOps{failRoot: e.usb, failRename: true}
	w, err := open(ctx, e.destination(t), e.opts(nil), ops)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	if _, err := w.Flush(ctx); !errors.Is(err, ErrNotSaved) {
		t.Fatalf("err = %v", err)
	}
	Cleanup(e.ledger)
	wantTree(t, e.usb)
}

func TestCanceledFlushKeepsDestinationAndData(t *testing.T) {
	e := newEnv(t)
	w, err := Open(ctx, e.destination(t), e.opts(&scriptedPrompter{}))
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := w.Flush(c); !errors.Is(err, ErrNotSaved) {
		t.Fatalf("err = %v", err)
	}
	if len(w.Pending()) != 1 || len(e.warnings) != 0 {
		t.Fatalf("pending %d warnings %q", len(w.Pending()), e.warnings)
	}
	if _, err := w.Flush(ctx); err != nil {
		t.Fatalf("flush after cancel: %v", err)
	}
}

func TestConcurrentStageAndFlush(t *testing.T) {
	e := newEnv(t)
	w, err := Open(ctx, e.destination(t), e.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				_ = w.Stage("report.json", []byte{byte(i), byte(j)})
				_, _ = w.Flush(ctx)
				_ = w.Pending()
			}
		}()
	}
	wg.Wait()
	if _, err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	verifyCompanion(t, filepath.Join(w.ScanDir(), "report.json"))
}

func TestOpenRequiresDependencies(t *testing.T) {
	e := newEnv(t)
	if _, err := Open(ctx, e.destination(t), Options{}); err == nil {
		t.Fatal("Open without dependencies succeeded")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// File IDs can repeat for a different file: FAT32/exFAT derive them from the
// directory entry, and Linux reuses inode numbers. Same ID with a different
// size must not count as the tool's file.
func TestSameObjectRequiresMatchingSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json.partial")
	must(t, os.WriteFile(p, []byte("ours"), 0o600))
	recorded, err := os.Lstat(p)
	must(t, err)
	r := runtime.Resource{Kind: runtime.ResourceFile, Path: p, Identity: recorded}
	if !sameObject(r, recorded) {
		t.Fatal("identical file not recognized")
	}
	must(t, os.WriteFile(p, []byte("someone else's longer content"), 0o600)) // same inode, new size
	now, err := os.Lstat(p)
	must(t, err)
	if !os.SameFile(recorded, now) {
		t.Skip("filesystem gave the rewritten file a new identity; nothing to test")
	}
	if sameObject(r, now) {
		t.Fatal("same file ID with a different size was treated as the tool's file")
	}
	r.Kind = runtime.ResourceDirectory
	if sameObject(r, now) {
		t.Fatal("a regular file matched a directory record")
	}
}

func TestCorruptedWriteIsNotReportedAsSaved(t *testing.T) {
	e := newEnv(t)
	ops := &flakyOps{failRoot: e.usb, corruptReads: true}
	w, err := open(ctx, e.destination(t), e.opts(nil), ops)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Stage("report.json", jsonV1))
	res, err := w.Flush(ctx)
	if !errors.Is(err, ErrNotSaved) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v", err)
	}
	if len(res.Files) != 0 || len(w.Pending()) != 1 {
		t.Fatalf("corrupted write reported as saved: files=%v pending=%d", res.Files, len(w.Pending()))
	}
}
