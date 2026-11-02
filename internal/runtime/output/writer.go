package output

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

// Errors returned by the writer.
var (
	ErrNotAllowed      = errors.New("output: name is not part of the report layout")
	ErrDestinationLost = errors.New("output: destination is no longer usable")
	ErrNotSaved        = errors.New("output: report not saved; it is still held in memory")
)

// Artifacts are the only files a scan directory may hold, besides one
// .sha256 companion for each (CLAUDE.md M2).
var Artifacts = []string{"report.json", "report.md"}

// CompanionSuffix names the checksum companion of an artifact.
const CompanionSuffix = ".sha256"

const (
	partialSuffix     = ".partial"
	scanDirPrefix     = "scan_"
	scanTimeLayout    = "20060102T150405Z"
	maxScanDirSuffix  = 99
	maxPromptAttempts = 10
)

// AlternatePrompter asks the operator for another destination after the
// current one became unusable. ok=false means the operator declined.
// Alternate is called from inside Writer.Flush while the writer is locked, so
// it must not call any Writer method; anything it needs to show the operator
// is passed in.
type AlternatePrompter interface {
	Alternate(ctx context.Context, lost error, attempt int) (path string, ok bool)
}

// Options configures a Writer. Inspector, Ledger and Clock are required.
type Options struct {
	Inspector    platform.VolumeInspector
	Ledger       *runtime.Ledger
	Clock        platform.Clock
	MinFreeBytes uint64
	Prompter     AlternatePrompter
	// Warn receives operator-facing warnings as they happen.
	Warn func(string)
}

// Result describes a completed or attempted flush.
type Result struct {
	ScanDir   string
	Files     []string
	Relocated bool
	Warnings  []string
}

// Writer is the only component that writes files. It writes report
// artifacts into one new scan directory under an approved destination and
// nowhere else.
type Writer struct {
	mu   sync.Mutex
	opts Options
	ops  fileOps

	dest    runtime.Destination
	scanDir string

	staged    map[string][]byte
	written   map[string][sha256.Size]byte
	warnings  []string
	relocated bool
}

// Open creates a scan directory under dest. dest must come from
// runtime.ValidateOutput.
func Open(ctx context.Context, dest runtime.Destination, opts Options) (*Writer, error) {
	return open(ctx, dest, opts, osOps{})
}

func open(ctx context.Context, dest runtime.Destination, opts Options, ops fileOps) (*Writer, error) {
	if opts.Inspector == nil || opts.Ledger == nil || opts.Clock == nil {
		return nil, errors.New("output: Inspector, Ledger and Clock are required")
	}
	w := &Writer{opts: opts, ops: ops, staged: map[string][]byte{}, written: map[string][sha256.Size]byte{}}
	if err := w.start(ctx, dest); err != nil {
		cleanupUnder(opts.Ledger, ops, dest.Volume.Root)
		return nil, err
	}
	return w, nil
}

// start creates the scan directory for dest and makes it current.
func (w *Writer) start(ctx context.Context, dest runtime.Destination) error {
	// Check before creating anything, so a bad destination leaves no trace.
	if err := checkVolume(ctx, w.opts.Inspector, dest, dest.Root); err != nil {
		return err
	}
	scanDir, err := w.makeScanDir(dest)
	if err != nil {
		return err
	}
	// Re-inspect now that the directory exists: if anything redirected the
	// path to another volume, it shows up here.
	if err := checkVolume(ctx, w.opts.Inspector, dest, scanDir); err != nil {
		return err
	}
	w.opts.Ledger.Approve(dest.Root)
	w.dest, w.scanDir = dest, scanDir
	w.written = map[string][sha256.Size]byte{}
	return nil
}

func (w *Writer) makeScanDir(dest runtime.Destination) (string, error) {
	volRoot := filepath.Clean(dest.Volume.Root)
	rel, err := filepath.Rel(volRoot, dest.Root)
	if err != nil || !within(volRoot, dest.Root) {
		return "", &runtime.Rejection{Path: dest.Root, Reasons: []string{"destination is not inside its volume " + volRoot}}
	}
	cur := volRoot
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			cur = filepath.Join(cur, part)
			if err := w.ensureDir(cur); err != nil {
				return "", err
			}
		}
	}

	base := scanDirPrefix + w.opts.Clock.Now().UTC().Format(scanTimeLayout)
	for i := 1; i <= maxScanDirSuffix; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s_%d", base, i)
		}
		p := filepath.Join(dest.Root, name)
		err := w.ops.Mkdir(p)
		if err == nil {
			w.recordDir(p)
			return p, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", notWritable(p, err)
		}
	}
	return "", notWritable(dest.Root, fmt.Errorf("no unused scan directory name for %s", base))
}

// ensureDir creates dir if it is missing and records it. An existing entry
// must be a real directory.
func (w *Writer) ensureDir(dir string) error {
	err := w.ops.Mkdir(dir)
	switch {
	case err == nil:
		w.recordDir(dir)
		return nil
	case errors.Is(err, fs.ErrExist):
		fi, lerr := w.ops.Lstat(dir)
		if lerr != nil {
			return notWritable(dir, lerr)
		}
		if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 || !fi.IsDir() {
			return &runtime.Rejection{Path: dir, Reasons: []string{"exists and is not a plain directory"}}
		}
		return nil
	default:
		return notWritable(dir, err)
	}
}

func (w *Writer) recordDir(dir string) {
	fi, err := w.ops.Lstat(dir)
	if err != nil {
		fi = nil
	}
	w.opts.Ledger.Record(runtime.ResourceDirectory, dir, runtime.StateCreated, fi)
}

func notWritable(path string, err error) error {
	return &runtime.Rejection{Path: path, Reasons: []string{fmt.Sprintf("could not create a directory, so the destination is not writable: %v", err)}}
}

func checkVolume(ctx context.Context, insp platform.VolumeInspector, dest runtime.Destination, path string) error {
	vol, err := insp.Volume(ctx, path)
	if err != nil {
		return fmt.Errorf("%w: %s can no longer be inspected: %v", ErrDestinationLost, path, err)
	}
	if want, ok := dest.Volume.VolumeID.Get(); ok {
		got, ok := vol.VolumeID.Get()
		if !ok {
			return fmt.Errorf("%w: the volume at %s can no longer be identified (%s)", ErrDestinationLost, path, vol.VolumeID.Reason())
		}
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("%w: %s is now on a different volume (%s, expected %s)", ErrDestinationLost, path, got, want)
		}
	}
	if !strings.EqualFold(filepath.Clean(vol.Root), filepath.Clean(dest.Volume.Root)) {
		return fmt.Errorf("%w: %s now resolves to volume %s, expected %s", ErrDestinationLost, path, vol.Root, dest.Volume.Root)
	}
	if sys, ok := vol.IsSystem.Get(); !ok || sys {
		return fmt.Errorf("%w: %s resolves to the system volume or one that cannot be confirmed otherwise", ErrDestinationLost, path)
	}
	return nil
}

// ScanDir returns the current scan directory.
func (w *Writer) ScanDir() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanDir
}

// Stage holds an artifact in memory until the next Flush. Only names in
// Artifacts are accepted.
func (w *Writer) Stage(name string, data []byte) error {
	if !slices.Contains(Artifacts, name) {
		return fmt.Errorf("%w: %q (allowed: %s)", ErrNotAllowed, name, strings.Join(Artifacts, ", "))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.staged[name] = slices.Clone(data)
	delete(w.written, name)
	return nil
}

// Pending returns copies of staged artifacts that are not yet durably written
// to the current destination. After a destination is lost, every artifact is
// pending again.
func (w *Writer) Pending() map[string][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string][]byte{}
	for name, data := range w.staged {
		if w.written[name] != sha256.Sum256(data) {
			out[name] = slices.Clone(data)
		}
	}
	return out
}

// Flush writes every pending artifact and its .sha256 companion. If the
// destination becomes unusable, the artifacts stay in memory, a warning is
// issued, and the Prompter (if any) is asked for an alternate destination,
// which is validated like --output. Without an accepted alternate, Flush
// returns ErrNotSaved and the data remains available from Pending.
func (w *Writer) Flush(ctx context.Context) (Result, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		err := w.flushOnce(ctx)
		if err == nil {
			return w.result(), nil
		}
		if ctx.Err() != nil {
			return w.result(), fmt.Errorf("%w: %w", ErrNotSaved, err)
		}
		w.abandon(err)
		if w.opts.Prompter == nil {
			w.warn("No alternate destination can be requested here. The report is still held in memory only and has not been saved.")
			return w.result(), fmt.Errorf("%w: %w", ErrNotSaved, err)
		}
		if !w.relocate(ctx, err) {
			return w.result(), fmt.Errorf("%w: %w", ErrNotSaved, err)
		}
	}
}

func (w *Writer) flushOnce(ctx context.Context) error {
	if err := checkVolume(ctx, w.opts.Inspector, w.dest, w.scanDir); err != nil {
		return err
	}
	names := make([]string, 0, len(w.staged))
	for name := range w.staged {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := w.staged[name]
		sum := sha256.Sum256(data)
		if w.written[name] == sum {
			continue
		}
		if err := w.writeFile(name, data); err != nil {
			return err
		}
		companion := fmt.Appendf(nil, "%x  %s\n", sum, name)
		if err := w.writeFile(name+CompanionSuffix, companion); err != nil {
			return err
		}
		w.written[name] = sum
	}
	return nil
}

// writeFile writes data to name.partial, syncs it, renames it into place and
// reads it back to confirm the content.
func (w *Writer) writeFile(name string, data []byte) error {
	final := filepath.Join(w.scanDir, name)
	tmp := final + partialSuffix
	f, err := w.ops.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	fi, statErr := f.Stat()
	if statErr != nil {
		fi = nil
	}
	id := w.opts.Ledger.Record(runtime.ResourceFile, tmp, runtime.StateTemporary, fi)

	_, werr := f.Write(data)
	serr := f.Sync()
	// Refresh the identity from our own handle so it records the final size.
	if fi, err := f.Stat(); err == nil {
		w.opts.Ledger.SetIdentity(id, fi)
	}
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		w.removeTemp(id)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := w.ops.Rename(tmp, final); err != nil {
		w.removeTemp(id)
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	w.opts.Ledger.Renamed(id, final, runtime.StateFinal)

	got, err := w.ops.ReadFile(final)
	if err != nil {
		return fmt.Errorf("read back %s: %w", final, err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		return fmt.Errorf("read back %s: content does not match what was written", final)
	}
	return nil
}

func (w *Writer) removeTemp(id int) {
	for _, r := range w.opts.Ledger.Resources() {
		if r.ID == id {
			removeIfOwned(w.opts.Ledger, w.ops, r)
			return
		}
	}
}

// abandon gives up on the current destination after err.
func (w *Writer) abandon(err error) {
	w.warn(fmt.Sprintf("Output destination %s is no longer usable: %v. The report is still held in memory and has not been lost. Choose another removable or non-system destination to save it.",
		w.dest.Root, err))
	cleanupUnder(w.opts.Ledger, w.ops, w.dest.Volume.Root)
	w.opts.Ledger.MarkLostUnder(w.dest.Root, "destination became unusable: "+err.Error())
	w.written = map[string][sha256.Size]byte{}
}

func (w *Writer) relocate(ctx context.Context, lost error) bool {
	for attempt := 1; attempt <= maxPromptAttempts; attempt++ {
		path, ok := w.opts.Prompter.Alternate(ctx, lost, attempt)
		if !ok {
			w.warn("No alternate destination was chosen. The report is still held in memory only and has not been saved.")
			return false
		}
		dest, err := runtime.ValidateOutput(ctx, w.opts.Inspector, runtime.OutputRequest{Override: path, MinFreeBytes: w.opts.MinFreeBytes})
		if err == nil {
			if err = w.start(ctx, dest); err != nil {
				cleanupUnder(w.opts.Ledger, w.ops, dest.Volume.Root)
			}
		}
		if err == nil {
			w.relocated = true
			w.warn(fmt.Sprintf("Saving the report to the alternate destination %s.", w.scanDir))
			return true
		}
		w.warn(fmt.Sprintf("Alternate destination %q was refused: %v", path, err))
		lost = err
	}
	w.warn("Too many alternate destinations were refused. The report is still held in memory only and has not been saved.")
	return false
}

func (w *Writer) warn(msg string) {
	w.warnings = append(w.warnings, msg)
	if w.opts.Warn != nil {
		w.opts.Warn(msg)
	}
}

func (w *Writer) result() Result {
	r := Result{ScanDir: w.scanDir, Relocated: w.relocated, Warnings: slices.Clone(w.warnings)}
	for name, data := range w.staged {
		if w.written[name] == sha256.Sum256(data) {
			r.Files = append(r.Files, filepath.Join(w.scanDir, name), filepath.Join(w.scanDir, name+CompanionSuffix))
		}
	}
	sort.Strings(r.Files)
	return r
}

// Cleanup removes temporary files the tool created and directories it
// created that are now empty, using only the ledger. Final reports are never
// removed. It is safe to call more than once and is meant to be registered as
// a shutdown hook.
func Cleanup(l *runtime.Ledger) {
	cleanupUnder(l, osOps{}, "")
}

// cleanupUnder cleans resources under root, or all resources when root is "".
// Only the tool's own temporary files and empty directories are touched, so a
// whole-volume scope is safe.
func cleanupUnder(l *runtime.Ledger, ops fileOps, root string) {
	res := l.Resources()
	in := func(r runtime.Resource) bool {
		return root == "" || within(root, r.Path)
	}
	for _, r := range res {
		if r.Kind == runtime.ResourceFile && r.State == runtime.StateTemporary && in(r) {
			removeIfOwned(l, ops, r)
		}
	}
	for i := len(res) - 1; i >= 0; i-- {
		r := res[i]
		if r.Kind != runtime.ResourceDirectory || r.State != runtime.StateCreated || !in(r) {
			continue
		}
		empty, err := ops.IsEmptyDir(r.Path)
		if err != nil || !empty {
			continue // kept: it holds reports, or it is gone, which removeIfOwned would also record
		}
		removeIfOwned(l, ops, r)
	}
}

// removeIfOwned removes r only if the object at r.Path is the exact object
// the tool created, judged against the identity captured from its own handle.
func removeIfOwned(l *runtime.Ledger, ops fileOps, r runtime.Resource) {
	if r.Identity == nil {
		l.Update(r.ID, runtime.StateNotRemoved, "identity was not captured at creation, so removal could not be attributed safely")
		return
	}
	cur, err := ops.Lstat(r.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		l.Update(r.ID, runtime.StateRemoved, "already absent")
		return
	case err != nil:
		l.Update(r.ID, runtime.StateRemoveFailed, err.Error())
		return
	case !sameObject(r, cur):
		l.Update(r.ID, runtime.StateNotRemoved, "the object now at this path is not the one Canaveral created; left untouched")
		return
	}
	if err := ops.Remove(r.Path); err != nil {
		l.Update(r.ID, runtime.StateRemoveFailed, err.Error())
		return
	}
	l.Update(r.ID, runtime.StateRemoved, "removed by cleanup")
}

// sameObject reports whether cur is the object recorded in r. File IDs alone
// are not enough: FAT32 and exFAT derive them from directory-entry position
// and Linux reuses inode numbers, so a different file at the same path can
// share an ID. Files must also still be regular files of the size the tool
// last wrote.
func sameObject(r runtime.Resource, cur os.FileInfo) bool {
	if !os.SameFile(r.Identity, cur) {
		return false
	}
	switch r.Kind {
	case runtime.ResourceDirectory:
		return cur.IsDir() && cur.Mode()&fs.ModeSymlink == 0
	case runtime.ResourceFile:
		return cur.Mode().IsRegular() && cur.Size() == r.Identity.Size()
	default:
		return false
	}
}

// within reports whether path is root or inside it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
