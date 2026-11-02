package integrity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

var ctx = context.Background()

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func id(index, size uint64) models.FileIdentity {
	return models.FileIdentity{VolumeSerial: 0xABCD, FileIndex: index, Size: size, ModTime: 1000}
}

// scriptFS serves files whose behavior can change per open and per read.
type scriptFS struct {
	mu    sync.Mutex
	files map[string]*scripted
	opens atomic.Int64
	reads atomic.Int64
}

type scripted struct {
	content []byte
	ids     []models.FileIdentity // identity per Identity() call on one handle; last repeats
	idErr   error
	readErr error         // returned after the first chunk
	onRead  func()        // called on the first Read of each handle
	reopen  []openOutcome // outcome of later opens (after the first); last repeats
}

type openOutcome struct {
	id  models.FileIdentity
	err error
}

func (s *scriptFS) Open(_ context.Context, path string) (platform.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.opens.Add(1)
	f, ok := s.files[path]
	if !ok {
		return nil, fmt.Errorf("open %s: %w", path, platform.ErrNotFound)
	}
	h := &handle{fs: s, f: f, r: bytes.NewReader(f.content), ids: f.ids}
	if n > 1 && len(f.reopen) > 0 {
		o := f.reopen[0]
		if len(f.reopen) > 1 {
			f.reopen = f.reopen[1:]
		}
		if o.err != nil {
			return nil, o.err
		}
		h.ids = []models.FileIdentity{o.id}
	}
	return h, nil
}

func (s *scriptFS) ReadDir(context.Context, string) ([]models.DirEntry, error) {
	return nil, platform.ErrUnsupported
}

type handle struct {
	fs    *scriptFS
	f     *scripted
	r     *bytes.Reader
	ids   []models.FileIdentity
	calls int
	read  bool
}

func (h *handle) Read(p []byte) (int, error) {
	h.fs.reads.Add(1)
	if !h.read {
		h.read = true
		if h.f.onRead != nil {
			h.f.onRead()
		}
	} else if h.f.readErr != nil {
		return 0, h.f.readErr
	}
	return h.r.Read(p)
}

func (h *handle) Identity() (models.FileIdentity, error) {
	if h.f.idErr != nil {
		return models.FileIdentity{}, h.f.idErr
	}
	i := min(h.calls, len(h.ids)-1)
	h.calls++
	return h.ids[i], nil
}

func (h *handle) Close() error { return nil }

func stable(content []byte, index uint64) *scripted {
	return &scripted{content: content, ids: []models.FileIdentity{id(index, uint64(len(content)))}}
}

func TestHashMatchesSHA256(t *testing.T) {
	content := bytes.Repeat([]byte("canaveral "), 350_000) // 3.5 MB, several chunks
	fs := &fake.FileSystem{Files: map[string]fake.FileFixture{
		`C:\Windows\System32\svchost.exe`: {Content: content, Identity: id(7, uint64(len(content)))},
	}}
	rec := NewHasher(fs, nil).Hash(ctx, `C:\Windows\System32\svchost.exe`)
	got, ok := rec.SHA256.Get()
	if rec.State != models.HashComplete || !ok || got != digest(content) || rec.BytesRead != uint64(len(content)) || rec.Cached {
		t.Fatalf("record %+v", rec)
	}
	if i, ok := rec.Identity.Get(); !ok || i.FileIndex != 7 {
		t.Fatalf("identity %+v", rec.Identity)
	}
}

func TestEmptyFile(t *testing.T) {
	fs := &scriptFS{files: map[string]*scripted{"e": stable(nil, 1)}}
	rec := NewHasher(fs, nil).Hash(ctx, "e")
	if got, _ := rec.SHA256.Get(); rec.State != models.HashComplete || got != digest(nil) {
		t.Fatalf("%+v", rec)
	}
}

func TestCacheIsKeyedByIdentityNotPath(t *testing.T) {
	content := []byte("same bytes")
	fs := &scriptFS{files: map[string]*scripted{
		"a":         stable(content, 1),
		"hardlink":  stable(content, 1), // same file reached by another path
		"replaced":  stable([]byte("different"), 2),
		"same-path": stable(content, 1),
	}}
	cache := NewCache(0)
	h := NewHasher(fs, cache)

	first := h.Hash(ctx, "a")
	readsAfterFirst := fs.reads.Load()
	second := h.Hash(ctx, "hardlink")
	if !second.Cached || fs.reads.Load() != readsAfterFirst || second.SHA256 != first.SHA256 {
		t.Fatalf("same identity via another path was not served from cache: %+v", second)
	}

	// A different file at the same path must be hashed again.
	fs.files["a"] = stable([]byte("new content at the old path"), 3)
	third := h.Hash(ctx, "a")
	if third.Cached || third.SHA256 == first.SHA256 {
		t.Fatalf("replaced file served a stale digest: %+v", third)
	}
	if cache.Len() != 2 {
		t.Fatalf("cache holds %d entries", cache.Len())
	}
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := NewCache(2)
	c.put(id(1, 1), "one")
	c.put(id(2, 1), "two")
	c.get(id(1, 1))
	c.put(id(3, 1), "three")
	if _, ok := c.get(id(2, 1)); ok {
		t.Fatal("least recently used entry survived")
	}
	if _, ok := c.get(id(1, 1)); !ok {
		t.Fatal("recently used entry evicted")
	}
	c.put(id(1, 1), "one")
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
}

// Acceptance (M4): a file modified mid-hash is ChangedDuringInspection, and
// no digest is reported for it.
func TestChangedDuringInspection(t *testing.T) {
	content := []byte("original executable bytes")
	n := uint64(len(content))
	cases := map[string]struct {
		file *scripted
		want string
	}{
		"size changed while reading": {
			&scripted{content: content, ids: []models.FileIdentity{id(1, n), id(1, n+100)}}, "size",
		},
		"last-write time changed while reading": {
			&scripted{content: content, ids: []models.FileIdentity{id(1, n), {VolumeSerial: 0xABCD, FileIndex: 1, Size: n, ModTime: 2000}}},
			"last-write time changed",
		},
		"fewer bytes than the size": {
			&scripted{content: content[:10], ids: []models.FileIdentity{id(1, n)}}, "10 bytes were read",
		},
		"path replaced by another file": {
			&scripted{content: content, ids: []models.FileIdentity{id(1, n)}, reopen: []openOutcome{{id: id(99, n)}}},
			"path now refers to a different file",
		},
		"deleted during inspection": {
			&scripted{content: content, ids: []models.FileIdentity{id(1, n)}, reopen: []openOutcome{{err: platform.ErrNotFound}}},
			"no longer opens",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fs := &scriptFS{files: map[string]*scripted{"f": c.file}}
			cache := NewCache(0)
			rec := NewHasher(fs, cache).Hash(ctx, "f")
			if rec.State != models.HashChanged || rec.SHA256.IsKnown() || !strings.Contains(rec.Reason, c.want) {
				t.Fatalf("record %+v", rec)
			}
			if !strings.Contains(rec.SHA256.Reason(), "changed during inspection") {
				t.Fatalf("digest reason %q", rec.SHA256.Reason())
			}
			if cache.Len() != 0 {
				t.Fatal("a changed file's digest was cached")
			}
		})
	}
}

func TestUnavailable(t *testing.T) {
	fs := &scriptFS{files: map[string]*scripted{
		"read-fails": {content: bytes.Repeat([]byte{1}, 3*chunkSize), ids: []models.FileIdentity{id(1, 3*chunkSize)}, readErr: errors.New("The device is not ready.")},
	}}
	h := NewHasher(fs, NewCache(0))

	missing := h.Hash(ctx, "missing")
	if missing.State != models.HashUnavailable || missing.SHA256.IsKnown() || !strings.Contains(missing.Reason, "not found") {
		t.Fatalf("missing: %+v", missing)
	}
	rf := h.Hash(ctx, "read-fails")
	if rf.State != models.HashUnavailable || rf.SHA256.IsKnown() || !strings.Contains(rf.Reason, "device is not ready") || rf.BytesRead == 0 {
		t.Fatalf("read failure: %+v", rf)
	}

	denied := NewHasher(&fake.FileSystem{Errs: map[string]error{`C:\Windows\System32\config\SAM`: fmt.Errorf("sharing violation: %w", platform.ErrAccessDenied)}}, nil)
	if r := denied.Hash(ctx, `C:\Windows\System32\config\SAM`); r.State != models.HashUnavailable || !strings.Contains(r.Reason, "sharing violation") {
		t.Fatalf("locked file: %+v", r)
	}
}

func TestUnknownIdentityIsHashedButNotCachedOrTrusted(t *testing.T) {
	content := []byte("bytes")
	fs := &scriptFS{files: map[string]*scripted{"f": {content: content, idErr: errors.New("GetFileInformationByHandle failed")}}}
	cache := NewCache(0)
	rec := NewHasher(fs, cache).Hash(ctx, "f")
	if got, _ := rec.SHA256.Get(); rec.State != models.HashComplete || got != digest(content) || rec.Identity.IsKnown() ||
		!strings.Contains(rec.Reason, "could not be ruled out") || cache.Len() != 0 {
		t.Fatalf("%+v (cache %d)", rec, cache.Len())
	}
}

func TestCanceled(t *testing.T) {
	c, cancel := context.WithCancel(ctx)
	cancel()
	fs := &scriptFS{files: map[string]*scripted{"f": stable([]byte("x"), 1)}}
	if r := NewHasher(fs, nil).Hash(c, "f"); r.State != models.HashUnavailable || !strings.Contains(r.Reason, "canceled") {
		t.Fatalf("%+v", r)
	}
}

func TestConcurrentHashing(t *testing.T) {
	files := map[string]*scripted{}
	for i := range 20 {
		files[fmt.Sprint(i)] = stable([]byte(fmt.Sprintf("file %d", i)), uint64(i+1))
	}
	fs := &scriptFS{files: files}
	h := NewHasher(fs, NewCache(5))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				p := fmt.Sprint((i + g) % 20)
				if r := h.Hash(ctx, p); r.State != models.HashComplete {
					t.Errorf("%s: %+v", p, r)
				}
			}
		}()
	}
	wg.Wait()
}
