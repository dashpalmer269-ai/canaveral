package integrity

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

const chunkSize = 1 << 20

// DefaultCacheEntries bounds the hash cache.
const DefaultCacheEntries = 100_000

// Cache maps file identity to digest. It is keyed by identity (volume serial,
// file index, size, last-write time), never by path alone, so a replaced file
// is always hashed again. It is safe for concurrent use and evicts the least
// recently used entry when full.
type Cache struct {
	mu      sync.Mutex
	max     int
	entries map[models.FileIdentity]*list.Element
	lru     *list.List
}

type cacheEntry struct {
	id     models.FileIdentity
	digest string
}

// NewCache returns a cache holding at most max entries (DefaultCacheEntries
// if max <= 0).
func NewCache(max int) *Cache {
	if max <= 0 {
		max = DefaultCacheEntries
	}
	return &Cache{max: max, entries: map[models.FileIdentity]*list.Element{}, lru: list.New()}
}

func (c *Cache) get(id models.FileIdentity) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[id]
	if !ok {
		return "", false
	}
	c.lru.MoveToFront(el)
	return el.Value.(cacheEntry).digest, true
}

func (c *Cache) put(id models.FileIdentity, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[id]; ok {
		c.lru.MoveToFront(el)
		return
	}
	c.entries[id] = c.lru.PushFront(cacheEntry{id: id, digest: digest})
	for c.lru.Len() > c.max {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.entries, old.Value.(cacheEntry).id)
	}
}

// Len returns the number of cached digests.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Hasher computes SHA-256 digests of files through a platform.FileSystem.
// It is safe for concurrent use.
type Hasher struct {
	fs    platform.FileSystem
	cache *Cache
}

// NewHasher returns a hasher. cache may be nil to disable caching.
func NewHasher(fs platform.FileSystem, cache *Cache) *Hasher {
	return &Hasher{fs: fs, cache: cache}
}

// Hash streams the file at path through SHA-256. A digest is reported only
// when the file provably did not change while it was read; otherwise the
// state is ChangedDuringInspection and no digest is given. A file that cannot
// be read is Unavailable. Nothing is ever guessed.
func (h *Hasher) Hash(ctx context.Context, path string) models.HashRecord {
	rec := models.HashRecord{Path: path}
	f, err := h.fs.Open(ctx, path)
	if err != nil {
		return unavailable(rec, "could not be opened: "+err.Error())
	}
	defer func() { _ = f.Close() }()

	before, idErr := f.Identity()
	if idErr != nil {
		rec.Identity = models.Unavailable[models.FileIdentity]("file identity could not be read: " + idErr.Error())
	} else {
		rec.Identity = models.Known(before)
		if h.cache != nil {
			if d, ok := h.cache.get(before); ok {
				rec.State, rec.SHA256, rec.Cached = models.HashComplete, models.Known(d), true
				return rec
			}
		}
	}

	sum := sha256.New()
	n, err := copyCtx(ctx, sum, f)
	rec.BytesRead = n
	if err != nil {
		return unavailable(rec, fmt.Sprintf("reading failed after %d bytes: %v", n, err))
	}

	if idErr != nil {
		// Without an identity, change during reading cannot be detected. The
		// digest is of the bytes actually read; it is reported, but never
		// cached, and the limitation is stated.
		rec.State = models.HashComplete
		rec.SHA256 = models.Known(hex.EncodeToString(sum.Sum(nil)))
		rec.Reason = "file identity unavailable, so a change during reading could not be ruled out"
		return rec
	}
	if why := h.changed(ctx, path, f, before, n); why != "" {
		rec.State = models.HashChanged
		rec.SHA256 = models.Unavailable[string]("the file changed during inspection: " + why)
		rec.Reason = why
		return rec
	}

	digest := hex.EncodeToString(sum.Sum(nil))
	rec.State, rec.SHA256 = models.HashComplete, models.Known(digest)
	if h.cache != nil {
		h.cache.put(before, digest)
	}
	return rec
}

// changed explains why the file cannot be shown to be unchanged, or returns "".
func (h *Hasher) changed(ctx context.Context, path string, f platform.File, before models.FileIdentity, n uint64) string {
	after, err := f.Identity()
	if err != nil {
		return "its identity could not be re-read after hashing: " + err.Error()
	}
	if diff := identityDiff(before, after); diff != "" {
		return "while it was being read, " + diff
	}
	if n != before.Size {
		return fmt.Sprintf("%d bytes were read but the file is %d bytes", n, before.Size)
	}
	again, err := h.fs.Open(ctx, path)
	if err != nil {
		return "the path no longer opens after hashing (deleted or renamed during inspection): " + err.Error()
	}
	defer func() { _ = again.Close() }()
	now, err := again.Identity()
	if err != nil {
		return "the path's identity could not be re-read after hashing: " + err.Error()
	}
	if diff := identityDiff(before, now); diff != "" {
		return "the path now refers to a different file: " + diff
	}
	return ""
}

func identityDiff(a, b models.FileIdentity) string {
	var parts []string
	if a.VolumeSerial != b.VolumeSerial || a.FileIndex != b.FileIndex {
		parts = append(parts, fmt.Sprintf("file ID %08x:%016x became %08x:%016x", a.VolumeSerial, a.FileIndex, b.VolumeSerial, b.FileIndex))
	}
	if a.Size != b.Size {
		parts = append(parts, fmt.Sprintf("size %d became %d", a.Size, b.Size))
	}
	if a.ModTime != b.ModTime {
		parts = append(parts, "last-write time changed")
	}
	return strings.Join(parts, ", ")
}

func copyCtx(ctx context.Context, w io.Writer, r io.Reader) (uint64, error) {
	buf := make([]byte, chunkSize)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n]) // hash.Hash writes never fail
			total += uint64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func unavailable(rec models.HashRecord, reason string) models.HashRecord {
	rec.State = models.HashUnavailable
	rec.SHA256 = models.Unavailable[string](reason)
	rec.Reason = reason
	return rec
}
