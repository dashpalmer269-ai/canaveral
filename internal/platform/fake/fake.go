package fake

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

// Compile-time interface checks.
var (
	_ platform.Clock             = (*Clock)(nil)
	_ platform.ProcessSource     = (*ProcessSource)(nil)
	_ platform.PrivilegeSource   = (*Privileges)(nil)
	_ platform.SocketSource      = (*SocketSource)(nil)
	_ platform.FileSystem        = (*FileSystem)(nil)
	_ platform.SignatureVerifier = (*SignatureVerifier)(nil)
	_ platform.RegistryReader    = (*Registry)(nil)
	_ platform.EventLogReader    = (*EventLog)(nil)
)

// Clock is a manually advanced clock. It is safe for concurrent use.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock set to start (converted to UTC).
func NewClock(start time.Time) *Clock {
	return &Clock{now: start.UTC()}
}

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ProcessSource returns fixed process records, or Err if set.
type ProcessSource struct {
	Records []models.ProcessRecord
	Err     error
}

// Processes returns a copy of the configured records.
func (p *ProcessSource) Processes(ctx context.Context) ([]models.ProcessRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.Err != nil {
		return nil, p.Err
	}
	return slices.Clone(p.Records), nil
}

// Privileges returns a fixed elevation result, or Err if set.
type Privileges struct {
	Info models.ElevationInfo
	Err  error
}

// Elevation returns the configured info.
func (p *Privileges) Elevation(ctx context.Context) (models.ElevationInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.ElevationInfo{}, err
	}
	return p.Info, p.Err
}

// ProcessSequence returns a different snapshot on each call, for testing
// races between snapshots. After the last snapshot it keeps returning the
// last one.
type ProcessSequence struct {
	mu        sync.Mutex
	Snapshots [][]models.ProcessRecord
	calls     int
}

// Processes returns the next snapshot.
func (p *ProcessSequence) Processes(ctx context.Context) ([]models.ProcessRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.Snapshots) == 0 {
		return nil, fmt.Errorf("fake: no process snapshots: %w", platform.ErrNotFound)
	}
	i := min(p.calls, len(p.Snapshots)-1)
	p.calls++
	return slices.Clone(p.Snapshots[i]), nil
}

// SocketSource returns fixed records per table. A table with neither records
// nor an error configured returns an error: an unconfigured fixture is never
// reported as an empty table.
type SocketSource struct {
	Tables map[models.SocketTable][]models.SocketRecord
	Errs   map[models.SocketTable]error
}

// Sockets returns a copy of the records for table.
func (s *SocketSource) Sockets(ctx context.Context, table models.SocketTable) ([]models.SocketRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.Errs[table]; err != nil {
		return nil, err
	}
	recs, ok := s.Tables[table]
	if !ok {
		return nil, fmt.Errorf("fake: no fixture for socket table %s: %w", table, platform.ErrNotFound)
	}
	return slices.Clone(recs), nil
}

// FileFixture is one fake file.
type FileFixture struct {
	Content     []byte
	Identity    models.FileIdentity
	IdentityErr error
}

// FileSystem is an in-memory read-only file system. Paths match exactly.
type FileSystem struct {
	Files map[string]FileFixture
	Dirs  map[string][]models.DirEntry
	Errs  map[string]error
}

// Open returns a reader over the fixture content for path.
func (f *FileSystem) Open(ctx context.Context, path string) (platform.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.Errs[path]; err != nil {
		return nil, err
	}
	fx, ok := f.Files[path]
	if !ok {
		return nil, fmt.Errorf("fake: open %s: %w", path, platform.ErrNotFound)
	}
	return &file{r: bytes.NewReader(fx.Content), id: fx.Identity, idErr: fx.IdentityErr}, nil
}

// ReadDir returns a copy of the fixture entries for path.
func (f *FileSystem) ReadDir(ctx context.Context, path string) ([]models.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.Errs[path]; err != nil {
		return nil, err
	}
	entries, ok := f.Dirs[path]
	if !ok {
		return nil, fmt.Errorf("fake: readdir %s: %w", path, platform.ErrNotFound)
	}
	return slices.Clone(entries), nil
}

type file struct {
	r      *bytes.Reader
	id     models.FileIdentity
	idErr  error
	closed bool
}

func (f *file) Read(p []byte) (int, error) {
	if f.closed {
		return 0, fmt.Errorf("fake: read on closed file")
	}
	return f.r.Read(p)
}

func (f *file) Identity() (models.FileIdentity, error) {
	if f.idErr != nil {
		return models.FileIdentity{}, f.idErr
	}
	return f.id, nil
}

func (f *file) Close() error {
	f.closed = true
	return nil
}

// SignatureVerifier returns fixed results per path. Paths without a fixture
// verify as Unavailable, never as Valid or Unsigned.
type SignatureVerifier struct {
	Results map[string]models.SignatureRecord
}

// Verify returns the fixture result for path.
func (s *SignatureVerifier) Verify(ctx context.Context, path string) models.SignatureRecord {
	if err := ctx.Err(); err != nil {
		return models.SignatureRecord{State: models.SignatureUnavailable, Source: models.SignatureSourceNone, Detail: err.Error()}
	}
	if r, ok := s.Results[path]; ok {
		return r
	}
	return models.SignatureRecord{
		State:  models.SignatureUnavailable,
		Source: models.SignatureSourceNone,
		Detail: "fake: no fixture for " + path,
	}
}

// Registry is an in-memory registry. Key paths match case-insensitively, as
// on Windows. Build it with NewRegistry.
type Registry struct {
	keys map[string]models.RegistryKey
	errs map[string]error
}

// NewRegistry returns a registry containing keys.
func NewRegistry(keys ...models.RegistryKey) *Registry {
	r := &Registry{keys: map[string]models.RegistryKey{}, errs: map[string]error{}}
	for _, k := range keys {
		r.keys[regKey(k.Hive, k.Path)] = k
	}
	return r
}

// FailKey makes ReadKey for hive\path return err.
func (r *Registry) FailKey(hive models.RegistryHive, path string, err error) {
	r.errs[regKey(hive, path)] = err
}

// ReadKey returns a copy of the fixture key.
func (r *Registry) ReadKey(ctx context.Context, hive models.RegistryHive, path string) (models.RegistryKey, error) {
	if err := ctx.Err(); err != nil {
		return models.RegistryKey{}, err
	}
	k := regKey(hive, path)
	if err := r.errs[k]; err != nil {
		return models.RegistryKey{}, err
	}
	key, ok := r.keys[k]
	if !ok {
		return models.RegistryKey{}, fmt.Errorf("fake: registry key %s\\%s: %w", hive, path, platform.ErrNotFound)
	}
	key.SubKeys = slices.Clone(key.SubKeys)
	key.Values = slices.Clone(key.Values)
	for i := range key.Values {
		key.Values[i].Data = slices.Clone(key.Values[i].Data)
	}
	return key, nil
}

func regKey(hive models.RegistryHive, path string) string {
	return string(hive) + `\` + strings.ToLower(strings.Trim(path, `\`))
}

// EventLog is an in-memory event log.
type EventLog struct {
	Channels map[string]models.ChannelInfo
	Records  map[string][]models.EventRecord
	Errs     map[string]error
}

// Channel returns the fixture channel info.
func (e *EventLog) Channel(ctx context.Context, name string) (models.ChannelInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.ChannelInfo{}, err
	}
	if err := e.Errs[name]; err != nil {
		return models.ChannelInfo{}, err
	}
	info, ok := e.Channels[name]
	if !ok {
		return models.ChannelInfo{}, fmt.Errorf("fake: channel %s: %w", name, platform.ErrNotFound)
	}
	return info, nil
}

// Query filters the fixture records by event ID and time window, in fixture
// order, and caps the result at q.MaxEvents when it is positive.
func (e *EventLog) Query(ctx context.Context, q models.EventQuery) ([]models.EventRecord, bool, error) {
	if _, err := e.Channel(ctx, q.Channel); err != nil {
		return nil, false, err
	}
	var out []models.EventRecord
	for _, r := range e.Records[q.Channel] {
		if len(q.EventIDs) > 0 && !slices.Contains(q.EventIDs, r.EventID) {
			continue
		}
		if !q.Since.IsZero() && r.TimeCreated.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && r.TimeCreated.After(q.Until) {
			continue
		}
		if q.MaxEvents > 0 && len(out) == q.MaxEvents {
			return out, true, nil
		}
		out = append(out, r)
	}
	return out, false, nil
}
