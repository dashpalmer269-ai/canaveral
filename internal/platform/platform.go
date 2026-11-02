package platform

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// Sentinel errors. Implementations wrap them so collectors can turn a failure
// into an accurate coverage record instead of a guessed value.
var (
	ErrNotFound     = errors.New("not found")
	ErrAccessDenied = errors.New("access denied")
	ErrUnsupported  = errors.New("not supported on this platform")
)

// Clock is the single time source for observations (CLAUDE.md 4.1).
// Implementations return UTC.
type Clock interface {
	Now() time.Time
}

// SystemClock is the real clock, in UTC.
type SystemClock struct{}

// Now returns the current time in UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ProcessSource enumerates running processes. Fields that cannot be read for a
// process are returned as models.Unavailable, never guessed.
type ProcessSource interface {
	Processes(ctx context.Context) ([]models.ProcessRecord, error)
}

// PrivilegeSource describes the tool's own privileges.
type PrivilegeSource interface {
	Elevation(ctx context.Context) (models.ElevationInfo, error)
}

// SocketSource reads one socket table at a time so each table can fail and be
// reported separately.
type SocketSource interface {
	Sockets(ctx context.Context, table models.SocketTable) ([]models.SocketRecord, error)
}

// FileSystem opens files read-only. On Windows, files are opened with
// FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE and minimal access rights
// so investigated files are never locked or modified (CLAUDE.md 1.2).
type FileSystem interface {
	Open(ctx context.Context, path string) (File, error)
	ReadDir(ctx context.Context, path string) ([]models.DirEntry, error)
}

// File is an open, read-only file. Identity is taken from the same handle as
// the reads, so a hash and its identity describe the same file.
type File interface {
	io.Reader
	Identity() (models.FileIdentity, error)
	Close() error
}

// SignatureVerifier checks a file's signature offline and without writes
// (CLAUDE.md A1, A2). A failure is reported as models.SignatureUnavailable in
// the record rather than as an error.
type SignatureVerifier interface {
	Verify(ctx context.Context, path string) models.SignatureRecord
}

// RegistryReader reads registry keys. It has no write or hive-loading methods
// by design (CLAUDE.md A3).
type RegistryReader interface {
	ReadKey(ctx context.Context, hive models.RegistryHive, path string) (models.RegistryKey, error)
}

// VolumeInspector describes the volume that holds a path. The path does not
// have to exist yet, but its volume must.
type VolumeInspector interface {
	Volume(ctx context.Context, path string) (models.VolumeInfo, error)
}

// EventLogReader reads event log channels without changing their settings.
type EventLogReader interface {
	Channel(ctx context.Context, name string) (models.ChannelInfo, error)
	// Query returns at most q.MaxEvents records. truncated reports whether more
	// matching records existed.
	Query(ctx context.Context, q models.EventQuery) (records []models.EventRecord, truncated bool, err error)
}
