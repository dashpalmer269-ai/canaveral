//go:build windows

package integrity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/windows"
)

// appendOnFirstRead wraps the real file system: the first read of each file
// lets another writer append to it, as if the file were modified mid-hash.
type appendOnFirstRead struct{ windows.FileSystem }

type appendingFile struct {
	platform.File
	path string
	done bool
}

func (a appendOnFirstRead) Open(ctx context.Context, path string) (platform.File, error) {
	f, err := a.FileSystem.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	return &appendingFile{File: f, path: path}, nil
}

func (f *appendingFile) Read(p []byte) (int, error) {
	if !f.done {
		f.done = true
		w, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			_, _ = w.WriteString("appended by another writer")
			_ = w.Close()
		}
	}
	return f.File.Read(p)
}

func TestRealHashMatchesOSDigest(t *testing.T) {
	exe, _ := os.Executable()
	rec := NewHasher(windows.FileSystem{}, NewCache(0)).Hash(context.Background(), exe)
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := rec.SHA256.Get(); rec.State != models.HashComplete || !ok || got != digest(b) {
		t.Fatalf("record %+v", rec)
	}
}

// Acceptance (M4) on real NTFS: a file modified mid-hash is reported as
// ChangedDuringInspection with no digest.
func TestRealModifiedMidHash(t *testing.T) {
	p := filepath.Join(t.TempDir(), "changing.bin")
	if err := os.WriteFile(p, make([]byte, 3*chunkSize), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := NewHasher(appendOnFirstRead{}, NewCache(0)).Hash(context.Background(), p)
	if rec.State != models.HashChanged || rec.SHA256.IsKnown() || !strings.Contains(rec.Reason, "size") {
		t.Fatalf("record %+v", rec)
	}
	t.Logf("reason: %s", rec.Reason)
}

func TestRealLockedFileIsUnavailable(t *testing.T) {
	sam := filepath.Join(os.Getenv("SystemRoot"), "System32", "config", "SAM")
	rec := NewHasher(windows.FileSystem{}, nil).Hash(context.Background(), sam)
	if rec.State != models.HashUnavailable || rec.SHA256.IsKnown() {
		t.Fatalf("record %+v", rec)
	}
	t.Logf("SAM: %s", rec.Reason)
}
