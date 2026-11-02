//go:build windows

package windows

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

func TestFileReadsExactBytesAndIdentity(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	f, err := FileSystem{}.Open(ctx, exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read %d bytes (err %v), want %d", len(got), err, len(want))
	}
	id1, err := f.Identity()
	if err != nil || id1.Size != uint64(len(want)) || id1.FileIndex == 0 || id1.ModTime == 0 {
		t.Fatalf("identity %+v err %v", id1, err)
	}
	g, err := FileSystem{}.Open(ctx, exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if id2, _ := g.Identity(); id2 != id1 {
		t.Fatalf("two handles to one file disagree: %+v vs %+v", id1, id2)
	}
}

// Investigated files must never be locked: other processes can still write,
// rename and delete a file while the tool holds it open, and the open
// handle's identity reflects their changes.
func TestOpenNeverLocksTheFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(p, []byte("first version"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := FileSystem{}.Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	before, _ := f.Identity()

	w, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("another writer was blocked by the tool's handle: %v", err)
	}
	if _, err := w.WriteString(" plus more"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	after, _ := f.Identity()
	if after.Size == before.Size {
		t.Fatalf("handle identity did not reflect the append: %+v -> %+v", before, after)
	}
	moved := filepath.Join(dir, "moved.bin")
	if err := os.Rename(p, moved); err != nil {
		t.Fatalf("rename blocked by the tool's handle: %v", err)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatalf("delete blocked by the tool's handle: %v", err)
	}
}

func TestOpenLongPath(t *testing.T) {
	dir := t.TempDir()
	for range 6 {
		dir = filepath.Join(dir, strings.Repeat("d", 50))
	}
	if err := os.MkdirAll(`\\?\`+dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "long.bin")
	if len(p) <= 260 {
		t.Fatalf("path only %d characters", len(p))
	}
	if err := os.WriteFile(`\\?\`+p, []byte("deep"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := FileSystem{}.Open(ctx, p)
	if err != nil {
		t.Fatalf("long path (%d chars): %v", len(p), err)
	}
	defer func() { _ = f.Close() }()
	if b, _ := io.ReadAll(f); string(b) != "deep" {
		t.Fatalf("read %q", b)
	}
}

func TestOpenFailures(t *testing.T) {
	if _, err := (FileSystem{}).Open(ctx, `C:\canaveral-no-such-file.exe`); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := (FileSystem{}).Open(ctx, os.Getenv("SystemRoot")); err == nil {
		t.Error("a directory opened as a file")
	}
	// The SAM hive is held open exclusively by the system.
	sam := filepath.Join(os.Getenv("SystemRoot"), "System32", "config", "SAM")
	_, err := FileSystem{}.Open(ctx, sam)
	if err == nil {
		t.Fatal("the locked SAM hive opened")
	}
	t.Logf("SAM: %v", err)
}

func TestReadDir(t *testing.T) {
	entries, err := FileSystem{}.ReadDir(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32"))
	if err != nil || len(entries) < 100 {
		t.Fatalf("%d entries, err %v", len(entries), err)
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name, "svchost.exe") {
			if e.IsDir || e.Size == 0 || e.ModTime == 0 {
				t.Fatalf("svchost.exe entry %+v", e)
			}
			return
		}
	}
	t.Fatal("svchost.exe not listed")
}

func TestExtendedPath(t *testing.T) {
	cases := map[string]string{
		`C:\Windows\System32\svchost.exe`: `\\?\C:\Windows\System32\svchost.exe`,
		`C:\a\..\b\x.exe`:                 `\\?\C:\b\x.exe`,
		`\\server\share\x.exe`:            `\\?\UNC\server\share\x.exe`,
		`\\?\C:\already`:                  `\\?\C:\already`,
		`relative\x.exe`:                  `relative\x.exe`,
	}
	for in, want := range cases {
		if got := extendedPath(in); got != want {
			t.Errorf("extendedPath(%q) = %q, want %q", in, got, want)
		}
	}
}
