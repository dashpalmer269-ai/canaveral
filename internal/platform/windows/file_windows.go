//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.FileSystem = FileSystem{}

// readAccess is the only access ever requested for investigated files.
const readAccess = windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

// shareAll lets every other process keep reading, writing and deleting the
// file while the tool has it open, so investigated files are never locked
// (CLAUDE.md 1.2).
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// FileSystem opens files read-only with minimal access rights.
type FileSystem struct{}

// Open opens path for reading.
func (FileSystem) Open(ctx context.Context, path string) (platform.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := openRead(path)
	if err != nil {
		return nil, err
	}
	return &file{h: h, path: path}, nil
}

// openRead opens an existing file with read access only. Directories are
// refused (they cannot be opened without FILE_FLAG_BACKUP_SEMANTICS).
func openRead(path string) (windows.Handle, error) {
	p16, err := windows.UTF16PtrFromString(extendedPath(path))
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	h, err := windows.CreateFile(p16, readAccess, shareAll, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, mapErr(err))
	}
	return h, nil
}

// extendedPath adds the \\?\ prefix to an absolute path so paths longer than
// MAX_PATH open. Relative or already-prefixed paths are returned unchanged.
func extendedPath(path string) string {
	switch {
	case strings.HasPrefix(path, `\\?\`), strings.HasPrefix(path, `\\.\`):
		return path
	case strings.HasPrefix(path, `\\`):
		return `\\?\UNC\` + strings.TrimPrefix(filepath.Clean(path), `\\`)
	case filepath.IsAbs(path):
		return `\\?\` + filepath.Clean(path)
	default:
		return path
	}
}

// ReadDir lists a directory. Listing only reads directory metadata.
func (FileSystem) ReadDir(ctx context.Context, path string) ([]models.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", path, mapErr(err))
	}
	out := make([]models.DirEntry, 0, len(entries))
	for _, e := range entries {
		d := models.DirEntry{Name: e.Name(), IsDir: e.IsDir(), Reparse: e.Type()&(os.ModeSymlink|os.ModeIrregular) != 0}
		if info, err := e.Info(); err == nil {
			d.Size = uint64(max(info.Size(), 0))
			ft := windows.NsecToFiletime(info.ModTime().UnixNano())
			d.ModTime = models.FileTime(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))
		}
		out = append(out, d)
	}
	return out, nil
}

type file struct {
	h    windows.Handle
	path string
}

func (f *file) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var n uint32
	err := windows.ReadFile(f.h, p, &n, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return int(n), io.EOF
		}
		return int(n), fmt.Errorf("read %s: %w", f.path, err)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

// Identity reads the identity of the open handle, so it always describes
// the bytes being read, even if the path is renamed or replaced meanwhile.
func (f *file) Identity() (models.FileIdentity, error) {
	return handleIdentity(f.h)
}

func (f *file) Close() error { return windows.CloseHandle(f.h) }

func handleIdentity(h windows.Handle) (models.FileIdentity, error) {
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bhfi); err != nil {
		return models.FileIdentity{}, fmt.Errorf("GetFileInformationByHandle: %w", err)
	}
	return models.FileIdentity{
		VolumeSerial: bhfi.VolumeSerialNumber,
		FileIndex:    uint64(bhfi.FileIndexHigh)<<32 | uint64(bhfi.FileIndexLow),
		Size:         uint64(bhfi.FileSizeHigh)<<32 | uint64(bhfi.FileSizeLow),
		ModTime:      models.FileTime(uint64(bhfi.LastWriteTime.HighDateTime)<<32 | uint64(bhfi.LastWriteTime.LowDateTime)),
	}, nil
}
