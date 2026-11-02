package output

import (
	"errors"
	"io"
	"os"
)

// fileOps is every filesystem operation the writer performs. Tests replace
// it to simulate a device that disappears mid-write.
type fileOps interface {
	Mkdir(path string) error
	// Create creates a new file exclusively; it never truncates an existing one.
	Create(path string) (writableFile, error)
	Rename(oldpath, newpath string) error
	Remove(path string) error
	ReadFile(path string) ([]byte, error)
	Lstat(path string) (os.FileInfo, error)
	IsEmptyDir(path string) (bool, error)
}

type writableFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
	Stat() (os.FileInfo, error)
}

type osOps struct{}

func (osOps) Mkdir(path string) error { return os.Mkdir(path, 0o700) }

func (osOps) Create(path string) (writableFile, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func (osOps) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }
func (osOps) Remove(path string) error             { return os.Remove(path) }
func (osOps) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (osOps) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func (osOps) IsEmptyDir(path string) (bool, error) {
	d, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = d.Close() }()
	_, err = d.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}
