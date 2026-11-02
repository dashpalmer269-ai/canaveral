//go:build windows

package main

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestReleaseManifest loads the built executable as a data file and reads
// resource RT_MANIFEST #1 with the Windows resource API, proving the linker
// embedded the manifest where Windows looks for it. CI sets CANAVERAL_EXE to
// the release build.
func TestReleaseManifest(t *testing.T) {
	exe := os.Getenv("CANAVERAL_EXE")
	if exe == "" {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("CANAVERAL_EXE must be set in CI")
		}
		t.Skip("CANAVERAL_EXE not set")
	}
	want, err := os.ReadFile("../../cmd/canaveral/canaveral.manifest")
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.LoadLibraryEx(exe, 0, windows.LOAD_LIBRARY_AS_DATAFILE|windows.LOAD_LIBRARY_AS_IMAGE_RESOURCE)
	if err != nil {
		t.Fatalf("LoadLibraryEx(%s): %v", exe, err)
	}
	defer func() { _ = windows.FreeLibrary(h) }()
	res, err := windows.FindResource(h, windows.ResourceID(manifestID), windows.RT_MANIFEST)
	if err != nil {
		t.Fatalf("FindResource(RT_MANIFEST, 1): %v", err)
	}
	got, err := windows.LoadResourceData(h, res)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("embedded manifest (%d bytes) differs from canaveral.manifest (%d bytes)", len(got), len(want))
	}
}
