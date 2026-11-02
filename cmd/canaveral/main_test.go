package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

func usbVolume(root string, isSys bool) models.VolumeInfo {
	return models.VolumeInfo{
		Root: root, VolumeID: models.Known("vol:" + root), DriveType: models.DriveRemovable,
		BusType: models.Known(models.BusUSB), RemovableMedia: models.Known(true), ReadOnly: models.Known(false),
		FreeBytes: models.Known[uint64](1 << 33), IsSystem: models.Known(isSys),
	}
}

func snapshot(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, _ os.DirEntry, _ error) error { out = append(out, p); return nil })
	return out
}

func TestDiagOutputAcceptsAndWritesNothing(t *testing.T) {
	usb := t.TempDir()
	vols := fake.NewVolumes(usbVolume(usb, false))
	before := snapshot(t, usb)
	var out bytes.Buffer
	code := diagOutput(context.Background(), nil, vols, func() (string, error) { return filepath.Join(usb, "Canaveral.exe"), nil }, &out, &out)
	if code != 0 || !strings.Contains(out.String(), "Decision: ACCEPTED") || !strings.Contains(out.String(), filepath.Join(usb, "Canaveral_Reports")) {
		t.Fatalf("code %d output:\n%s", code, out.String())
	}
	if after := snapshot(t, usb); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("diag-output wrote something: %v", after)
	}
}

func TestDiagOutputRefusesSystemVolume(t *testing.T) {
	sys := t.TempDir()
	vols := fake.NewVolumes(usbVolume(sys, true))
	var out bytes.Buffer
	code := diagOutput(context.Background(), []string{"--output", filepath.Join(sys, "r")}, vols, func() (string, error) { return "", errors.New("unknown") }, &out, &out)
	if code != 1 || !strings.Contains(out.String(), "Decision: REFUSED") || !strings.Contains(out.String(), "system volume") {
		t.Fatalf("code %d output:\n%s", code, out.String())
	}
}

func TestDiagOutputWithoutInspector(t *testing.T) {
	var out bytes.Buffer
	if code := diagOutput(context.Background(), nil, nil, os.Executable, &out, &out); code != 1 || !strings.Contains(out.String(), "only implemented for Windows") {
		t.Fatalf("code %d output %s", code, out.String())
	}
}

func TestRunVersionAndDefault(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := run(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "Nothing was inspected") {
		t.Fatalf("default: code %d err %q", code, errOut.String())
	}
}
