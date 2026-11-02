//go:build windows

package windows

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

func TestSystemVolumeIsDetected(t *testing.T) {
	windir, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{windir, filepath.Join(windir, "System32"), filepath.Join(windir[:3], "canaveral-does-not-exist", "x")} {
		info, err := VolumeInspector{}.Volume(context.Background(), p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		sys, ok := info.IsSystem.Get()
		if !ok || !sys {
			t.Errorf("%s: IsSystem = %v (%s), want known true", p, sys, info.IsSystem.Reason())
		}
		if info.DriveType != models.DriveFixed {
			t.Errorf("%s: DriveType = %s", p, info.DriveType)
		}
		if id, ok := info.VolumeID.Get(); !ok || !strings.HasPrefix(id, `\\?\Volume{`) {
			t.Errorf("%s: VolumeID = %q (%s)", p, id, info.VolumeID.Reason())
		}
		if free, ok := info.FreeBytes.Get(); !ok || free == 0 {
			t.Errorf("%s: FreeBytes = %d (%s)", p, free, info.FreeBytes.Reason())
		}
		if !info.ReadOnly.IsKnown() {
			t.Errorf("%s: ReadOnly unknown: %s", p, info.ReadOnly.Reason())
		}
		t.Logf("%s -> root=%s bus=%v(%s) removable=%v(%s)", p, info.Root,
			must(info.BusType.Get()), info.BusType.Reason(), must(info.RemovableMedia.Get()), info.RemovableMedia.Reason())
	}
}

func TestMissingDriveLetterIsNotFound(t *testing.T) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}
	for l := 'Z'; l >= 'D'; l-- {
		if mask&(1<<(l-'A')) == 0 {
			_, err := VolumeInspector{}.Volume(context.Background(), string(l)+`:\Canaveral_Reports`)
			if !errors.Is(err, platform.ErrNotFound) {
				t.Fatalf("unused drive %c: err = %v, want ErrNotFound", l, err)
			}
			return
		}
	}
	t.Skip("every drive letter D-Z is in use")
}

func TestParseDeviceDescriptor(t *testing.T) {
	b := make([]byte, 40)
	b[10] = 1
	b[28] = 7 // BusTypeUsb
	bus, removable, err := parseDeviceDescriptor(b)
	if err != nil || bus != models.BusUSB || !removable {
		t.Fatalf("bus=%s removable=%v err=%v", bus, removable, err)
	}
	if _, _, err := parseDeviceDescriptor(b[:20]); err == nil {
		t.Fatal("short descriptor accepted")
	}
	if busType(99) != models.BusUnknown {
		t.Fatal("unknown bus code not mapped to Unknown")
	}
}

func must[T any](v T, _ bool) T { return v }
