package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

var ctx = context.Background()

const gib = 1 << 30

type volOpt func(*models.VolumeInfo)

func vol(root string, dt models.DriveType, bus models.BusType, opts ...volOpt) models.VolumeInfo {
	v := models.VolumeInfo{
		Root: root, VolumeID: models.Known("vol:" + root), DriveType: dt,
		BusType: models.Known(bus), RemovableMedia: models.Known(dt == models.DriveRemovable),
		ReadOnly: models.Known(false), FreeBytes: models.Known[uint64](8 * gib), IsSystem: models.Known(false),
	}
	for _, o := range opts {
		o(&v)
	}
	return v
}

func system(v *models.VolumeInfo) { v.IsSystem = models.Known(true) }

// layout returns real directories standing in for volumes.
func layout(t *testing.T) (base, sys, usb, data string) {
	t.Helper()
	base = t.TempDir()
	for _, d := range []string{"sys", "usb", "data"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return base, filepath.Join(base, "sys"), filepath.Join(base, "usb"), filepath.Join(base, "data")
}

func rejectedWith(t *testing.T, err error, want string) {
	t.Helper()
	var rej *Rejection
	if !errors.As(err, &rej) || !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want a Rejection", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("rejection %q does not mention %q", err, want)
	}
}

func TestDefaultUsesExecutableVolume(t *testing.T) {
	_, sys, usb, _ := layout(t)
	insp := fake.NewVolumes(vol(sys, models.DriveFixed, models.BusNVMe, system), vol(usb, models.DriveRemovable, models.BusUSB))
	d, err := ValidateOutput(ctx, insp, OutputRequest{ExePath: filepath.Join(usb, "tools", "Canaveral.exe")})
	if err != nil {
		t.Fatal(err)
	}
	if d.Root != filepath.Join(usb, ReportDirName) || d.Explicit || len(d.Basis) == 0 {
		t.Fatalf("destination %+v", d)
	}
}

func TestFixedVolumeOnUSBBusAcceptedByDefault(t *testing.T) {
	_, _, usb, _ := layout(t)
	insp := fake.NewVolumes(vol(usb, models.DriveFixed, models.BusUSB))
	d, err := ValidateOutput(ctx, insp, OutputRequest{ExePath: filepath.Join(usb, "Canaveral.exe")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(d.Basis, " "), "USB bus") {
		t.Fatalf("basis %v", d.Basis)
	}
}

func TestFixedInternalNeedsExplicitOutput(t *testing.T) {
	_, _, _, data := layout(t)
	insp := fake.NewVolumes(vol(data, models.DriveFixed, models.BusSATA))
	_, err := ValidateOutput(ctx, insp, OutputRequest{ExePath: filepath.Join(data, "Canaveral.exe")})
	rejectedWith(t, err, "pass --output")

	d, err := ValidateOutput(ctx, insp, OutputRequest{ExePath: filepath.Join(data, "Canaveral.exe"), Override: filepath.Join(data, "reports")})
	if err != nil {
		t.Fatalf("explicit --output on a fixed non-system drive: %v", err)
	}
	if !d.Explicit || d.Root != filepath.Join(data, "reports") {
		t.Fatalf("destination %+v", d)
	}
}

func TestRejections(t *testing.T) {
	_, sys, usb, data := layout(t)
	type tc struct {
		name string
		vol  models.VolumeInfo
		req  func(root string) OutputRequest
		want string
	}
	dflt := func(root string) OutputRequest { return OutputRequest{ExePath: filepath.Join(root, "Canaveral.exe")} }
	expl := func(root string) OutputRequest { return OutputRequest{Override: filepath.Join(root, "out")} }
	cases := []tc{
		{"system volume by default", vol(sys, models.DriveFixed, models.BusNVMe, system), dflt, "system volume"},
		{"system volume explicitly", vol(sys, models.DriveFixed, models.BusNVMe, system), expl, "system volume"},
		{"removable system volume", vol(sys, models.DriveRemovable, models.BusUSB, system), expl, "system volume"},
		{"system status unknown", vol(usb, models.DriveRemovable, models.BusUSB, func(v *models.VolumeInfo) {
			v.IsSystem = models.Unavailable[bool]("GUID unknown")
		}), dflt, "could not be confirmed"},
		{"fixed with unknown bus by default", vol(data, models.DriveFixed, models.BusSATA, func(v *models.VolumeInfo) {
			v.BusType = models.Unavailable[models.BusType]("ioctl failed")
		}), dflt, "bus type is unknown"},
		{"network drive", vol(data, models.DriveRemote, models.BusUnknown), expl, "network drive"},
		{"cd-rom", vol(data, models.DriveCDROM, models.BusATAPI), expl, "drive type CDROM"},
		{"ram disk", vol(data, models.DriveRAMDisk, models.BusUnknown), expl, "drive type RAMDisk"},
		{"unknown drive type", vol(data, models.DriveUnknown, models.BusUnknown), expl, "drive type Unknown"},
		{"read-only", vol(usb, models.DriveRemovable, models.BusUSB, func(v *models.VolumeInfo) { v.ReadOnly = models.Known(true) }), dflt, "read-only"},
		{"free space unknown", vol(usb, models.DriveRemovable, models.BusUSB, func(v *models.VolumeInfo) {
			v.FreeBytes = models.Unavailable[uint64]("device not ready")
		}), dflt, "free space"},
		{"insufficient free space", vol(usb, models.DriveRemovable, models.BusUSB, func(v *models.VolumeInfo) { v.FreeBytes = models.Known[uint64](1 << 20) }), dflt, "below the required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := ValidateOutput(ctx, fake.NewVolumes(c.vol), c.req(c.vol.Root))
			rejectedWith(t, err, c.want)
			if d.Root != "" {
				t.Fatalf("a rejection returned a destination: %+v", d)
			}
		})
	}
}

func TestCustomMinimumFreeSpace(t *testing.T) {
	_, _, usb, _ := layout(t)
	insp := fake.NewVolumes(vol(usb, models.DriveRemovable, models.BusUSB, func(v *models.VolumeInfo) { v.FreeBytes = models.Known[uint64](200 << 20) }))
	req := OutputRequest{ExePath: filepath.Join(usb, "Canaveral.exe"), MinFreeBytes: 500 << 20}
	_, err := ValidateOutput(ctx, insp, req)
	rejectedWith(t, err, "below the required 524288000")
	req.MinFreeBytes = 100 << 20
	if _, err := ValidateOutput(ctx, insp, req); err != nil {
		t.Fatal(err)
	}
}

func TestEveryReasonIsReported(t *testing.T) {
	_, sys, _, _ := layout(t)
	v := vol(sys, models.DriveFixed, models.BusNVMe, system, func(v *models.VolumeInfo) {
		v.ReadOnly = models.Known(true)
		v.FreeBytes = models.Known[uint64](0)
	})
	_, err := ValidateOutput(ctx, fake.NewVolumes(v), OutputRequest{ExePath: filepath.Join(sys, "Canaveral.exe")})
	var rej *Rejection
	if !errors.As(err, &rej) || len(rej.Reasons) != 4 {
		t.Fatalf("want 4 reasons (system, fixed NVMe, read-only, free space), got %v", err)
	}
}

func TestBadPathsAreRejected(t *testing.T) {
	_, _, usb, _ := layout(t)
	insp := fake.NewVolumes(vol(usb, models.DriveRemovable, models.BusUSB))

	_, err := ValidateOutput(ctx, insp, OutputRequest{Override: "reports"})
	rejectedWith(t, err, "must be absolute")
	_, err = ValidateOutput(ctx, insp, OutputRequest{})
	rejectedWith(t, err, "could not be determined")
	_, err = ValidateOutput(ctx, insp, OutputRequest{ExePath: "Canaveral.exe"})
	rejectedWith(t, err, "could not be determined")
	_, err = ValidateOutput(ctx, insp, OutputRequest{Override: filepath.Join(t.TempDir(), "elsewhere")})
	rejectedWith(t, err, "could not be inspected")
	_, err = ValidateOutput(ctx, insp, OutputRequest{ExePath: filepath.Join(t.TempDir(), "Canaveral.exe")})
	rejectedWith(t, err, "executable's volume could not be inspected")

	file := filepath.Join(usb, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ValidateOutput(ctx, insp, OutputRequest{Override: file})
	rejectedWith(t, err, "not a directory")
	_, err = ValidateOutput(ctx, insp, OutputRequest{Override: filepath.Join(file, "sub")})
	rejectedWith(t, err, "not a directory")
}

// A link inside the USB volume that points at the system drive must not be
// accepted, even though the path string is under the USB root.
func TestLinkInPathIsRejected(t *testing.T) {
	_, sys, usb, _ := layout(t)
	insp := fake.NewVolumes(vol(sys, models.DriveFixed, models.BusNVMe, system), vol(usb, models.DriveRemovable, models.BusUSB))
	link := filepath.Join(usb, "reports-link")
	if err := os.Symlink(sys, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	_, err := ValidateOutput(ctx, insp, OutputRequest{Override: filepath.Join(link, "out")})
	rejectedWith(t, err, "link, junction or mount point")
	_, err = ValidateOutput(ctx, insp, OutputRequest{Override: link})
	rejectedWith(t, err, "link, junction or mount point")
}

// Acceptance (M2): never silently falls back to the host system drive. Every
// combination involving a system (or possibly-system) volume is refused, for
// default and explicit destinations alike, and no destination is returned.
func TestNeverFallsBackToSystemDrive(t *testing.T) {
	_, sys, _, _ := layout(t)
	drives := []models.DriveType{models.DriveRemovable, models.DriveFixed, models.DriveRemote, models.DriveCDROM, models.DriveRAMDisk, models.DriveUnknown}
	buses := []models.Value[models.BusType]{models.Known(models.BusUSB), models.Known(models.BusSATA), models.Unavailable[models.BusType]("x")}
	systems := []models.Value[bool]{models.Known(true), models.Unavailable[bool]("GUID unknown")}
	n := 0
	for _, dt := range drives {
		for _, bus := range buses {
			for _, isSys := range systems {
				for _, explicit := range []bool{false, true} {
					v := vol(sys, dt, models.BusUnknown, func(v *models.VolumeInfo) { v.BusType, v.IsSystem = bus, isSys })
					req := OutputRequest{ExePath: filepath.Join(sys, "Canaveral.exe")}
					if explicit {
						req.Override = filepath.Join(sys, "Canaveral_Reports")
					}
					d, err := ValidateOutput(ctx, fake.NewVolumes(v), req)
					if err == nil || d.Root != "" {
						t.Errorf("drive=%s bus=%v system=%v explicit=%v: accepted %+v", dt, bus, isSys, explicit, d)
					}
					n++
				}
			}
		}
	}
	if n != 72 {
		t.Fatalf("swept %d combinations", n)
	}
}
