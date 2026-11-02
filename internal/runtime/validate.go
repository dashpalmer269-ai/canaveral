package runtime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

// ReportDirName is the report directory created at the root of the
// executable's volume when no --output is given.
const ReportDirName = "Canaveral_Reports"

// DefaultMinFreeBytes is the free space required on the output volume.
const DefaultMinFreeBytes uint64 = 50 << 20

// OutputRequest describes where the operator wants reports to go.
type OutputRequest struct {
	// ExePath is the running executable's path (os.Executable). It decides
	// the default destination when Override is empty.
	ExePath string
	// Override is an explicit --output path, or an alternate destination the
	// operator typed after the first one was lost. Explicit paths may be on a
	// fixed, non-system volume; default paths may not.
	Override string
	// MinFreeBytes is the required free space; 0 means DefaultMinFreeBytes.
	MinFreeBytes uint64
}

// Destination is an approved output root. Reports are written only to new
// scan directories inside Root.
type Destination struct {
	Root     string
	Volume   models.VolumeInfo
	Explicit bool
	// Basis explains why the destination was accepted, for the report.
	Basis []string
}

// Rejection explains why a destination was refused. Every applicable reason
// is listed, not only the first.
type Rejection struct {
	Path    string
	Reasons []string
}

func (r *Rejection) Error() string {
	return fmt.Sprintf("output destination %q refused: %s", r.Path, strings.Join(r.Reasons, "; "))
}

// ErrRejected matches any *Rejection with errors.Is.
var ErrRejected = errors.New("output destination refused")

// Is lets errors.Is(err, ErrRejected) match a Rejection.
func (r *Rejection) Is(target error) bool { return target == ErrRejected }

// lstat is a variable so the path-component check can be exercised in tests.
var lstat = os.Lstat

// ValidateOutput decides whether reports may be written under the requested
// destination. It never substitutes another location: if the request cannot
// be satisfied it returns a *Rejection and no Destination.
func ValidateOutput(ctx context.Context, insp platform.VolumeInspector, req OutputRequest) (Destination, error) {
	minFree := req.MinFreeBytes
	if minFree == 0 {
		minFree = DefaultMinFreeBytes
	}
	explicit := req.Override != ""

	var root string
	if explicit {
		if !filepath.IsAbs(req.Override) {
			return Destination{}, &Rejection{Path: req.Override, Reasons: []string{
				"the output path must be absolute; a relative path would depend on the current directory, which may be on the system drive",
			}}
		}
		root = filepath.Clean(req.Override)
	} else {
		if req.ExePath == "" || !filepath.IsAbs(req.ExePath) {
			return Destination{}, &Rejection{Path: req.ExePath, Reasons: []string{
				"the executable's own location could not be determined, so there is no default output drive; pass --output",
			}}
		}
		exeVol, err := insp.Volume(ctx, req.ExePath)
		if err != nil {
			return Destination{}, &Rejection{Path: req.ExePath, Reasons: []string{
				"the executable's volume could not be inspected: " + err.Error(),
			}}
		}
		root = filepath.Join(exeVol.Root, ReportDirName)
	}

	vol, err := insp.Volume(ctx, root)
	if err != nil {
		return Destination{}, &Rejection{Path: root, Reasons: []string{"the volume could not be inspected: " + err.Error()}}
	}

	var reasons, basis []string
	reject := func(format string, a ...any) { reasons = append(reasons, fmt.Sprintf(format, a...)) }

	switch sys, ok := vol.IsSystem.Get(); {
	case !ok:
		reject("it could not be confirmed that %s is not the system volume (%s)", vol.Root, vol.IsSystem.Reason())
	case sys:
		reject("%s is the system volume; reports are never written to the host system drive", vol.Root)
	}

	bus, busKnown := vol.BusType.Get()
	externalBus := busKnown && (bus == models.BusUSB || bus == models.BusSD || bus == models.BusMMC)
	switch vol.DriveType {
	case models.DriveRemovable:
		basis = append(basis, fmt.Sprintf("%s is a removable volume", vol.Root))
	case models.DriveFixed:
		switch {
		case externalBus:
			basis = append(basis, fmt.Sprintf("%s is on the %s bus", vol.Root, bus))
		case explicit:
			basis = append(basis, fmt.Sprintf("%s is a fixed volume chosen explicitly by the operator", vol.Root))
		case busKnown:
			reject("%s is a fixed %s volume, not removable or USB; pass --output to choose a non-system drive explicitly", vol.Root, bus)
		default:
			reject("%s is a fixed volume whose bus type is unknown (%s); pass --output to choose a non-system drive explicitly", vol.Root, vol.BusType.Reason())
		}
	case models.DriveRemote:
		reject("%s is a network drive; writing there would send report data over the network", vol.Root)
	default:
		reject("%s has drive type %s, which cannot hold reports", vol.Root, vol.DriveType)
	}

	if ro, ok := vol.ReadOnly.Get(); ok && ro {
		reject("%s is read-only", vol.Root)
	}

	switch free, ok := vol.FreeBytes.Get(); {
	case !ok:
		reject("free space on %s could not be determined (%s)", vol.Root, vol.FreeBytes.Reason())
	case free < minFree:
		reject("%s has %d bytes free, below the required %d", vol.Root, free, minFree)
	}

	reasons = append(reasons, checkPathComponents(vol.Root, root)...)

	if len(reasons) > 0 {
		return Destination{}, &Rejection{Path: root, Reasons: reasons}
	}
	return Destination{Root: root, Volume: vol, Explicit: explicit, Basis: basis}, nil
}

// checkPathComponents refuses paths that pass through a symlink, junction or
// other reparse point below the volume root, since those can redirect writes
// to another volume, and paths whose existing final element is not a
// directory.
func checkPathComponents(volRoot, root string) []string {
	rel, err := filepath.Rel(volRoot, root)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return []string{fmt.Sprintf("%s is not inside volume %s", root, volRoot)}
	}
	if rel == "." {
		return nil
	}
	cur := filepath.Clean(volRoot)
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // the rest will be created by the writer
		}
		if err != nil {
			return []string{fmt.Sprintf("%s could not be checked: %v", cur, err)}
		}
		if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return []string{fmt.Sprintf("%s is a link, junction or mount point, which could redirect writes", cur)}
		}
		if !fi.IsDir() {
			return []string{fmt.Sprintf("%s exists and is not a directory", cur)}
		}
	}
	return nil
}
