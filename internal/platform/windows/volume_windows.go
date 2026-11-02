//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.VolumeInspector = VolumeInspector{}

// ioctlStorageQueryProperty is IOCTL_STORAGE_QUERY_PROPERTY
// (CTL_CODE(IOCTL_STORAGE_BASE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)).
const ioctlStorageQueryProperty = 0x002D1400

const pathBufLen = 1024

// VolumeInspector reads volume properties with read-only Win32 calls. The
// only handle it opens is a volume device handle with zero access rights,
// used for IOCTL_STORAGE_QUERY_PROPERTY.
type VolumeInspector struct{}

// Volume describes the volume holding path. path does not need to exist.
func (VolumeInspector) Volume(ctx context.Context, path string) (models.VolumeInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.VolumeInfo{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return models.VolumeInfo{}, fmt.Errorf("resolve %s: %w", path, err)
	}
	root, err := volumePathName(abs)
	if err != nil {
		return models.VolumeInfo{}, err
	}
	root16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return models.VolumeInfo{}, err
	}

	info := models.VolumeInfo{Root: root, DriveType: driveType(windows.GetDriveType(root16))}
	if info.DriveType == models.DriveNoRootDir {
		return info, fmt.Errorf("no volume is mounted at %s: %w", root, platform.ErrNotFound)
	}

	info.VolumeID = volumeGUID(root16)

	var serial, maxComponent, flags uint32
	if err := windows.GetVolumeInformation(root16, nil, 0, &serial, &maxComponent, &flags, nil, 0); err != nil {
		info.ReadOnly = models.Unavailable[bool]("GetVolumeInformation: " + err.Error())
	} else {
		info.ReadOnly = models.Known(flags&windows.FILE_READ_ONLY_VOLUME != 0)
	}

	var freeToCaller, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(root16, &freeToCaller, &total, &totalFree); err != nil {
		info.FreeBytes = models.Unavailable[uint64]("GetDiskFreeSpaceEx: " + err.Error())
	} else {
		info.FreeBytes = models.Known(freeToCaller)
	}

	info.IsSystem = isSystemVolume(info.VolumeID)
	info.BusType, info.RemovableMedia = storageProperties(info.VolumeID)
	return info, nil
}

func volumePathName(abs string) (string, error) {
	p16, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, pathBufLen)
	if err := windows.GetVolumePathName(p16, &buf[0], uint32(len(buf))); err != nil {
		return "", fmt.Errorf("GetVolumePathName %s: %w", abs, mapErr(err))
	}
	return windows.UTF16ToString(buf), nil
}

func volumeGUID(root16 *uint16) models.Value[string] {
	buf := make([]uint16, pathBufLen)
	if err := windows.GetVolumeNameForVolumeMountPoint(root16, &buf[0], uint32(len(buf))); err != nil {
		return models.Unavailable[string]("GetVolumeNameForVolumeMountPoint: " + err.Error())
	}
	return models.Known(windows.UTF16ToString(buf))
}

func isSystemVolume(id models.Value[string]) models.Value[bool] {
	guid, ok := id.Get()
	if !ok {
		return models.Unavailable[bool]("volume GUID unknown, so it cannot be compared with the system volume: " + id.Reason())
	}
	windir, err := windows.GetWindowsDirectory()
	if err != nil {
		return models.Unavailable[bool]("GetWindowsDirectory: " + err.Error())
	}
	sysRoot, err := volumePathName(windir)
	if err != nil {
		return models.Unavailable[bool](err.Error())
	}
	sysRoot16, err := windows.UTF16PtrFromString(sysRoot)
	if err != nil {
		return models.Unavailable[bool](err.Error())
	}
	sysID, ok := volumeGUID(sysRoot16).Get()
	if !ok {
		return models.Unavailable[bool]("system volume GUID unknown")
	}
	return models.Known(strings.EqualFold(guid, sysID))
}

// storageProperties queries the device descriptor of a volume. The handle is
// opened with zero desired access, which is enough for this IOCTL and cannot
// read or write volume data.
func storageProperties(id models.Value[string]) (models.Value[models.BusType], models.Value[bool]) {
	guid, ok := id.Get()
	if !ok {
		r := "volume GUID unknown: " + id.Reason()
		return models.Unavailable[models.BusType](r), models.Unavailable[bool](r)
	}
	dev16, err := windows.UTF16PtrFromString(strings.TrimSuffix(guid, `\`))
	if err != nil {
		return models.Unavailable[models.BusType](err.Error()), models.Unavailable[bool](err.Error())
	}
	h, err := windows.CreateFile(dev16, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		r := "open volume device: " + err.Error()
		return models.Unavailable[models.BusType](r), models.Unavailable[bool](r)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	// STORAGE_PROPERTY_QUERY{PropertyId: StorageDeviceProperty, QueryType: PropertyStandardQuery}
	var query [12]byte
	out := make([]byte, 1024)
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &query[0], uint32(len(query)), &out[0], uint32(len(out)), &n, nil); err != nil {
		r := "IOCTL_STORAGE_QUERY_PROPERTY: " + err.Error()
		return models.Unavailable[models.BusType](r), models.Unavailable[bool](r)
	}
	bus, removable, err := parseDeviceDescriptor(out[:n])
	if err != nil {
		return models.Unavailable[models.BusType](err.Error()), models.Unavailable[bool](err.Error())
	}
	return models.Known(bus), models.Known(removable)
}

// parseDeviceDescriptor reads STORAGE_DEVICE_DESCRIPTOR: RemovableMedia is the
// BOOLEAN at offset 10 and BusType the uint32 at offset 28.
func parseDeviceDescriptor(b []byte) (models.BusType, bool, error) {
	if len(b) < 32 {
		return "", false, fmt.Errorf("STORAGE_DEVICE_DESCRIPTOR too short: %d bytes", len(b))
	}
	return busType(binary.LittleEndian.Uint32(b[28:32])), b[10] != 0, nil
}

func driveType(t uint32) models.DriveType {
	switch t {
	case windows.DRIVE_NO_ROOT_DIR:
		return models.DriveNoRootDir
	case windows.DRIVE_REMOVABLE:
		return models.DriveRemovable
	case windows.DRIVE_FIXED:
		return models.DriveFixed
	case windows.DRIVE_REMOTE:
		return models.DriveRemote
	case windows.DRIVE_CDROM:
		return models.DriveCDROM
	case windows.DRIVE_RAMDISK:
		return models.DriveRAMDisk
	default:
		return models.DriveUnknown
	}
}

var busTypes = []models.BusType{
	models.BusUnknown, models.BusSCSI, models.BusATAPI, models.BusATA, models.Bus1394,
	models.BusSSA, models.BusFibre, models.BusUSB, models.BusRAID, models.BusISCSI,
	models.BusSAS, models.BusSATA, models.BusSD, models.BusMMC, models.BusVirtual,
	models.BusFileBackedVirtual, models.BusSpaces, models.BusNVMe, models.BusSCM, models.BusUFS,
}

func busType(v uint32) models.BusType {
	if int(v) < len(busTypes) {
		return busTypes[v]
	}
	return models.BusUnknown
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND),
		errors.Is(err, windows.ERROR_INVALID_DRIVE), errors.Is(err, windows.ERROR_NOT_READY):
		return fmt.Errorf("%w: %w", platform.ErrNotFound, err)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("%w: %w", platform.ErrAccessDenied, err)
	default:
		return err
	}
}
