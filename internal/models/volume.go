package models

// DriveType is the Windows drive type of a volume.
type DriveType string

// Drive types (GetDriveType).
const (
	DriveUnknown   DriveType = "Unknown"
	DriveNoRootDir DriveType = "NoRootDir"
	DriveRemovable DriveType = "Removable"
	DriveFixed     DriveType = "Fixed"
	DriveRemote    DriveType = "Remote"
	DriveCDROM     DriveType = "CDROM"
	DriveRAMDisk   DriveType = "RAMDisk"
)

// BusType is the storage bus a volume's device is attached to
// (STORAGE_BUS_TYPE). External USB SSDs often report DriveFixed with BusUSB.
type BusType string

// Bus types.
const (
	BusUnknown           BusType = "Unknown"
	BusSCSI              BusType = "SCSI"
	BusATAPI             BusType = "ATAPI"
	BusATA               BusType = "ATA"
	Bus1394              BusType = "1394"
	BusSSA               BusType = "SSA"
	BusFibre             BusType = "Fibre"
	BusUSB               BusType = "USB"
	BusRAID              BusType = "RAID"
	BusISCSI             BusType = "iSCSI"
	BusSAS               BusType = "SAS"
	BusSATA              BusType = "SATA"
	BusSD                BusType = "SD"
	BusMMC               BusType = "MMC"
	BusVirtual           BusType = "Virtual"
	BusFileBackedVirtual BusType = "FileBackedVirtual"
	BusSpaces            BusType = "Spaces"
	BusNVMe              BusType = "NVMe"
	BusSCM               BusType = "SCM"
	BusUFS               BusType = "UFS"
)

// VolumeInfo describes the volume that holds a path.
type VolumeInfo struct {
	// Root is the volume mount point holding the path, with a trailing
	// separator, for example `E:\`.
	Root string
	// VolumeID is the stable volume name, for example `\\?\Volume{GUID}\`.
	// It detects a different device appearing at the same drive letter.
	VolumeID       Value[string]
	DriveType      DriveType
	BusType        Value[BusType]
	RemovableMedia Value[bool]
	ReadOnly       Value[bool]
	// FreeBytes is the free space available to the calling user.
	FreeBytes Value[uint64]
	// IsSystem reports whether this is the volume holding the Windows
	// directory. Unknown must be treated as "might be the system volume".
	IsSystem Value[bool]
}
