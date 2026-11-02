package models

import (
	"net/netip"
	"time"
)

// FileTime is a raw Windows FILETIME: 100-nanosecond intervals since
// 1601-01-01 UTC. It is kept raw so identity comparisons are exact.
type FileTime uint64

// ProcessKey identifies one process instance. A PID alone is not an identity
// because Windows reuses PIDs; the creation time distinguishes instances.
type ProcessKey struct {
	PID        uint32
	CreateTime FileTime
}

// ProcessRecord is one process as reported by a ProcessSource.
type ProcessRecord struct {
	PID       uint32
	ParentPID uint32
	// Name is the executable name from the process snapshot.
	Name        string
	CreateTime  Value[FileTime]
	ImagePath   Value[string]
	CommandLine Value[string]
	UserSID     Value[string]
	UserName    Value[string]
	SessionID   Value[uint32]
}

// SocketTable names one of the Windows socket tables.
type SocketTable string

// Socket tables. Each is queried separately so each can fail separately.
const (
	TableTCPv4 SocketTable = "TCPv4"
	TableTCPv6 SocketTable = "TCPv6"
	TableUDPv4 SocketTable = "UDPv4"
	TableUDPv6 SocketTable = "UDPv6"
)

// AllSocketTables lists every socket table.
var AllSocketTables = []SocketTable{TableTCPv4, TableTCPv6, TableUDPv4, TableUDPv6}

// Protocol is a transport protocol.
type Protocol string

// Protocols.
const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// TCPState is a TCP connection state as reported by Windows.
type TCPState string

// TCP states. UDP sockets have no state; their State is TCPStateNone and no
// TCP-like state is ever invented for them.
const (
	TCPStateNone        TCPState = ""
	TCPStateClosed      TCPState = "CLOSED"
	TCPStateListen      TCPState = "LISTENING"
	TCPStateSynSent     TCPState = "SYN_SENT"
	TCPStateSynReceived TCPState = "SYN_RECEIVED"
	TCPStateEstablished TCPState = "ESTABLISHED"
	TCPStateFinWait1    TCPState = "FIN_WAIT_1"
	TCPStateFinWait2    TCPState = "FIN_WAIT_2"
	TCPStateCloseWait   TCPState = "CLOSE_WAIT"
	TCPStateClosing     TCPState = "CLOSING"
	TCPStateLastAck     TCPState = "LAST_ACK"
	TCPStateTimeWait    TCPState = "TIME_WAIT"
	TCPStateDeleteTCB   TCPState = "DELETE_TCB"
)

// SocketRecord is one socket table entry as reported by a SocketSource.
type SocketRecord struct {
	Table    SocketTable
	Protocol Protocol
	Local    netip.AddrPort
	// Remote is the zero (invalid) AddrPort for UDP sockets.
	Remote netip.AddrPort
	State  TCPState
	// OwnerPID is the PID Windows reported. 0 means Windows reported no owner;
	// such sockets are unattributed and must never be assigned a guessed owner.
	OwnerPID uint32
	// EntryCreateTime is when the socket table entry was created
	// (liCreateTimestamp). It is NOT the owning process's creation time and is
	// only usable as a consistency check (CLAUDE.md A5).
	EntryCreateTime Value[FileTime]
	// OwnerModule is the owning module or service name, for example the
	// service inside a shared svchost.exe.
	OwnerModule Value[string]
}

// FileIdentity identifies file content on disk independently of its path
// (CLAUDE.md 3): volume serial + file index + size + last-write time.
type FileIdentity struct {
	VolumeSerial uint32
	FileIndex    uint64
	Size         uint64
	ModTime      FileTime
}

// DirEntry is one directory entry returned by a FileSystem.
type DirEntry struct {
	Name    string
	IsDir   bool
	Reparse bool
	Size    uint64
	ModTime FileTime
}

// SignatureState is the outcome of a signature check. Invalid, Unsigned and
// Unavailable are distinct states and must never be conflated.
type SignatureState string

// Signature states.
const (
	SignatureValid       SignatureState = "Valid"
	SignatureInvalid     SignatureState = "Invalid"
	SignatureUnsigned    SignatureState = "Unsigned"
	SignatureUnavailable SignatureState = "Unavailable"
)

// SignatureSource is which verification path produced a signature result
// (CLAUDE.md A1).
type SignatureSource string

// Signature sources.
const (
	SignatureSourceEmbedded SignatureSource = "Embedded"
	SignatureSourceCatalog  SignatureSource = "Catalog"
	SignatureSourceNone     SignatureSource = "None"
)

// SignatureRecord is the result of verifying one file.
type SignatureRecord struct {
	State    SignatureState
	Source   SignatureSource
	Signer   Value[string]
	SignedAt Value[time.Time]
	// Detail carries the verifier's status text or the reason a check was
	// unavailable.
	Detail string
}

// RegistryHive is a registry root readable without loading hives.
type RegistryHive string

// Registry hives. Per-user data is read through HKU\<SID>; HKCU is never used
// because it would resolve to the tool's own user.
const (
	HiveLocalMachine RegistryHive = "HKLM"
	HiveUsers        RegistryHive = "HKU"
)

// RegistryValue is one raw registry value.
type RegistryValue struct {
	Name string
	// Type is the raw REG_* type code.
	Type uint32
	Data []byte
}

// RegistryKey is a read-only snapshot of one registry key.
type RegistryKey struct {
	Hive      RegistryHive
	Path      string
	LastWrite Value[FileTime]
	SubKeys   []string
	Values    []RegistryValue
}

// EventQuery selects events from one channel. MaxEvents caps the result.
type EventQuery struct {
	Channel   string
	EventIDs  []uint32
	Since     time.Time
	Until     time.Time
	MaxEvents int
}

// EventRecord is one rendered event log record.
type EventRecord struct {
	Channel     string
	Provider    string
	EventID     uint32
	RecordID    uint64
	TimeCreated time.Time
	XML         string
}

// ChannelInfo describes an event log channel, so a disabled or empty channel
// is never misread as "nothing happened".
type ChannelInfo struct {
	Channel     string
	Enabled     bool
	RecordCount Value[uint64]
}
