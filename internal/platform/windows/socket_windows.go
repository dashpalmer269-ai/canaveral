//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.SocketSource = SocketSource{}

// These IP Helper functions are not wrapped by x/sys/windows. They are
// loaded by name, which lint cannot inspect; all of them are read-only
// queries (CLAUDE.md A5).
var (
	iphlpapi                        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable         = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable         = iphlpapi.NewProc("GetExtendedUdpTable")
	procGetOwnerModuleFromTCPEntry  = iphlpapi.NewProc("GetOwnerModuleFromTcpEntry")
	procGetOwnerModuleFromTCP6Entry = iphlpapi.NewProc("GetOwnerModuleFromTcp6Entry")
	procGetOwnerModuleFromUDPEntry  = iphlpapi.NewProc("GetOwnerModuleFromUdpEntry")
	procGetOwnerModuleFromUDP6Entry = iphlpapi.NewProc("GetOwnerModuleFromUdp6Entry")
)

const (
	afInet                    = 2
	afInet6                   = 23
	tcpTableOwnerModuleAll    = 8 // TCP_TABLE_OWNER_MODULE_ALL
	udpTableOwnerModule       = 2 // UDP_TABLE_OWNER_MODULE
	tcpipOwnerModuleInfoBasic = 0 // TCPIP_OWNER_MODULE_INFO_BASIC
)

type tableSpec struct {
	proc    *windows.LazyProc
	af      uintptr
	class   uintptr
	rowSize int
	parse   func([]byte) models.SocketRecord
	owner   *windows.LazyProc
}

var tables = map[models.SocketTable]tableSpec{
	models.TableTCPv4: {procGetExtendedTCPTable, afInet, tcpTableOwnerModuleAll, tcp4RowSize, parseTCP4Row, procGetOwnerModuleFromTCPEntry},
	models.TableTCPv6: {procGetExtendedTCPTable, afInet6, tcpTableOwnerModuleAll, tcp6RowSize, parseTCP6Row, procGetOwnerModuleFromTCP6Entry},
	models.TableUDPv4: {procGetExtendedUDPTable, afInet, udpTableOwnerModule, udp4RowSize, parseUDP4Row, procGetOwnerModuleFromUDPEntry},
	models.TableUDPv6: {procGetExtendedUDPTable, afInet6, udpTableOwnerModule, udp6RowSize, parseUDP6Row, procGetOwnerModuleFromUDP6Entry},
}

// SocketSource reads the module-aware TCP and UDP tables.
type SocketSource struct{}

// Sockets reads one table and resolves each row's owning module.
func (SocketSource) Sockets(ctx context.Context, table models.SocketTable) ([]models.SocketRecord, error) {
	spec, ok := tables[table]
	if !ok {
		return nil, fmt.Errorf("unknown socket table %q: %w", table, platform.ErrUnsupported)
	}
	if err := spec.proc.Find(); err != nil {
		return nil, fmt.Errorf("%s: %w: %v", spec.proc.Name, platform.ErrUnsupported, err)
	}
	buf, err := readTable(spec)
	if err != nil {
		return nil, err
	}
	rows, err := tableRows(buf, spec.rowSize)
	if err != nil {
		return nil, err
	}
	recs := make([]models.SocketRecord, 0, len(rows))
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rec := spec.parse(r)
		rec.OwnerModule = ownerModule(spec.owner, r)
		recs = append(recs, rec)
	}
	runtime.KeepAlive(buf)
	return recs, nil
}

func readTable(spec tableSpec) ([]byte, error) {
	var size uint32
	var buf []byte
	for range 8 {
		var p unsafe.Pointer
		if size > 0 {
			buf = make([]byte, size)
			p = unsafe.Pointer(&buf[0])
		}
		r, _, _ := spec.proc.Call(uintptr(p), uintptr(unsafe.Pointer(&size)), 0, spec.af, spec.class, 0)
		switch errno := windows.Errno(r); {
		case errno == 0 && buf != nil:
			return buf, nil
		case errno == 0 || errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER):
			size += 4096 // the table can grow between calls
		default:
			return nil, fmt.Errorf("%s: %w", spec.proc.Name, mapErr(errno))
		}
	}
	return nil, fmt.Errorf("%s: the table kept growing faster than it could be read", spec.proc.Name)
}

// tcpipOwnerModuleBasicInfo is TCPIP_OWNER_MODULE_BASIC_INFO.
type tcpipOwnerModuleBasicInfo struct {
	moduleName *uint16
	modulePath *uint16
}

// ownerModule asks Windows which module owns the socket in row. For a socket
// in a shared svchost.exe this is the service name.
func ownerModule(proc *windows.LazyProc, row []byte) models.Value[string] {
	if err := proc.Find(); err != nil {
		return models.Unavailable[string](proc.Name + " is not available: " + err.Error())
	}
	var size uint32
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&row[0])), tcpipOwnerModuleInfoBasic, 0, uintptr(unsafe.Pointer(&size)))
	if errno := windows.Errno(r); !errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) || size == 0 {
		return models.Unavailable[string](proc.Name + ": " + errno.Error())
	}
	buf := make([]byte, size)
	r, _, _ = proc.Call(uintptr(unsafe.Pointer(&row[0])), tcpipOwnerModuleInfoBasic, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if errno := windows.Errno(r); errno != 0 {
		return models.Unavailable[string](proc.Name + ": " + errno.Error())
	}
	info := (*tcpipOwnerModuleBasicInfo)(unsafe.Pointer(&buf[0]))
	name := windows.UTF16PtrToString(info.moduleName)
	runtime.KeepAlive(buf)
	if name == "" {
		return models.Unavailable[string](proc.Name + " returned an empty module name")
	}
	return models.Known(name)
}
