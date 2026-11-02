package windows

// This file has no build tag: it parses raw Windows structures with plain
// byte offsets so the layouts are unit-tested on every platform.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// Row sizes of the *_OWNER_MODULE socket rows (iprtrmib.h / tcpmib.h /
// udpmib.h). OwningModuleInfo is ULONGLONG[16], and LARGE_INTEGER members
// force 8-byte alignment.
const (
	tcp4RowSize = 160 // MIB_TCPROW_OWNER_MODULE
	tcp6RowSize = 192 // MIB_TCP6ROW_OWNER_MODULE
	udp4RowSize = 160 // MIB_UDPROW_OWNER_MODULE
	udp6RowSize = 176 // MIB_UDP6ROW_OWNER_MODULE
	// tableHeader is dwNumEntries plus padding to the rows' 8-byte alignment.
	tableHeader = 8
)

func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// port decodes a DWORD port field: the port is in network byte order in its
// first two bytes.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// tableRows splits a MIB_*TABLE_OWNER_MODULE buffer into row slices and
// rejects a buffer too short for the row count it claims.
func tableRows(buf []byte, rowSize int) ([][]byte, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("socket table buffer too short: %d bytes", len(buf))
	}
	n := int(le32(buf))
	if n == 0 {
		return nil, nil
	}
	if need := tableHeader + n*rowSize; len(buf) < need {
		return nil, fmt.Errorf("socket table claims %d rows (%d bytes) but the buffer has %d bytes", n, need, len(buf))
	}
	rows := make([][]byte, n)
	for i := range rows {
		off := tableHeader + i*rowSize
		rows[i] = buf[off : off+rowSize : off+rowSize]
	}
	return rows, nil
}

func entryTime(v uint64) models.Value[models.FileTime] {
	if v == 0 {
		return models.Unavailable[models.FileTime]("Windows reported no creation timestamp for this socket entry")
	}
	return models.Known(models.FileTime(v))
}

func addr6(b []byte, scope uint32) netip.Addr {
	a := netip.AddrFrom16([16]byte(b[:16]))
	if scope != 0 {
		a = a.WithZone(strconv.FormatUint(uint64(scope), 10))
	}
	return a
}

var tcpStates = map[uint32]models.TCPState{
	1: models.TCPStateClosed, 2: models.TCPStateListen, 3: models.TCPStateSynSent,
	4: models.TCPStateSynReceived, 5: models.TCPStateEstablished, 6: models.TCPStateFinWait1,
	7: models.TCPStateFinWait2, 8: models.TCPStateCloseWait, 9: models.TCPStateClosing,
	10: models.TCPStateLastAck, 11: models.TCPStateTimeWait, 12: models.TCPStateDeleteTCB,
}

// tcpState maps MIB_TCP_STATE. An unknown value is reported as such, never
// mapped to a guess.
func tcpState(v uint32) models.TCPState {
	if s, ok := tcpStates[v]; ok {
		return s
	}
	return models.TCPState(fmt.Sprintf("UNKNOWN(%d)", v))
}

// parseTCP4Row: dwState 0, dwLocalAddr 4, dwLocalPort 8, dwRemoteAddr 12,
// dwRemotePort 16, dwOwningPid 20, liCreateTimestamp 24.
func parseTCP4Row(r []byte) models.SocketRecord {
	return models.SocketRecord{
		Table:           models.TableTCPv4,
		Protocol:        models.ProtocolTCP,
		State:           tcpState(le32(r[0:])),
		Local:           netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), port(r[8:])),
		Remote:          netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), port(r[16:])),
		OwnerPID:        le32(r[20:]),
		EntryCreateTime: entryTime(le64(r[24:])),
	}
}

// parseTCP6Row: ucLocalAddr 0, dwLocalScopeId 16, dwLocalPort 20,
// ucRemoteAddr 24, dwRemoteScopeId 40, dwRemotePort 44, dwState 48,
// dwOwningPid 52, liCreateTimestamp 56.
func parseTCP6Row(r []byte) models.SocketRecord {
	return models.SocketRecord{
		Table:           models.TableTCPv6,
		Protocol:        models.ProtocolTCP,
		Local:           netip.AddrPortFrom(addr6(r[0:], le32(r[16:])), port(r[20:])),
		Remote:          netip.AddrPortFrom(addr6(r[24:], le32(r[40:])), port(r[44:])),
		State:           tcpState(le32(r[48:])),
		OwnerPID:        le32(r[52:]),
		EntryCreateTime: entryTime(le64(r[56:])),
	}
}

// parseUDP4Row: dwLocalAddr 0, dwLocalPort 4, dwOwningPid 8,
// liCreateTimestamp 16. UDP has no remote endpoint and no state.
func parseUDP4Row(r []byte) models.SocketRecord {
	return models.SocketRecord{
		Table:           models.TableUDPv4,
		Protocol:        models.ProtocolUDP,
		Local:           netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[0:4])), port(r[4:])),
		OwnerPID:        le32(r[8:]),
		EntryCreateTime: entryTime(le64(r[16:])),
	}
}

// parseUDP6Row: ucLocalAddr 0, dwLocalScopeId 16, dwLocalPort 20,
// dwOwningPid 24, liCreateTimestamp 32.
func parseUDP6Row(r []byte) models.SocketRecord {
	return models.SocketRecord{
		Table:           models.TableUDPv6,
		Protocol:        models.ProtocolUDP,
		Local:           netip.AddrPortFrom(addr6(r[0:], le32(r[16:])), port(r[20:])),
		OwnerPID:        le32(r[24:]),
		EntryCreateTime: entryTime(le64(r[32:])),
	}
}

var protectionSigners = []string{
	"None", "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem", "App",
}

// protectionName formats a PS_PROTECTION byte: Type in bits 0-2 (0 none,
// 1 protected light, 2 protected), Signer in bits 4-7.
func protectionName(b byte) string {
	typ, signer := b&0x7, int(b>>4)
	if typ == 0 {
		return "None"
	}
	name := "Unknown(" + strconv.Itoa(signer) + ")"
	if signer < len(protectionSigners) {
		name = protectionSigners[signer]
	}
	switch typ {
	case 1:
		return "PsProtectedSigner" + name + "-Light"
	case 2:
		return "PsProtectedSigner" + name
	default:
		return fmt.Sprintf("PsProtectedSigner%s-Type%d", name, typ)
	}
}

// integrityName names a mandatory integrity level RID.
func integrityName(rid uint32) string {
	switch rid {
	case 0x0000:
		return "Untrusted"
	case 0x1000:
		return "Low"
	case 0x2000:
		return "Medium"
	case 0x2100:
		return "MediumPlus"
	case 0x3000:
		return "High"
	case 0x4000:
		return "System"
	case 0x5000:
		return "Protected"
	default:
		return fmt.Sprintf("0x%04X", rid)
	}
}

// accountLookupIsLocal reports whether resolving sid to a name stays on this
// machine. Well-known, builtin and service SIDs always do; machine-local
// accounts do when their SID is under the local account domain. Domain and
// Azure AD accounts can require contacting a domain controller or the cloud,
// which would be network traffic, so they are not looked up.
func accountLookupIsLocal(sid, machineDomainSID string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	for _, p := range []string{"S-1-5-32-", "S-1-5-80-", "S-1-5-82-", "S-1-5-83-", "S-1-5-90-", "S-1-5-96-"} {
		if len(sid) > len(p) && sid[:len(p)] == p {
			return true
		}
	}
	return machineDomainSID != "" && len(sid) > len(machineDomainSID)+1 &&
		sid[:len(machineDomainSID)+1] == machineDomainSID+"-"
}
