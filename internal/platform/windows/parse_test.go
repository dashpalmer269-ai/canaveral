package windows

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

// putPort writes a port the way Windows stores it: network order in the
// DWORD's first two bytes.
func putPort(b []byte, off int, p uint16) { b[off], b[off+1] = byte(p>>8), byte(p) }

func table(rowSize int, rows ...[]byte) []byte {
	buf := make([]byte, tableHeader+rowSize*len(rows))
	put32(buf, 0, uint32(len(rows)))
	for i, r := range rows {
		copy(buf[tableHeader+i*rowSize:], r)
	}
	return buf
}

func TestParseTCP4Row(t *testing.T) {
	r := make([]byte, tcp4RowSize)
	put32(r, 0, 5) // ESTABLISHED
	copy(r[4:8], []byte{192, 168, 1, 20})
	putPort(r, 8, 51515)
	copy(r[12:16], []byte{203, 0, 113, 9})
	putPort(r, 16, 443)
	put32(r, 20, 4321)
	put64(r, 24, 133700000000000000)
	rows, err := tableRows(table(tcp4RowSize, r), tcp4RowSize)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d err %v", len(rows), err)
	}
	got := parseTCP4Row(rows[0])
	if got.Local != netip.MustParseAddrPort("192.168.1.20:51515") || got.Remote != netip.MustParseAddrPort("203.0.113.9:443") {
		t.Fatalf("endpoints %v -> %v", got.Local, got.Remote)
	}
	ts, ok := got.EntryCreateTime.Get()
	if got.State != models.TCPStateEstablished || got.OwnerPID != 4321 || !ok || ts != 133700000000000000 ||
		got.Protocol != models.ProtocolTCP || got.Table != models.TableTCPv4 {
		t.Fatalf("row %+v", got)
	}
}

func TestParseTCP6RowWithZone(t *testing.T) {
	r := make([]byte, tcp6RowSize)
	copy(r[0:16], netip.MustParseAddr("fe80::1").AsSlice())
	put32(r, 16, 12) // interface index as scope
	putPort(r, 20, 5355)
	copy(r[24:40], netip.MustParseAddr("2001:4860:4860::8888").AsSlice())
	putPort(r, 44, 53)
	put32(r, 48, 2) // LISTENING
	put32(r, 52, 1000)
	got := parseTCP6Row(r)
	if got.Local != netip.MustParseAddrPort("[fe80::1%12]:5355") || got.Remote != netip.MustParseAddrPort("[2001:4860:4860::8888]:53") {
		t.Fatalf("endpoints %v -> %v", got.Local, got.Remote)
	}
	if got.State != models.TCPStateListen || got.OwnerPID != 1000 || got.EntryCreateTime.IsKnown() {
		t.Fatalf("row %+v (a zero timestamp must be Unavailable)", got)
	}
}

func TestParseUDPRowsHaveNoStateOrRemote(t *testing.T) {
	r4 := make([]byte, udp4RowSize)
	copy(r4[0:4], []byte{0, 0, 0, 0})
	putPort(r4, 4, 5353)
	put32(r4, 8, 77)
	put64(r4, 16, 1)
	r6 := make([]byte, udp6RowSize)
	copy(r6[0:16], netip.IPv6Loopback().AsSlice())
	putPort(r6, 20, 1900)
	put32(r6, 24, 88)
	put64(r6, 32, 2)
	for _, got := range []models.SocketRecord{parseUDP4Row(r4), parseUDP6Row(r6)} {
		if got.State != models.TCPStateNone || got.Remote.IsValid() || got.Protocol != models.ProtocolUDP {
			t.Fatalf("UDP row invented TCP data: %+v", got)
		}
	}
	if g := parseUDP4Row(r4); g.Local != netip.MustParseAddrPort("0.0.0.0:5353") || g.OwnerPID != 77 {
		t.Fatalf("udp4 %+v", g)
	}
	if g := parseUDP6Row(r6); g.Local != netip.MustParseAddrPort("[::1]:1900") || g.OwnerPID != 88 {
		t.Fatalf("udp6 %+v", g)
	}
}

func TestTableRowsValidatesLength(t *testing.T) {
	buf := table(tcp4RowSize, make([]byte, tcp4RowSize), make([]byte, tcp4RowSize))
	if _, err := tableRows(buf[:len(buf)-1], tcp4RowSize); err == nil || !strings.Contains(err.Error(), "claims 2 rows") {
		t.Fatalf("truncated table accepted: %v", err)
	}
	if _, err := tableRows([]byte{1}, tcp4RowSize); err == nil {
		t.Fatal("tiny buffer accepted")
	}
	if rows, err := tableRows(table(udp6RowSize), udp6RowSize); err != nil || len(rows) != 0 {
		t.Fatalf("empty table: %d %v", len(rows), err)
	}
}

func TestUnknownTCPStateIsNotGuessed(t *testing.T) {
	if s := tcpState(99); s != "UNKNOWN(99)" {
		t.Fatalf("state %q", s)
	}
}

func TestProtectionName(t *testing.T) {
	cases := map[byte]string{
		0x00: "None",
		0x31: "PsProtectedSignerAntimalware-Light",
		0x41: "PsProtectedSignerLsa-Light",
		0x62: "PsProtectedSignerWinTcb",
		0x72: "PsProtectedSignerWinSystem",
		0xF1: "PsProtectedSignerUnknown(15)-Light",
	}
	for b, want := range cases {
		if got := protectionName(b); got != want {
			t.Errorf("protectionName(%#x) = %q, want %q", b, got, want)
		}
	}
}

func TestIntegrityName(t *testing.T) {
	if integrityName(0x3000) != "High" || integrityName(0x2000) != "Medium" || integrityName(0x4000) != "System" || integrityName(0x1234) != "0x1234" {
		t.Fatal("integrity names wrong")
	}
}

func TestAccountLookupIsLocal(t *testing.T) {
	machine := "S-1-5-21-111-222-333"
	local := []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544", "S-1-5-80-123-456", "S-1-5-90-0-1", "S-1-5-96-0-1", machine + "-1001"}
	remote := []string{"S-1-5-21-999-888-777-1104", "S-1-12-1-1-2-3-4", "S-1-5-21-111-222-3334-1001", machine, "S-1-5-32"}
	for _, s := range local {
		if !accountLookupIsLocal(s, machine) {
			t.Errorf("%s should be looked up locally", s)
		}
	}
	for _, s := range remote {
		if accountLookupIsLocal(s, machine) {
			t.Errorf("%s must not be looked up (could leave the machine)", s)
		}
	}
	if accountLookupIsLocal(machine+"-1001", "") {
		t.Error("with an unknown machine SID, no account-domain SID may be treated as local")
	}
}

func TestIntegrityRID(t *testing.T) {
	for sid, want := range map[string]uint32{"S-1-16-12288": 0x3000, "S-1-16-8192": 0x2000, "S-1-16-16384": 0x4000, "S-1-16-0": 0} {
		if got, err := integrityRID(sid); err != nil || got != want {
			t.Errorf("integrityRID(%s) = %d, %v", sid, got, err)
		}
	}
	for _, bad := range []string{"", "S-1-16-", "S-1-5-18", "S-1-16-abc", "S-1-16-99999999999"} {
		if _, err := integrityRID(bad); err == nil {
			t.Errorf("integrityRID(%q) accepted", bad)
		}
	}
}
