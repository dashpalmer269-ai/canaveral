//go:build windows

package windows

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

func ownSockets(t *testing.T, table models.SocketTable) []models.SocketRecord {
	t.Helper()
	recs, err := SocketSource{}.Sockets(ctx, table)
	if err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	var mine []models.SocketRecord
	for _, r := range recs {
		if r.OwnerPID == uint32(os.Getpid()) {
			mine = append(mine, r)
		}
	}
	return mine
}

func find(recs []models.SocketRecord, local netip.AddrPort, state models.TCPState) (models.SocketRecord, bool) {
	for _, r := range recs {
		if r.Local == local && r.State == state {
			return r, true
		}
	}
	return models.SocketRecord{}, false
}

// The parser offsets are checked against live tables: sockets this test
// opens must appear with the right address, port, state and owner.
func TestOwnTCPSocketsAppear(t *testing.T) {
	for _, tc := range []struct {
		network, addr string
		table         models.SocketTable
	}{
		{"tcp4", "127.0.0.1:0", models.TableTCPv4},
		{"tcp6", "[::1]:0", models.TableTCPv6},
	} {
		l, err := net.Listen(tc.network, tc.addr)
		if err != nil {
			if tc.table == models.TableTCPv6 {
				t.Logf("IPv6 loopback unavailable, skipping: %v", err)
				continue
			}
			t.Fatal(err)
		}
		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := l.Accept()
			if err == nil {
				accepted <- c
			}
		}()
		c, err := net.Dial(tc.network, l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		srv := <-accepted

		listenAP := netip.MustParseAddrPort(l.Addr().String())
		clientAP := netip.MustParseAddrPort(c.LocalAddr().String())
		mine := ownSockets(t, tc.table)

		ls, ok := find(mine, listenAP, models.TCPStateListen)
		if !ok {
			t.Fatalf("%s: listener %v not found among own sockets %+v", tc.table, listenAP, mine)
		}
		cs, ok := find(mine, clientAP, models.TCPStateEstablished)
		if !ok || cs.Remote != listenAP {
			t.Fatalf("%s: client %v -> %v not found among own sockets %+v", tc.table, clientAP, listenAP, mine)
		}
		if ls.Protocol != models.ProtocolTCP || ls.Table != tc.table {
			t.Fatalf("listener row %+v", ls)
		}
		t.Logf("%s listener %v module=%v entry-time=%v; client %v", tc.table, ls.Local, ls.OwnerModule, ls.EntryCreateTime, cs.Local)
		_ = c.Close()
		_ = srv.Close()
		_ = l.Close()
	}
}

func TestOwnUDPSocketsAppear(t *testing.T) {
	for _, tc := range []struct {
		network, addr string
		table         models.SocketTable
	}{
		{"udp4", "127.0.0.1:0", models.TableUDPv4},
		{"udp6", "[::1]:0", models.TableUDPv6},
	} {
		pc, err := net.ListenPacket(tc.network, tc.addr)
		if err != nil {
			if tc.table == models.TableUDPv6 {
				t.Logf("IPv6 loopback unavailable, skipping: %v", err)
				continue
			}
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(pc.LocalAddr().String())
		r, ok := find(ownSockets(t, tc.table), ap, models.TCPStateNone)
		if !ok {
			t.Fatalf("%s: %v not found", tc.table, ap)
		}
		if r.Protocol != models.ProtocolUDP || r.Remote.IsValid() {
			t.Fatalf("UDP row %+v", r)
		}
		_ = pc.Close()
	}
}

// Acceptance (M3): shared svchost sockets show the owning service name when
// Windows supplies it.
func TestSvchostSocketsNameTheirService(t *testing.T) {
	procs := processes(t)
	withService, svchost := 0, 0
	examples := map[string]bool{}
	for _, table := range models.AllSocketTables {
		recs, err := SocketSource{}.Sockets(ctx, table)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if !strings.EqualFold(procs[r.OwnerPID].Name, "svchost.exe") {
				continue
			}
			svchost++
			if m, ok := r.OwnerModule.Get(); ok && !strings.EqualFold(m, "svchost.exe") {
				withService++
				examples[m] = true
			}
		}
	}
	t.Logf("%d svchost sockets, %d with a service name; services: %v", svchost, withService, examples)
	if svchost > 0 && withService == 0 {
		t.Fatal("no svchost socket carried a service name")
	}
}
