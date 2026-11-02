package network

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/collectors/process"
	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

var at = time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)

func proc(pid uint32, name string, created models.FileTime) models.ProcessRecord {
	return models.ProcessRecord{PID: pid, ParentPID: 4, Name: name, CreateTime: models.Known(created),
		ImagePath: models.Known(`C:\x\` + name), CommandLine: models.Known(name), UserSID: models.Known("S-1-5-18"),
		UserName: models.Known("SYSTEM"), Protection: models.Known("None")}
}

func noTime(r models.ProcessRecord) models.ProcessRecord {
	r.CreateTime = models.Unavailable[models.FileTime]("access denied")
	return r
}

func sock(pid uint32, local, remote string, entry models.FileTime) models.SocketRecord {
	r := models.SocketRecord{Table: models.TableTCPv4, Protocol: models.ProtocolTCP, State: models.TCPStateEstablished,
		Local: netip.MustParseAddrPort(local), OwnerPID: pid, OwnerModule: models.Known("app.exe")}
	if remote != "" {
		r.Remote = netip.MustParseAddrPort(remote)
	}
	if entry != 0 {
		r.EntryCreateTime = models.Known(entry)
	} else {
		r.EntryCreateTime = models.Unavailable[models.FileTime]("none")
	}
	return r
}

func snap(recs ...models.ProcessRecord) process.Snapshot { return process.Build(at, recs) }

func one(t *testing.T, r models.SocketRecord, before, after process.Snapshot) Socket {
	t.Helper()
	s := Attribute(at, []models.SocketRecord{r}, before, after)
	if len(s.Sockets) != 1 {
		t.Fatalf("%d sockets", len(s.Sockets))
	}
	got := s.Sockets[0]
	if got.Confidence == "" || got.ConfidenceReason == "" {
		t.Fatalf("socket without confidence or reason: %+v", got)
	}
	return got
}

func TestStableOwnerIsHighConfidence(t *testing.T) {
	ps := snap(proc(4, "System", 100), proc(1234, "app.exe", 5000))
	got := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 6000), ps, ps)
	if got.Confidence != ConfidenceHigh || got.OwnerName != "app.exe" {
		t.Fatalf("%+v", got)
	}
	if k, ok := got.Owner.Get(); !ok || k != (models.ProcessKey{PID: 1234, CreateTime: 5000}) {
		t.Fatalf("owner %+v %s", k, got.Owner.Reason())
	}
	if got.LocalClass != ClassPrivate || got.RemoteClass != ClassReserved {
		t.Fatalf("classes %s %s", got.LocalClass, got.RemoteClass)
	}
}

// Acceptance (M3): PID 0 or unresolvable owners are unattributed, never guessed.
func TestUnattributedSockets(t *testing.T) {
	ps := snap(proc(1234, "app.exe", 5000))
	cases := map[string]models.SocketRecord{
		"no owning process (PID 0)":   sock(0, "10.0.0.5:50000", "203.0.113.9:443", 0),
		"in neither process snapshot": sock(4444, "10.0.0.5:50001", "203.0.113.9:443", 6000),
	}
	for want, r := range cases {
		got := one(t, r, ps, ps)
		if got.Confidence != ConfidenceNone || got.Owner.IsKnown() || got.OwnerName != "" || !strings.Contains(got.ConfidenceReason, want) {
			t.Errorf("%s: %+v", want, got)
		}
	}
}

// Acceptance (M3): same PID with a different creation time is a distinct
// identity; a PID reused during collection leaves the owner ambiguous.
func TestPIDReusedDuringCollectionIsAmbiguous(t *testing.T) {
	before := snap(proc(1234, "old.exe", 5000))
	after := snap(proc(1234, "new.exe", 9000))
	got := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 6000), before, after)
	if got.Confidence != ConfidenceNone || got.Owner.IsKnown() || !strings.Contains(got.ConfidenceReason, "two different processes") {
		t.Fatalf("%+v", got)
	}
}

func TestOwnerExitedOrStartedDuringCollection(t *testing.T) {
	ps := snap(proc(1234, "app.exe", 5000))
	empty := snap()
	exited := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 6000), ps, empty)
	if exited.Confidence != ConfidenceReduced || !strings.Contains(exited.ConfidenceReason, "exited during collection") || !exited.Owner.IsKnown() {
		t.Fatalf("exited: %+v", exited)
	}
	started := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 6000), empty, ps)
	if started.Confidence != ConfidenceReduced || !strings.Contains(started.ConfidenceReason, "started during collection") {
		t.Fatalf("started: %+v", started)
	}
}

// Acceptance (M3): a socket entry created before its process lowers
// confidence but is not rejected (inherited handles, CLAUDE.md A5).
func TestSocketOlderThanProcessLowersConfidence(t *testing.T) {
	ps := snap(proc(1234, "child.exe", 5000))
	got := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 4000), ps, ps)
	if got.Confidence != ConfidenceReduced || !got.Owner.IsKnown() || got.OwnerName != "child.exe" ||
		!strings.Contains(got.ConfidenceReason, "created before this process started") {
		t.Fatalf("%+v", got)
	}
}

func TestUnknownCreationTimeIsReduced(t *testing.T) {
	ps := snap(noTime(proc(1234, "app.exe", 0)))
	got := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 6000), ps, ps)
	if got.Confidence != ConfidenceReduced || got.Owner.IsKnown() || got.OwnerName != "app.exe" || !strings.Contains(got.ConfidenceReason, "PID reuse cannot be ruled out") {
		t.Fatalf("%+v", got)
	}
	// Readable in only one of the two snapshots: identity cannot be confirmed.
	got = one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 6000), snap(noTime(proc(1234, "app.exe", 0))), snap(proc(1234, "app.exe", 5000)))
	if got.Confidence != ConfidenceReduced || !strings.Contains(got.ConfidenceReason, "cannot be confirmed") {
		t.Fatalf("half-known identity: %+v", got)
	}
}

func TestMissingSocketTimestampIsNoted(t *testing.T) {
	ps := snap(proc(1234, "app.exe", 5000))
	got := one(t, sock(1234, "10.0.0.5:50000", "203.0.113.9:443", 0), ps, ps)
	if got.Confidence != ConfidenceHigh || !strings.Contains(got.ConfidenceReason, "no socket timestamp") {
		t.Fatalf("%+v", got)
	}
}

func TestKernelOwnedSocketIsExplained(t *testing.T) {
	ps := snap(proc(4, "System", 100))
	r := sock(4, "0.0.0.0:445", "0.0.0.0:0", 200)
	r.State = models.TCPStateListen
	got := one(t, r, ps, ps)
	if got.Confidence != ConfidenceHigh || !strings.Contains(got.ConfidenceReason, "kernel (System)") || got.LocalClass != ClassUnspecified {
		t.Fatalf("%+v", got)
	}
}

// Acceptance (M3): shared svchost sockets show the owning service name when
// Windows supplies it.
func TestSvchostServiceName(t *testing.T) {
	ps := snap(proc(1500, "svchost.exe", 300), proc(1600, "svchost.exe", 310), proc(1700, "app.exe", 320))
	dns := sock(1500, "0.0.0.0:5353", "", 400)
	dns.Table, dns.Protocol, dns.State = models.TableUDPv4, models.ProtocolUDP, models.TCPStateNone
	dns.OwnerModule = models.Known("Dnscache")
	unknownSvc := sock(1600, "0.0.0.0:135", "0.0.0.0:0", 400)
	unknownSvc.OwnerModule = models.Unavailable[string]("ERROR_NOT_FOUND")
	plain := sock(1700, "10.0.0.5:50000", "203.0.113.9:443", 400)
	plain.OwnerModule = models.Known("app.exe")
	s := Attribute(at, []models.SocketRecord{dns, unknownSvc, plain}, ps, ps)
	if s.Sockets[0].Service != "Dnscache" || s.Sockets[1].Service != "" || s.Sockets[2].Service != "" {
		t.Fatalf("services %q %q %q", s.Sockets[0].Service, s.Sockets[1].Service, s.Sockets[2].Service)
	}
	if s.Sockets[0].RemoteClass != ClassUnknown {
		t.Fatalf("UDP remote class %s", s.Sockets[0].RemoteClass)
	}
	var moduleNote bool
	for _, n := range s.Coverage {
		if n.Item == "owning module" && strings.Contains(n.Reason, "1 sockets") {
			moduleNote = true
		}
	}
	if !moduleNote {
		t.Fatalf("missing owning-module coverage: %+v", s.Coverage)
	}
}

func TestCollectTakesTwoProcessSnapshots(t *testing.T) {
	seq := &fake.ProcessSequence{Snapshots: [][]models.ProcessRecord{
		{proc(1234, "app.exe", 5000), proc(2000, "gone.exe", 5100)},
		{proc(1234, "app.exe", 5000), proc(3000, "new.exe", 5200)},
	}}
	ss := &fake.SocketSource{
		Tables: map[models.SocketTable][]models.SocketRecord{
			models.TableTCPv4: {sock(1234, "10.0.0.5:1", "203.0.113.9:443", 6000), sock(2000, "10.0.0.5:2", "203.0.113.9:443", 6000), sock(3000, "10.0.0.5:3", "203.0.113.9:443", 6000)},
			models.TableTCPv6: {},
			models.TableUDPv4: {},
		},
		Errs: map[models.SocketTable]error{models.TableUDPv6: platform.ErrAccessDenied},
	}
	res, err := Collect(context.Background(), seq, ss, fake.NewClock(at))
	if err != nil {
		t.Fatal(err)
	}
	conf := map[uint32]Confidence{}
	for _, s := range res.Sockets.Sockets {
		conf[s.OwnerPID] = s.Confidence
	}
	if conf[1234] != ConfidenceHigh || conf[2000] != ConfidenceReduced || conf[3000] != ConfidenceReduced {
		t.Fatalf("confidences %v", conf)
	}
	var udp6 *models.CoverageNote
	for i, n := range res.Sockets.Coverage {
		if n.Item == "UDPv6 table" {
			udp6 = &res.Sockets.Coverage[i]
		}
	}
	if udp6 == nil || udp6.Status != models.CoverageUnavailable || !strings.Contains(udp6.Reason, "access denied") {
		t.Fatalf("failed table not reported: %+v", res.Sockets.Coverage)
	}
}

// Acceptance (M3): forced failures yield Unavailable/coverage, never values.
func TestCollectFailures(t *testing.T) {
	clock := fake.NewClock(at)
	_, err := Collect(context.Background(), &fake.ProcessSource{Err: platform.ErrAccessDenied}, &fake.SocketSource{}, clock)
	if !errors.Is(err, platform.ErrAccessDenied) {
		t.Fatalf("process failure: %v", err)
	}
	allFail := &fake.SocketSource{Errs: map[models.SocketTable]error{}}
	for _, tb := range models.AllSocketTables {
		allFail.Errs[tb] = platform.ErrAccessDenied
	}
	res, err := Collect(context.Background(), &fake.ProcessSource{Records: []models.ProcessRecord{proc(4, "System", 1)}}, allFail, clock)
	if err == nil || len(res.Sockets.Sockets) != 0 {
		t.Fatalf("all tables failed: err=%v sockets=%d", err, len(res.Sockets.Sockets))
	}
	unavailable := 0
	for _, n := range res.Sockets.Coverage {
		if n.Status == models.CoverageUnavailable {
			unavailable++
		}
	}
	if unavailable != 4 {
		t.Fatalf("%d tables reported unavailable", unavailable)
	}
}
