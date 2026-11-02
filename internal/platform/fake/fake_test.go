package fake

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var ctx = context.Background()

func TestUnconfiguredFixturesFailInsteadOfLookingEmpty(t *testing.T) {
	if _, err := (&SocketSource{}).Sockets(ctx, models.TableTCPv4); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("socket table without fixture: err = %v", err)
	}
	if _, err := (&FileSystem{}).Open(ctx, `C:\x.exe`); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("open without fixture: err = %v", err)
	}
	if _, err := (&FileSystem{}).ReadDir(ctx, `C:\Users`); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("readdir without fixture: err = %v", err)
	}
	if _, err := NewRegistry().ReadKey(ctx, models.HiveLocalMachine, `SOFTWARE\X`); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("registry without fixture: err = %v", err)
	}
	if _, _, err := (&EventLog{}).Query(ctx, models.EventQuery{Channel: "System"}); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("event channel without fixture: err = %v", err)
	}
	r := (&SignatureVerifier{}).Verify(ctx, `C:\x.exe`)
	if r.State != models.SignatureUnavailable || r.Source != models.SignatureSourceNone {
		t.Errorf("signature without fixture = %+v, want Unavailable/None", r)
	}
}

func TestConfiguredErrorsPropagate(t *testing.T) {
	ps := &ProcessSource{Err: platform.ErrAccessDenied}
	if _, err := ps.Processes(ctx); !errors.Is(err, platform.ErrAccessDenied) {
		t.Errorf("process err = %v", err)
	}
	ss := &SocketSource{Errs: map[models.SocketTable]error{models.TableUDPv6: platform.ErrUnsupported}}
	if _, err := ss.Sockets(ctx, models.TableUDPv6); !errors.Is(err, platform.ErrUnsupported) {
		t.Errorf("socket err = %v", err)
	}
	reg := NewRegistry()
	reg.FailKey(models.HiveUsers, `S-1-5-21-1\Software`, platform.ErrAccessDenied)
	if _, err := reg.ReadKey(ctx, models.HiveUsers, `s-1-5-21-1\SOFTWARE`); !errors.Is(err, platform.ErrAccessDenied) {
		t.Errorf("registry err = %v", err)
	}
}

func TestCanceledContext(t *testing.T) {
	c, cancel := context.WithCancel(ctx)
	cancel()
	ps := &ProcessSource{Records: []models.ProcessRecord{{PID: 4}}}
	if _, err := ps.Processes(c); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestReturnedSlicesAreCopies(t *testing.T) {
	ps := &ProcessSource{Records: []models.ProcessRecord{{PID: 4, Name: "System"}}}
	got, _ := ps.Processes(ctx)
	got[0].Name = "changed"
	if ps.Records[0].Name != "System" {
		t.Fatal("caller mutated fixture")
	}

	reg := NewRegistry(models.RegistryKey{
		Hive: models.HiveLocalMachine, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Values: []models.RegistryValue{{Name: "x", Type: 1, Data: []byte{1}}},
	})
	k, err := reg.ReadKey(ctx, models.HiveLocalMachine, `software\microsoft\windows\currentversion\run`)
	if err != nil {
		t.Fatal(err)
	}
	k.Values[0].Data[0] = 9
	k2, _ := reg.ReadKey(ctx, models.HiveLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
	if k2.Values[0].Data[0] != 1 {
		t.Fatal("caller mutated registry fixture")
	}
}

func TestFileReadAndIdentity(t *testing.T) {
	id := models.FileIdentity{VolumeSerial: 1, FileIndex: 2, Size: 5, ModTime: 3}
	fs := &FileSystem{Files: map[string]FileFixture{`C:\a.exe`: {Content: []byte("hello"), Identity: id}}}
	f, err := fs.Open(ctx, `C:\a.exe`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q err=%v", b, err)
	}
	if got, err := f.Identity(); err != nil || got != id {
		t.Fatalf("identity %+v err=%v", got, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(make([]byte, 1)); err == nil {
		t.Fatal("read after close succeeded")
	}
}

func TestEventQueryFiltersAndTruncates(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var recs []models.EventRecord
	for i := range 10 {
		id := uint32(7045)
		if i%2 == 1 {
			id = 7036
		}
		recs = append(recs, models.EventRecord{Channel: "System", EventID: id, RecordID: uint64(i), TimeCreated: t0.Add(time.Duration(i) * time.Hour)})
	}
	el := &EventLog{
		Channels: map[string]models.ChannelInfo{"System": {Channel: "System", Enabled: true}},
		Records:  map[string][]models.EventRecord{"System": recs},
	}

	got, truncated, err := el.Query(ctx, models.EventQuery{Channel: "System", EventIDs: []uint32{7045}, Since: t0.Add(2 * time.Hour)})
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	if len(got) != 4 || got[0].RecordID != 2 {
		t.Fatalf("got %d records, first %v", len(got), got)
	}

	got, truncated, _ = el.Query(ctx, models.EventQuery{Channel: "System", MaxEvents: 3})
	if len(got) != 3 || !truncated {
		t.Fatalf("cap: got %d truncated=%v", len(got), truncated)
	}
	got, truncated, _ = el.Query(ctx, models.EventQuery{Channel: "System", MaxEvents: 10})
	if len(got) != 10 || truncated {
		t.Fatalf("exact cap: got %d truncated=%v", len(got), truncated)
	}
}

func TestClockAdvance(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))
	c := NewClock(start)
	if c.Now().Location() != time.UTC || !c.Now().Equal(start) {
		t.Fatalf("now = %v", c.Now())
	}
	c.Advance(5 * time.Second)
	if !c.Now().Equal(start.Add(5 * time.Second)) {
		t.Fatalf("advanced now = %v", c.Now())
	}
}
