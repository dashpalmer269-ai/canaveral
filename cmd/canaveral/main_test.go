package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

func usbVolume(root string, isSys bool) models.VolumeInfo {
	return models.VolumeInfo{
		Root: root, VolumeID: models.Known("vol:" + root), DriveType: models.DriveRemovable,
		BusType: models.Known(models.BusUSB), RemovableMedia: models.Known(true), ReadOnly: models.Known(false),
		FreeBytes: models.Known[uint64](1 << 33), IsSystem: models.Known(isSys),
	}
}

func snapshot(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, _ os.DirEntry, _ error) error { out = append(out, p); return nil })
	return out
}

func TestDiagOutputAcceptsAndWritesNothing(t *testing.T) {
	usb := t.TempDir()
	vols := fake.NewVolumes(usbVolume(usb, false))
	before := snapshot(t, usb)
	var out bytes.Buffer
	code := diagOutput(context.Background(), nil, vols, func() (string, error) { return filepath.Join(usb, "Canaveral.exe"), nil }, &out, &out)
	if code != 0 || !strings.Contains(out.String(), "Decision: ACCEPTED") || !strings.Contains(out.String(), filepath.Join(usb, "Canaveral_Reports")) {
		t.Fatalf("code %d output:\n%s", code, out.String())
	}
	if after := snapshot(t, usb); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("diag-output wrote something: %v", after)
	}
}

func TestDiagOutputRefusesSystemVolume(t *testing.T) {
	sys := t.TempDir()
	vols := fake.NewVolumes(usbVolume(sys, true))
	var out bytes.Buffer
	code := diagOutput(context.Background(), []string{"--output", filepath.Join(sys, "r")}, vols, func() (string, error) { return "", errors.New("unknown") }, &out, &out)
	if code != 1 || !strings.Contains(out.String(), "Decision: REFUSED") || !strings.Contains(out.String(), "system volume") {
		t.Fatalf("code %d output:\n%s", code, out.String())
	}
}

func TestDiagOutputWithoutInspector(t *testing.T) {
	var out bytes.Buffer
	if code := diagOutput(context.Background(), nil, nil, os.Executable, &out, &out); code != 1 || !strings.Contains(out.String(), "only implemented for Windows") {
		t.Fatalf("code %d output %s", code, out.String())
	}
}

func TestRunVersionAndDefault(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := run(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "No scan or report exists yet") {
		t.Fatalf("default: code %d err %q", code, errOut.String())
	}
}

func TestDiagSnapshot(t *testing.T) {
	proc := func(pid uint32, name string, ct models.FileTime) models.ProcessRecord {
		return models.ProcessRecord{PID: pid, ParentPID: 4, Name: name, CreateTime: models.Known(ct),
			ImagePath: models.Known(name), CommandLine: models.Known(name), UserSID: models.Known("S-1-5-18"),
			UserName: models.Known("SYSTEM"), Protection: models.Known("None")}
	}
	denied := models.ProcessRecord{PID: 900, ParentPID: 4, Name: "MsMpEng.exe",
		CreateTime: models.Unavailable[models.FileTime]("Access is denied."), ImagePath: models.Unavailable[string]("Access is denied."),
		CommandLine: models.Unavailable[string]("Access is denied."), UserSID: models.Unavailable[string]("Access is denied."),
		UserName: models.Unavailable[string]("Access is denied."), Protection: models.Unavailable[string]("Access is denied.")}
	tcp := models.SocketRecord{Table: models.TableTCPv4, Protocol: models.ProtocolTCP, State: models.TCPStateEstablished,
		Local: netip.MustParseAddrPort("10.0.0.5:50000"), Remote: netip.MustParseAddrPort("8.8.8.8:443"), OwnerPID: 1234,
		EntryCreateTime: models.Known[models.FileTime](6000), OwnerModule: models.Known("app.exe")}
	orphan := tcp
	orphan.Local, orphan.OwnerPID = netip.MustParseAddrPort("10.0.0.5:50001"), 0
	src := sources{
		processes: &fake.ProcessSource{Records: []models.ProcessRecord{proc(4, "System", 1), proc(1234, "app.exe", 5000), denied}},
		sockets: &fake.SocketSource{Tables: map[models.SocketTable][]models.SocketRecord{
			models.TableTCPv4: {tcp, orphan}, models.TableTCPv6: {}, models.TableUDPv4: {}, models.TableUDPv6: {}}},
		privileges: &fake.Privileges{Info: models.ElevationInfo{Elevated: models.Known(false),
			IntegrityLevel: models.Known("Medium"), AdminMember: models.Known(false)}},
	}
	var b strings.Builder
	if code := snapshotReport(context.Background(), &b, src, fake.NewClock(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))); code != 0 {
		t.Fatalf("code %d\n%s", code, b.String())
	}
	out := b.String()
	for _, want := range []string{
		"elevated=false", "Not elevated", "Attribution: High 1, Reduced 0, None 1",
		"app.exe", "(unattributed)", "Public", "no owning process (PID 0)",
		"PID 900 (MsMpEng.exe)", "Access is denied.", "not findings",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDiagSnapshotWithoutPlatform(t *testing.T) {
	var b strings.Builder
	if code := snapshotReport(context.Background(), &b, sources{}, fake.NewClock(time.Now())); code != 1 || !strings.Contains(b.String(), "only implemented for Windows") {
		t.Fatalf("code %d %s", code, b.String())
	}
}

func TestGuardedRecordsPanicBeforeShutdown(t *testing.T) {
	lc := runtime.NewLifecycle(context.Background(), time.Second)
	cleaned := false
	lc.OnShutdown("cleanup", func(context.Context) error { cleaned = true; return nil })
	code := guarded(lc, func() int { panic("collector bug") })
	if code != runtime.ExitPanic || !cleaned || !strings.Contains(lc.Cause(), "panic in main") || len(lc.Panics()) != 1 {
		t.Fatalf("code=%d cleaned=%v cause=%q panics=%d", code, cleaned, lc.Cause(), len(lc.Panics()))
	}
}

func TestGuardedReportsInterruption(t *testing.T) {
	lc := runtime.NewLifecycle(context.Background(), time.Second)
	code := guarded(lc, func() int {
		lc.Shutdown("signal: interrupt") // what the signal watcher does on Ctrl+C
		return runtime.ExitError
	})
	if code != runtime.ExitInterrupted {
		t.Fatalf("code %d, want %d", code, runtime.ExitInterrupted)
	}
}

func TestGuardedNormalExitRunsShutdown(t *testing.T) {
	lc := runtime.NewLifecycle(context.Background(), time.Second)
	if code := guarded(lc, func() int { return 0 }); code != 0 || lc.Cause() != "exit" {
		t.Fatalf("code %d cause %q", code, lc.Cause())
	}
}
