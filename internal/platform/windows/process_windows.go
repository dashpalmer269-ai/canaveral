//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.ProcessSource = ProcessSource{}

// ProcessSource enumerates processes with a Toolhelp snapshot and opens each
// one with PROCESS_QUERY_LIMITED_INFORMATION only. It never enables
// SeDebugPrivilege: adjusting the token can write a 4703 audit event on the
// host, and limited query access reaches most processes, including protected
// ones.
type ProcessSource struct{}

// Processes returns one record per running process.
func (ProcessSource) Processes(ctx context.Context) ([]models.ProcessRecord, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", mapErr(err))
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var recs []models.ProcessRecord
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		recs = append(recs, describeProcess(e.ProcessID, e.ParentProcessID, windows.UTF16ToString(e.ExeFile[:])))
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("Process32Next: %w", mapErr(err))
	}
	return recs, nil
}

func describeProcess(pid, ppid uint32, name string) models.ProcessRecord {
	rec := models.ProcessRecord{PID: pid, ParentPID: ppid, Name: name}

	var sess uint32
	if err := windows.ProcessIdToSessionId(pid, &sess); err != nil {
		rec.SessionID = models.Unavailable[uint32]("ProcessIdToSessionId: " + err.Error())
	} else {
		rec.SessionID = models.Known(sess)
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		reason := "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION): " + err.Error()
		rec.CreateTime = models.Unavailable[models.FileTime](reason)
		rec.ImagePath = models.Unavailable[string](reason)
		rec.CommandLine = models.Unavailable[string](reason)
		rec.UserSID = models.Unavailable[string](reason)
		rec.UserName = models.Unavailable[string](reason)
		rec.Protection = models.Unavailable[string](reason)
		return rec
	}
	defer func() { _ = windows.CloseHandle(h) }()

	rec.CreateTime = creationTime(h)
	rec.ImagePath = imagePath(h)
	rec.CommandLine = commandLine(h)
	rec.Protection = protection(h)
	rec.UserSID, rec.UserName = tokenUser(h)
	return rec
}

func creationTime(h windows.Handle) models.Value[models.FileTime] {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return models.Unavailable[models.FileTime]("GetProcessTimes: " + err.Error())
	}
	ft := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	if ft == 0 {
		return models.Unavailable[models.FileTime]("GetProcessTimes reported a zero creation time")
	}
	return models.Known(models.FileTime(ft))
}

func imagePath(h windows.Handle) models.Value[string] {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return models.Unavailable[string]("QueryFullProcessImageName: " + err.Error())
	}
	return models.Known(windows.UTF16ToString(buf[:size]))
}

func commandLine(h windows.Handle) models.Value[string] {
	size := uint32(4096)
	for range 5 {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &ret)
		if err == nil {
			s := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
			runtime.KeepAlive(buf)
			return models.Known(s)
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) && !errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) && !errors.Is(err, windows.STATUS_BUFFER_OVERFLOW) {
			return models.Unavailable[string]("NtQueryInformationProcess(ProcessCommandLineInformation): " + err.Error())
		}
		if ret > size {
			size = ret
		} else {
			size *= 2
		}
	}
	return models.Unavailable[string]("NtQueryInformationProcess(ProcessCommandLineInformation): buffer kept growing")
}

func protection(h windows.Handle) models.Value[string] {
	var b byte
	var ret uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessProtectionInformation, unsafe.Pointer(&b), 1, &ret); err != nil {
		return models.Unavailable[string]("NtQueryInformationProcess(ProcessProtectionInformation): " + err.Error())
	}
	return models.Known(protectionName(b))
}

func tokenUser(h windows.Handle) (models.Value[string], models.Value[string]) {
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		r := "OpenProcessToken: " + err.Error()
		return models.Unavailable[string](r), models.Unavailable[string](r)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		r := "GetTokenInformation(TokenUser): " + err.Error()
		return models.Unavailable[string](r), models.Unavailable[string](r)
	}
	sid := tu.User.Sid.String()
	return models.Known(sid), accounts.name(tu.User.Sid, sid)
}

// accounts caches SID-to-name lookups, restricted to lookups that stay on
// this machine (see accountLookupIsLocal).
var accounts = &accountCache{names: map[string]models.Value[string]{}}

type accountCache struct {
	once       sync.Once
	machineSID string
	mu         sync.Mutex
	names      map[string]models.Value[string]
}

func (c *accountCache) name(sid *windows.SID, s string) models.Value[string] {
	c.once.Do(func() { c.machineSID = machineDomainSID() })
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.names[s]; ok {
		return v
	}
	var v models.Value[string]
	if !accountLookupIsLocal(s, c.machineSID) {
		v = models.Unavailable[string]("not resolved: looking up a domain or cloud account can contact a domain controller, which would be network traffic")
	} else if account, domain, _, err := sid.LookupAccount(""); err != nil {
		v = models.Unavailable[string]("LookupAccountSid: " + err.Error())
	} else if domain != "" {
		v = models.Known(domain + `\` + account)
	} else {
		v = models.Known(account)
	}
	c.names[s] = v
	return v
}

// machineDomainSID returns the local account domain SID by looking up the
// computer's own name, which LookupAccountName resolves from the local SAM.
func machineDomainSID() string {
	name, err := windows.ComputerName()
	if err != nil {
		return ""
	}
	sid, _, accType, err := windows.LookupSID("", name)
	if err != nil || accType != windows.SidTypeDomain {
		return ""
	}
	return sid.String()
}
