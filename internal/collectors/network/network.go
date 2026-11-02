package network

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/collectors/process"
	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

// Source is the coverage source name for this collector.
const Source = "collectors/network"

// Confidence is how strongly a socket is attributed to its owning process.
type Confidence string

// Attribution confidence levels (CLAUDE.md M3).
const (
	ConfidenceHigh    Confidence = "High"
	ConfidenceReduced Confidence = "Reduced"
	ConfidenceNone    Confidence = "None"
)

// Socket is one socket table entry with its attributed owner.
type Socket struct {
	models.SocketRecord
	// Owner is the owning process identity. It is Unavailable when the owner
	// cannot be identified; such sockets are unattributed, never guessed.
	Owner models.Value[models.ProcessKey]
	// OwnerName is the owning process's executable name, if attributed.
	OwnerName string
	// Service is the owning service name for a socket inside a shared
	// svchost.exe, when Windows supplies it.
	Service          string
	Confidence       Confidence
	ConfidenceReason string
	LocalClass       AddressClass
	RemoteClass      AddressClass
}

// Snapshot is one read of all socket tables.
type Snapshot struct {
	At       time.Time
	Sockets  []Socket
	Coverage []models.CoverageNote
}

// Result holds the process snapshots taken before and after the socket
// tables, and the attributed sockets.
type Result struct {
	Before  process.Snapshot
	After   process.Snapshot
	Sockets Snapshot
}

// Collect takes a process snapshot, reads every socket table, then takes a
// second process snapshot, and attributes each socket using both. Comparing
// the two snapshots exposes processes that exited, started or had their PID
// reused while the tables were being read.
func Collect(ctx context.Context, ps platform.ProcessSource, ss platform.SocketSource, clock platform.Clock) (Result, error) {
	var res Result
	before, err := process.Collect(ctx, ps, clock)
	res.Before = before
	if err != nil {
		return res, err
	}

	at := clock.Now().UTC()
	var recs []models.SocketRecord
	var cov []models.CoverageNote
	failed := 0
	for _, t := range models.AllSocketTables {
		rows, err := ss.Sockets(ctx, t)
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			failed++
			cov = append(cov, models.CoverageNote{Source: Source, Item: string(t) + " table", Status: models.CoverageUnavailable,
				Reason: "could not be read: " + err.Error(), At: at})
			continue
		}
		cov = append(cov, models.CoverageNote{Source: Source, Item: string(t) + " table", Status: models.CoverageComplete,
			Reason: fmt.Sprintf("%d entries", len(rows)), At: at})
		recs = append(recs, rows...)
	}

	after, err := process.Collect(ctx, ps, clock)
	res.After = after
	if err != nil {
		return res, err
	}
	res.Sockets = Attribute(at, recs, before, after)
	res.Sockets.Coverage = append(cov, res.Sockets.Coverage...)
	if failed == len(models.AllSocketTables) {
		return res, fmt.Errorf("no socket table could be read")
	}
	return res, nil
}

// Attribute assigns an owner and a confidence to every record. It never
// assigns an owner with more confidence than the snapshots support.
func Attribute(at time.Time, recs []models.SocketRecord, before, after process.Snapshot) Snapshot {
	s := Snapshot{At: at, Sockets: make([]Socket, 0, len(recs))}
	counts := map[Confidence]int{}
	noModule := 0
	for _, r := range recs {
		sock := Socket{
			SocketRecord: r,
			LocalClass:   Classify(r.Local.Addr()),
			RemoteClass:  Classify(r.Remote.Addr()),
		}
		attribute(&sock, before, after)
		if p, ok := pick(r.OwnerPID, before, after); ok && strings.EqualFold(p.Name, "svchost.exe") {
			if m, ok := r.OwnerModule.Get(); ok && !strings.EqualFold(m, "svchost.exe") {
				sock.Service = m
			}
		}
		if !r.OwnerModule.IsKnown() && r.OwnerPID != 0 {
			noModule++
		}
		counts[sock.Confidence]++
		s.Sockets = append(s.Sockets, sock)
	}
	s.Coverage = append(s.Coverage, models.CoverageNote{
		Source: Source, Item: "socket attribution", Status: models.CoverageComplete, At: at,
		Reason: fmt.Sprintf("%d sockets: %d attributed with high confidence, %d with reduced confidence, %d unattributed",
			len(recs), counts[ConfidenceHigh], counts[ConfidenceReduced], counts[ConfidenceNone]),
	})
	if noModule > 0 {
		s.Coverage = append(s.Coverage, models.CoverageNote{
			Source: Source, Item: "owning module", Status: models.CoveragePartial, At: at,
			Reason: fmt.Sprintf("Windows supplied no owning module for %d sockets that have an owning PID", noModule),
		})
	}
	return s
}

// pick returns the process for pid, preferring the later snapshot.
func pick(pid uint32, before, after process.Snapshot) (process.Process, bool) {
	if p, ok := after.ByPID(pid); ok {
		return p, true
	}
	return before.ByPID(pid)
}

func attribute(s *Socket, before, after process.Snapshot) {
	pid := s.OwnerPID
	if pid == 0 {
		s.unattributed("Windows reported no owning process (PID 0); TIME_WAIT sockets and some kernel-held sockets have no owner")
		return
	}
	b, inB := before.ByPID(pid)
	a, inA := after.ByPID(pid)

	var p process.Process
	switch {
	case !inB && !inA:
		s.unattributed(fmt.Sprintf("owning PID %d was in neither process snapshot taken around the socket read", pid))
		return
	case inB && inA && b.KeyComplete && a.KeyComplete && b.Key != a.Key:
		s.unattributed(fmt.Sprintf("PID %d belonged to two different processes during collection; the owner is ambiguous", pid))
		return
	case inB && inA && b.KeyComplete && a.KeyComplete:
		p = a
		s.Confidence = ConfidenceHigh
		s.ConfidenceReason = fmt.Sprintf("PID %d had the same process identity before and after the socket tables were read", pid)
	case inB && inA && a.KeyComplete:
		p = a
		s.Confidence = ConfidenceReduced
		s.ConfidenceReason = fmt.Sprintf("PID %d's creation time was unreadable in the first snapshot, so its identity across the socket read cannot be confirmed", pid)
	case inB && inA:
		p = a // its incomplete key is handled below
	case inB:
		p = b
		s.Confidence = ConfidenceReduced
		s.ConfidenceReason = fmt.Sprintf("PID %d exited during collection; attributed from the snapshot taken before the socket read", pid)
	default:
		p = a
		s.Confidence = ConfidenceReduced
		s.ConfidenceReason = fmt.Sprintf("PID %d started during collection; attributed from the snapshot taken after the socket read", pid)
	}
	s.OwnerName = p.Name

	if !p.KeyComplete {
		s.Owner = models.Unavailable[models.ProcessKey](fmt.Sprintf("the creation time of PID %d could not be read", pid))
		s.Confidence = ConfidenceReduced
		s.ConfidenceReason = fmt.Sprintf("PID %d is running, but its creation time could not be read, so PID reuse cannot be ruled out", pid)
		return
	}
	s.Owner = models.Known(p.Key)

	// The socket entry timestamp is the socket's creation time, not the
	// process's (CLAUDE.md A5). A socket older than its process is possible
	// through handle inheritance, so it lowers confidence instead of
	// rejecting the attribution.
	if ts, ok := s.EntryCreateTime.Get(); ok {
		if ts < p.Key.CreateTime {
			s.Confidence = ConfidenceReduced
			s.ConfidenceReason += "; the socket entry was created before this process started, which happens with inherited handles or after PID reuse"
		}
	} else if s.Confidence == ConfidenceHigh {
		s.ConfidenceReason += "; no socket timestamp was available to cross-check"
	}
	if pid == 4 {
		s.ConfidenceReason += "; PID 4 is the kernel (System), so the user-mode component that requested this socket is not identified"
	}
}

func (s *Socket) unattributed(reason string) {
	s.Owner = models.Unavailable[models.ProcessKey](reason)
	s.Confidence = ConfidenceNone
	s.ConfidenceReason = reason
}
