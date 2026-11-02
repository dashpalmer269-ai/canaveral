package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dashpalmer269-ai/canaveral/internal/collectors/network"
	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

// sources are the platform implementations the diagnostics use. Fields are
// nil on platforms without an implementation.
type sources struct {
	volumes    platform.VolumeInspector
	processes  platform.ProcessSource
	sockets    platform.SocketSource
	privileges platform.PrivilegeSource
}

// diagSnapshot prints privileges, the process inventory's coverage and every
// attributed socket. It never writes anything but its own output.
func diagSnapshot(ctx context.Context, src sources, stdout io.Writer) int {
	var b strings.Builder
	code := snapshotReport(ctx, &b, src, platform.SystemClock{})
	return emit(stdout, b.String(), code)
}

func snapshotReport(ctx context.Context, b *strings.Builder, src sources, clock platform.Clock) int {
	fmt.Fprintf(b, "Canaveral %s diag-snapshot (read-only: nothing is written)\n\n", version)
	if src.processes == nil || src.sockets == nil || src.privileges == nil {
		b.WriteString("Process and socket collection is only implemented for Windows.\n")
		return runtime.ExitError
	}

	elev, err := src.privileges.Elevation(ctx)
	if err != nil {
		fmt.Fprintf(b, "Privileges: unavailable (%v)\n", err)
	} else {
		fmt.Fprintf(b, "Privileges: elevated=%s integrity=%s administrators-group=%s\n",
			show(elev.Elevated), show(elev.IntegrityLevel), show(elev.AdminMember))
		if e, ok := elev.Elevated.Get(); ok && !e {
			b.WriteString("  Not elevated: other users' processes and protected processes will be partly unreadable.\n" +
				"  They are listed as coverage gaps below, never as findings.\n")
		}
	}

	res, err := network.Collect(ctx, src.processes, src.sockets, clock)
	if err != nil {
		fmt.Fprintf(b, "\nCollection failed: %v\n", err)
		writeCoverage(b, append(res.Before.Coverage, res.Sockets.Coverage...))
		return runtime.ExitError
	}

	fmt.Fprintf(b, "Processes: %d in the first snapshot, %d in the second\n", len(res.Before.Processes), len(res.After.Processes))
	perTable := map[models.SocketTable]int{}
	perConf := map[network.Confidence]int{}
	for _, s := range res.Sockets.Sockets {
		perTable[s.Table]++
		perConf[s.Confidence]++
	}
	fmt.Fprintf(b, "Sockets: %d (TCPv4 %d, TCPv6 %d, UDPv4 %d, UDPv6 %d)\n", len(res.Sockets.Sockets),
		perTable[models.TableTCPv4], perTable[models.TableTCPv6], perTable[models.TableUDPv4], perTable[models.TableUDPv6])
	fmt.Fprintf(b, "Attribution: High %d, Reduced %d, None %d\n\n", perConf[network.ConfidenceHigh], perConf[network.ConfidenceReduced], perConf[network.ConfidenceNone])

	socks := append([]network.Socket(nil), res.Sockets.Sockets...)
	sort.SliceStable(socks, func(i, j int) bool {
		if socks[i].Table != socks[j].Table {
			return socks[i].Table < socks[j].Table
		}
		return socks[i].Local.Port() < socks[j].Local.Port()
	})
	rows := [][]string{{"TABLE", "LOCAL", "REMOTE", "STATE", "PID", "OWNER", "CONF", "SERVICE", "CLASSES"}}
	var notes []string
	for _, s := range socks {
		remote := "-"
		if s.Remote.IsValid() {
			remote = s.Remote.String()
		}
		owner := s.OwnerName
		if owner == "" {
			owner = "(unattributed)"
		}
		state := string(s.State)
		if state == "" {
			state = "-"
		}
		rows = append(rows, []string{string(s.Table), s.Local.String(), remote, state, fmt.Sprint(s.OwnerPID), owner,
			string(s.Confidence), dash(s.Service), string(s.LocalClass) + "/" + string(s.RemoteClass)})
		if s.Confidence != network.ConfidenceHigh {
			notes = append(notes, fmt.Sprintf("  %s %s pid %d: [%s] %s", s.Table, s.Local, s.OwnerPID, s.Confidence, s.ConfidenceReason))
		}
	}
	writeTable(b, rows)
	if len(notes) > 0 {
		b.WriteString("\nWhy some sockets are not High confidence:\n")
		b.WriteString(strings.Join(notes, "\n") + "\n")
	}
	writeCoverage(b, append(res.After.Coverage, res.Sockets.Coverage...))
	return runtime.ExitOK
}

func writeCoverage(b *strings.Builder, notes []models.CoverageNote) {
	if len(notes) == 0 {
		return
	}
	b.WriteString("\nCoverage:\n")
	for _, n := range notes {
		fmt.Fprintf(b, "  [%s] %s: %s\n", n.Status, n.Item, n.Reason)
	}
}

func writeTable(b *strings.Builder, rows [][]string) {
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			widths[i] = max(widths[i], len(c))
		}
	}
	for _, r := range rows {
		for i, c := range r {
			if i == len(r)-1 {
				b.WriteString(c)
			} else {
				fmt.Fprintf(b, "%-*s  ", widths[i], c)
			}
		}
		b.WriteString("\n")
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
