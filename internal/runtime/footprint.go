package runtime

import (
	"fmt"
	"strings"
)

// WindowsGeneratedArtifacts lists host changes Windows itself may make while
// the tool runs or the drive is attached. A user-mode program cannot prevent
// or verify their absence; they are disclosed, never suppressed (CLAUDE.md
// A16, SPEC section 3).
var WindowsGeneratedArtifacts = []string{
	"Prefetch entry for Canaveral.exe and other execution records Windows keeps for any program it runs",
	"USB device records created when the drive was connected (USBSTOR and MountedDevices registry entries, setupapi.dev.log)",
	"NTFS last-access time updates on files that are read, where last-access updates are enabled",
	"WMI service activity (wmiprvse.exe) when WMI is queried",
	"Event log entries Windows writes on its own, such as process creation or UAC events when auditing is enabled",
	"Windows Error Reporting files if the process crashes",
	"Paging file or hibernation file contents, which may hold pieces of the tool's memory",
}

// FootprintReview summarizes what the tool itself created on the host.
type FootprintReview struct {
	Approved []string
	// Inside are tool-created resources inside an approved output root.
	Inside []Resource
	// Outside are tool-created resources outside every approved root. This
	// is expected to be empty; anything here is a defect to investigate.
	Outside []Resource
	// Leftovers are temporary or lost resources that may still exist.
	Leftovers []Resource
	// WindowsGenerated is the disclosure list of changes outside the tool's
	// control.
	WindowsGenerated []string
	Summary          string
}

// Review builds the footprint review from the ledger.
func (l *Ledger) Review() FootprintReview {
	res := l.Resources()
	approved := l.Approved()
	rv := FootprintReview{Approved: approved, WindowsGenerated: append([]string(nil), WindowsGeneratedArtifacts...)}

	for _, r := range res {
		inside := false
		for _, root := range approved {
			if within(root, r.Path) {
				inside = true
				break
			}
		}
		if inside {
			rv.Inside = append(rv.Inside, r)
		} else {
			rv.Outside = append(rv.Outside, r)
		}
		switch r.State {
		case StateTemporary, StateRemoveFailed, StateNotRemoved, StateLost:
			rv.Leftovers = append(rv.Leftovers, r)
		}
	}

	var b strings.Builder
	if len(rv.Outside) == 0 {
		fmt.Fprintf(&b, "Canaveral's own write path recorded %d resources, all inside the approved output location (%s).",
			len(rv.Inside), strings.Join(approved, ", "))
	} else {
		fmt.Fprintf(&b, "WARNING: Canaveral recorded %d resources outside the approved output location. Review them below.", len(rv.Outside))
	}
	if len(rv.Leftovers) > 0 {
		fmt.Fprintf(&b, " %d resources may remain on the output device and could not be confirmed removed.", len(rv.Leftovers))
	}
	b.WriteString(" Windows may also have recorded activity on its own, listed below; a user-mode tool cannot prevent or verify this.")
	rv.Summary = b.String()
	return rv
}
