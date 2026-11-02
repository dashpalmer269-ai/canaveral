// Command canaveral is the entry point for the Canaveral forensic triage tool.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) (code int) {
	lc := runtime.NewLifecycle(context.Background(), runtime.DefaultShutdownTimeout)
	defer lc.RecoverTo(&code)
	stopSignals := lc.WatchSignals()
	defer stopSignals()
	defer lc.Shutdown("exit")

	if len(args) > 0 && args[0] == "diag-output" {
		return diagOutput(lc.Context(), args[1:], volumeInspector(), os.Executable, stdout, stderr)
	}

	fs := flag.NewFlagSet("canaveral", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		return emit(stdout, version+"\n", runtime.ExitOK)
	}
	return emit(stderr, fmt.Sprintf("Canaveral %s: pre-implementation build (milestone M2).\n", version)+
		"No collectors are implemented. Nothing was inspected and no report was produced.\n"+
		"Available: 'diag-output [--output PATH]' shows where reports would be written, without writing anything.\n", 2)
}

// emit writes text and returns code, or ExitError if the write failed.
func emit(w io.Writer, text string, code int) int {
	if _, err := io.WriteString(w, text); err != nil {
		return runtime.ExitError
	}
	return code
}

// diagOutput reports the output-destination decision. It never writes.
func diagOutput(ctx context.Context, args []string, insp platform.VolumeInspector, exe func() (string, error), stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diag-output", flag.ContinueOnError)
	fs.SetOutput(stderr)
	override := fs.String("output", "", "explicit output directory to check instead of the default")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var b strings.Builder
	code := diagReport(ctx, &b, *override, insp, exe)
	return emit(stdout, b.String(), code)
}

func diagReport(ctx context.Context, stdout *strings.Builder, override string, insp platform.VolumeInspector, exe func() (string, error)) int {
	fmt.Fprintf(stdout, "Canaveral %s diag-output (read-only: nothing is written)\n\n", version)
	if insp == nil {
		fmt.Fprintln(stdout, "Volume inspection is only implemented for Windows; this build cannot decide an output destination.")
		return runtime.ExitError
	}

	exePath, err := exe()
	if err != nil {
		fmt.Fprintf(stdout, "Executable:        unavailable (%v)\n", err)
		exePath = ""
	} else {
		fmt.Fprintf(stdout, "Executable:        %s\n", exePath)
		if v, err := insp.Volume(ctx, exePath); err != nil {
			fmt.Fprintf(stdout, "Executable volume: unavailable (%v)\n", err)
		} else {
			printVolume(stdout, "Executable volume", v)
		}
	}

	req := runtime.OutputRequest{ExePath: exePath, Override: override}
	dest, err := runtime.ValidateOutput(ctx, insp, req)
	fmt.Fprintln(stdout)
	var rej *runtime.Rejection
	switch {
	case err == nil:
		kind := "default (executable's volume)"
		if dest.Explicit {
			kind = "explicit --output"
		}
		fmt.Fprintf(stdout, "Destination:       %s [%s]\n", dest.Root, kind)
		printVolume(stdout, "Destination volume", dest.Volume)
		fmt.Fprintln(stdout, "\nDecision: ACCEPTED")
		for _, b := range dest.Basis {
			fmt.Fprintf(stdout, "  - %s\n", b)
		}
		return runtime.ExitOK
	case errors.As(err, &rej):
		fmt.Fprintf(stdout, "Destination:       %s\n", rej.Path)
		fmt.Fprintln(stdout, "\nDecision: REFUSED")
		for _, r := range rej.Reasons {
			fmt.Fprintf(stdout, "  - %s\n", r)
		}
		return runtime.ExitError
	default:
		fmt.Fprintf(stdout, "Decision: REFUSED (%v)\n", err)
		return runtime.ExitError
	}
}

func printVolume(w *strings.Builder, label string, v models.VolumeInfo) {
	fmt.Fprintf(w, "%-18s root=%s\n", label+":", v.Root)
	pad := "                   "
	fmt.Fprintf(w, "%sid=%s\n", pad, show(v.VolumeID))
	fmt.Fprintf(w, "%sdrive type=%s  bus=%s  removable media=%s\n", pad, v.DriveType, show(v.BusType), show(v.RemovableMedia))
	fmt.Fprintf(w, "%ssystem volume=%s  read-only=%s  free bytes=%s\n", pad, show(v.IsSystem), show(v.ReadOnly), show(v.FreeBytes))
}

func show[T any](v models.Value[T]) string {
	if x, ok := v.Get(); ok {
		return fmt.Sprint(x)
	}
	return "unavailable (" + v.Reason() + ")"
}
