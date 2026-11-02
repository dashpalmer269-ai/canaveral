package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dashpalmer269-ai/canaveral/internal/integrity"
	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/runtime"
)

// keyBinaries are always inspected: the M4 regression set, as path segments
// under %SystemRoot%.
var keyBinaries = [][]string{{"System32", "svchost.exe"}, {"explorer.exe"}, {"System32", "lsass.exe"}}

func keyPath(root string, segs []string) string {
	return filepath.Join(append([]string{root}, segs...)...)
}

// diagIntegrity hashes and verifies files and prints the results. It only
// reads the files; it writes nothing but its own output.
func diagIntegrity(ctx context.Context, args []string, src sources, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diag-integrity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", `directory whose files to inspect (default %SystemRoot%\System32)`)
	limit := fs.Int("limit", 500, "maximum number of files taken from --dir")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var b strings.Builder
	code := integrityReport(ctx, &b, src, *dir, *limit, fs.Args())
	return emit(stdout, b.String(), code)
}

func integrityReport(ctx context.Context, b *strings.Builder, src sources, dir string, limit int, extra []string) int {
	fmt.Fprintf(b, "Canaveral %s diag-integrity (read-only: nothing is written)\n\n", version)
	if src.files == nil || src.signatures == nil {
		b.WriteString("Hashing and signature verification are only implemented for Windows.\n")
		return runtime.ExitError
	}
	root := os.Getenv("SystemRoot")
	if dir == "" {
		dir = filepath.Join(root, "System32")
	}

	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		if k := strings.ToLower(p); !seen[k] {
			seen[k] = true
			paths = append(paths, p)
		}
	}
	for _, k := range keyBinaries {
		add(keyPath(root, k))
	}
	for _, p := range extra {
		add(p)
	}
	if limit > 0 {
		entries, err := src.files.ReadDir(ctx, dir)
		if err != nil {
			fmt.Fprintf(b, "Listing %s failed: %v\n", dir, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		taken := 0
		for _, e := range entries {
			if taken >= limit {
				break
			}
			if e.IsDir || e.Reparse {
				continue
			}
			add(filepath.Join(dir, e.Name))
			taken++
		}
	}

	in := integrity.NewInspector(src.files, src.signatures, integrity.NewCache(0))
	hashStates := map[models.HashState]int{}
	sigStates := map[string]int{}
	var key, notable []integrity.Report
	for _, p := range paths {
		if ctx.Err() != nil {
			fmt.Fprintf(b, "Canceled after %d files.\n", len(key)+len(notable))
			return runtime.ExitInterrupted
		}
		r := in.Inspect(ctx, p)
		hashStates[r.Hash.State]++
		sigStates[string(r.Signature.State)+" via "+string(r.Signature.Source)]++
		if isKey(p, root) {
			key = append(key, r)
		} else if r.Signature.State != models.SignatureValid || r.Hash.State != models.HashComplete {
			notable = append(notable, r)
		}
	}

	fmt.Fprintf(b, "Inspected %d files (key binaries plus up to %d from %s)\n", len(paths), limit, dir)
	fmt.Fprintf(b, "Hash results:      %s\n", counts(hashStates))
	fmt.Fprintf(b, "Signature results: %s\n", counts(sigStates))
	b.WriteString("Revocation:        " + models.RevocationOfflineByDesign + "\n")

	b.WriteString("\nKey binaries:\n")
	for _, r := range key {
		writeIntegrity(b, r)
	}
	if len(notable) > 0 {
		fmt.Fprintf(b, "\nFiles that are not validly signed or could not be hashed (%d). These are facts for review, not findings:\n", len(notable))
		for i, r := range notable {
			if i == 50 {
				fmt.Fprintf(b, "  ... %d more\n", len(notable)-50)
				break
			}
			writeIntegrity(b, r)
		}
	}
	return runtime.ExitOK
}

func isKey(p, root string) bool {
	for _, k := range keyBinaries {
		if strings.EqualFold(p, keyPath(root, k)) {
			return true
		}
	}
	return false
}

func writeIntegrity(b *strings.Builder, r integrity.Report) {
	fmt.Fprintf(b, "  %s\n", r.Path)
	if d, ok := r.Hash.SHA256.Get(); ok {
		fmt.Fprintf(b, "    sha256:    %s\n", d)
	} else {
		fmt.Fprintf(b, "    sha256:    %s (%s)\n", r.Hash.State, r.Hash.SHA256.Reason())
	}
	s := r.Signature
	fmt.Fprintf(b, "    signature: %s via %s, signer %s, timestamp %s\n", s.State, s.Source, show(s.Signer), show(s.SignedAt))
	if c, ok := s.CatalogFile.Get(); ok {
		fmt.Fprintf(b, "    catalog:   %s\n", c)
	}
	fmt.Fprintf(b, "    detail:    %s\n", s.Detail)
	if r.ChangedDuringInspection {
		fmt.Fprintf(b, "    CHANGED DURING INSPECTION: %s\n", r.Note)
	}
}

func counts[K ~string](m map[K]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[K(k)])
	}
	return strings.Join(parts, ", ")
}
