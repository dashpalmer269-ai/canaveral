package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"testing"
)

func TestObjectEmbedsManifest(t *testing.T) {
	manifest, err := os.ReadFile("../../cmd/canaveral/canaveral.manifest")
	if err != nil {
		t.Fatal(err)
	}
	obj := build(manifest)
	if !bytes.Equal(obj, build(manifest)) {
		t.Fatal("output is not reproducible")
	}

	f, err := pe.NewFile(bytes.NewReader(obj))
	if err != nil {
		t.Fatalf("not a valid COFF object: %v", err)
	}
	if f.Machine != machineAMD64 || len(f.Sections) != 1 || f.Sections[0].Name != ".rsrc" {
		t.Fatalf("machine %#x sections %v", f.Machine, f.Sections)
	}
	s := f.Sections[0]
	if len(s.Relocs) != 1 || s.Relocs[0].Type != relAMD64Addr32NB || s.Relocs[0].VirtualAddress != offDataEntry {
		t.Fatalf("relocations %+v", s.Relocs)
	}
	if len(f.Symbols) != 1 || f.Symbols[0].Name != ".rsrc" || f.Symbols[0].SectionNumber != 1 {
		t.Fatalf("symbols %+v", f.Symbols)
	}
	data, err := s.Data()
	if err != nil {
		t.Fatal(err)
	}

	// Walk type -> name -> language -> data entry, as Windows does.
	le := binary.LittleEndian
	entry := func(dirOff uint32) (id, target uint32) {
		if n := le.Uint16(data[dirOff+14:]); n != 1 {
			t.Fatalf("directory at %d has %d entries", dirOff, n)
		}
		return le.Uint32(data[dirOff+16:]), le.Uint32(data[dirOff+20:])
	}
	id, next := entry(offTypeDir)
	if id != rtManifest || next&subdirFlag == 0 {
		t.Fatalf("type entry %d %#x", id, next)
	}
	id, next = entry(next &^ subdirFlag)
	if id != manifestID || next&subdirFlag == 0 {
		t.Fatalf("name entry %d %#x", id, next)
	}
	id, next = entry(next &^ subdirFlag)
	if id != langEnUS || next&subdirFlag != 0 {
		t.Fatalf("language entry %d %#x", id, next)
	}
	off, size := le.Uint32(data[next:]), le.Uint32(data[next+4:])
	if !bytes.Equal(data[off:off+size], manifest) {
		t.Fatal("embedded manifest differs from the source file")
	}
	if !bytes.Contains(manifest, []byte(`level="requireAdministrator"`)) {
		t.Fatal("manifest does not request administrator rights (CLAUDE.md A8)")
	}
}
