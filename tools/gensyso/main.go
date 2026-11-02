// Command gensyso writes a COFF object (.syso) that embeds a Windows
// application manifest as resource RT_MANIFEST #1. The Go linker merges it
// into the executable's .rsrc section. It replaces a third-party resource
// compiler so the build depends only on this repository. It is a build tool;
// it is never part of Canaveral.exe.
//
//	go run ./tools/gensyso -manifest cmd/canaveral/canaveral.manifest -o cmd/canaveral/rsrc_windows_amd64.syso
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

const (
	machineAMD64     = 0x8664
	rtManifest       = 24
	manifestID       = 1
	langEnUS         = 0x0409
	scnInitData      = 0x00000040
	scnMemRead       = 0x40000000
	relAMD64Addr32NB = 3 // IMAGE_REL_AMD64_ADDR32NB: RVA of the target
	symClassStatic   = 3
	subdirFlag       = 0x80000000

	fileHeaderSize    = 20
	sectionHeaderSize = 40
	relocSize         = 10
	symbolSize        = 18

	// Offsets inside the .rsrc section.
	offTypeDir    = 0
	offNameDir    = 24
	offLangDir    = 48
	offDataEntry  = 72
	offData       = 88
	dirHeaderSize = 16
)

func main() {
	manifest := flag.String("manifest", "", "manifest XML file")
	out := flag.String("o", "", "output .syso file")
	flag.Parse()
	if *manifest == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: gensyso -manifest FILE -o FILE")
		os.Exit(2)
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, build(data), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// build returns the COFF object bytes. The output depends only on manifest,
// so it is reproducible.
func build(manifest []byte) []byte {
	// .rsrc section: three directory levels, one data entry, then the data.
	var sec bytes.Buffer
	dir := func(entries uint16) {
		w(&sec, uint32(0), uint32(0), uint16(0), uint16(0), uint16(0), entries) // no named entries, N id entries
	}
	dir(1)
	w(&sec, uint32(rtManifest), uint32(subdirFlag|offNameDir))
	dir(1)
	w(&sec, uint32(manifestID), uint32(subdirFlag|offLangDir))
	dir(1)
	w(&sec, uint32(langEnUS), uint32(offDataEntry))
	// IMAGE_RESOURCE_DATA_ENTRY. OffsetToData holds the data's offset within
	// the section; the ADDR32NB relocation adds the section's RVA.
	w(&sec, uint32(offData), uint32(len(manifest)), uint32(0), uint32(0))
	sec.Write(manifest)
	for sec.Len()%8 != 0 {
		sec.WriteByte(0)
	}

	rawPtr := uint32(fileHeaderSize + sectionHeaderSize)
	relocPtr := rawPtr + uint32(sec.Len())
	symPtr := relocPtr + relocSize

	var f bytes.Buffer
	// IMAGE_FILE_HEADER
	w(&f, uint16(machineAMD64), uint16(1), uint32(0), symPtr, uint32(1), uint16(0), uint16(0))
	// IMAGE_SECTION_HEADER
	f.WriteString(".rsrc\x00\x00\x00")
	w(&f, uint32(0), uint32(0), uint32(sec.Len()), rawPtr, relocPtr, uint32(0), uint16(1), uint16(0), uint32(scnInitData|scnMemRead))
	f.Write(sec.Bytes())
	// IMAGE_RELOCATION
	w(&f, uint32(offDataEntry), uint32(0), uint16(relAMD64Addr32NB))
	// IMAGE_SYMBOL for the section, then an empty string table.
	f.WriteString(".rsrc\x00\x00\x00")
	w(&f, uint32(0), int16(1), uint16(0), uint8(symClassStatic), uint8(0))
	w(&f, uint32(4))
	return f.Bytes()
}

func w(b *bytes.Buffer, vals ...any) {
	for _, v := range vals {
		_ = binary.Write(b, binary.LittleEndian, v)
	}
}
