package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/fake"
)

func TestDiagIntegrity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemRoot", root)
	sys32 := filepath.Join(root, "System32")
	svchost := filepath.Join(sys32, "svchost.exe")
	explorer := filepath.Join(root, "explorer.exe")
	lsass := filepath.Join(sys32, "lsass.exe")
	unsigned := filepath.Join(sys32, "zz-unsigned.exe")
	tool := filepath.Join(sys32, "aa-tool.exe")
	fid := func(i uint64) models.FileIdentity {
		return models.FileIdentity{VolumeSerial: 1, FileIndex: i, Size: 4, ModTime: 1}
	}
	files := map[string]fake.FileFixture{
		svchost:  {Content: []byte("svch"), Identity: fid(1)},
		explorer: {Content: []byte("expl"), Identity: fid(2)},
		lsass:    {Content: []byte("lsas"), Identity: fid(3)},
		unsigned: {Content: []byte("othr"), Identity: fid(4)},
		tool:     {Content: []byte("tool"), Identity: fid(5)},
	}
	valid := func(i uint64) models.SignatureRecord {
		return models.SignatureRecord{State: models.SignatureValid, Source: models.SignatureSourceCatalog,
			Signer: models.Known("Microsoft Windows"), CatalogFile: models.Known("example.cat"),
			Identity: models.Known(fid(i)), Revocation: models.RevocationOfflineByDesign}
	}
	src := sources{
		files: &fake.FileSystem{Files: files, Dirs: map[string][]models.DirEntry{sys32: {
			{Name: "svchost.exe"}, {Name: "lsass.exe"}, {Name: "zz-unsigned.exe"}, {Name: "aa-tool.exe"}, {Name: "drivers", IsDir: true},
		}}},
		signatures: &fake.SignatureVerifier{Results: map[string]models.SignatureRecord{
			svchost: valid(1), explorer: valid(2), lsass: valid(3), tool: valid(5),
			unsigned: {State: models.SignatureUnsigned, Source: models.SignatureSourceNone, Identity: models.Known(fid(4)), Detail: "no catalog lists this file"},
		}},
	}
	var b strings.Builder
	if code := integrityReport(context.Background(), &b, src, "", 10, nil); code != 0 {
		t.Fatalf("code %d\n%s", code, b.String())
	}
	out := b.String()
	for _, want := range []string{
		"Inspected 5 files", "Hashed 5", "Unsigned via None 1", "Valid via Catalog 4",
		svchost, "Microsoft Windows", "offline by design", "zz-unsigned.exe", "not findings",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "aa-tool.exe") {
		t.Errorf("a validly signed, cleanly hashed non-key file was listed:\n%s", out)
	}

	var none strings.Builder
	if code := integrityReport(context.Background(), &none, sources{}, "", 1, nil); code != 1 || !strings.Contains(none.String(), "only implemented for Windows") {
		t.Fatalf("no platform: %d %s", code, none.String())
	}
}
