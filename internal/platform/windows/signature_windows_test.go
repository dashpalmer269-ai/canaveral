//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// The hand-declared structures must match the Windows x64 layouts.
func TestTrustStructLayouts(t *testing.T) {
	var s cryptProviderSgnr
	var c cryptProviderCert
	var w winTrustCatalogInfo
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"CRYPT_PROVIDER_SGNR.sftVerifyAsOf", unsafe.Offsetof(s.verifyAsOf), 4},
		{"CRYPT_PROVIDER_SGNR.csCertChain", unsafe.Offsetof(s.certChainLen), 12},
		{"CRYPT_PROVIDER_SGNR.pasCertChain", unsafe.Offsetof(s.certChain), 16},
		{"CRYPT_PROVIDER_SGNR.csCounterSigners", unsafe.Offsetof(s.counterSignersLen), 44},
		{"CRYPT_PROVIDER_SGNR.pasCounterSigners", unsafe.Offsetof(s.counterSigners), 48},
		{"sizeof CRYPT_PROVIDER_SGNR", unsafe.Sizeof(s), 64},
		{"CRYPT_PROVIDER_CERT.pCert", unsafe.Offsetof(c.cert), 8},
		{"WINTRUST_CATALOG_INFO.pcwszCatalogFilePath", unsafe.Offsetof(w.catalogFilePath), 8},
		{"WINTRUST_CATALOG_INFO.hMemberFile", unsafe.Offsetof(w.memberFile), 32},
		{"WINTRUST_CATALOG_INFO.cbCalculatedFileHash", unsafe.Offsetof(w.calculatedFileHashSize), 48},
		{"WINTRUST_CATALOG_INFO.hCatAdmin", unsafe.Offsetof(w.catAdmin), 64},
		{"sizeof WINTRUST_CATALOG_INFO", unsafe.Sizeof(w), 72},
		{"sizeof CATALOG_INFO", unsafe.Sizeof(catalogInfo{}), 524},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func system32(name string) string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", name)
}

// Acceptance (M4), the key regression test: core Windows binaries verify as
// validly signed, via the catalog or an embedded signature.
func TestWindowsBinariesVerify(t *testing.T) {
	for _, p := range []string{system32("svchost.exe"), filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), system32("lsass.exe")} {
		rec := SignatureVerifier{}.Verify(ctx, p)
		signer, _ := rec.Signer.Get()
		t.Logf("%s: state=%s source=%s signer=%q catalog=%v signedAt=%v revocation=%q detail=%s",
			p, rec.State, rec.Source, signer, rec.CatalogFile, rec.SignedAt, rec.Revocation, rec.Detail)
		if rec.State != models.SignatureValid {
			t.Errorf("%s: state %s (%s)", p, rec.State, rec.Detail)
		}
		if rec.Source != models.SignatureSourceCatalog && rec.Source != models.SignatureSourceEmbedded {
			t.Errorf("%s: source %s", p, rec.Source)
		}
		if !strings.Contains(signer, "Microsoft") {
			t.Errorf("%s: signer %q", p, signer)
		}
		if rec.Revocation != models.RevocationOfflineByDesign {
			t.Errorf("%s: revocation %q", p, rec.Revocation)
		}
		if rec.Source == models.SignatureSourceCatalog && !rec.CatalogFile.IsKnown() {
			t.Errorf("%s: catalog source without a catalog path", p)
		}
		fsID, err := identityOf(p)
		if id, ok := rec.Identity.Get(); err != nil || !ok || id != fsID {
			t.Errorf("%s: verified identity %+v, file system identity %+v (%v)", p, rec.Identity, fsID, err)
		}
	}
}

func identityOf(p string) (models.FileIdentity, error) {
	f, err := FileSystem{}.Open(ctx, p)
	if err != nil {
		return models.FileIdentity{}, err
	}
	defer func() { _ = f.Close() }()
	return f.Identity()
}

// An embedded Authenticode signature verifies through the embedded path.
func TestEmbeddedSignatureVerifies(t *testing.T) {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		rec := SignatureVerifier{}.Verify(ctx, p)
		signer, _ := rec.Signer.Get()
		t.Logf("%s: state=%s source=%s signer=%q signedAt=%v detail=%s", p, rec.State, rec.Source, signer, rec.SignedAt, rec.Detail)
		if rec.State == models.SignatureValid && rec.Source == models.SignatureSourceEmbedded {
			return
		}
	}
	t.Fatal("no embedded-signed binary verified through the embedded path")
}

// Acceptance (M4): an unsigned file is Unsigned with source None.
func TestUnsignedFile(t *testing.T) {
	exe, _ := os.Executable() // go test binaries are not signed
	rec := SignatureVerifier{}.Verify(ctx, exe)
	if rec.State != models.SignatureUnsigned || rec.Source != models.SignatureSourceNone || rec.Signer.IsKnown() {
		t.Fatalf("%+v", rec)
	}
	t.Logf("unsigned: %s", rec.Detail)
}

// Acceptance (M4): a failure to read is Unavailable, distinct from Unsigned
// and Invalid.
func TestUnreadableFileIsUnavailable(t *testing.T) {
	for _, p := range []string{`C:\canaveral-no-such-file.exe`, system32(`config\SAM`)} {
		rec := SignatureVerifier{}.Verify(ctx, p)
		if rec.State != models.SignatureUnavailable || rec.Source != models.SignatureSourceNone {
			t.Errorf("%s: %+v", p, rec)
		}
		t.Logf("%s: %s", p, rec.Detail)
	}
}

// Acceptance (M4): a present but failing signature is Invalid. The fixture is
// a script built from scratch in CI and signed with a throwaway certificate
// whose root is not trusted, so verification fails on the chain. No existing
// signed file is modified.
func TestUntrustedSignatureIsInvalid(t *testing.T) {
	p := os.Getenv("CANAVERAL_UNTRUSTED_SIGNED")
	if p == "" {
		if os.Getenv("CANAVERAL_REQUIRE_FIXTURES") == "1" {
			t.Fatal("CANAVERAL_UNTRUSTED_SIGNED must be set when CANAVERAL_REQUIRE_FIXTURES=1")
		}
		t.Skip("CANAVERAL_UNTRUSTED_SIGNED not set")
	}
	rec := SignatureVerifier{}.Verify(ctx, p)
	signer, _ := rec.Signer.Get()
	t.Logf("%s: state=%s source=%s signer=%q detail=%s", p, rec.State, rec.Source, signer, rec.Detail)
	if rec.State != models.SignatureInvalid || rec.Source != models.SignatureSourceEmbedded {
		t.Fatalf("untrusted signature: %+v", rec)
	}
	if !strings.Contains(rec.Detail, "UNTRUSTEDROOT") {
		t.Fatalf("detail does not name the untrusted root: %s", rec.Detail)
	}
}
