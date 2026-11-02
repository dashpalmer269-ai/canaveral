package integrity

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

type countingVerifier struct {
	calls atomic.Int64
	rec   models.SignatureRecord
}

func (v *countingVerifier) Verify(context.Context, string) models.SignatureRecord {
	v.calls.Add(1)
	return v.rec
}

func validSig(id models.FileIdentity) models.SignatureRecord {
	return models.SignatureRecord{State: models.SignatureValid, Source: models.SignatureSourceCatalog,
		Signer: models.Known("Microsoft Windows"), Identity: models.Known(id), Revocation: models.RevocationOfflineByDesign}
}

func TestInspectCombinesAndCaches(t *testing.T) {
	content := []byte("svchost bytes")
	fid := id(5, uint64(len(content)))
	fs := &scriptFS{files: map[string]*scripted{"svchost.exe": stable(content, 5)}}
	v := &countingVerifier{rec: validSig(fid)}
	in := NewInspector(fs, v, NewCache(0))

	r := in.Inspect(ctx, "svchost.exe")
	if r.Hash.State != models.HashComplete || r.Signature.State != models.SignatureValid || r.ChangedDuringInspection {
		t.Fatalf("%+v", r)
	}
	r2 := in.Inspect(ctx, "svchost.exe")
	if v.calls.Load() != 1 || !r2.Hash.Cached || r2.Signature.State != models.SignatureValid {
		t.Fatalf("second inspection: verifier calls %d, %+v", v.calls.Load(), r2)
	}
}

func TestInspectDetectsChangeBetweenHashAndSignature(t *testing.T) {
	content := []byte("bytes")
	fs := &scriptFS{files: map[string]*scripted{"f": stable(content, 5)}}
	v := &countingVerifier{rec: validSig(id(6, 99))} // the verifier saw another file
	in := NewInspector(fs, v, NewCache(0))
	r := in.Inspect(ctx, "f")
	if !r.ChangedDuringInspection || !strings.Contains(r.Note, "between hashing and signature verification") {
		t.Fatalf("%+v", r)
	}
	in.Inspect(ctx, "f")
	if v.calls.Load() != 2 {
		t.Fatal("an inconsistent result was cached")
	}
}

func TestInspectReportsChangeDuringHash(t *testing.T) {
	content := []byte("bytes")
	n := uint64(len(content))
	fs := &scriptFS{files: map[string]*scripted{"f": {content: content, ids: []models.FileIdentity{id(5, n), id(5, n+1)}}}}
	r := NewInspector(fs, &countingVerifier{rec: validSig(id(5, n+1))}, NewCache(0)).Inspect(ctx, "f")
	if !r.ChangedDuringInspection || r.Hash.State != models.HashChanged || !strings.Contains(r.Note, "changed while it was hashed") {
		t.Fatalf("%+v", r)
	}
}

func TestUnavailableSignatureIsNotCached(t *testing.T) {
	content := []byte("bytes")
	fid := id(5, uint64(len(content)))
	fs := &scriptFS{files: map[string]*scripted{"f": stable(content, 5)}}
	v := &countingVerifier{rec: models.SignatureRecord{State: models.SignatureUnavailable, Identity: models.Known(fid)}}
	in := NewInspector(fs, v, NewCache(0))
	in.Inspect(ctx, "f")
	in.Inspect(ctx, "f")
	if v.calls.Load() != 2 {
		t.Fatalf("Unavailable result cached (%d calls)", v.calls.Load())
	}
}

func TestInspectWithoutCache(t *testing.T) {
	content := []byte("bytes")
	fid := id(5, uint64(len(content)))
	fs := &scriptFS{files: map[string]*scripted{"f": stable(content, 5)}}
	v := &countingVerifier{rec: validSig(fid)}
	in := NewInspector(fs, v, nil)
	in.Inspect(ctx, "f")
	in.Inspect(ctx, "f")
	if v.calls.Load() != 2 {
		t.Fatalf("calls %d", v.calls.Load())
	}
}
