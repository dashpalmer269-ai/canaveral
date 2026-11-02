package integrity

import (
	"context"
	"sync"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

// Report is the integrity result for one file.
type Report struct {
	Path      string
	Hash      models.HashRecord
	Signature models.SignatureRecord
	// ChangedDuringInspection is true when the file changed while it was
	// hashed, or when the hash and the signature check saw different files.
	ChangedDuringInspection bool
	Note                    string
}

// Inspector hashes and verifies files. Signature results are cached by file
// identity, like hashes. It is safe for concurrent use.
type Inspector struct {
	hasher   *Hasher
	verifier platform.SignatureVerifier

	mu   sync.Mutex
	sigs map[models.FileIdentity]models.SignatureRecord
	max  int
}

// NewInspector returns an inspector. cache may be nil to disable caching.
func NewInspector(fs platform.FileSystem, verifier platform.SignatureVerifier, cache *Cache) *Inspector {
	in := &Inspector{hasher: NewHasher(fs, cache), verifier: verifier, sigs: map[models.FileIdentity]models.SignatureRecord{}}
	if cache != nil {
		in.max = cache.max
	}
	return in
}

// Inspect hashes path and verifies its signature.
func (in *Inspector) Inspect(ctx context.Context, path string) Report {
	r := Report{Path: path, Hash: in.hasher.Hash(ctx, path)}
	hashID, hashIDKnown := r.Hash.Identity.Get()

	if hashIDKnown && r.Hash.State == models.HashComplete {
		if s, ok := in.cachedSig(hashID); ok {
			r.Signature = s
			return r
		}
	}
	r.Signature = in.verifier.Verify(ctx, path)

	switch sigID, sigIDKnown := r.Signature.Identity.Get(); {
	case r.Hash.State == models.HashChanged:
		r.ChangedDuringInspection = true
		r.Note = "the file changed while it was hashed: " + r.Hash.Reason
	case hashIDKnown && sigIDKnown && sigID != hashID:
		r.ChangedDuringInspection = true
		r.Note = "the file changed between hashing and signature verification (" + identityDiff(hashID, sigID) + "); the hash and the signature result may describe different versions"
	case hashIDKnown && sigIDKnown && r.Hash.State == models.HashComplete:
		in.storeSig(hashID, r.Signature)
	}
	return r
}

func (in *Inspector) cachedSig(id models.FileIdentity) (models.SignatureRecord, bool) {
	if in.max == 0 {
		return models.SignatureRecord{}, false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	s, ok := in.sigs[id]
	return s, ok
}

// storeSig caches conclusive results only; Unavailable is always retried.
func (in *Inspector) storeSig(id models.FileIdentity, s models.SignatureRecord) {
	if in.max == 0 || s.State == models.SignatureUnavailable {
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.sigs) >= in.max {
		for k := range in.sigs { // bounded: drop an arbitrary entry
			delete(in.sigs, k)
			break
		}
	}
	in.sigs[id] = s
}
