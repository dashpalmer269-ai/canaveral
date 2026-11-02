package windows

import (
	"strings"
	"testing"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// Acceptance (M4): Invalid, Unsigned and Unavailable are three distinct
// states. The mapping is checked code by code, with no files involved.
func TestClassifyTrust(t *testing.T) {
	cases := []struct {
		code, lastErr uint32
		want          models.SignatureState
		mentions      string
	}{
		{trustSuccess, 0, models.SignatureValid, "verified"},

		{trustNoSignature, 0, models.SignatureUnsigned, "TRUST_E_NOSIGNATURE"},
		{trustNoSignature, trustNoSignature, models.SignatureUnsigned, "TRUST_E_NOSIGNATURE"},
		{trustNoSignature, trustSubjectFormUnknown, models.SignatureUnsigned, ""},
		{trustSubjectFormUnknown, 0, models.SignatureUnsigned, "SUBJECT_FORM_UNKNOWN"},
		{trustProviderUnknown, 0, models.SignatureUnsigned, "PROVIDER_UNKNOWN"},
		// NOSIGNATURE with an unrelated last error: a signature exists but fails.
		{trustNoSignature, trustBadDigest, models.SignatureInvalid, "signature is present"},

		{trustBadDigest, 0, models.SignatureInvalid, "do not match"},
		{trustCertSignature, 0, models.SignatureInvalid, "CERT_SIGNATURE"},
		{certUntrustedRoot, 0, models.SignatureInvalid, "UNTRUSTEDROOT"},
		{certExpired, 0, models.SignatureInvalid, "EXPIRED"},
		{trustExplicitDistrust, 0, models.SignatureInvalid, "DISTRUST"},
		{certRevoked, 0, models.SignatureInvalid, "REVOKED"},
		{certWrongUsage, 0, models.SignatureInvalid, "WRONG_USAGE"},
		{trustBasicConstraints, 0, models.SignatureInvalid, "BASIC_CONSTRAINTS"},

		// Not proof of anything: Unavailable, never Invalid.
		// Offline chain building can fail for legitimate files (A2).
		{certChaining, 0, models.SignatureUnavailable, "not proof of a bad signature"},
		{trustTimeStamp, 0, models.SignatureUnavailable, "completed offline"},
		{trustSystemError, 0, models.SignatureUnavailable, "SYSTEM_ERROR"},
		{trustSubjectNotTrusted, 0, models.SignatureUnavailable, "SUBJECT_NOT_TRUSTED"},
		{cryptSecuritySettings, 0, models.SignatureUnavailable, "SECURITY_SETTINGS"},
		{cryptFileError, 0, models.SignatureUnavailable, "could not be read"},
		{errorAccessDeniedHRESULT, 0, models.SignatureUnavailable, "denied"},
		{errorSharingViolationHRES, 0, models.SignatureUnavailable, "sharing violation"},
		{0x80001234, 0, models.SignatureUnavailable, "unrecognized"},
	}
	for _, c := range cases {
		state, detail := classifyTrust(c.code, c.lastErr)
		if state != c.want || !strings.Contains(detail, c.mentions) {
			t.Errorf("classifyTrust(0x%08X, 0x%08X) = %s %q, want %s mentioning %q", c.code, c.lastErr, state, detail, c.want, c.mentions)
		}
	}
}

func TestInvalidAndUnsignedSetsAreDisjoint(t *testing.T) {
	for code := range invalidCodes {
		if noSignatureCodes[code] {
			t.Errorf("0x%08X is in both sets", code)
		}
		if _, ok := trustNames[code]; !ok {
			t.Errorf("0x%08X has no description", code)
		}
	}
}
