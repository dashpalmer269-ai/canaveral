package windows

// This file has no build tag: it holds the mapping from WinVerifyTrust result
// codes to signature states, so the mapping is unit-tested on every platform.

import (
	"fmt"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// WinVerifyTrust result codes (HRESULTs) that the mapping distinguishes.
const (
	trustSuccess              uint32 = 0x00000000
	trustNoSignature          uint32 = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustSubjectFormUnknown   uint32 = 0x800B0003 // TRUST_E_SUBJECT_FORM_UNKNOWN
	trustProviderUnknown      uint32 = 0x800B0001 // TRUST_E_PROVIDER_UNKNOWN
	trustBadDigest            uint32 = 0x80096010 // TRUST_E_BAD_DIGEST
	trustCertSignature        uint32 = 0x80096004 // TRUST_E_CERT_SIGNATURE
	trustBasicConstraints     uint32 = 0x80096019 // TRUST_E_BASIC_CONSTRAINTS
	trustTimeStamp            uint32 = 0x80096005 // TRUST_E_TIME_STAMP
	trustExplicitDistrust     uint32 = 0x800B0111 // TRUST_E_EXPLICIT_DISTRUST
	trustSubjectNotTrusted    uint32 = 0x800B0004 // TRUST_E_SUBJECT_NOT_TRUSTED
	trustSystemError          uint32 = 0x80096001 // TRUST_E_SYSTEM_ERROR
	certExpired               uint32 = 0x800B0101 // CERT_E_EXPIRED
	certUntrustedRoot         uint32 = 0x800B0109 // CERT_E_UNTRUSTEDROOT
	certChaining              uint32 = 0x800B010A // CERT_E_CHAINING
	certRevoked               uint32 = 0x800B010C // CERT_E_REVOKED
	certWrongUsage            uint32 = 0x800B0110 // CERT_E_WRONG_USAGE
	cryptSecuritySettings     uint32 = 0x80092026 // CRYPT_E_SECURITY_SETTINGS
	cryptFileError            uint32 = 0x80092003 // CRYPT_E_FILE_ERROR
	errorAccessDeniedHRESULT  uint32 = 0x80070005 // E_ACCESSDENIED
	errorSharingViolationHRES uint32 = 0x80070020 // HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION)
)

var trustNames = map[uint32]string{
	trustNoSignature:          "TRUST_E_NOSIGNATURE: no signature of this kind is present",
	trustSubjectFormUnknown:   "TRUST_E_SUBJECT_FORM_UNKNOWN: the file format cannot carry this kind of signature",
	trustProviderUnknown:      "TRUST_E_PROVIDER_UNKNOWN: no trust provider handles this file type",
	trustBadDigest:            "TRUST_E_BAD_DIGEST: the file's contents do not match its signature",
	trustCertSignature:        "TRUST_E_CERT_SIGNATURE: a certificate's signature could not be verified",
	trustBasicConstraints:     "TRUST_E_BASIC_CONSTRAINTS: a certificate in the chain is not allowed to issue certificates",
	trustTimeStamp:            "TRUST_E_TIME_STAMP: the timestamp signature could not be verified; with network retrieval disabled this can mean the timestamp authority's chain could not be completed offline, so it is not proof of a bad timestamp",
	trustExplicitDistrust:     "TRUST_E_EXPLICIT_DISTRUST: the signing certificate is explicitly distrusted",
	trustSubjectNotTrusted:    "TRUST_E_SUBJECT_NOT_TRUSTED: the trust policy did not accept the file",
	trustSystemError:          "TRUST_E_SYSTEM_ERROR: a system error occurred during verification",
	certExpired:               "CERT_E_EXPIRED: the signing certificate expired and the signature has no valid timestamp",
	certUntrustedRoot:         "CERT_E_UNTRUSTEDROOT: the certificate chain ends in a root that is not trusted",
	certChaining:              "CERT_E_CHAINING: the certificate chain could not be built to a trusted root offline; usually an intermediate or root certificate that Windows would download is not cached on this machine, so trust could not be established, which is not proof of a bad signature",
	certRevoked:               "CERT_E_REVOKED: the signing certificate is revoked",
	certWrongUsage:            "CERT_E_WRONG_USAGE: the certificate is not valid for code signing",
	cryptSecuritySettings:     "CRYPT_E_SECURITY_SETTINGS: a local security policy prevented verification",
	cryptFileError:            "CRYPT_E_FILE_ERROR: the file could not be read for verification",
	errorAccessDeniedHRESULT:  "E_ACCESSDENIED: access to the file was denied",
	errorSharingViolationHRES: "the file is in use by another process (sharing violation)",
}

// invalidCodes are results that prove a signature is present and fails
// verification. Only these produce SignatureInvalid; any result not listed
// here or among the "no signature" codes is reported as Unavailable, so the
// tool never claims "invalid" without proof.
//
// CERT_E_CHAINING and TRUST_E_TIME_STAMP are deliberately absent: with
// network retrieval disabled (A2), Windows returns them when a certificate it
// would normally download is not cached, which happens for legitimate files
// (seen in CI on a Microsoft-signed System32 DLL). CERT_E_UNTRUSTEDROOT stays:
// the chain was built and ends at a root that is not trusted.
var invalidCodes = map[uint32]bool{
	trustBadDigest: true, trustCertSignature: true, trustBasicConstraints: true,
	trustExplicitDistrust: true, certExpired: true,
	certUntrustedRoot: true, certRevoked: true, certWrongUsage: true,
}

// noSignatureCodes mean "no signature of this kind": for the embedded check
// this sends verification on to the catalog check.
var noSignatureCodes = map[uint32]bool{
	trustNoSignature: true, trustSubjectFormUnknown: true, trustProviderUnknown: true,
}

// trustText names a result code for the report.
func trustText(code uint32) string {
	if s, ok := trustNames[code]; ok {
		return fmt.Sprintf("0x%08X %s", code, s)
	}
	return fmt.Sprintf("0x%08X (unrecognized trust result)", code)
}

// classifyTrust maps a WinVerifyTrust result to a signature state.
// lastError is GetLastError after the call: when the result is
// TRUST_E_NOSIGNATURE but the last error is not one of the "no signature"
// codes, a signature is present but could not be validated (per the
// documented WinVerifyTrust usage), which is Invalid.
func classifyTrust(code, lastError uint32) (models.SignatureState, string) {
	switch {
	case code == trustSuccess:
		return models.SignatureValid, "signature verified"
	case code == trustNoSignature && lastError != 0 && !noSignatureCodes[lastError]:
		return models.SignatureInvalid, "a signature is present but could not be validated: " + trustText(lastError)
	case noSignatureCodes[code]:
		return models.SignatureUnsigned, trustText(code)
	case invalidCodes[code]:
		return models.SignatureInvalid, trustText(code)
	default:
		return models.SignatureUnavailable, "verification could not reach a result: " + trustText(code)
	}
}
