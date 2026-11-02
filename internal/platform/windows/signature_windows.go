//go:build windows

package windows

import (
	"context"
	"encoding/hex"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.SignatureVerifier = SignatureVerifier{}

// wintrust.dll functions that x/sys does not wrap. All are read-only queries
// against the file and the system catalog database.
var (
	wintrust                                 = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust                       = wintrust.NewProc("WinVerifyTrust")
	procWTHelperProvDataFromStateData        = wintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procCryptCATAdminAcquireContext2         = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = wintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATCatalogInfoFromContext       = wintrust.NewProc("CryptCATCatalogInfoFromContext")
)

// Offline, write-free trust settings (CLAUDE.md A2): no revocation checks
// and no URL retrieval, so nothing goes online or into the CryptNet cache.
const offlineProvFlags = windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL

// winTrustCatalogInfo is WINTRUST_CATALOG_INFO.
type winTrustCatalogInfo struct {
	size                   uint32
	catalogVersion         uint32
	catalogFilePath        *uint16
	memberTag              *uint16
	memberFilePath         *uint16
	memberFile             windows.Handle
	calculatedFileHash     *byte
	calculatedFileHashSize uint32
	catalogContext         uintptr
	catAdmin               windows.Handle
}

// catalogInfo is CATALOG_INFO.
type catalogInfo struct {
	size        uint32
	catalogFile [windows.MAX_PATH]uint16
}

// cryptProviderSgnr is the leading part of CRYPT_PROVIDER_SGNR. Blank fields
// keep the layout identical to the Windows definition.
type cryptProviderSgnr struct {
	_                 uint32 // cbStruct
	verifyAsOf        windows.Filetime
	certChainLen      uint32
	certChain         *cryptProviderCert
	_                 uint32  // dwSignerType
	_                 uintptr // psSigner
	_                 uint32  // dwError
	counterSignersLen uint32
	counterSigners    *cryptProviderSgnr
	_                 uintptr // pChainContext
}

// cryptProviderCert is the leading part of CRYPT_PROVIDER_CERT.
type cryptProviderCert struct {
	_    uint32 // cbStruct
	cert *windows.CertContext
}

// sysPtr turns an address returned by a Windows API, pointing at memory that
// Windows owns (never the Go heap), into a typed pointer.
func sysPtr[T any](addr uintptr) *T { return (*T)(unsafe.Add(nil, addr)) }

// SignatureVerifier checks Authenticode signatures, embedded first and then
// through the system catalogs (CLAUDE.md A1), offline (A2).
type SignatureVerifier struct{}

// Verify checks path. Failures become SignatureUnavailable with a reason.
func (SignatureVerifier) Verify(ctx context.Context, path string) models.SignatureRecord {
	rec := models.SignatureRecord{Source: models.SignatureSourceNone, Revocation: models.RevocationOfflineByDesign}
	if err := ctx.Err(); err != nil {
		return unavailableSig(rec, err.Error())
	}
	h, err := openRead(path)
	if err != nil {
		return unavailableSig(rec, err.Error())
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if id, err := handleIdentity(h); err != nil {
		rec.Identity = models.Unavailable[models.FileIdentity](err.Error())
	} else {
		rec.Identity = models.Known(id)
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return unavailableSig(rec, err.Error())
	}

	// Embedded signature.
	fileInfo := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path16, File: h}
	state, detail := verifyTrust(&rec, windows.WTD_CHOICE_FILE, unsafe.Pointer(&fileInfo))
	runtime.KeepAlive(&fileInfo)
	if state != models.SignatureUnsigned {
		rec.State, rec.Source, rec.Detail = state, models.SignatureSourceEmbedded, detail
		if state == models.SignatureUnavailable && !rec.Signer.IsKnown() {
			rec.Source = models.SignatureSourceNone // nothing shows a signature was even read
		}
		return rec
	}

	// No embedded signature: look for a catalog that lists the file's hash.
	return verifyCatalog(rec, h, path16, detail)
}

func verifyCatalog(rec models.SignatureRecord, h windows.Handle, path16 *uint16, embeddedDetail string) models.SignatureRecord {
	if err := procCryptCATAdminAcquireContext2.Find(); err != nil {
		return unavailableSig(rec, "catalog verification is not available: "+err.Error())
	}
	var tried []string
	// Current catalogs use SHA-256 member hashes; older ones use SHA-1.
	for _, alg := range []string{"SHA256", "SHA1"} {
		found, out := catalogAttempt(rec, h, path16, alg)
		if found {
			return out
		}
		tried = append(tried, alg+": "+out.Detail)
	}
	rec.State, rec.Source = models.SignatureUnsigned, models.SignatureSourceNone
	rec.Detail = "no embedded signature (" + embeddedDetail + ") and no system catalog lists this file (" + strings.Join(tried, "; ") + ")"
	return rec
}

// catalogAttempt looks the file up by its catalog hash computed with alg.
// found reports whether a catalog listing the file was found and checked.
func catalogAttempt(rec models.SignatureRecord, h windows.Handle, path16 *uint16, alg string) (bool, models.SignatureRecord) {
	alg16, _ := windows.UTF16PtrFromString(alg)
	var admin windows.Handle
	if ok, _, err := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(alg16)), 0, 0); ok == 0 {
		rec.Detail = "CryptCATAdminAcquireContext2: " + err.Error()
		return false, rec
	}
	defer func() { _, _, _ = procCryptCATAdminReleaseContext.Call(uintptr(admin), 0) }()

	if _, err := windows.Seek(h, 0, 0); err != nil {
		rec.Detail = "seek: " + err.Error()
		return false, rec
	}
	var size uint32
	_, _, _ = procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(admin), uintptr(h), uintptr(unsafe.Pointer(&size)), 0, 0)
	if size == 0 || size > 64 {
		rec.Detail = "the file's catalog hash could not be computed"
		return false, rec
	}
	hash := make([]byte, size)
	if ok, _, err := procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(admin), uintptr(h), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0); ok == 0 {
		rec.Detail = "CryptCATAdminCalcHashFromFileHandle2: " + err.Error()
		return false, rec
	}

	catInfo, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(uintptr(admin), uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
	if catInfo == 0 {
		rec.Detail = "no catalog lists this hash"
		return false, rec
	}
	defer func() { _, _, _ = procCryptCATAdminReleaseCatalogContext.Call(uintptr(admin), catInfo, 0) }()

	ci := catalogInfo{size: uint32(unsafe.Sizeof(catalogInfo{}))}
	if ok, _, err := procCryptCATCatalogInfoFromContext.Call(catInfo, uintptr(unsafe.Pointer(&ci)), 0); ok == 0 {
		rec.State, rec.Source = models.SignatureUnavailable, models.SignatureSourceNone
		rec.Detail = "a catalog lists the file but its path could not be read: " + err.Error()
		return true, rec
	}
	catPath := windows.UTF16ToString(ci.catalogFile[:])
	rec.CatalogFile = models.Known(catPath)

	tag16, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	info := winTrustCatalogInfo{
		size:                   uint32(unsafe.Sizeof(winTrustCatalogInfo{})),
		catalogFilePath:        &ci.catalogFile[0],
		memberTag:              tag16,
		memberFilePath:         path16,
		memberFile:             h,
		calculatedFileHash:     &hash[0],
		calculatedFileHashSize: size,
		catAdmin:               admin,
	}
	state, detail := verifyTrust(&rec, windows.WTD_CHOICE_CATALOG, unsafe.Pointer(&info))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(hash)
	rec.State, rec.Detail = state, detail+" (catalog "+catPath+", "+alg+" member hash)"
	rec.Source = models.SignatureSourceCatalog
	if state == models.SignatureUnavailable && !rec.Signer.IsKnown() {
		rec.Source = models.SignatureSourceNone
	}
	return true, rec
}

// verifyTrust runs WinVerifyTrust for one union choice, records the signer
// and timestamp when a signature was evaluated, and always closes the state.
func verifyTrust(rec *models.SignatureRecord, choice uint32, union unsafe.Pointer) (models.SignatureState, string) {
	if err := procWinVerifyTrust.Find(); err != nil {
		return models.SignatureUnavailable, "WinVerifyTrust is not available: " + err.Error()
	}
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: union,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       offlineProvFlags,
	}
	action := windows.WINTRUST_ACTION_GENERIC_VERIFY_V2
	r, _, lastErr := procWinVerifyTrust.Call(uintptr(windows.InvalidHWND), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	code := uint32(r)
	var last uint32
	if e, ok := lastErr.(windows.Errno); ok {
		last = uint32(e)
	}
	state, detail := classifyTrust(code, last)
	if state != models.SignatureUnsigned {
		// Also for Unavailable: when the chain could not be completed offline
		// the signature still names its signer, which the record keeps (as
		// the signature's claim, since the state is not Valid).
		readSigner(rec, data.StateData)
	}

	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_, _, _ = procWinVerifyTrust.Call(uintptr(windows.InvalidHWND), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	runtime.KeepAlive(&data)
	return state, detail
}

// readSigner fills the signer name and timestamp from WinVerifyTrust state.
func readSigner(rec *models.SignatureRecord, state windows.Handle) {
	rec.Signer = models.Unavailable[string]("no signer information was available")
	rec.SignedAt = models.Unavailable[time.Time]("no signer information was available")
	if procWTHelperProvDataFromStateData.Find() != nil || procWTHelperGetProvSignerFromChain.Find() != nil {
		return
	}
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return
	}
	sg, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sg == 0 {
		return
	}
	signer := sysPtr[cryptProviderSgnr](sg)
	if signer.certChainLen > 0 && signer.certChain != nil && signer.certChain.cert != nil {
		if name := certName(signer.certChain.cert); name != "" {
			rec.Signer = models.Known(name)
		}
	}
	if signer.counterSignersLen > 0 && signer.counterSigners != nil {
		ts := signer.counterSigners.verifyAsOf
		rec.SignedAt = models.Known(time.Unix(0, ts.Nanoseconds()).UTC())
	} else {
		rec.SignedAt = models.Unavailable[time.Time]("the signature has no timestamp")
	}
}

func certName(cert *windows.CertContext) string {
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], n)
	return windows.UTF16ToString(buf)
}

func unavailableSig(rec models.SignatureRecord, reason string) models.SignatureRecord {
	rec.State, rec.Source, rec.Detail = models.SignatureUnavailable, models.SignatureSourceNone, reason
	return rec
}
