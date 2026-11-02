//go:build windows

package windows

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
)

var _ platform.PrivilegeSource = Privileges{}

// Privileges reads the tool's own token. It only queries; it never adjusts
// privileges.
type Privileges struct{}

// Elevation reports elevation, integrity level and Administrators membership.
func (Privileges) Elevation(ctx context.Context) (models.ElevationInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.ElevationInfo{}, err
	}
	tok := windows.GetCurrentProcessToken()
	var info models.ElevationInfo

	var elev uint32
	var n uint32
	if err := windows.GetTokenInformation(tok, windows.TokenElevation, (*byte)(unsafe.Pointer(&elev)), uint32(unsafe.Sizeof(elev)), &n); err != nil {
		info.Elevated = models.Unavailable[bool]("GetTokenInformation(TokenElevation): " + err.Error())
	} else {
		info.Elevated = models.Known(elev != 0)
	}

	info.IntegrityLevel = integrityLevel(tok)

	if admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
		info.AdminMember = models.Unavailable[bool]("CreateWellKnownSid: " + err.Error())
	} else if member, err := windows.Token(0).IsMember(admins); err != nil {
		info.AdminMember = models.Unavailable[bool]("CheckTokenMembership: " + err.Error())
	} else {
		info.AdminMember = models.Known(member)
	}
	return info, nil
}

func integrityLevel(tok windows.Token) models.Value[string] {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return models.Unavailable[string]("GetTokenInformation(TokenIntegrityLevel) returned no size")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return models.Unavailable[string]("GetTokenInformation(TokenIntegrityLevel): " + err.Error())
	}
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	count := sid.SubAuthorityCount()
	if count == 0 {
		return models.Unavailable[string]("integrity SID has no RID")
	}
	return models.Known(integrityName(sid.SubAuthority(uint32(count - 1))))
}
