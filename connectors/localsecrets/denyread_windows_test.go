package localsecrets

import (
	"syscall"
	"testing"

	"github.com/segurata/segurata/internal/winsys"
)

func denyRead(t *testing.T, path string) {
	t.Helper()
	user, err := winsys.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, winsys.WriteDAC, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := uint32(winsys.DaclSecurityInformation | winsys.ProtectedDaclSecurityInformation)
	allow := "(A;;FA;;;" + user + ")(A;;FA;;;SY)"
	t.Cleanup(func() {
		defer syscall.CloseHandle(h)
		if err := winsys.SetSecurityDescriptor(h, "D:P"+allow, info); err != nil {
			t.Errorf("restoring fixture access: %v", err)
		}
	})
	// Deny FILE_READ_DATA while retaining access to restore the fixture ACL.
	if err := winsys.SetSecurityDescriptor(h, "D:P(D;;0x1;;;"+user+")"+allow, info); err != nil {
		t.Fatal(err)
	}
}
