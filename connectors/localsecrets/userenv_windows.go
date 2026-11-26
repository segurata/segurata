package localsecrets

import (
	"syscall"
	"unsafe"

	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/winsys"
)

var userEnvironment = func() (map[string]string, error) {
	return registryStrings(syscall.HKEY_CURRENT_USER, secretrisk.UserEnvKey[len(`HKCU\`):])
}

// registryStrings are the string values of a key, expandable ones as stored (%VAR% unexpanded).
func registryStrings(root syscall.Handle, path string) (map[string]string, error) {
	vals, err := winsys.RegValues(root, path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, v := range vals {
		if (v.Type == syscall.REG_SZ || v.Type == syscall.REG_EXPAND_SZ) && len(v.Data) >= 2 {
			out[v.Name] = syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&v.Data[0])), len(v.Data)/2))
		}
	}
	return out, nil
}
