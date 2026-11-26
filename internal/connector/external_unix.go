//go:build unix

package connector

import "os"

func executable(_ string, st os.FileInfo) bool { return st.Mode()&0o111 != 0 }

func trimExecutableExt(name string) string { return name }
