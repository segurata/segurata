package testcorpus

import (
	"encoding/base32"
	"encoding/binary"
)

// AWSKeyID builds a synthetic AWS access key id (prefix AKIA or ASIA) that encodes account the way
// real ones do (see attribution.AWSAccountFromKeyID): the 48-bit field holds the account shifted
// left by 7 over low7, with the bit the decoding mask drops set when top is true, then 32 bits of
// filler. An account whose top 5 bits (account >> 36) are 8 or 9 yields a key id of the older
// format (fifth character I or J), which carries no account.
func AWSKeyID(prefix string, account uint64, top bool, low7 byte) string {
	v := account<<7 | uint64(low7&0x7f)
	if top {
		v |= 1 << 47
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return prefix + base32.StdEncoding.EncodeToString(append(b[2:8:8], 0xA5, 0x5A, 0x3C, 0xC3))
}
