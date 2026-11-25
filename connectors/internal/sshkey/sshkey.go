// Package sshkey reads the public half of a private key and fingerprints it the way ssh-keygen
// does (SHA256, unpadded base64), standard library only: the SSH public key wire format for RSA,
// ECDSA and Ed25519 (RFC 4253 section 6.6, RFC 5656 section 3.1, RFC 8709 section 4) and the
// OpenSSH private key container (PROTOCOL.key in OpenSSH's source), which stores the public key in
// clear even when the private part is encrypted. The private key is decoded in memory only, and
// nothing here keeps or returns any part of it.
package sshkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

var (
	// ErrEncrypted is a key whose public half cannot be read without its passphrase (an encrypted
	// PKCS#8 or PKCS#1 PEM; an OpenSSH key stores it in clear).
	ErrEncrypted = errors.New("encrypted")
	// ErrUnreadable is a body that is not a whole private key of a kind this package reads.
	ErrUnreadable = errors.New("unreadable")
)

// Public is an SSH public key in wire format.
type Public struct {
	Type string // "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", …
	Blob []byte
}

// Fingerprint is ssh-keygen's default, "SHA256:<unpadded base64 of the blob's SHA-256>".
func (p Public) Fingerprint() string {
	sum := sha256.Sum256(p.Blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

const opensshMagic = "openssh-key-v1\x00"

// FromPrivate reads the public key of a private key given as its PEM body (the base64 between the
// BEGIN and END lines, headers dropped). openssh reports the OpenSSH container, which only SSH uses;
// a PKCS#1, PKCS#8 or SEC 1 key may as well sign TLS certificates or JWTs.
func FromPrivate(body string) (pub Public, openssh bool, err error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if err != nil {
		return Public{}, false, ErrUnreadable
	}
	if strings.HasPrefix(string(der), opensshMagic) {
		pub, err = fromOpenSSH(der[len(opensshMagic):])
		return pub, true, err
	}
	var key any
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		key = k
	} else if k, err := x509.ParseECPrivateKey(der); err == nil {
		key = k
	} else if pub, ok := explicitEC(der); ok {
		return pub, false, nil
	} else if encryptedPKCS8(der) {
		return Public{}, false, ErrEncrypted
	} else {
		return Public{}, false, ErrUnreadable
	}
	pub, err = fromKey(key)
	return pub, false, err
}

// fromOpenSSH reads the first public key of an OpenSSH private key container, after its magic:
// cipher name, KDF name, KDF options, number of keys, then each public key blob.
func fromOpenSSH(b []byte) (Public, error) {
	r := reader{b: b}
	r.str() // cipher
	r.str() // kdf
	r.str() // kdf options
	n := r.u32()
	blob := r.str()
	if r.bad || n < 1 {
		return Public{}, ErrUnreadable
	}
	return parseBlob(blob)
}

// explicitEC reads an EC key that names its curve by explicit parameters rather than by OID, which
// crypto/x509 refuses: the ssh-keygen of macOS (LibreSSL) writes P-256 keys so in its PEM and
// PKCS#8 output. The SEC 1 ECPrivateKey (RFC 5915 section 3) carries its public point, and the
// curve is the NIST one whose field prime the parameters give.
func explicitEC(der []byte) (Public, bool) {
	var p8 struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
	}
	if _, err := asn1.Unmarshal(der, &p8); err == nil && p8.Algo.Algorithm.Equal(oidECPublicKey) {
		der = p8.Key
		if len(p8.Algo.Parameters.FullBytes) > 0 {
			return explicitECWith(der, p8.Algo.Parameters.FullBytes)
		}
	}
	return explicitECWith(der, nil)
}

var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func explicitECWith(der, params []byte) (Public, bool) {
	var k struct {
		Version int
		Key     []byte
		Params  asn1.RawValue  `asn1:"optional,explicit,tag:0"`
		Pub     asn1.BitString `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(der, &k); err != nil || k.Version != 1 || len(k.Pub.Bytes) == 0 {
		return Public{}, false
	}
	if len(k.Params.FullBytes) > 0 {
		params = k.Params.Bytes // the explicit [0] wrapper holds the ECParameters SEQUENCE
	}
	var ecp struct {
		Version int
		Field   struct {
			Type  asn1.ObjectIdentifier
			Prime *big.Int
		}
	}
	if _, err := asn1.Unmarshal(params, &ecp); err != nil || ecp.Field.Prime == nil {
		return Public{}, false
	}
	for c := range curves {
		if c.Params().P.Cmp(ecp.Field.Prime) == 0 {
			key, err := ecdsa.ParseUncompressedPublicKey(c, k.Pub.Bytes)
			if err != nil {
				return Public{}, false
			}
			pub, err := fromKey(key)
			return pub, err == nil
		}
	}
	return Public{}, false
}

// encryptedPKCS8 reports whether der is an EncryptedPrivateKeyInfo (RFC 5208 section 6).
func encryptedPKCS8(der []byte) bool {
	var info struct {
		Algo pkix.AlgorithmIdentifier
		Data []byte
	}
	rest, err := asn1.Unmarshal(der, &info)
	return err == nil && len(rest) == 0 && len(info.Data) > 0
}

// fromKey is the SSH public key of a parsed private or public key.
func fromKey(key any) (Public, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fromKey(&k.PublicKey)
	case *ecdsa.PrivateKey:
		return fromKey(&k.PublicKey)
	case ed25519.PrivateKey:
		return fromKey(k.Public())
	case *rsa.PublicKey:
		return build("ssh-rsa", mpint(big.NewInt(int64(k.E))), mpint(k.N)), nil
	case *ecdsa.PublicKey:
		curve, ok := curves[k.Curve]
		if !ok {
			return Public{}, ErrUnreadable
		}
		point, err := k.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return Public{}, ErrUnreadable
		}
		return build("ecdsa-sha2-"+curve, str([]byte(curve)), str(point)), nil
	case ed25519.PublicKey:
		return build("ssh-ed25519", str(k)), nil
	}
	return Public{}, ErrUnreadable
}

var curves = map[elliptic.Curve]string{elliptic.P256(): "nistp256", elliptic.P384(): "nistp384", elliptic.P521(): "nistp521"}

// build is string(typ) followed by the already encoded fields.
func build(typ string, fields ...[]byte) Public {
	blob := str([]byte(typ))
	for _, f := range fields {
		blob = append(blob, f...)
	}
	return Public{Type: typ, Blob: blob}
}

// str is an SSH string: a uint32 length, then the bytes.
func str(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

// mpint is a non-negative SSH mpint: big-endian, a leading zero byte when the top bit is set, and
// no bytes at all for zero.
func mpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return str(b)
}

// ParseAuthorized reads the key of one line of an authorized_keys or .pub file, or of GitHub's
// key listings: "[options] <type> <base64> [comment]". ok is false for comments, blank lines and
// anything that does not hold a well-formed key blob of the type it names.
func ParseAuthorized(line string) (Public, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Public{}, false
	}
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if !knownType(fields[i]) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[i+1])
		if err != nil {
			return Public{}, false
		}
		p, err := parseBlob(blob)
		if err != nil || p.Type != fields[i] {
			return Public{}, false
		}
		return p, true
	}
	return Public{}, false
}

func knownType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-")
}

// parseBlob checks that blob starts with its type name and keeps it whole: the fingerprint is the
// hash of the whole blob.
func parseBlob(blob []byte) (Public, error) {
	r := reader{b: blob}
	typ := r.str()
	if r.bad || len(typ) == 0 || !knownType(string(typ)) {
		return Public{}, ErrUnreadable
	}
	return Public{Type: string(typ), Blob: blob}, nil
}

// reader reads SSH wire fields; bad is set on the first short read.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) u32() uint32 {
	if len(r.b) < 4 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) str() []byte {
	n := r.u32()
	if r.bad || uint64(n) > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s
}
