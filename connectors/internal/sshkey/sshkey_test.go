package sshkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A public key and the fingerprint `ssh-keygen -l` printed for it (public material only).
const (
	vectorLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdZ+DotVIcW0FmwLj70h1qpfioiemXeuVJsS5KNq5g6 vec"
	vectorFP   = "SHA256:t4E3YrucZT6YR+j92Ct8t8+XEVpT/3oy1uKze/yb/RM"
)

func TestParseAuthorizedVector(t *testing.T) {
	for _, line := range []string{
		vectorLine,
		`from="10.0.0.1",no-pty ` + vectorLine,
		"  " + strings.TrimSuffix(vectorLine, " vec") + "  ",
	} {
		p, ok := ParseAuthorized(line)
		if !ok || p.Fingerprint() != vectorFP || p.Type != "ssh-ed25519" {
			t.Errorf("ParseAuthorized(%q) = %v %v, want %s", line, p.Fingerprint(), ok, vectorFP)
		}
	}
	for _, line := range []string{"", "# comment", "ssh-ed25519 notbase64!", "ssh-rsa " + strings.Fields(vectorLine)[1], "nothing here"} {
		if _, ok := ParseAuthorized(line); ok {
			t.Errorf("ParseAuthorized(%q) ok, want not", line)
		}
	}
}

// pemBody is the base64 between the BEGIN and END lines, headers dropped, as local-secrets gives it.
func pemBody(text string) string {
	var b strings.Builder
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, "-----") && !strings.Contains(l, ":") {
			b.WriteString(strings.TrimSpace(l))
		}
	}
	return b.String()
}

// TestFromPrivateMatchesSSHKeygen generates keys with ssh-keygen in every type and container it
// writes, and checks the fingerprint read from the private key is the one ssh-keygen prints for
// its .pub.
func TestFromPrivateMatchesSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	cases := []struct {
		name    string
		args    []string
		openssh bool
	}{
		{"ed25519", []string{"-t", "ed25519"}, true},
		{"rsa", []string{"-t", "rsa", "-b", "2048"}, true},
		{"ecdsa256", []string{"-t", "ecdsa", "-b", "256"}, true},
		{"ecdsa384", []string{"-t", "ecdsa", "-b", "384"}, true},
		{"ecdsa521", []string{"-t", "ecdsa", "-b", "521"}, true},
		{"rsa-pem", []string{"-t", "rsa", "-b", "2048", "-m", "PEM"}, false},
		{"ecdsa-pem", []string{"-t", "ecdsa", "-b", "256", "-m", "PEM"}, false},
		{"rsa-pkcs8", []string{"-t", "rsa", "-b", "2048", "-m", "PKCS8"}, false},
		{"ed25519-pkcs8", []string{"-t", "ed25519", "-m", "PKCS8"}, true}, // ssh-keygen writes ed25519 keys as OpenSSH whatever -m says
		{"ecdsa-pkcs8", []string{"-t", "ecdsa", "-b", "384", "-m", "PKCS8"}, false},
		{"ed25519-passphrase", []string{"-t", "ed25519", "-N", "a passphrase"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(dir, c.name)
			args := append([]string{"-q", "-C", "test", "-f", f}, c.args...)
			if !strings.Contains(strings.Join(c.args, " "), "-N") {
				args = append(args, "-N", "")
			}
			if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
				t.Skipf("ssh-keygen %v: %v %s", c.args, err, out)
			}
			out, err := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", f+".pub").Output()
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Fields(string(out))[1]
			priv, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			pub, openssh, err := FromPrivate(pemBody(string(priv)))
			if err != nil || pub.Fingerprint() != want || openssh != c.openssh {
				t.Errorf("FromPrivate = %s openssh=%v err=%v, want %s openssh=%v", pub.Fingerprint(), openssh, err, want, c.openssh)
			}
			line, _ := os.ReadFile(f + ".pub")
			if p, ok := ParseAuthorized(string(line)); !ok || p.Fingerprint() != want {
				t.Errorf("ParseAuthorized(.pub) = %s %v, want %s", p.Fingerprint(), ok, want)
			}
		})
	}
	t.Run("encrypted-pkcs8", func(t *testing.T) {
		f := filepath.Join(dir, "enc")
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PKCS8", "-N", "a passphrase", "-f", f).CombinedOutput(); err != nil {
			t.Skipf("ssh-keygen: %v %s", err, out)
		}
		priv, _ := os.ReadFile(f)
		if _, _, err := FromPrivate(pemBody(string(priv))); !errors.Is(err, ErrEncrypted) {
			t.Errorf("FromPrivate(encrypted PKCS#8) err = %v, want ErrEncrypted", err)
		}
	})
}

// TestFromPrivateGoKeys needs no ssh-keygen: keys made in Go, against the blob built field by field.
func TestFromPrivateGoKeys(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	ec1, _ := x509.MarshalECPrivateKey(ecKey)
	for name, c := range map[string]struct {
		der  []byte
		want string
	}{
		"ed25519": {must(x509.MarshalPKCS8PrivateKey(edKey)), "ssh-ed25519"},
		"ecdsa":   {ec1, "ecdsa-sha2-nistp256"},
		"rsa":     {x509.MarshalPKCS1PrivateKey(rsaKey), "ssh-rsa"},
	} {
		pub, openssh, err := FromPrivate(base64.StdEncoding.EncodeToString(c.der))
		if err != nil || openssh || pub.Type != c.want {
			t.Errorf("%s: FromPrivate = %q %v %v", name, pub.Type, openssh, err)
			continue
		}
		line := pub.Type + " " + base64.StdEncoding.EncodeToString(pub.Blob)
		if p, ok := ParseAuthorized(line); !ok || p.Fingerprint() != pub.Fingerprint() {
			t.Errorf("%s: the derived blob does not read back", name)
		}
	}
	edPub := edKey.Public().(ed25519.PublicKey)
	pub, _, _ := FromPrivate(base64.StdEncoding.EncodeToString(must(x509.MarshalPKCS8PrivateKey(edKey))))
	if want := append(str([]byte("ssh-ed25519")), str(edPub)...); string(pub.Blob) != string(want) {
		t.Error("ed25519 blob is not string(type) || string(key)")
	}
}

// TestExplicitEC builds a SEC 1 key with explicit curve parameters, as LibreSSL writes them, alone
// and inside PKCS#8.
func TestExplicitEC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	named, _ := x509.MarshalECPrivateKey(key)
	want, _ := fromKey(&key.PublicKey)
	type fieldID struct {
		Type  asn1.ObjectIdentifier
		Prime *big.Int
	}
	params := must(asn1.Marshal(struct {
		Version int
		Field   fieldID
		Order   *big.Int
	}{1, fieldID{asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, elliptic.P384().Params().P}, elliptic.P384().Params().N}))
	var sec1 struct {
		Version int
		Key     []byte
		Params  asn1.RawValue  `asn1:"optional,explicit,tag:0"`
		Pub     asn1.BitString `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(named, &sec1); err != nil {
		t.Fatal(err)
	}
	sec1.Params = asn1.RawValue{FullBytes: must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: params}))}
	explicit := must(asn1.Marshal(sec1))
	p8 := must(asn1.Marshal(struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: params}}, explicit}))
	for name, der := range map[string][]byte{"sec1": explicit, "pkcs8": p8} {
		if _, err := x509.ParseECPrivateKey(der); err == nil && name == "sec1" {
			t.Fatal("crypto/x509 reads explicit parameters now; the fallback is not exercised")
		}
		pub, _, err := FromPrivate(base64.StdEncoding.EncodeToString(der))
		if err != nil || pub.Fingerprint() != want.Fingerprint() {
			t.Errorf("%s: FromPrivate = %s %v, want %s", name, pub.Fingerprint(), err, want.Fingerprint())
		}
	}
}

func TestFromPrivateRejects(t *testing.T) {
	for _, body := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("not a key")),
		base64.StdEncoding.EncodeToString([]byte(opensshMagic + "\x00\x00\x00\x04none")), // truncated container
	} {
		if _, _, err := FromPrivate(body); !errors.Is(err, ErrUnreadable) {
			t.Errorf("FromPrivate(%q) err = %v, want ErrUnreadable", body, err)
		}
	}
}

func TestMpint(t *testing.T) {
	for _, c := range []struct {
		n    int64
		want string
	}{{0, "\x00\x00\x00\x00"}, {0x7f, "\x00\x00\x00\x01\x7f"}, {0x80, "\x00\x00\x00\x02\x00\x80"}, {65537, "\x00\x00\x00\x03\x01\x00\x01"}} {
		if got := string(mpint(bigInt(c.n))); got != c.want {
			t.Errorf("mpint(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func bigInt(n int64) *big.Int { return big.NewInt(n) }
