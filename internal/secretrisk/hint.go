package secretrisk

import (
	"strconv"
	"strings"
)

// passwordLike types hold human-chosen secrets: their hint shows only the length.
var passwordLike = map[string]bool{
	"assignment": true, "url-credentials": true, "netrc-password": true, "docker-auth": true,
	"url-token-param": true, "curl-auth-user": true,
}

const (
	tailLen    = 4   // the last characters a hint shows, as provider consoles do to tell keys apart
	unknownLen = "?" // the length of a hint made from a provider's mask that gives none
)

// Redact returns the only hint a finding may show of a secret: the known prefix (from the
// "|"-separated prefixes), the last four characters of a long random key, and the length.
func Redact(typ, prefixes, secret string) string {
	if secret == "" {
		return ""
	}
	h := Hint{Prefix: KnownPrefix(prefixes, secret), Len: len(secret)}
	if !passwordLike[typ] && len(secret) >= 24 && len(secret)-len(h.Prefix) >= 20 {
		h.Tail = secret[len(secret)-tailLen:]
	}
	return h.String()
}

// RedactID is the hint of an identifier that names a secret without being one (an AWS access key
// id): "AKIA…WXYZ(20)".
func RedactID(prefixes, id string) string {
	if id == "" {
		return ""
	}
	h := Hint{Prefix: KnownPrefix(prefixes, id), Len: len(id)}
	if len(id)-len(h.Prefix) > tailLen {
		h.Tail = id[len(id)-tailLen:]
	}
	return h.String()
}

// KnownPrefix is the prefix from the "|"-separated list that secret starts with, or "".
func KnownPrefix(prefixes, secret string) string {
	for _, p := range strings.Split(prefixes, "|") {
		if p != "" && strings.HasPrefix(secret, p) {
			return p
		}
	}
	return ""
}

// Hint is what Redact showed of a value. Len is 0 when its source did not give the length.
type Hint struct {
	Prefix, Tail string
	Len          int
}

// String is Redact's format: "prefix…tail(len)", "(?)" for an unknown length.
func (h Hint) String() string {
	n := unknownLen
	if h.Len > 0 {
		n = strconv.Itoa(h.Len)
	}
	return h.Prefix + "…" + h.Tail + "(" + n + ")"
}

// ParseHint reads Redact's format. ok is false for hints of no single one-line value ("PEM", a
// whole file, "").
func ParseHint(redacted string) (h Hint, ok bool) {
	i, j := strings.Index(redacted, "…"), strings.LastIndexByte(redacted, '(')
	if i < 0 || j < i || !strings.HasSuffix(redacted, ")") {
		return Hint{}, false
	}
	h = Hint{Prefix: redacted[:i], Tail: redacted[i+len("…") : j]}
	if num := redacted[j+1 : len(redacted)-1]; num == unknownLen {
		return h, h.Prefix != "" || h.Tail != ""
	} else if n, err := strconv.Atoi(num); err == nil && n > 0 {
		h.Len = n
		return h, len(h.Prefix)+len(h.Tail) <= n
	}
	return Hint{}, false
}

// Masked turns what a provider shows of a key into Redact's format, keeping at most the last four
// characters, with length n (0: unknown). It reads OpenRouter's label "sk-or-v1-27e...d4d",
// Anthropic's partial_key_hint "sk-ant-api03-R2D...igAA", OpenAI's redacted_value
// "sk-proj-****…abcd" and an ellipsis; "" when the text masks nothing.
func Masked(masked string, n int) string {
	h, ok := parseMasked(masked)
	if !ok {
		return ""
	}
	if len(h.Tail) > tailLen {
		h.Tail = h.Tail[len(h.Tail)-tailLen:]
	}
	if n >= len(h.Prefix)+len(h.Tail) {
		h.Len = n
	}
	return h.String()
}

// ReadHint reads Redact's format or, failing that, a provider's raw mask, which findings written
// before every connector used Redact's format still carry.
func ReadHint(s string) (Hint, bool) {
	if h, ok := ParseHint(s); ok {
		return h, true
	}
	return ParseHint(Masked(s, 0))
}

func parseMasked(s string) (Hint, bool) {
	for _, sep := range []string{"...", "…"} {
		if i := strings.Index(s, sep); i >= 0 {
			pre, tail := s[:i], s[i+len(sep):]
			h := Hint{Prefix: strings.TrimRight(pre, "*"), Tail: strings.TrimLeft(tail, "*")}
			return h, h.Prefix != "" || h.Tail != ""
		}
	}
	if i, j := strings.IndexByte(s, '*'), strings.LastIndexByte(s, '*'); i >= 0 {
		h := Hint{Prefix: s[:i], Tail: s[j+1:]}
		return h, h.Prefix != "" || h.Tail != ""
	}
	return Hint{}, false
}

// Agrees reports whether two hints can describe the same value.
func (h Hint) Agrees(o Hint) bool {
	if h.Len > 0 && o.Len > 0 && h.Len != o.Len {
		return false
	}
	return (strings.HasPrefix(h.Prefix, o.Prefix) || strings.HasPrefix(o.Prefix, h.Prefix)) &&
		(strings.HasSuffix(h.Tail, o.Tail) || strings.HasSuffix(o.Tail, h.Tail))
}

// Fits reports whether value could be the one the hint describes. A hint without a length fits
// nothing: it cannot tell where a value ends.
func (h Hint) Fits(value string) bool {
	return h.Len > 0 && len(value) == h.Len && strings.HasPrefix(value, h.Prefix) && strings.HasSuffix(value, h.Tail)
}
