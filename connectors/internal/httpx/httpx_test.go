package httpx

import "testing"

func TestErrorMessage(t *testing.T) {
	cases := map[string]string{
		`{"error":{"message":"bad key"}}`: "bad key",
		`{"success":false,"errors":[{"code":9109,"message":"Unauthorized"},{"code":1,"message":"again"}]}`: "Unauthorized; again",
		`{"error":"plain string"}`: `{"error":"plain string"}`,
		`  not json  `:             "not json",
	}
	for body, want := range cases {
		if got := ErrorMessage([]byte(body)); got != want {
			t.Errorf("%s: got %q, want %q", body, got, want)
		}
	}
}

func TestMatchesRedacted(t *testing.T) {
	for _, c := range []struct {
		redacted, secret string
		want             bool
	}{
		{"sk-proj-****dYwA", "sk-proj-abcdefdYwA", true},
		{"sk-proj-****dYwA", "sk-proj-abcdefXXXX", false},
		{"sk-or-v1-27e...d4d", "sk-or-v1-27e0123456d4d", true},
		{"sk-or-v1-27e...d4d", "sk-or-v1-28e0123456d4d", false},
		{"sk-admin-…abcd", "sk-admin-0000abcd", true},
		{"no-mask", "no-mask", false},
		{"sk-****", "sk-anything", false}, // no visible suffix
		{"sk-proj-****dYwA", "", false},
	} {
		if got := MatchesRedacted(c.redacted, c.secret); got != c.want {
			t.Errorf("MatchesRedacted(%q, %q) = %v", c.redacted, c.secret, got)
		}
	}
}
