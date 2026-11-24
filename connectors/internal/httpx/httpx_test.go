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
		if got := errorMessage([]byte(body)); got != want {
			t.Errorf("%s: got %q, want %q", body, got, want)
		}
	}
}
