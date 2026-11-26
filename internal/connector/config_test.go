package connector_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestStrings(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:                "[] <nil>",
		`{"k": null}`:       "[] <nil>",
		`{"k": []}`:         "[] <nil>",
		`{"k": ["a", "b"]}`: "[a b] <nil>",
		`{"k": "a"}`:        `[] demo config: "k" must be a list of strings`,
		`{"k": ["a", 3]}`:   `[] demo config: "k" must be a list of strings`,
		`{"k": ["a", ""]}`:  `[] demo config: "k" must be a list of strings`,
	} {
		got, err := connector.Strings(decode(t, raw), "demo", "k")
		if s := fmt.Sprint(got, " ", err); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
	if got, _ := connector.Strings(decode(t, `{"k": []}`), "demo", "k"); got == nil {
		t.Error("an empty list is not an absent one")
	}
}

func TestLenientStrings(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:                       "[] false",
		`{"k": "a"}`:               "[] false",
		`{"k": []}`:                "[] true",
		`{"k": ["a", 3, "", "b"]}`: "[a b] true",
	} {
		got, ok := connector.LenientStrings(decode(t, raw), "k")
		if s := fmt.Sprint(got, " ", ok); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
}

func TestPositiveInt(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:          "7 <nil>",
		`{"n": null}`: "7 <nil>",
		`{"n": 3}`:    "3 <nil>",
		`{"n": 0}`:    `7 demo config: "n" must be a whole number above 0`,
		`{"n": 1.5}`:  `7 demo config: "n" must be a whole number above 0`,
		`{"n": "3"}`:  `7 demo config: "n" must be a whole number above 0`,
	} {
		got, err := connector.PositiveInt(decode(t, raw), "demo", "n", 7)
		if s := fmt.Sprint(got, " ", err); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
}

func TestBool(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:           "false <nil>",
		`{"b": null}`:  "false <nil>",
		`{"b": true}`:  "true <nil>",
		`{"b": "yes"}`: `false demo config: "b" must be true or false`,
	} {
		got, err := connector.Bool(decode(t, raw), "demo", "b")
		if s := fmt.Sprint(got, " ", err); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
}
