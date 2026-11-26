package cfgkey_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/cfgkey"
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
		`{"k": "a"}`:        `[] demo config: "k" must be a list of non-empty strings`,
		`{"k": ["a", 3]}`:   `[] demo config: "k" must be a list of non-empty strings`,
		`{"k": ["a", ""]}`:  `[] demo config: "k" must be a list of non-empty strings`,
		`{"k": ["a", " "]}`: `[] demo config: "k" must be a list of non-empty strings`,
	} {
		got, err := cfgkey.Strings(decode(t, raw), "demo", "k")
		if s := fmt.Sprint(got, " ", err); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
	if got, _ := cfgkey.Strings(decode(t, `{"k": []}`), "demo", "k"); got == nil {
		t.Error("an empty list is not an absent one")
	}
}

func TestSelection(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:           "[] <nil>",
		`{"k": null}`:  "[] <nil>",
		`{"k": ["a"]}`: "[a] <nil>",
		`{"k": []}`:    `[] demo config: "k" must name at least one entry; leave it out for all`,
		`{"k": "a"}`:   `[] demo config: "k" must be a list of non-empty strings`,
	} {
		got, err := cfgkey.Selection(decode(t, raw), "demo", "k")
		if s := fmt.Sprint(got, " ", err); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
}

func TestString(t *testing.T) {
	for raw, want := range map[string]string{
		`{}`:           "<nil>",
		`{"s": null}`:  "<nil>",
		`{"s": "a"}`:   "a <nil>",
		`{"s": ""}`:    `demo config: "s" must be a non-empty string`,
		`{"s": "  "}`:  `demo config: "s" must be a non-empty string`,
		`{"s": 3}`:     `demo config: "s" must be a non-empty string`,
		`{"s": ["a"]}`: `demo config: "s" must be a non-empty string`,
	} {
		got, err := cfgkey.String(decode(t, raw), "demo", "s")
		if s := strings.TrimSpace(fmt.Sprint(got, " ", err)); s != want {
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
		`{"n": -2}`:   `7 demo config: "n" must be a whole number above 0`,
		`{"n": "3"}`:  `7 demo config: "n" must be a whole number above 0`,
	} {
		got, err := cfgkey.PositiveInt(decode(t, raw), "demo", "n", 7)
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
		`{"b": 1}`:     `false demo config: "b" must be true or false`,
	} {
		got, err := cfgkey.Bool(decode(t, raw), "demo", "b", false)
		if s := fmt.Sprint(got, " ", err); s != want {
			t.Errorf("%s: got %s, want %s", raw, s, want)
		}
	}
	if got, _ := cfgkey.Bool(decode(t, `{}`), "demo", "b", true); !got {
		t.Error("an absent key gives the default")
	}
}
