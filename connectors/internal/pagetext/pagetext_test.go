package pagetext

import (
	"reflect"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 23, 21, 0, 0, 0, time.UTC)

func TestLines(t *testing.T) {
	got := Lines("  a \n\n\tb\r\n  \nc")
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("Lines = %q", got)
	}
}

func TestDate(t *testing.T) {
	day := func(y int, m time.Month, d int) *time.Time {
		t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
		return &t
	}
	cases := map[string]*time.Time{
		"March 24, 2020":          day(2020, 3, 24),
		"May 15, 7:37 PM":         day(2026, 5, 15),
		"September 6, 2025":       day(2025, 9, 6),
		"Sep 6, 2025":             day(2025, 9, 6),
		"18 de noviembre de 2025": day(2025, 11, 18),
		"21 de septiembre, 12:28": day(2026, 9, 21),
		"3 de Enero de 2019":      day(2019, 1, 3),
		"18 nov 2025":             day(2025, 11, 18),
		"15 mar. 2016":            day(2016, 3, 15),
		"7 sept. 2015":            day(2015, 9, 7),
		"Nov 11, 2026":            day(2026, 11, 11),
		"Yesterday, 4:40\u202fPM": day(2026, 11, 22),
		"Today, 9:15 AM":          day(2026, 11, 23),
		"ayer, 16:40":             day(2026, 11, 22),
		"Hoy, 9:15":               day(2026, 11, 23),
		"February 30, 2024":       nil,
		"Smarch 3, 2020":          nil,
		"a while ago":             nil,
		"":                        nil,
	}
	for in, want := range cases {
		got := Date(in, now)
		if (got == nil) != (want == nil) || (got != nil && !got.Equal(*want)) {
			t.Errorf("Date(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUnion(t *testing.T) {
	if got := Union([]string{"a", "b"}, []string{"b", "c", "c"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("Union = %q", got)
	}
	if got := Union(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("Union(nil, nil) = %#v, want empty and non-nil", got)
	}
}
