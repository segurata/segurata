// Package pagetext holds the helpers CDP connectors share to read the innerText of account
// pages: line splitting and dates in English and Spanish. Standard library only.
package pagetext

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Lines splits innerText into trimmed, non-empty lines.
func Lines(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

var months = map[string]time.Month{
	"january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
	"august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "sept": 9,
	"oct": 10, "nov": 11, "dec": 12,
	"enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6, "julio": 7,
	"agosto": 8, "septiembre": 9, "setiembre": 9, "octubre": 10, "noviembre": 11, "diciembre": 12,
	"ene": 1, "abr": 4, "ago": 8, "dic": 12,
}

var (
	relativeDayRE = regexp.MustCompile(`(?i)^(today|yesterday|hoy|ayer)\b`)
	// "March 24, 2020", "May 15, 7:37 PM", "Mar 24, 2020"
	enDateRE = regexp.MustCompile(`^([A-Za-z]+)\.? (\d{1,2})(?:, (\d{4}))?\b`)
	// "18 de noviembre de 2025", "21 de septiembre, 12:28", "18 nov 2025"
	esDateRE = regexp.MustCompile(`^(\d{1,2})(?: de)? ([a-zñ]+)\.?(?:(?: de)? (\d{4}))?\b`)
)

// Date turns a date as account pages print it into a UTC date, in English or Spanish. Pages omit
// the year for dates in the current year ("May 15, 7:37 PM") and say "Yesterday" or "Today" for
// the last two days; now supplies what is missing. The time of day is dropped:
// the page shows it in the browser's zone, which is not recorded. Unparseable → nil, never a guess.
func Date(s string, now time.Time) *time.Time {
	s = strings.TrimSpace(s)
	if m := relativeDayRE.FindStringSubmatch(s); m != nil {
		d := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		if strings.EqualFold(m[1], "yesterday") || strings.EqualFold(m[1], "ayer") {
			d = d.AddDate(0, 0, -1)
		}
		return &d
	}
	var monthName, day, year string
	if m := enDateRE.FindStringSubmatch(s); m != nil {
		monthName, day, year = m[1], m[2], m[3]
	} else if m := esDateRE.FindStringSubmatch(strings.ToLower(s)); m != nil {
		day, monthName, year = m[1], m[2], m[3]
	} else {
		return nil
	}
	month, ok := months[strings.ToLower(monthName)]
	if !ok {
		return nil
	}
	d, _ := strconv.Atoi(day)
	y := now.Year()
	if year != "" {
		y, _ = strconv.Atoi(year)
	}
	t := time.Date(y, month, d, 0, 0, 0, 0, time.UTC)
	if t.Day() != d || t.Month() != month { // "February 30" rolled over
		return nil
	}
	return &t
}
