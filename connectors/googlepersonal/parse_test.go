package googlepersonal

import (
	"reflect"
	"testing"
)

func TestIsReauth(t *testing.T) {
	cases := map[string]bool{
		reauthEN:                         true,
		"Verify that it's you to go on":  true,
		reauthES:                         true,
		overviewENAccess:                 false,
		"Third-party apps & services\nX": false,
	}
	for text, want := range cases {
		if got := isReauth(text); got != want {
			t.Errorf("isReauth(%.30q) = %v, want %v", text, got, want)
		}
	}
}

func TestParseOverview(t *testing.T) {
	cases := []struct {
		name string
		text string
		want overview
	}{
		{"en access, truncated list", overviewENAccess, overview{
			Scopes:       []string{"See your profile info", "See and download your contacts"},
			CrossAccount: true,
		}},
		{"en sign-in only", overviewENSignIn, overview{}},
		{"es access", overviewESAccess, overview{Scopes: []string{
			"Ver, editar, crear y eliminar solo los archivos específicos de Google Drive que usas con esta aplicación",
			"Ver eventos de todos tus calendarios",
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseOverview(c.text); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v\nwant %#v", got, c.want)
			}
		})
	}
}

func TestParseDetail(t *testing.T) {
	cases := []struct {
		name string
		text string
		want detail
	}{
		{"en oauth", detailENOAuth, detail{GivenOn: "March 24, 2020", Scopes: []string{
			"See your profile info",
			"See and download your contacts",
			"Read, compose, and send emails from your Gmail account",
			"Allow this application to run when you are not present",
		}}},
		{"en sign in with google", detailENSignIn, detail{GivenOn: "May 15, 7:37 PM"}},
		{"es oauth", detailESOAuth, detail{GivenOn: "18 de noviembre de 2025", Scopes: []string{
			"Ver, editar, crear y eliminar solo los archivos específicos de Google Drive que usas con esta aplicación",
			"Ver eventos de todos tus calendarios",
			"Ver la información de tu perfil",
		}}},
		{"no date", "Acme can:\nSee your profile info\nIf you remove access", detail{Scopes: []string{"See your profile info"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseDetail(c.text); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v\nwant %#v", got, c.want)
			}
		})
	}
}
