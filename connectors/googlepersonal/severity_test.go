package googlepersonal

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestClassifyScopes(t *testing.T) {
	cases := []struct {
		scope string
		want  finding.Severity
	}{
		// high
		{"Read, compose, and send emails from your Gmail account", finding.SevHigh},
		{"Manage drafts and send emails", finding.SevHigh},
		{"View your email messages and settings", finding.SevHigh},
		{"Read, compose, send, and permanently delete all your email from Gmail", finding.SevHigh},
		{"See, edit, create, and delete all of your Google Drive files", finding.SevHigh},
		{"See and download all your Google Drive files", finding.SevHigh},
		{"Ver, modificar, crear y eliminar archivos de Google Drive", finding.SevHigh},
		{"Ver y descargar archivos de Google Drive", finding.SevHigh},
		{"See, edit, create, and delete all your Google Sheets spreadsheets", finding.SevHigh},
		{"Ver, editar, crear y eliminar todas tus hojas de cálculo de Hojas de cálculo de Google", finding.SevHigh},
		{"See, edit, configure, and delete your Google Cloud data and see the email address for your Google Account.", finding.SevHigh},
		{"Ver, modificar, configurar y eliminar tus datos de Google Cloud y ver la dirección de correo de tu cuenta de Google.", finding.SevHigh},
		{"View and manage your Google Compute Engine resources", finding.SevHigh},
		{"Allow this application to run when you are not present", finding.SevHigh},
		{"Permitir que esta aplicación se ejecute cuando no estés presente", finding.SevHigh},
		{"Consultar, editar, crear y eliminar tus cuentas y datos de Google Ads.", finding.SevHigh},
		// medium
		{"See and download your contacts", finding.SevMedium},
		{"Ver y descargar tus contactos", finding.SevMedium},
		{"See, edit, share, and permanently delete all the calendars you can access using Google Calendar", finding.SevMedium},
		{"View and edit events on all your calendars", finding.SevMedium},
		{"Ver y editar eventos de todos tus calendarios", finding.SevMedium},
		{"Manage your YouTube account", finding.SevMedium},
		{"View customer related information", finding.SevMedium}, // unknown scope
		// low
		{"See, edit, create, and delete only the specific Google Drive files you use with this app", finding.SevLow},
		{"Ver, editar, crear y eliminar solo los archivos específicos de Google Drive que usas con esta aplicación", finding.SevLow},
		{"See, create, and delete its own configuration data in your Google Drive", finding.SevLow},
		{"View events on all your calendars", finding.SevLow},
		{"Ver eventos de todos tus calendarios", finding.SevLow},
		// info
		{"See your profile info", finding.SevInfo},
		{"Ver la información de tu perfil", finding.SevInfo},
	}
	for _, c := range cases {
		if got := classify(c.scope).sev; got != c.want {
			t.Errorf("classify(%q) = %s, want %s", c.scope, got, c.want)
		}
	}
}

func TestAssess(t *testing.T) {
	cases := []struct {
		name      string
		scopes    []string
		wantSev   finding.Severity
		wantLabel string
	}{
		{"sign-in only", nil, finding.SevInfo, "sign you in with your Google account"},
		{"profile only", []string{"See your profile info"}, finding.SevInfo, "see your profile info"},
		{"worst wins", []string{"See your profile info", "See and download your contacts", "Manage drafts and send emails"}, finding.SevHigh, "read and send email from your Gmail"},
		{"tie keeps first", []string{"See and download your contacts", "Manage your YouTube account"}, finding.SevMedium, "see and download your contacts"},
		{"unknown", []string{"Connect to an external service"}, finding.SevMedium, "access some of your Google Account data"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sev, label := assess(c.scopes)
			if sev != c.wantSev || label != c.wantLabel {
				t.Fatalf("assess = %s %q, want %s %q", sev, label, c.wantSev, c.wantLabel)
			}
		})
	}
}
