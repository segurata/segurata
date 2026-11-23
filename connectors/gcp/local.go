package gcp

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// localAccount is the account name for findings about files on this machine.
const localAccount = "local"

// gcloudADCClientID is the OAuth client `gcloud auth application-default login` uses when no
// --client-id-file is given (googlecloudsdk/api_lib/auth/util.py).
const gcloudADCClientID = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"

// credFile holds only the non-secret fields of a Google credential JSON. private_key,
// refresh_token and client_secret are deliberately absent, so they are never decoded or printed.
type credFile struct {
	Type           string `json:"type"`
	Account        string `json:"account"`
	ClientID       string `json:"client_id"`
	ClientEmail    string `json:"client_email"`
	PrivateKeyID   string `json:"private_key_id"`
	ProjectID      string `json:"project_id"`
	QuotaProjectID string `json:"quota_project_id"`
}

// gcloudConfigDir follows gcloud: CLOUDSDK_CONFIG, else %APPDATA%\gcloud on Windows, else ~/.config/gcloud.
func gcloudConfigDir(getenv func(string) string, home string) string {
	if d := getenv("CLOUDSDK_CONFIG"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" && getenv("APPDATA") != "" {
		return filepath.Join(getenv("APPDATA"), "gcloud")
	}
	return filepath.Join(home, ".config", "gcloud")
}

func readCred(path string) (credFile, os.FileMode, *time.Time, error) {
	var c credFile
	st, err := os.Stat(path)
	if err != nil {
		return c, 0, nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, 0, nil, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, 0, nil, err
	}
	mt := st.ModTime().UTC()
	return c, st.Mode().Perm(), &mt, nil
}

func modeString(m os.FileMode) string { return fmt.Sprintf("%04o", m) }

// tooOpen reports whether group or others can read the file.
func tooOpen(m os.FileMode) bool { return runtime.GOOS != "windows" && m&0o044 != 0 }

// localFindings inspects credentials on disk: the ADC file, GOOGLE_APPLICATION_CREDENTIALS and
// any service-account key JSON lying in the gcloud config folder.
func localFindings(getenv func(string) string, home string) []finding.Finding {
	dir := gcloudConfigDir(getenv, home)
	adc := filepath.Join(dir, "application_default_credentials.json")
	var out []finding.Finding
	seen := map[string]bool{}
	if c, mode, mt, err := readCred(adc); err == nil {
		seen[adc] = true
		out = append(out, credFinding(adc, "ADC", c, mode, mt))
	}
	if p := getenv("GOOGLE_APPLICATION_CREDENTIALS"); p != "" {
		if abs, err := filepath.Abs(p); err == nil && !seen[abs] {
			seen[abs] = true
			if c, mode, mt, err := readCred(abs); err == nil {
				out = append(out, credFinding(abs, "GOOGLE_APPLICATION_CREDENTIALS", c, mode, mt))
			}
		}
	}
	skip := map[string]bool{"virtenv": true, "logs": true, "cache": true}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if seen[path] || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		c, mode, mt, err := readCred(path)
		if err != nil || c.Type != "service_account" {
			return nil
		}
		seen[path] = true
		out = append(out, credFinding(path, "gcloud config folder", c, mode, mt))
		return nil
	})
	return out
}

func credFinding(path, source string, c credFile, mode os.FileMode, modTime *time.Time) finding.Finding {
	ev := map[string]any{"path": path, "source": source, "type": c.Type, "mode": modeString(mode), "modified_at": modTime}
	f := finding.Finding{
		Account:  localAccount,
		Resource: finding.Resource{Type: "local_credential", ID: path, Name: filepath.Base(path)},
		Kind:     finding.KindExposure,
	}
	switch c.Type {
	case "service_account":
		ev["client_email"], ev["private_key_id"], ev["project_id"] = c.ClientEmail, c.PrivateKeyID, c.ProjectID
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Service account private key for %s on disk (%s)", c.ClientEmail, source)
		f.Remediation = finding.Remediation{
			Summary: "Anyone who copies this file acts as the service account until the key is deleted. Delete the key " +
				"in IAM (key id in evidence) if nothing needs it, delete the file, and use impersonation " +
				"(gcloud --impersonate-service-account) instead of key files. If gcloud stored it after " +
				"activate-service-account, `gcloud auth revoke " + c.ClientEmail + "` removes gcloud's copy.",
			URL: "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
		}
	case "authorized_user":
		ev["account"], ev["quota_project_id"], ev["client_id"] = c.Account, c.QuotaProjectID, c.ClientID
		ev["scopes"] = "not stored in the file; learning them would mean exchanging the refresh token, which securizame does not do"
		defaultClient := c.ClientID == gcloudADCClientID
		ev["gcloud_default_client"] = defaultClient
		who := c.Account
		if who == "" {
			who = "a Google user"
		}
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Refresh token for %s on disk (%s), usable by any local program", who, source)
		where := "the OAuth client " + c.ClientID
		if defaultClient {
			where = `"Google Auth Library" (the client gcloud uses for ADC)`
		}
		f.Remediation = finding.Remediation{
			Summary: "Any program running as you can use this token with every scope it was granted. See those scopes " +
				"under " + where + " at myaccount.google.com/connections. If it holds more than the script needs " +
				"(for example full Drive), revoke it there or with `gcloud auth application-default revoke`, then log in " +
				"again with only the needed scopes: `gcloud auth application-default login --client-id-file=client.json " +
				"--scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/spreadsheets," +
				"https://www.googleapis.com/auth/drive.file` (gcloud requires cloud-platform, and scopes outside Google " +
				"Cloud such as Drive or Sheets need your own OAuth client via --client-id-file).",
			URL: "https://myaccount.google.com/connections",
		}
	default:
		f.Severity = finding.SevLow
		f.Title = fmt.Sprintf("Google credential of type %q on disk (%s)", c.Type, source)
		f.Remediation = finding.Remediation{
			Summary: "Check that this credential configuration is still in use; delete it if not.",
			URL:     "https://cloud.google.com/docs/authentication/application-default-credentials",
		}
	}
	if tooOpen(mode) {
		f.Severity = finding.SevHigh
		f.Title += ", readable by other users"
		f.Remediation.Summary = "Run `chmod 600 " + path + "`. " + f.Remediation.Summary
	}
	f.Evidence = ev
	return f
}
