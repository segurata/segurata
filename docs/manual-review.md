# Manual review of third-party access

Where each service lets you see and revoke the apps connected to your account. Services with a
connector are inventoried by securizame; the rest have to be reviewed by hand. Review them every
quarter, and right after a service you used to sign in with announces a breach.

Starting list from [amureki/revokeaccess](https://github.com/amureki/revokeaccess), extended with
the services securizame covers. Links checked on 2026-11-23: signed out, each one redirects to the
service's login page.

| Service | Where to revoke | securizame |
|---|---|---|
| Google | https://myaccount.google.com/connections | `google-personal` |
| Google Workspace (admin) | Admin console › Security › API controls | `workspace/` prototype |
| GitHub OAuth apps | https://github.com/settings/applications | `connected-apps/` prototype |
| GitHub Apps (installed) | https://github.com/settings/installations | `connected-apps/` prototype |
| X | https://x.com/settings/connected_apps | `connected-apps/` prototype |
| Slack | `<workspace>.slack.com/apps/manage` | `connected-apps/` prototype |
| Notion | Settings › Connections (a dialog with no URL) | `connected-apps/` prototype, developer connections only |
| Microsoft | https://account.live.com/consent/Manage | `connected-apps/` prototype, unverified |
| Dropbox | https://www.dropbox.com/account/connected_apps | `connected-apps/` prototype, unverified |
| Facebook | https://www.facebook.com/settings/?tab=applications | Manual |
| Instagram | https://www.instagram.com/accounts/manage_access/ | Manual |
| LinkedIn | https://www.linkedin.com/mypreferences/d/permitted-services (now redirects to "Data sharing for permitted services") | Manual |
| Spotify | https://www.spotify.com/account/apps/ | Manual |
| Apple (Sign in with Apple) | https://account.apple.com/account/manage › Sign in with Apple | Manual |

The old GitHub path `/settings/connections/applications` redirects to `/settings/applications`.

Facebook, Instagram and LinkedIn are candidates for a browser (CDP) connector: they show the list on
a page of the signed-in account, like X and Dropbox.
