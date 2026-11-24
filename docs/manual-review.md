# Manual review of third-party access

Where each service lets you see and revoke the apps connected to your account. Services with a
connector are inventoried by segurata; the rest have to be reviewed by hand. Review them every
quarter, and right after a service you used to sign in with announces a breach.

Starting list from [amureki/revokeaccess](https://github.com/amureki/revokeaccess), extended with
the services segurata covers. Links checked on 2026-11-23: signed out, each one redirects to the
service's login page.

| Service | Where to revoke | segurata |
|---|---|---|
| Google | https://myaccount.google.com/connections | `google-personal` |
| Google Workspace (admin) | Admin console › Security › API controls | `workspace` |
| GitHub OAuth apps | https://github.com/settings/applications | `connected-apps` |
| GitHub Apps (installed) | https://github.com/settings/installations | `connected-apps`, names only (permissions need sudo mode) |
| X | https://x.com/settings/connected_apps | `connected-apps` |
| Slack | `<workspace>.slack.com/apps/manage` | `connected-apps` |
| Notion | Settings › Connections (a dialog with no URL) | `connected-apps`, developer connections only |
| Microsoft (personal account) | https://account.live.com/consent/Manage | `connected-apps`, session check only (unverified) |
| Microsoft work or school account: apps | https://myapplications.microsoft.com/ (My Apps; users cannot revoke there) | `connected-apps` (`microsoft-work`), names only |
| Microsoft work or school account: delegated consents | Microsoft Entra admin center › Enterprise applications › the app › Permissions (admins only) | Manual |
| Microsoft work or school account: sign-in methods | https://mysignins.microsoft.com/security-info (asks for a fresh MFA sign-in) | `connected-apps` (`microsoft-work`), step-up detected only (unverified past it) |
| Dropbox | https://www.dropbox.com/account/connected_apps › "View Dropbox content" | `connected-apps` ("Launch from Dropbox" is not read) |
| Facebook | https://www.facebook.com/settings/?tab=applications | `connected-apps`, first page only ("See more" is not clicked) |
| Instagram | https://www.instagram.com/accounts/manage_access/ | `connected-apps`; a non-empty list is `unverified` |
| LinkedIn | https://www.linkedin.com/mypreferences/d/data-sharing-for-permitted-services (the old `/permitted-services` redirects here) | `connected-apps`; a non-empty list is `unverified` |
| Spotify | https://www.spotify.com/account/apps/ | Manual |
| Apple (Sign in with Apple) | https://account.apple.com/account/manage › Sign in with Apple | Manual |

The old GitHub path `/settings/connections/applications` redirects to `/settings/applications`.

Microsoft has two kinds of account with separate pages. account.live.com is for personal
accounts; with a work or school account signed in it sends the browser to the personal sign-in
form, which does not say whether a personal account exists. My Apps (myapps.microsoft.com
redirects to myapplications.microsoft.com) lists the apps a work account can open, without their
permissions; My Account (myaccount.microsoft.com) links to it and lists organizations and
devices. Checked 2026-11-24.

Facebook keeps the list under Settings › Apps and websites. Accounts Center's "App connections"
is a different list (Meta AI links to other services). Instagram's page has Active, Expired and
Removed tabs; the connector reads Active.
