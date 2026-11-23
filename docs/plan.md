# Securizar la vida digital: plan para hoy

Leyenda: **P0** hoy, **P1** esta semana, **P2** este mes. **[S]** se puede auditar con un script, con el método entre paréntesis. Los minutos son estimados.

## 1. Cuentas Google y administración de Workspace

| P | Acción | Amenaza | Min | Dónde | [S] |
|---|---|---|---|---|---|
| P0 | Pasar Security Checkup en cada cuenta: sesiones, dispositivos, teléfono y correo de recuperación | Recuperación apuntando a un número o correo antiguo; sesiones robadas | 5 por cuenta | https://myaccount.google.com/security-checkup | CDP, scrape por cuenta |
| P0 | Revocar apps de terceros con acceso a Gmail o Drive que ya no uses | Un grant OAuth sobrevive al cambio de contraseña y a la 2FA | 10 por cuenta | https://myaccount.google.com/connections | **CDP** (las cuentas personales no tienen API) |
| P0 | Passkey o llave FIDO2 en todas las cuentas; quitar SMS como segundo factor | Phishing con proxy (AiTM) y SIM swap | 5 por cuenta | https://myaccount.google.com/signinoptions/passkeys | CDP |
| P1 | Advanced Protection en la Gmail personal y en las cuentas de administrador | Phishing dirigido a un directivo; restringe OAuth y descargas | 15 | https://landing.google.com/advancedprotection/ | No |
| P0 | En Workspace: obligar 2SV con llave de seguridad al menos para los administradores | Toma de una cuenta de administrador, que da control sobre todo el dominio | 15 por tenant | Admin › Seguridad › Verificación en dos pasos | **API**: Directory `users.list` (`isEnrolledIn2Sv`, `isEnforcedIn2Sv`) |
| P0 | Superadmin en una cuenta aparte que no se use a diario | Separar el uso diario del rol con más privilegios | 20 | admin.google.com | API Directory (`isAdmin`) |
| P1 | API controls: bloquear apps no configuradas y marcar como de confianza solo las necesarias | Consentimiento OAuth malicioso por parte de empleados | 30 por tenant | Admin › Seguridad › API controls (`admin.google.com/ac/owl`) | **API**: Directory `tokens.list` por usuario y Reports `applicationName=token` |
| P1 | Pasar la checklist oficial: alertas, DMARC, reenvío externo, uso compartido de Drive | Exfiltración silenciosa | 60 | https://support.google.com/a/answer/9184226 | API parcial (Reports, Gmail settings) |
| P2 | Inactive Account Manager | Recuperación si te pasa algo | 5 | https://myaccount.google.com/inactive | No |

## 2. Gestor de contraseñas, passkeys y llaves físicas

- **P0** Dos llaves FIDO2 (YubiKey o similar), una de ellas guardada en una caja fuerte. Registrar las dos en Google, GitHub, Cloudflare, AWS root, Stripe, el gestor y los exchanges. Sin llave de respaldo, perder la principal te deja fuera de todas las cuentas. 30 min.
- **P0** Proteger el gestor con contraseña maestra larga más llave física, y revisar su informe de contraseñas reutilizadas o filtradas (1Password Watchtower, Bitwarden Reports). El gestor es el punto único de fallo. 20 min. [S] Exportar el informe por CLI (`op`, `bw`) sin volcar los secretos.
- **P1** Migrar a passkeys donde existan y eliminar TOTP en SMS. 30 min.
- **P1** Imprimir los códigos de recuperación y guardarlos en papel, fuera del gestor y fuera del Mac. 20 min.

## 3. Correo y teléfono: SIM swap

- **P0** Pedir a la operadora un PIN o clave para portabilidades y duplicados de SIM, si lo ofrece. Un duplicado da acceso a SMS, recuperaciones y banca. 15 min. Fuente: INCIBE.
- **P0** Quitar el número de teléfono como método de recuperación en Google, GitHub y los exchanges, o dejarlo solo como último recurso detrás de una llave. 15 min. [S] CDP.
- **P1** Usar un número secundario o eSIM no público para la 2FA de banca. 30 min.
- Señal de alarma: te quedas sin cobertura donde siempre la tienes. Llamar a la operadora y al banco de inmediato. La línea de ayuda de INCIBE es el **017**.

## 4. Grants OAuth y apps conectadas fuera de Google

| Servicio | URL | [S] |
|---|---|---|
| GitHub (OAuth apps, GitHub Apps, sesiones) | https://github.com/settings/applications, `/settings/installations`, `/settings/sessions` | CDP (no hay API de usuario para los grants OAuth); `gh api /user/installations` |
| Microsoft | https://account.live.com/consent/Manage | CDP |
| Dropbox | https://www.dropbox.com/account/connected_apps | CDP |
| X | https://x.com/settings/connected_apps | CDP |
| Apple ("Iniciar sesión con Apple", dispositivos) | https://account.apple.com/account/manage | CDP |
| Slack | `<workspace>.slack.com/apps/manage` | API `admin.apps.approved.list` en Enterprise; si no, CDP |
| Notion | Settings › Connections, dentro de la app | CDP |

**P0** para GitHub, Google y Microsoft (10 min cada uno). **P1** para el resto. La amenaza es la misma en todos: un token de larga vida en manos de una app abandonada o comprometida.

## 5. macOS y Brave

- **P0** Comprobar que FileVault está activado, que macOS está actualizado y que el firewall está encendido. Un portátil robado sin cifrar lo expone todo. 10 min. [S] **CLI**: `fdesetup status`, `softwareupdate -l`, `socketfilterfw --getglobalstate`, `spctl --status`, `csrutil status`.
- **P0** Revisar las extensiones de Brave en `brave://extensions` y borrar las que no uses. Las extensiones compradas por terceros roban cookies de sesión. 10 min. [S] **Archivo local**: `~/Library/Application Support/BraveSoftware/Brave-Browser/*/Preferences` (IDs y permisos).
- **P1** Revisar los ítems de inicio y los servicios en segundo plano. 10 min. [S] `sfltool dumpbtm`.
- **P1** En el iPhone: Stolen Device Protection y Advanced Data Protection para iCloud. 10 min.
- **P2** Lockdown Mode solo si el perfil de riesgo lo pide.

## 6. Secretos de desarrollo

- **P0** Escanear con gitleaks o trufflehog todos los repos de `~/src`, incluido el historial de git. Un token que lleva años en el historial sigue siendo válido. 30 min. [S] **Escaneo local**.
- **P0** Inventariar los secretos que hay en claro en disco: `.env*`, `~/.aws/credentials`, `~/.config/gcloud`, `~/.npmrc`, `~/.netrc`, `~/.docker/config.json`, historial de la shell (patrones `sk-`, `ghp_`, `AKIA`). 20 min. [S] Escaneo local, informando la ruta y el tipo, nunca el valor.
- **P0** Comprobar si las claves SSH tienen passphrase; mover las claves al agente SSH de 1Password o a una llave FIDO (`ed25519-sk`). Revisar las claves dadas de alta en GitHub. 20 min. [S] `ssh-keygen -y -P "" -f clave`: si funciona, la clave no tiene passphrase. `gh api /user/keys /user/ssh_signing_keys /user/gpg_keys`.
- **P0** AWS: MFA con llave en root, root sin access keys, rotar las claves con más de 90 días. 20 min. [S] `aws iam get-account-summary` y `aws iam generate-credential-report`.
- **P1** GCP: eliminar claves JSON de service accounts; preferir Workload Identity. [S] `gcloud iam service-accounts keys list`.
- **P1** Cloudflare: sustituir la Global API Key por tokens con permisos mínimos, TTL y restricción de IP. [S] API `GET /user/tokens`.
- **P1** Stripe: usar restricted keys y quitar las secret keys sin uso. [S] Inventario por CDP del dashboard.
- **P1** Claves de servicios de IA: una por proyecto, con límite de gasto, y revocar las que no se usen. [S] Escaneo local más consolas de cada proveedor.
- **P1** Activar secret scanning y push protection en las organizaciones de GitHub. [S] `gh api /repos/{o}/{r}` (`security_and_analysis`).

## 7. Finanzas y cripto

- **P0** Binance y Bybit: llave física o passkey, quitar SMS, lista blanca de direcciones de retiro con bloqueo de 24 h, código antiphishing en los correos. Sin lista blanca, quien entre en la cuenta vacía los fondos en minutos. 20 min por exchange.
- **P0** API keys de los exchanges: sin permiso de retiro y restringidas a una IP; borrar las que no se usen. 10 min.
- **P1** Wise y bancos: 2FA por app, alertas de cada movimiento, límites bajos de transferencia. 15 min.
- [S] Solo inventario manual o por CDP. No automatizar nada que pueda escribir en estas cuentas.

## 8. Brechas y data brokers

- **P0** Comprobar todos los correos en Have I Been Pwned y verificar los dominios de las empresas en Domain Search. 15 min. [S] **API v3** (de pago para buscar por cuenta; Pwned Passwords es gratuita y usa k-anonimato).
- **P2** Inscribirse en la Lista Robinson (https://www.listarobinson.es/) y ejercer el derecho de supresión del RGPD ante brokers concretos.

## 9. Copias de seguridad y recuperación

- **P1** Regla 3-2-1: Time Machine cifrado más una copia externa cifrada. Protege contra ransomware y robo. 30 min. [S] `tmutil latestbackup`, `tmutil destinationinfo`.
- **P1** Kit de emergencia en papel: códigos de recuperación, kit del gestor, ubicación de la llave de respaldo.
- **P2** Google Takeout periódico de las cuentas críticas.

## Primer plan para el repo `securizame`

1. `google-oauth-audit`: CDP contra Brave, recorre `myaccount.google.com/connections` con cada cuenta logueada (`?authuser=N`) y devuelve JSON. Solo lectura.
2. `workspace-audit`: Admin SDK (Directory `users` y `tokens`, Reports `token`) por tenant: 2SV, administradores, grants.
3. `connected-apps-audit`: CDP genérico para GitHub, Microsoft, Dropbox, X, Apple y Notion.
4. `local-secrets-scan`: gitleaks, rutas de credenciales y passphrase de las claves SSH.
5. `macos-posture`: comprobaciones por CLI.
6. `cloud-creds-audit`: AWS, GCP, Cloudflare y GitHub por CLI o API.
7. `hibp-check`: API v3.
8. `checklists/`: una por área, con estas mismas filas.

## Fuentes (todas comprobadas el 2026-11-23)

1. Google Advanced Protection: https://support.google.com/accounts/answer/7539956
2. Checklists de seguridad de Google Workspace: https://support.google.com/a/answer/9184226
3. Workspace, control del acceso de apps: https://support.google.com/a/answer/7281227
4. Eventos de auditoría de tokens OAuth (Admin SDK): https://developers.google.com/admin-sdk/reports/v1/appendix/activity/token
5. CISA, MFA resistente al phishing: https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf
6. NCSC UK, Top tips for staying secure online: https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online
7. INCIBE, duplicado de SIM: https://www.incibe.es/ciudadania/blog/por-que-un-ciberdelincuente-le-interesa-duplicar-tu-tarjeta-sim
8. EFF Surveillance Self-Defense: https://ssd.eff.org/
9. Personal Security Checklist (Lissy93): https://github.com/Lissy93/personal-security-checklist
10. GitHub, revisar integraciones autorizadas: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-authorized-integrations
11. AWS, buenas prácticas para el usuario root: https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
12. Apple, seguridad de datos en iCloud (ADP) y Stolen Device Protection: https://support.apple.com/en-us/102651 y https://support.apple.com/en-us/120340

Otras URLs comprobadas: HIBP API v3 (https://haveibeenpwned.com/API/v3), gitleaks (https://github.com/gitleaks/gitleaks), buenas prácticas de claves de service accounts en GCP (https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys), claves de Stripe (https://docs.stripe.com/keys), tokens de Cloudflare (https://developers.cloudflare.com/fundamentals/api/get-started/create-token/).

**Límites de la verificación:**
- No se pudo comprobar `slack.com/apps/manage`: devuelve 403 a clientes sin sesión.
- Los paneles de los exchanges y la ruta `admin.google.com/ac/owl` requieren sesión, así que tampoco se pudieron comprobar.
- El servidor de INCIBE bloquea `curl`; su página se confirmó leyéndola con WebFetch.
- Brave Search había agotado su cuota y la búsqueda se hizo con WebSearch.
