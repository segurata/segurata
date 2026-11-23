# Arquitectura

securizame inventaría la huella digital de una persona o una empresa pequeña (cuentas de consumo,
nubes, proveedores de IA, secretos en el disco), la valora y, solo cuando se pide, la limpia.

## Piezas

```
securizame (binario Go)
├── núcleo: config, referencias a secretos, ejecución de conectores, salida, informe
├── conectores integrados (compilados dentro)
└── conectores externos: ejecutables securizame-<nombre> en el PATH, en cualquier lenguaje
```

Los dos tipos de conector cumplen el mismo contrato. Un integrado implementa la interfaz Go
`connector.Connector`; uno externo habla el protocolo de abajo por stdin/stdout y el núcleo lo
envuelve en esa misma interfaz. El resto del programa no distingue uno de otro.

### Verbos

| Verbo | Qué hace | Toca algo fuera |
|---|---|---|
| `inventory` | Lista lo que hay: grants, claves, ajustes, gasto | Nunca |
| `assess` | Asigna gravedad y remedio a cada hallazgo | Nunca |
| `remediate` | Aplica un remedio a un hallazgo concreto | Sí, uno a uno, con `--dry-run` por defecto y confirmación explícita |

En v0 la gravedad la pone cada conector al inventariar (`assess` va dentro de `inventory`).
`remediate` describe siempre, antes de actuar, el alcance exacto de lo que va a quitar. En Google,
"Quitar todo el acceso" en la ficha de permisos también borra el "Iniciar sesión con Google" de
esa app, y eso hay que avisarlo antes, no descubrirlo después.

## Modelo de hallazgo

Una línea JSON por hallazgo (`internal/finding`):

```json
{
  "type": "finding",
  "id": "sha256(connector|account|resource.type|resource.id)[:16]",
  "connector": "google-personal",
  "account": "persona@example.com",
  "resource": {"type": "oauth_grant", "id": "…", "name": "Dropbox"},
  "kind": "grant",
  "severity": "high",
  "title": "Dropbox puede ver y descargar tus contactos",
  "evidence": {"scopes": ["…"]},
  "created_at": "2020-03-24T00:00:00Z",
  "last_used_at": null,
  "remediation": {"summary": "…", "url": "https://…", "automatable": false},
  "observed_at": "2026-11-23T21:00:00Z"
}
```

- `kind`: `grant` (acceso de terceros), `credential` (clave, token, cuenta de servicio), `setting`
  (configuración de seguridad), `spend` (gasto, presupuesto o límite), `exposure` (secreto a la vista).
- `severity`: `info`, `low`, `medium`, `high`, `critical`.
- `last_used_at`: lo que dé el proveedor. Si no lo da, `null`, nunca una fecha inventada.
- `evidence` jamás lleva un secreto. Como mucho un prefijo redactado y la longitud
  (`finding.Redact`).

Además de hallazgos, un conector emite registros de estado por cuenta, que dicen por qué no se pudo
mirar algo:

```json
{"type": "status", "connector": "openai", "account": "org-…", "state": "missing_credentials", "detail": "…"}
```

`state`: `ok`, `reauth`, `signedout`, `missing_credentials`, `unsupported`, `error`.

## Protocolo de conectores externos (v1)

Un conector externo es un ejecutable `securizame-<nombre>` con dos subcomandos.

`securizame-<nombre> describe` imprime un objeto JSON:

```json
{"name": "ejemplo", "version": "0.1.0", "protocol": 1,
 "summary": "Qué inventaría", "needs": ["cdp", "cli:gcloud", "secret:EJEMPLO_API_KEY"]}
```

`securizame-<nombre> inventory` lee una petición JSON por stdin y escribe registros JSON Lines
(`finding`, `status` o `log`) por stdout:

```json
{"protocol": 1, "cdp_url": "http://127.0.0.1:9222", "config": {"…": "…"},
 "secrets": {"EJEMPLO_API_KEY": "valor ya resuelto por el núcleo"}}
```

Reglas:
- Salida 0 si terminó, aunque algunas cuentas den `status` de error. Distinto de 0 solo si el
  conector no pudo ni empezar.
- stderr es para diagnóstico humano; el núcleo lo muestra con `--verbose`.
- El conector nunca escribe secretos en stdout ni en stderr.

## Secretos que usan los conectores

Las claves de administración (OpenAI, Anthropic, OpenRouter, Vercel, Supabase…) no viven en ficheros
planos. La config dice dónde está cada una, y el núcleo la resuelve al vuelo y se la pasa al
conector en la petición, sin escribirla a disco:

| Referencia | Se resuelve con |
|---|---|
| `env:NOMBRE` | Variable de entorno |
| `keychain:servicio` | `security find-generic-password -s servicio -w` (Llavero de macOS) |
| `op://vault/item/campo` | `op read` (1Password CLI) |

Config en `~/.config/securizame/config.json`:

```json
{
  "cdp_url": "http://127.0.0.1:9222",
  "connectors": {
    "openai": {"secrets": {"OPENAI_ADMIN_KEY": "keychain:securizame-openai-admin"}},
    "gcp": {"config": {"projects": ["mi-proyecto"]}}
  }
}
```

## Conectores de v0

| Conector | Cómo mira | Qué busca |
|---|---|---|
| `google-personal` | CDP sobre el navegador con sesión | Apps vinculadas, permisos, fechas, cuentas que piden volver a entrar |
| `gcp` | CLI `gcloud` | Claves de API sin restricciones, claves de cuentas de servicio y su antigüedad, cuentas de servicio con roles amplios, presupuestos y alertas de facturación, credenciales ADC locales y sus permisos |
| `aws` | CLI `aws` | Root con claves o sin MFA, claves de acceso antiguas o sin usar, presupuestos |
| `azure` | CLI `az` | Presupuestos, secretos de app registrations a punto de caducar o sin caducidad |
| `openai` | API de administración | Claves, último uso, proyectos, límites y gasto |
| `anthropic` | API de administración | Claves, último uso, workspaces, límites y gasto |
| `openrouter` | API | Claves, límite de crédito por clave, gasto |
| `vercel` | API | Tokens, gestión de gasto (spend management) |
| `supabase` | API de gestión | Proyectos, claves de servicio, límite de gasto |

Los scripts Node de `google/`, `connected-apps/`, `workspace/`, `secrets/` y `macos/` son los
prototipos. Se quedan funcionando hasta que su conector Go los sustituya, y entonces se borran.

## Por qué Go y por qué tan pocas dependencias

- Un binario estático para macOS, Linux y Windows, sin runtime que instalar.
- Una herramienta de seguridad con cien dependencias es en sí misma un riesgo de cadena de
  suministro. El núcleo usa solo la biblioteca estándar (incluido un cliente WebSocket mínimo para
  CDP). Los conectores de nube llaman a las CLI oficiales (`gcloud`, `aws`, `az`), que ya están
  autenticadas en la máquina, en lugar de meter los SDK.
- Cualquier dependencia nueva pasa la cuarentena de 4 días y va fijada a versión exacta.

## Trabajo previo

Prowler y ScoutSuite ya revisan a fondo la postura de seguridad de AWS, Azure y GCP. Si hace falta esa
profundidad, se envuelven como conectores externos en vez de reescribirlos. securizame cubre lo que
ellos no tocan: cuentas de consumo, grants OAuth personales, gasto y claves de proveedores de IA y
secretos locales.
