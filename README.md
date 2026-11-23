# securizame

Scripts y listas para revisar y limpiar la seguridad de mis cuentas.

Regla de la casa: cada script **inventaría primero y en solo lectura**. Quitar accesos es otro paso,
a mano o con un script aparte, después de revisar la lista.

## Google: aplicaciones vinculadas

```bash
node google/linked-apps-inventory.mjs
```

Recorre todas las cuentas de Google con sesión abierta en el navegador y, para cada una, saca las
apps con acceso a datos (`access`, con sus permisos) y las que solo usan «Iniciar sesión con Google»
(`signin`). Las cuentas en las que Google pide volver a entrar salen como `reauth`.

- Requisito: Brave o Chrome arrancado con `--remote-debugging-port=9222` (otro puerto con
  `SECURIZAME_CDP`). Las páginas se abren en segundo plano y se cierran solas, sin tocar tus pestañas.
- Salida: `out/google-linked-apps-<fecha>.jsonl`. `out/` está en `.gitignore`, porque contiene
  correos y la lista de servicios de cada cuenta.
- Para quitar un acceso: <https://myaccount.google.com/connections> en la cuenta que toque, o el
  campo `href` de cada fila, que lleva directo a la ficha de la app.
