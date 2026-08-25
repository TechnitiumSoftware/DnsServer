# Cuidado con los `*-custom.json`

La consola lee tres ficheros opcionales que **no** están en el repo porque los
crea el administrador a mano en `www/json/`:

- `quick-block-lists-custom.json` (`main.js:816` en la consola antigua)
- `quick-forwarders-list-custom.json` (`main.js:855`)
- `dnsclient-server-list-custom.json` (`dnsclient.js:53`)

Cuando falta el `-custom`, la consola usa el `-builtin` correspondiente.

**El build de `webapp/` vacía `www/` antes de escribir.** Cualquier
`*-custom.json` que hubiera allí se pierde. En un despliegue sobre una
instalación existente hay que copiarlos fuera antes de desplegar y devolverlos
después. No es un problema en las instancias desechables de `dev/`, donde no
existen.
