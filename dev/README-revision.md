# Herramientas de la revisión pantalla a pantalla

El procedimiento está en
`docs/superpowers/plans/2026-08-26-technitium-ui-revision-pantalla-a-pantalla.md`
de ORBITLAB. Aquí sólo vive lo que se ejecuta.

## `medir-pantalla.js`

Todo lo que un número puede contestar de una pantalla: contraste real de cada
texto, espaciado fuera de la escala de tokens, tamaño del área sensible de cada
control, controles sin nombre accesible, desborde horizontal y ritmo vertical.

Se pega en la consola del navegador, o se pasa entero a `browser_evaluate`:

    medir()            // la pantalla abierta
    await recorrer()   // las doce secciones seguidas

Para un diálogo, hay que decirle cuál es la raíz:

    medir(document.querySelector('[role=dialog]'))

Y para un estado —hover, foco— se apunta primero y se compara con el reposo:

    medirEstado(document.querySelector('[role=menu] button'), 'rgb(25,28,31)')

**Lo que esto NO contesta**: si la pantalla se entiende, si el dato domina sobre
los controles, si el estado vacío dice qué hacer. Eso es de mirar la captura.

## El estado que hace falta antes de empezar

Sin prepararlo, doce diálogos no se pueden ni abrir. Medido el 2026-08-26 en el
contenedor `dev`: cero zonas firmadas, cero concesiones DHCP, sin cluster. Los
comandos de preparación están en el plan, sección 1.

**Nunca contra el LXC 101.** Sólo contra los desechables de `compose.yaml`.
