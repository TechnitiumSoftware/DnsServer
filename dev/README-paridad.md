# Comprobaciones de paridad

`paridad-login.mjs` compara los avisos de la pantalla de login entre la consola
nueva (5380) y la de upstream (5381). Necesita Playwright:

```bash
npm i -D playwright && npx playwright install chromium
node paridad-login.mjs
```

Encontró dos divergencias reales la primera vez que se ejecutó: faltaba el botón
«×» para descartar el aviso —que en upstream existe, así que su ausencia era una
diferencia de comportamiento— y faltaba el espacio entre el título y el texto.
