/*
Qué enseña cada pantalla cuando el servidor falla.

Es el punto 12 del plan de revisión, el único que decía «hay que escribirlo»
y seguía sin escribirse. Las demás herramientas miran una consola que funciona;
esta mira la que no.

Lo que se busca NO es que salte un aviso. Es lo contrario: **que una petición
fallida no acabe pintada como un estado vacío.** «No data for this period» y
«No hay nada que enseñar porque la llamada se cayó» son la misma imagen y
significan cosas opuestas, y de las dos, la primera es la que hace que alguien
cierre la pestaña convencido de que su DNS no ha recibido consultas. Es el mismo
fallo de fondo que la tabla aplastada de «User Details»: la pantalla miente sin
avisar.

No usa Playwright a propósito, como el resto de `dev/`: se pega en la consola
del navegador o se pasa a `browser_evaluate`. Meter un driver en
`package.json` aparecería en el diff del pull request.

    romper('api/', 'error')      el servidor contesta 200 con status=error
    romper('api/', '500')        contesta 500 con HTML, que ni siquiera es JSON
    romper('api/', 'red')        no contesta: fetch rechaza
    romper('dashboard', 'error') sólo lo que case con ese trozo de URL
    arreglar()                   devuelve el fetch de verdad

    await queDice()              qué se ve ahora: avisos, vacíos y cargas

Uso normal: `romper(...)`, recargar la pantalla —o volver a entrar en ella—, y
`await queDice()`.
*/

const fetchDeVerdad = window.fetch

/** Sustituye el `fetch` por uno que falla como se le pida. */
function romper(patron = 'api/', modo = 'error') {
  window.fetch = async (entrada, init) => {
    const url = typeof entrada === 'string' ? entrada : entrada.url
    if (!url.includes(patron)) return fetchDeVerdad(entrada, init)

    if (modo === 'red') throw new TypeError('Failed to fetch')

    if (modo === '500') {
      // 500 con cuerpo HTML: el caso en el que ni el JSON se puede leer.
      return new Response('<html><body>500</body></html>', {
        status: 500,
        headers: { 'Content-Type': 'text/html' },
      })
    }

    // El caso de verdad de esta API: 200 con el estado dentro del sobre.
    const cuerpo =
      modo === 'invalid-token'
        ? { status: 'invalid-token' }
        : { status: 'error', errorMessage: 'Simulated server failure.' }

    return new Response(JSON.stringify(cuerpo), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }
  return `roto: ${patron} → ${modo}`
}

function arreglar() {
  window.fetch = fetchDeVerdad
  return 'arreglado'
}

const visible = (e) => {
  const r = e.getBoundingClientRect()
  return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'
}

const texto = (e) => (e.innerText || '').replace(/\s+/g, ' ').trim()

/**
 * Qué se ve. Devuelve los avisos, los estados vacíos y si hay algo cargando,
 * más el veredicto: un vacío sin aviso es el hallazgo.
 */
async function queDice(ms = 1500) {
  await new Promise((r) => setTimeout(r, ms))
  const raiz = document.querySelector('main') ?? document.body

  const avisos = [...document.querySelectorAll('[role="alert"]')]
    .filter(visible)
    .map((e) => texto(e).slice(0, 120))

  /*
  Y el fallo dicho SIN un `role="alert"`, que también cuenta. Settings, por
  ejemplo, sustituye el formulario entero por «Unable to load the DNS Server
  settings.», que es una forma perfectamente buena de contarlo; buscar sólo
  alertas la daba por muda y era un falso positivo.
  */
  const dicho = /Unable to (load|check|reach)|Failed to|Error!/i.test(texto(raiz))

  /* Los estados vacíos de la consola: `ui/Empty` y los textos que upstream usa
     para «aquí no hay nada». Se buscan por clase y por frase, porque no todos
     pasan por el componente. */
  const vacios = [...raiz.querySelectorAll('[class*="_empty_"], [class*="_vacio_"]')]
    .filter(visible)
    .map((e) => texto(e).slice(0, 90))

  const porFrase = /No data for this period|No queries for this period|No .{0,24} found|Nothing to show/i
  const frases = [...raiz.querySelectorAll('div, p, td')]
    .filter((e) => e.children.length === 0 && visible(e) && porFrase.test(texto(e)))
    .map((e) => texto(e).slice(0, 90))

  const cargando = [...raiz.querySelectorAll('[class*="_loading_"], [aria-busy="true"]')].filter(visible).length

  const todosLosVacios = [...new Set([...vacios, ...frases])]

  return {
    ruta: location.pathname,
    avisos,
    vacios: todosLosVacios,
    cargando,
    /*
    El veredicto. Un vacío sin un aviso al lado es la pantalla diciendo «no hay
    nada» cuando lo que pasó es que la llamada se cayó.
    */
    dicho,
    veredicto:
      avisos.length > 0 || dicho
        ? 'AVISA'
        : todosLosVacios.length > 0
          ? 'MIENTE: enseña vacío y no dice que ha fallado'
          : cargando > 0
            ? 'SE QUEDA CARGANDO'
            : 'NI AVISO NI NADA',
  }
}
