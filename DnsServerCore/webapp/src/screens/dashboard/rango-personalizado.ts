/*
El rango personalizado del Dashboard.

`Custom` era un botón muerto: se marcaba como pulsado, las baldosas se quedaban
en «—» y no aparecía por ninguna parte dónde poner las fechas. La capa de API ya
aceptaba `{start, end}` desde el principio; lo que faltaba era pedirlas.

Lo raro está aquí, en una función pura, porque es lo único de todo esto que
tiene una regla que merece prueba: **cómo se convierte una fecha en instante**.

Upstream (`main.js:2604-2612`) hace algo que parece un descuido y no lo es: si el
rango cabe en siete días o menos, interpreta las fechas en la zona LOCAL del
navegador; si es más largo, en UTC. La razón es que por debajo de una semana el
servidor devuelve estadística por horas —y las horas hay que alinearlas con el
reloj de quien mira—, y por encima devuelve por días, que el servidor agrupa en
UTC. Interpretarlo todo igual desplazaría una de las dos vistas.
*/

/** Los dos instantes ISO que espera la API, con la regla de los siete días. */
export function instantesDelRango(inicio: string, fin: string): { start: string; end: string } {
  const dias = (Date.parse(`${fin}T00:00:00Z`) - Date.parse(`${inicio}T00:00:00Z`)) / 86_400_000 + 1
  const aIso = (d: string) => new Date(dias > 7 ? `${d}T00:00:00Z` : `${d}T00:00:00`).toISOString()
  return { start: aIso(inicio), end: aIso(fin) }
}

/**
 * Lo que falta por rellenar, con el texto literal de upstream
 * (`main.js:2591-2601`). `null` cuando el rango está completo.
 */
export function loQueFalta(inicio: string, fin: string): string | null {
  if (inicio === '') return 'Please select a start date.'
  if (fin === '') return 'Please select an end date.'
  return null
}
