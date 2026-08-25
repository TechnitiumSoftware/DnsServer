import { useEffect, useRef } from 'react'
import {
  Chart as ChartJS,
  LineController, DoughnutController,
  LineElement, PointElement, ArcElement,
  CategoryScale, LinearScale,
  Legend, Tooltip, Filler,
  type ChartData as ChartJsData, type ChartType,
} from 'chart.js'
import type { ChartData } from '../../api/dashboard'

ChartJS.register(LineController, DoughnutController, LineElement, PointElement, ArcElement, CategoryScale, LinearScale, Legend, Tooltip, Filler)

/*
Se usa Chart.js, no SVG a mano, por dos razones de comportamiento:
  · el servidor devuelve los datos YA en formato Chart.js (labels + datasets);
  · pulsar una serie de la leyenda la oculta, y eso es una interacción que
    existe hoy. Con SVG se perdería.
*/
export function Chart({
  tipo,
  data,
  alto = 230,
  aria,
}: {
  tipo: ChartType
  data: ChartData
  alto?: number
  aria: string
}) {
  const ref = useRef<HTMLCanvasElement>(null)
  const chart = useRef<ChartJS | null>(null)

  useEffect(() => {
    if (!ref.current) return
    const css = getComputedStyle(document.documentElement)
    const tinta = css.getPropertyValue('--mute').trim() || '#8b95a7'
    const linea = css.getPropertyValue('--line2').trim() || '#1a202b'

    chart.current = new ChartJS(ref.current, {
      type: tipo,
      data: data as unknown as ChartJsData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: { labels: { color: tinta, boxWidth: 10, boxHeight: 10, font: { size: 11 } } },
        },
        scales:
          tipo === 'line'
            ? {
                x: { ticks: { color: tinta, maxTicksLimit: 8, font: { size: 10 } }, grid: { color: linea } },
                y: { ticks: { color: tinta, font: { size: 10 } }, grid: { color: linea }, beginAtZero: true },
              }
            : undefined,
      },
    })
    return () => {
      chart.current?.destroy()
      chart.current = null
    }
  }, [tipo, data])

  return (
    <div style={{ height: alto }}>
      <canvas ref={ref} role="img" aria-label={aria} />
    </div>
  )
}
