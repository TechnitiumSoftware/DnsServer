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
Chart.js is used, not hand-written SVG, for two behavioural reasons:
  · the server returns the data ALREADY in Chart.js format (labels + datasets);
  · clicking a series in the legend hides it, and that is an interaction that
    exists today. With SVG it would be lost.
*/
export function Chart({
  type,
  data,
  height = 230,
  aria,
}: {
  type: ChartType
  data: ChartData
  height?: number
  aria: string
}) {
  const ref = useRef<HTMLCanvasElement>(null)
  const chart = useRef<ChartJS | null>(null)

  useEffect(() => {
    if (!ref.current) return
    const css = getComputedStyle(document.documentElement)
    const tinta = css.getPropertyValue('--mute').trim() || '#8b95a7'
    const line = css.getPropertyValue('--line2').trim() || '#1a202b'

    chart.current = new ChartJS(ref.current, {
      type: type,
      data: data as unknown as ChartJsData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: { labels: { color: tinta, boxWidth: 10, boxHeight: 10, font: { size: 11 } } },
        },
        scales:
          type === 'line'
            ? {
                x: { ticks: { color: tinta, maxTicksLimit: 8, font: { size: 10 } }, grid: { color: line } },
                y: { ticks: { color: tinta, font: { size: 10 } }, grid: { color: line }, beginAtZero: true },
              }
            : undefined,
      },
    })
    return () => {
      chart.current?.destroy()
      chart.current = null
    }
  }, [type, data])

  return (
    <div style={{ height: height }}>
      <canvas ref={ref} role="img" aria-label={aria} />
    </div>
  )
}
