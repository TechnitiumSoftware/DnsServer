import { chromium } from 'playwright'
const b = await chromium.launch()

async function nueva(p) {
  await p.goto('http://127.0.0.1:5380/', { waitUntil: 'networkidle' })
  const r = {}
  await p.getByRole('button', { name: 'Login' }).click()
  await p.waitForTimeout(400)
  r.sinUsuario = (await p.locator('[role=alert]').innerText()).replace(/\s+/g, ' ').trim()
  await p.getByLabel('Username').fill('admin')
  await p.getByRole('button', { name: 'Login' }).click()
  await p.waitForTimeout(400)
  r.sinPass = (await p.locator('[role=alert]').innerText()).replace(/\s+/g, ' ').trim()
  await p.getByLabel('Password').fill('incorrecta')
  await p.getByRole('button', { name: 'Login' }).click()
  await p.waitForTimeout(2000)
  r.malas = (await p.locator('[role=alert]').innerText()).replace(/\s+/g, ' ').trim()
  return r
}

async function vieja(p) {
  await p.goto('http://127.0.0.1:5381/', { waitUntil: 'networkidle' })
  const r = {}
  const alerta = async () => (await p.locator('#divAlert, .alert').first().innerText()).replace(/\s+/g,' ').trim()
  await p.click('#btnLogin'); await p.waitForTimeout(400); r.sinUsuario = await alerta()
  await p.fill('#txtUser', 'admin'); await p.click('#btnLogin'); await p.waitForTimeout(400); r.sinPass = await alerta()
  await p.fill('#txtPass', 'incorrecta'); await p.click('#btnLogin'); await p.waitForTimeout(2000); r.malas = await alerta()
  return r
}

const p1 = await b.newPage(); const n = await nueva(p1)
const p2 = await b.newPage(); const v = await vieja(p2)

let ok = true
for (const k of ['sinUsuario', 'sinPass', 'malas']) {
  const igual = n[k] === v[k]
  if (!igual) ok = false
  console.log(`${igual ? 'IGUAL  ' : 'DISTINTO'} ${k}`)
  console.log(`   nueva: ${n[k]}`)
  console.log(`   vieja: ${v[k]}`)
}
console.log(ok ? '\n=> PARIDAD DE MENSAJES: OK' : '\n=> HAY DIVERGENCIAS')
await b.close()
