// Renders the raster icons from public/favicon.svg, so the three files never drift apart:
//   public/favicon.ico           16 and 32 px PNG images in one ICO container
//   public/apple-touch-icon.png  180 px
// Run from ui/ after changing favicon.svg: node scripts/render-icons.mjs
// Uses the Playwright Chromium the browser tests already install.
import { readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from '@playwright/test'

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public')
const svg = await readFile(path.join(publicDir, 'favicon.svg'), 'utf8')
const source = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`

async function render(page, size) {
  await page.setViewportSize({ width: size, height: size })
  await page.setContent(
    `<style>html,body{margin:0;background:transparent}img{display:block}</style>`
      + `<img src="${source}" width="${size}" height="${size}" alt="">`,
  )
  await page.locator('img').evaluate((img) => img.decode())
  return page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } })
}

// ICO with PNG payloads (supported by every current browser and Windows since Vista).
function ico(images) {
  const header = Buffer.alloc(6)
  header.writeUInt16LE(0, 0)
  header.writeUInt16LE(1, 2)
  header.writeUInt16LE(images.length, 4)
  const entries = []
  let offset = 6 + 16 * images.length
  for (const { size, png } of images) {
    const entry = Buffer.alloc(16)
    entry.writeUInt8(size >= 256 ? 0 : size, 0)
    entry.writeUInt8(size >= 256 ? 0 : size, 1)
    entry.writeUInt8(0, 2)
    entry.writeUInt8(0, 3)
    entry.writeUInt16LE(1, 4)
    entry.writeUInt16LE(32, 6)
    entry.writeUInt32LE(png.length, 8)
    entry.writeUInt32LE(offset, 12)
    entries.push(entry)
    offset += png.length
  }
  return Buffer.concat([header, ...entries, ...images.map(({ png }) => png)])
}

const browser = await chromium.launch()
try {
  const page = await browser.newPage({ deviceScaleFactor: 1 })
  const icons = []
  for (const size of [16, 32]) icons.push({ size, png: await render(page, size) })
  await writeFile(path.join(publicDir, 'favicon.ico'), ico(icons))
  await writeFile(path.join(publicDir, 'apple-touch-icon.png'), await render(page, 180))
} finally {
  await browser.close()
}
