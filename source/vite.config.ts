import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { readFileSync } from 'fs'

// Read base path from yeti config.yaml automatically.
// Uses route_prefix if set, otherwise /{app_id}/.
function readYetiBasePath(): string {
  if (process.env.YETI_BASE_PATH) return process.env.YETI_BASE_PATH
  try {
    const config = readFileSync(path.resolve(__dirname, '../config.yaml'), 'utf-8')
    const prefixMatch = config.match(/^route_prefix:\s*["']?([^"'\n]+)["']?/m)
    if (prefixMatch) {
      const prefix = prefixMatch[1].trim()
      return prefix === '/' ? '/' : `${prefix.replace(/\/+$/, '')}/`
    }
    const idMatch = config.match(/^app_id:\s*["']?([^"'\n]+)["']?/m)
    if (idMatch) return `/${idMatch[1].trim()}/`
  } catch {}
  return './'
}
export default defineConfig({
  base: readYetiBasePath(),
  plugins: [react()],
  resolve: {
    alias: { '@yeti': path.resolve(__dirname, '../../../shared') },
  },
  build: {
    outDir: '../web',
    emptyOutDir: true,
  },
  server: {
    fs: { allow: ['..', '../../../shared'] },
    port: 5178,
    proxy: {
      '/yeti-auth': {
        target: 'https://localhost:9996',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
