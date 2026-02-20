import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  base: '/yeti-auth/',
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
