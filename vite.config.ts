// SPDX-License-Identifier: GPL-3.0-or-later
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import wasm from 'vite-plugin-wasm'

export default defineConfig({
  base: './',
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  plugins: [vue(), wasm()],
  build: { outDir: 'dist/webroot', emptyOutDir: true, target: 'esnext' },
  esbuild: { target: 'esnext' }
})
