import { readFileSync } from 'node:fs'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

// The Cargo workspace is the single source of the version number.
const cargo = readFileSync(path.resolve(__dirname, '../../Cargo.toml'), 'utf8')
const version = /\[workspace\.package\][^[]*?\nversion\s*=\s*"([^"]+)"/.exec(cargo)?.[1] ?? '0.0.0'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  define: {
    __STEMMA_VERSION__: JSON.stringify(version),
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
})
