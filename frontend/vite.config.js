import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/process_log': 'http://localhost:8000',
      '/status': 'http://localhost:8000',
    }
  }
})