import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // @ciperscope/types and @ciperscope/api-client are workspace packages
  // linked via pnpm and compiled to CommonJS (tsconfig "module": "CommonJS"
  // in each). Vite does not pre-bundle linked/symlinked workspace packages
  // by default, so their CommonJS dist output was being served raw via
  // /@fs/ with no CJS->ESM interop applied, and any named RUNTIME import
  // from them (e.g. isAuthResultPass, CiperscopeApiClient) failed with
  // "does not provide an export named ...". Explicitly including them here
  // routes them through esbuild's dependency pre-bundling, which performs
  // the CJS->ESM conversion. Only these two are listed: they are the only
  // @ciperscope/* packages imported as runtime values (not type-only) from
  // apps/web/src, confirmed by inspection.
  optimizeDeps: {
    include: ['@ciperscope/types', '@ciperscope/api-client'],
  },
  // The API's CORS_ORIGIN allowlist (packages/config/src/index.ts,
  // default "http://localhost:5173") is a fixed, exact-origin match — it
  // does not pattern-match ports. Without strictPort, Vite silently falls
  // forward to 5174, 5175, ... whenever 5173 is already taken by a stale
  // dev server, and every API request from that origin then fails CORS
  // preflight, which surfaces in the browser as an unhelpful, generic
  // "Failed to fetch" with no indication of the real cause. Failing fast
  // here instead of drifting to an unlisted port was the actual root cause
  // of the intermittently "broken" dev startup.
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/lucide-react')) {
            return 'vendor-icons';
          }
          if (id.includes('node_modules/recharts')) {
            return 'vendor-charts';
          }
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/') || id.includes('node_modules/react-router')) {
            return 'vendor-react';
          }
          if (id.includes('node_modules/@tanstack')) {
            return 'vendor-query';
          }
        }
      }
    }
  }
})
