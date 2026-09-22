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
})
