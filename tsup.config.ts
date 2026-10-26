import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/app-connect/index.ts', 'src/passkey-vault/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  external: ['react'],
})
