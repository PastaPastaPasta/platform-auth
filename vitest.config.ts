import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    environmentMatchGlobs: [
      ['src/browser/**', 'happy-dom'],
      ['src/react/**', 'happy-dom'],
      ['src/key-exchange/yappr-hooks.test.{ts,tsx}', 'happy-dom'],
    ],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        '**/*.test.{ts,tsx}',
        'src/index.ts',
        'src/**/index.ts',
        'src/__smoke__/**',
        'src/__fixtures__/**',
      ],
    },
  },
})
