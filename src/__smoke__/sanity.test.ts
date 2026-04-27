import { describe, expect, it } from 'vitest'

describe('test infrastructure', () => {
  it('runs assertions', () => {
    expect(1 + 1).toBe(2)
  })

  it('exposes WebCrypto subtle for AES-GCM tests', () => {
    expect(globalThis.crypto).toBeDefined()
    expect(globalThis.crypto.subtle).toBeDefined()
  })
})
