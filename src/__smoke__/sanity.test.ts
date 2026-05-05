import { describe, expect, it } from 'vitest'

describe('test infrastructure', () => {
  it('exposes WebCrypto getRandomValues for randomness-dependent tests', () => {
    expect(globalThis.crypto).toBeDefined()
    expect(globalThis.crypto.getRandomValues).toBeDefined()
  })

  it('exposes WebCrypto subtle for AES-GCM tests', () => {
    expect(globalThis.crypto).toBeDefined()
    expect(globalThis.crypto.subtle).toBeDefined()
  })
})
