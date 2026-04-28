import { describe, expect, it } from 'vitest'
import * as api from './index'

describe('public API surface', () => {
  it('exposes a stable, sorted set of named exports', () => {
    const keys = Object.keys(api).sort()
    expect(keys).toMatchSnapshot()
  })

  it('always exposes the load-bearing names consumers depend on', () => {
    const keys = new Set(Object.keys(api))
    for (const name of [
      'PlatformAuthController',
      'PlatformAuthProvider',
      'usePlatformAuth',
    ]) {
      expect(keys.has(name)).toBe(true)
    }
  })
})
