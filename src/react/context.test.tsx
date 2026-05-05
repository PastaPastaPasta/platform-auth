import React from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, renderHook } from '@testing-library/react'
import { PlatformAuthProvider, usePlatformAuth } from './context'
import { makeVaultUnlockResult } from '../core/__mocks__/dependencies'
import type { PlatformAuthController } from '../core/controller'
import type {
  AuthUser,
  PlatformAuthResult,
  PlatformAuthState,
} from '../core/types'

const IDENTITY_ID = 'IdentityFixture111111111111111111111111111111'

const READY_USER: AuthUser = {
  identityId: IDENTITY_ID,
  balance: 0,
  username: undefined,
  publicKeys: [],
}

const READY_RESULT: PlatformAuthResult = {
  user: READY_USER,
  intent: { kind: 'ready', identityId: IDENTITY_ID },
}

const LOGGED_OUT_RESULT: PlatformAuthResult = {
  user: null,
  intent: { kind: 'logged-out' },
}

const VAULT_RESULT = makeVaultUnlockResult(IDENTITY_ID, {
  loginKey: new Uint8Array(32).fill(0x11),
})

interface FakeController {
  controller: PlatformAuthController
  setState: (state: PlatformAuthState) => void
  listeners: Set<(state: PlatformAuthState) => void>
  methods: {
    restoreSession: ReturnType<typeof vi.fn>
    loginWithAuthKey: ReturnType<typeof vi.fn>
    loginWithPassword: ReturnType<typeof vi.fn>
    loginWithPasskey: ReturnType<typeof vi.fn>
    loginWithLoginKey: ReturnType<typeof vi.fn>
    createOrUpdateVaultFromLoginKey: ReturnType<typeof vi.fn>
    createOrUpdateVaultFromAuthKey: ReturnType<typeof vi.fn>
    addPasswordAccess: ReturnType<typeof vi.fn>
    addPasskeyAccess: ReturnType<typeof vi.fn>
    logout: ReturnType<typeof vi.fn>
    setUsername: ReturnType<typeof vi.fn>
    refreshUsername: ReturnType<typeof vi.fn>
    refreshBalance: ReturnType<typeof vi.fn>
  }
}

function createFakeController(initial?: Partial<PlatformAuthState>): FakeController {
  let state: PlatformAuthState = {
    user: null,
    isLoading: false,
    isAuthRestoring: true,
    error: null,
    ...initial,
  }
  const listeners = new Set<(state: PlatformAuthState) => void>()

  const methods = {
    restoreSession: vi.fn(async () => READY_USER),
    loginWithAuthKey: vi.fn(async () => READY_RESULT),
    loginWithPassword: vi.fn(async () => READY_RESULT),
    loginWithPasskey: vi.fn(async () => READY_RESULT),
    loginWithLoginKey: vi.fn(async () => READY_RESULT),
    createOrUpdateVaultFromLoginKey: vi.fn(async () => VAULT_RESULT),
    createOrUpdateVaultFromAuthKey: vi.fn(async () => VAULT_RESULT),
    addPasswordAccess: vi.fn(async () => undefined),
    addPasskeyAccess: vi.fn(async () => undefined),
    logout: vi.fn(async () => LOGGED_OUT_RESULT),
    setUsername: vi.fn(async () => undefined),
    refreshUsername: vi.fn(async () => undefined),
    refreshBalance: vi.fn(async () => undefined),
  }

  const controller = {
    getState: () => state,
    subscribe: (listener: (state: PlatformAuthState) => void) => {
      listeners.add(listener)
      listener(state)
      return () => {
        listeners.delete(listener)
      }
    },
    ...methods,
  } as unknown as PlatformAuthController

  const setState = (next: PlatformAuthState) => {
    state = next
    listeners.forEach((listener) => listener(state))
  }

  return { controller, setState, listeners, methods }
}

function wrap(controller: PlatformAuthController) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <PlatformAuthProvider controller={controller}>{children}</PlatformAuthProvider>
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('usePlatformAuth — provider boundary', () => {
  it('throws with the documented message when used outside a provider', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    try {
      expect(() => renderHook(() => usePlatformAuth())).toThrow(
        'usePlatformAuth must be used within a PlatformAuthProvider',
      )
    } finally {
      errorSpy.mockRestore()
    }
  })
})

describe('PlatformAuthProvider — initial state and subscription', () => {
  it('exposes the controller and the controller initial state on first render', () => {
    const fake = createFakeController({
      user: READY_USER,
      isLoading: false,
      isAuthRestoring: false,
      error: null,
    })

    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })

    expect(result.current.controller).toBe(fake.controller)
    expect(result.current.user).toEqual(READY_USER)
    expect(result.current.isLoading).toBe(false)
    expect(result.current.isAuthRestoring).toBe(false)
    expect(result.current.error).toBeNull()
  })

  it('registers exactly one subscriber on mount, keeps it through state changes, and removes it on unmount', () => {
    const fake = createFakeController()

    const { unmount } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })
    expect(fake.listeners.size).toBe(1)

    act(() => {
      fake.setState({
        user: READY_USER,
        isLoading: false,
        isAuthRestoring: false,
        error: null,
      })
    })
    expect(fake.listeners.size).toBe(1)

    unmount()
    expect(fake.listeners.size).toBe(0)
  })

  it('re-renders when the controller broadcasts a new state', () => {
    const fake = createFakeController()

    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })
    expect(result.current.user).toBeNull()
    expect(result.current.isAuthRestoring).toBe(true)

    act(() => {
      fake.setState({
        user: READY_USER,
        isLoading: false,
        isAuthRestoring: false,
        error: null,
      })
    })

    expect(result.current.user).toEqual(READY_USER)
    expect(result.current.isAuthRestoring).toBe(false)
  })

  it('propagates error strings from controller state and clears them when reset to null', () => {
    const fake = createFakeController()
    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })

    act(() => {
      fake.setState({
        user: null,
        isLoading: false,
        isAuthRestoring: false,
        error: 'Invalid password',
      })
    })

    expect(result.current.error).toBe('Invalid password')

    act(() => {
      fake.setState({
        user: null,
        isLoading: false,
        isAuthRestoring: false,
        error: null,
      })
    })

    expect(result.current.error).toBeNull()
  })
})

describe('PlatformAuthProvider — bound method forwarding', () => {
  it('forwards loginWithAuthKey arguments verbatim and returns the controller result', async () => {
    const fake = createFakeController()
    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })

    const out = await result.current.loginWithAuthKey(IDENTITY_ID, 'wif-priv', { skipUsernameCheck: true })

    expect(fake.methods.loginWithAuthKey).toHaveBeenCalledTimes(1)
    expect(fake.methods.loginWithAuthKey).toHaveBeenCalledWith(IDENTITY_ID, 'wif-priv', { skipUsernameCheck: true })
    expect(out).toEqual(READY_RESULT)
  })

  it('forwards loginWithPassword, loginWithPasskey, loginWithLoginKey with their arguments', async () => {
    const fake = createFakeController()
    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })

    const loginKey = new Uint8Array(32).fill(0x33)
    await result.current.loginWithPassword('user-or-id', 'pw')
    await result.current.loginWithPasskey('user-or-id')
    await result.current.loginWithLoginKey(IDENTITY_ID, loginKey, 7)

    expect(fake.methods.loginWithPassword).toHaveBeenCalledWith('user-or-id', 'pw')
    expect(fake.methods.loginWithPasskey).toHaveBeenCalledWith('user-or-id')
    expect(fake.methods.loginWithLoginKey).toHaveBeenCalledWith(IDENTITY_ID, loginKey, 7)
  })

  it('forwards vault, access, logout, username, and refresh methods', async () => {
    const fake = createFakeController()
    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })

    const loginKey = new Uint8Array(32).fill(0x44)
    await result.current.createOrUpdateVaultFromLoginKey(IDENTITY_ID, loginKey)
    await result.current.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-auth')
    await result.current.addPasswordAccess('pw', 100_000, 'label-pw')
    await result.current.addPasskeyAccess('label-pk')
    await result.current.logout()
    await result.current.setUsername('alice')
    await result.current.refreshUsername()
    await result.current.refreshBalance()
    await result.current.restoreSession()

    expect(fake.methods.createOrUpdateVaultFromLoginKey).toHaveBeenCalledWith(IDENTITY_ID, loginKey)
    expect(fake.methods.createOrUpdateVaultFromAuthKey).toHaveBeenCalledWith(IDENTITY_ID, 'wif-auth')
    expect(fake.methods.addPasswordAccess).toHaveBeenCalledWith('pw', 100_000, 'label-pw')
    expect(fake.methods.addPasskeyAccess).toHaveBeenCalledWith('label-pk')
    expect(fake.methods.logout).toHaveBeenCalledWith()
    expect(fake.methods.setUsername).toHaveBeenCalledWith('alice')
    expect(fake.methods.refreshUsername).toHaveBeenCalledWith()
    expect(fake.methods.refreshBalance).toHaveBeenCalledWith()
    expect(fake.methods.restoreSession).toHaveBeenCalledWith()
  })

  it('binds methods to the controller so destructured calls keep the right "this"', async () => {
    const fake = createFakeController()
    let observedThis: unknown = undefined
    fake.methods.loginWithAuthKey.mockImplementation(function (this: unknown) {
      observedThis = this
      return Promise.resolve(READY_RESULT)
    })

    const { result } = renderHook(() => usePlatformAuth(), { wrapper: wrap(fake.controller) })

    const { loginWithAuthKey } = result.current
    const out = await loginWithAuthKey(IDENTITY_ID, 'wif-priv')

    expect(out).toEqual(READY_RESULT)
    expect(observedThis).toBe(fake.controller)
  })
})

describe('PlatformAuthProvider — children and re-subscription on controller change', () => {
  it('renders children inside the context', () => {
    const fake = createFakeController()
    const { container } = render(
      <PlatformAuthProvider controller={fake.controller}>
        <span data-testid="child">child-content</span>
      </PlatformAuthProvider>,
    )
    expect(container.querySelector('[data-testid="child"]')?.textContent).toBe('child-content')
  })

  it('drops the old subscription and registers a new one when the controller prop changes', () => {
    const a = createFakeController()
    const b = createFakeController()

    const { rerender } = render(
      <PlatformAuthProvider controller={a.controller}>
        <span />
      </PlatformAuthProvider>,
    )
    expect(a.listeners.size).toBe(1)
    expect(b.listeners.size).toBe(0)

    rerender(
      <PlatformAuthProvider controller={b.controller}>
        <span />
      </PlatformAuthProvider>,
    )

    expect(a.listeners.size).toBe(0)
    expect(b.listeners.size).toBe(1)
  })
})
