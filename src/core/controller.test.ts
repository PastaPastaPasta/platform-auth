import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PlatformAuthController } from './controller'
import { createFakeDependencies, makeIdentityRecord } from './__mocks__/dependencies'
import type { AuthSessionSnapshot, AuthUser } from './types'

const IDENTITY_ID = 'IdentityFixture111111111111111111111111111111'
const PRIVATE_KEY = 'wif-private-fixture'

function makeUser(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    identityId: IDENTITY_ID,
    balance: 42,
    publicKeys: [],
    ...overrides,
  }
}

function makeSnapshot(overrides: Partial<AuthSessionSnapshot> = {}): AuthSessionSnapshot {
  return {
    user: overrides.user ?? makeUser(),
    timestamp: overrides.timestamp ?? 1_700_000_000,
  }
}

describe('PlatformAuthController.restoreSession', () => {
  it('returns null and clears restoring flag when no session is stored', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)

    const result = await controller.restoreSession()

    expect(result).toBeNull()
    expect(controller.getState().isAuthRestoring).toBe(false)
    expect(controller.getState().user).toBeNull()
    expect(fakes.events).toEqual([])
  })

  it('hydrates state, sets client identity, and emits session-restored when private key is present', async () => {
    const fakes = createFakeDependencies()
    fakes.sessionStore.state.snapshot = makeSnapshot()
    fakes.secretStore.state.privateKeys.set(IDENTITY_ID, PRIVATE_KEY)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.restoreSession()

    expect(result?.identityId).toBe(IDENTITY_ID)
    expect(controller.getState().user?.identityId).toBe(IDENTITY_ID)
    expect(controller.getState().isAuthRestoring).toBe(false)
    expect(fakes.clientIdentity?.current.identityId).toBe(IDENTITY_ID)
    expect(fakes.events).toEqual([
      { type: 'session-restored', user: result },
    ])
  })

  it('clears the session and returns null when no private key is stored for the snapshot identity', async () => {
    const fakes = createFakeDependencies()
    fakes.sessionStore.state.snapshot = makeSnapshot()

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.restoreSession()

    expect(result).toBeNull()
    expect(fakes.sessionStore.clearSession).toHaveBeenCalled()
    expect(fakes.sessionStore.state.snapshot).toBeNull()
    expect(controller.getState().user).toBeNull()
    expect(fakes.events).toEqual([])
  })

  it('records the error and clears state when the session store throws', async () => {
    const fakes = createFakeDependencies()
    fakes.sessionStore.getSession = vi.fn(async () => {
      throw new Error('storage offline')
    })

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.restoreSession()

    expect(result).toBeNull()
    expect(controller.getState().error).toBe('storage offline')
    expect(controller.getState().isAuthRestoring).toBe(false)
    expect(fakes.sessionStore.clearSession).toHaveBeenCalled()
  })

  it('schedules a username backfill when restoring a session that lacks one', async () => {
    const fakes = createFakeDependencies({
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
    })
    fakes.sessionStore.state.snapshot = makeSnapshot({
      user: makeUser({ username: undefined }),
    })
    fakes.secretStore.state.privateKeys.set(IDENTITY_ID, PRIVATE_KEY)

    const controller = new PlatformAuthController(fakes.deps)
    await controller.restoreSession()

    await vi.waitFor(() => {
      expect(controller.getState().user?.username).toBe('alice')
    })
    expect(fakes.usernames?.resolveUsername).toHaveBeenCalledWith(IDENTITY_ID)
  })

  it('starts the balance-refresh interval and triggers post-login tasks when background features are enabled', async () => {
    vi.useFakeTimers()
    try {
      const fakes = createFakeDependencies({
        quietBackground: false,
        balanceRefreshMs: 1000,
        identityRecords: new Map([
          [IDENTITY_ID, { id: IDENTITY_ID, balance: 200, publicKeys: [] }],
        ]),
      })
      fakes.sessionStore.state.snapshot = makeSnapshot()
      fakes.secretStore.state.privateKeys.set(IDENTITY_ID, PRIVATE_KEY)

      const getBalance = vi.mocked(fakes.identity.getBalance)
      const controller = new PlatformAuthController(fakes.deps)
      await controller.restoreSession()

      expect(fakes.sideEffects?.runPostLogin).toHaveBeenCalledWith(
        IDENTITY_ID,
        expect.objectContaining({ delayMs: 3000 }),
      )

      await vi.advanceTimersByTimeAsync(1000)
      expect(getBalance).toHaveBeenCalledWith(IDENTITY_ID)

      controller.dispose()
      const callsAfterDispose = getBalance.mock.calls.length

      await vi.advanceTimersByTimeAsync(5000)
      expect(getBalance).toHaveBeenCalledTimes(callsAfterDispose)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('PlatformAuthController.loginWithAuthKey', () => {
  let setup: ReturnType<typeof createFakeDependencies>

  beforeEach(() => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
  })

  it('returns intent="ready" on the happy path and persists session + private key', async () => {
    const controller = new PlatformAuthController(setup.deps)
    const result = await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(result.user?.username).toBe('alice')
    expect(setup.sessionStore.setSession).toHaveBeenCalled()
    expect(setup.secretStore.state.privateKeys.get(IDENTITY_ID)).toBe(PRIVATE_KEY)
    expect(setup.clientIdentity?.current.identityId).toBe(IDENTITY_ID)
    expect(setup.events.map((e) => e.type)).toEqual(['login-succeeded'])
  })

  it('returns intent="username-required" when the identity has no username', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(setup.deps)

    const result = await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(result.intent).toEqual({ kind: 'username-required', identityId: IDENTITY_ID })
    expect(setup.events.map((e) => e.type)).toEqual(['login-succeeded', 'username-required'])
  })

  it('skips the username gate when the caller passes skipUsernameCheck', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(setup.deps)

    const result = await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY, {
      skipUsernameCheck: true,
    })

    expect(result.intent.kind).toBe('ready')
    expect(setup.events.map((e) => e.type)).toEqual(['login-succeeded'])
  })

  it('returns intent="profile-required" when the user has a username but no profile', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set(),
    })
    const controller = new PlatformAuthController(setup.deps)

    const result = await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(result.intent).toEqual({
      kind: 'profile-required',
      identityId: IDENTITY_ID,
      username: 'alice',
    })
    expect(setup.events.map((e) => e.type)).toEqual(['login-succeeded', 'profile-required'])
  })

  it('throws and records error state when identityId or privateKey is missing', async () => {
    const controller = new PlatformAuthController(setup.deps)

    await expect(controller.loginWithAuthKey('', PRIVATE_KEY)).rejects.toThrow(
      /Identity ID and private key are required/,
    )
    expect(controller.getState().error).toMatch(/Identity ID and private key are required/)
    expect(controller.getState().isLoading).toBe(false)
  })

  it('throws when the identity port returns null for the requested ID', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map(),
    })
    const controller = new PlatformAuthController(setup.deps)

    await expect(controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)).rejects.toThrow(/Identity not found/)
    expect(setup.sessionStore.setSession).not.toHaveBeenCalled()
    expect(setup.secretStore.state.privateKeys.has(IDENTITY_ID)).toBe(false)
    expect(setup.events.map((e) => e.type)).not.toContain('login-succeeded')
  })

  it('skips the profile gate entirely when the profileGate feature is disabled', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set(),
      features: { profileGate: false },
    })
    const controller = new PlatformAuthController(setup.deps)

    const result = await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(result.intent.kind).toBe('ready')
    expect(setup.profiles?.hasProfile).not.toHaveBeenCalled()
  })

  it('skips the username gate entirely when the usernameGate feature is disabled', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      profiles: new Set([IDENTITY_ID]),
      features: { usernameGate: false },
    })
    const controller = new PlatformAuthController(setup.deps)

    const result = await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(result.intent.kind).toBe('ready')
    expect(setup.events.map((e) => e.type)).toEqual(['login-succeeded'])
  })

  it('flips isLoading true → false across a successful login (observed via subscribe)', async () => {
    const controller = new PlatformAuthController(setup.deps)
    const loadingSeq: boolean[] = []
    controller.subscribe((state) => loadingSeq.push(state.isLoading))

    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(loadingSeq).toContain(true)
    expect(loadingSeq[loadingSeq.length - 1]).toBe(false)
  })

  it('persists the session snapshot with the timestamp returned by deps.now', async () => {
    setup = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
      now: () => 1_700_000_000_000,
    })
    const controller = new PlatformAuthController(setup.deps)

    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(setup.sessionStore.setSession).toHaveBeenCalledWith(
      expect.objectContaining({ timestamp: 1_700_000_000_000 }),
    )
  })
})

describe('PlatformAuthController.subscribe', () => {
  it('notifies the listener immediately with the current state and on each patch', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)
    const listener = vi.fn()

    const unsubscribe = controller.subscribe(listener)
    expect(listener).toHaveBeenCalledTimes(1)
    expect(listener.mock.calls[0]?.[0]?.isAuthRestoring).toBe(true)

    await controller.restoreSession()
    expect(listener.mock.calls.length).toBeGreaterThan(1)

    listener.mockClear()
    unsubscribe()
    await controller.restoreSession()
    expect(listener).not.toHaveBeenCalled()
  })
})

describe('PlatformAuthController.dispose', () => {
  it('clears the listener set so future state changes are silent', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)
    const listener = vi.fn()
    controller.subscribe(listener)
    listener.mockClear()

    controller.dispose()
    await controller.restoreSession()

    expect(listener).not.toHaveBeenCalled()
  })
})
