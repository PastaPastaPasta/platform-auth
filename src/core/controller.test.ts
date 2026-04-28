import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PlatformAuthController } from './controller'
import {
  APP_PRIVATE_KEY,
  APP_PUBLIC_KEY,
  CONTRACT_ID_BYTES,
  FIXED_NONCE,
  IDENTITY_ID_BASE58,
  LOGIN_KEY,
  WALLET_PRIVATE_KEY,
  WALLET_PUBLIC_KEY,
  encryptLoginKeyForFixture,
} from '../__fixtures__/yappr-vectors'
import {
  decodeYapprContractId,
  deriveYapprSharedSecret,
  hash160,
} from '../key-exchange/yappr-protocol'
import {
  createFakeDependencies,
  makeIdentityRecord,
  makeVaultUnlockResult,
} from './__mocks__/dependencies'
import type {
  AuthSessionSnapshot,
  AuthUser,
  PasskeyAccess,
  PasskeyPrfAssertionResult,
} from './types'

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

  it('logs balance-refresh failures without throwing when the background refresh task rejects', async () => {
    vi.useFakeTimers()
    try {
      const fakes = createFakeDependencies({
        quietBackground: false,
        balanceRefreshMs: 1000,
      })
      const refreshError = new Error('balance backend offline')
      fakes.sessionStore.state.snapshot = makeSnapshot()
      fakes.secretStore.state.privateKeys.set(IDENTITY_ID, PRIVATE_KEY)
      vi.mocked(fakes.identity.getBalance).mockRejectedValue(refreshError)

      const controller = new PlatformAuthController(fakes.deps)
      await controller.restoreSession()

      await vi.advanceTimersByTimeAsync(1000)

      expect(vi.mocked(fakes.logger.error)).toHaveBeenCalledWith(
        'platform-auth: balance refresh failed',
        refreshError,
      )
      expect(controller.getState().user?.identityId).toBe(IDENTITY_ID)
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

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
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

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
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

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(setup.events.map((e) => e.type)).toEqual(['login-succeeded'])
  })

  it('flips isLoading true → false across a successful login (observed via subscribe)', async () => {
    const controller = new PlatformAuthController(setup.deps)
    const loadingSeq: boolean[] = []
    controller.subscribe((state) => loadingSeq.push(state.isLoading))

    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    expect(loadingSeq[loadingSeq.length - 1]).toBe(false)
    const firstTrue = loadingSeq.indexOf(true)
    expect(firstTrue).toBeGreaterThanOrEqual(0)
    expect(firstTrue).toBeLessThan(loadingSeq.length - 1)
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

describe('PlatformAuthController.loginWithPassword', () => {
  it('throws when the passwordLogin feature is disabled', async () => {
    const fakes = createFakeDependencies({ features: { passwordLogin: false } })
    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.loginWithPassword('alice', 'pw')).rejects.toThrow(
      /Password login is disabled/,
    )
  })

  it('returns the unlocked vault session when vault.unlockWithPassword succeeds', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const unlocked = makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: 'wif-vault-auth' })
    vi.mocked(fakes.vault!.unlockWithPassword).mockResolvedValueOnce(unlocked)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithPassword('alice', 'pw')

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.vault!.unlockWithPassword).toHaveBeenCalledWith('alice', 'pw')
    expect(fakes.secretStore.state.vaultDeks.get(IDENTITY_ID)).toEqual(unlocked.dek)
    expect(fakes.secretStore.state.privateKeys.get(IDENTITY_ID)).toBe('wif-vault-auth')
  })

  it('falls back to a legacy adapter when vault unlock fails', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
      legacyPasswordRecords: {
        'alice:pw': { identityId: IDENTITY_ID, privateKey: 'wif-legacy' },
      },
    })
    vi.mocked(fakes.vault!.unlockWithPassword).mockRejectedValueOnce(new Error('Invalid password'))

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithPassword('alice', 'pw')

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.secretStore.state.privateKeys.get(IDENTITY_ID)).toBe('wif-legacy')
  })

  it('aggregates "Invalid password" across vault + legacy adapters when both reject with that message', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      legacyPasswordRecords: {},
    })
    vi.mocked(fakes.vault!.unlockWithPassword).mockRejectedValueOnce(new Error('Invalid password'))

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPassword('alice', 'pw')).rejects.toThrow(/Invalid password/)
  })

  it('rethrows the last non-password error when no adapter authenticated', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      legacyPasswordRecords: {},
    })
    vi.mocked(fakes.vault!.unlockWithPassword).mockRejectedValueOnce(new Error('vault offline'))
    fakes.legacyPasswordLogins![0].loginWithPassword = vi.fn(async () => {
      throw new Error('legacy oops')
    })

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPassword('alice', 'pw')).rejects.toThrow(/legacy oops/)
  })

  it('throws "not configured" when no adapter is available and vault is absent', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.loginWithPassword('alice', 'pw')).rejects.toThrow(
      /Password login is not configured/,
    )
  })
})

describe('PlatformAuthController.loginWithPasskey', () => {
  function makeAccess(overrides: Partial<PasskeyAccess> = {}): PasskeyAccess {
    return {
      $id: 'access-1',
      $ownerId: IDENTITY_ID,
      label: 'Test passkey',
      credentialId: new Uint8Array([1, 2, 3]),
      credentialIdHash: new Uint8Array([4, 5, 6]),
      prfInput: new Uint8Array([7, 8, 9]),
      rpId: 'example.test',
      ...overrides,
    }
  }

  function makeAssertion(overrides: Partial<PasskeyPrfAssertionResult> = {}): PasskeyPrfAssertionResult {
    return {
      credentialId: new Uint8Array([1, 2, 3]),
      credentialIdHash: new Uint8Array([4, 5, 6]),
      prfInput: new Uint8Array([7, 8, 9]),
      prfOutput: new Uint8Array([10, 11, 12]),
      rpId: 'example.test',
      ...overrides,
    }
  }

  it('throws when the passkeyLogin feature is disabled', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: true,
      features: { passkeyLogin: false },
    })
    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.loginWithPasskey('alice')).rejects.toThrow(/Passkey login is disabled/)
  })

  it('throws when vault or passkeys port is not configured', async () => {
    const fakes = createFakeDependencies({ withPasskeys: true })
    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.loginWithPasskey('alice')).rejects.toThrow(
      /Passkey login is not configured/,
    )
  })

  it('unlocks via vault when an access matches the assertion (username path)', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const access = makeAccess()
    const assertion = makeAssertion()
    const unlocked = makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: 'wif-passkey' })
    vi.mocked(fakes.vault!.resolveIdentityId).mockResolvedValueOnce(IDENTITY_ID)
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([access])
    vi.mocked(fakes.passkeys!.getPrfAssertionForCredentials).mockResolvedValueOnce(assertion)
    vi.mocked(fakes.vault!.unlockWithPrf).mockResolvedValueOnce(unlocked)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithPasskey('alice')

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.vault!.unlockWithPrf).toHaveBeenCalledWith(IDENTITY_ID, access, assertion.prfOutput)
  })

  it('throws when the username has no matching access on this site', async () => {
    const fakes = createFakeDependencies({ withVault: true, withPasskeys: true })
    vi.mocked(fakes.vault!.resolveIdentityId).mockResolvedValueOnce(IDENTITY_ID)
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([])

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPasskey('alice')).rejects.toThrow(/No passkey login is configured/)
  })

  it('throws "Username not found" when the vault cannot resolve the supplied identifier', async () => {
    const fakes = createFakeDependencies({ withVault: true, withPasskeys: true })
    vi.mocked(fakes.vault!.resolveIdentityId).mockResolvedValueOnce(null)

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPasskey('unknown')).rejects.toThrow(/Username not found/)
  })

  it('throws the discoverable-path error message when no accesses are registered for the selected userHandle', async () => {
    const fakes = createFakeDependencies({ withVault: true, withPasskeys: true })
    vi.mocked(fakes.passkeys!.selectDiscoverablePasskey).mockResolvedValueOnce({
      credentialId: new Uint8Array([1]),
      credentialIdHash: new Uint8Array([2]),
      userHandle: IDENTITY_ID,
      rpId: 'example.test',
    })
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([])

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPasskey()).rejects.toThrow(
      /No passkey login is configured for this selected passkey/,
    )
  })

  it('throws when the discoverable selection has no userHandle', async () => {
    const fakes = createFakeDependencies({ withVault: true, withPasskeys: true })
    vi.mocked(fakes.passkeys!.selectDiscoverablePasskey).mockResolvedValueOnce({
      credentialId: new Uint8Array([1]),
      credentialIdHash: new Uint8Array([2]),
      rpId: 'example.test',
    })

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPasskey()).rejects.toThrow(
      /This passkey did not provide an account identifier/,
    )
  })

  it('throws when the assertion does not match any registered access', async () => {
    const fakes = createFakeDependencies({ withVault: true, withPasskeys: true })
    const access = makeAccess({ credentialIdHash: new Uint8Array([99]) })
    vi.mocked(fakes.vault!.resolveIdentityId).mockResolvedValueOnce(IDENTITY_ID)
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([access])
    vi.mocked(fakes.passkeys!.getPrfAssertionForCredentials).mockResolvedValueOnce(makeAssertion())

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPasskey('alice')).rejects.toThrow(
      /Selected passkey is not registered/,
    )
  })

  it('unlocks via the discoverable passkey selection path when no username is given', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const access = makeAccess()
    const unlocked = makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: 'wif-discov' })
    vi.mocked(fakes.passkeys!.selectDiscoverablePasskey).mockResolvedValueOnce({
      credentialId: access.credentialId!,
      credentialIdHash: access.credentialIdHash!,
      userHandle: IDENTITY_ID,
      rpId: 'example.test',
    })
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([access])
    vi.mocked(fakes.passkeys!.getPrfAssertionForCredentials).mockResolvedValueOnce(makeAssertion())
    vi.mocked(fakes.vault!.unlockWithPrf).mockResolvedValueOnce(unlocked)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithPasskey()

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.passkeys!.selectDiscoverablePasskey).toHaveBeenCalledWith('example.test')
  })

  it('throws when the discoverable selection identifies a credential not in the vault for this site', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: true,
    })
    const presentAccess = makeAccess({ credentialIdHash: new Uint8Array([1, 2, 3]) })
    vi.mocked(fakes.passkeys!.selectDiscoverablePasskey).mockResolvedValueOnce({
      credentialId: new Uint8Array([10]),
      credentialIdHash: new Uint8Array([20]),
      userHandle: IDENTITY_ID,
      rpId: 'example.test',
    })
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([presentAccess])

    const controller = new PlatformAuthController(fakes.deps)
    await expect(controller.loginWithPasskey()).rejects.toThrow(
      /selected passkey is not registered for this site/i,
    )
  })
})

describe('PlatformAuthController vault enrollment recovery branches', () => {
  function setupVaultLoggedIn() {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    return fakes
  }

  it('throws when an existing vault has only a password access and no DEK is held locally', async () => {
    const fakes = setupVaultLoggedIn()
    fakes.vault!.vaults.set(IDENTITY_ID, {
      version: 1,
      identityId: IDENTITY_ID,
      network: 'testnet',
      secretKind: 'auth-key',
      source: 'direct-key',
      updatedAt: 0,
    })
    fakes.vault!.status.set(IDENTITY_ID, {
      configured: true,
      hasVault: true,
      hasPasswordAccess: true,
      passkeyCount: 0,
      hasEncryptionKey: false,
      hasTransferKey: false,
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(
      controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-new'),
    ).rejects.toThrow(/already has a password unlock method/)
  })

  it('unlocks via passkey when an existing vault has passkey accesses but no local DEK', async () => {
    const fakes = setupVaultLoggedIn()
    fakes.vault!.vaults.set(IDENTITY_ID, {
      version: 1,
      identityId: IDENTITY_ID,
      network: 'testnet',
      secretKind: 'auth-key',
      source: 'direct-key',
      updatedAt: 0,
    })
    fakes.vault!.status.set(IDENTITY_ID, {
      configured: true,
      hasVault: true,
      hasPasswordAccess: false,
      passkeyCount: 1,
      hasEncryptionKey: false,
      hasTransferKey: false,
    })
    const access: PasskeyAccess = {
      $id: 'a-1',
      $ownerId: IDENTITY_ID,
      label: 'Device',
      credentialId: new Uint8Array([1]),
      credentialIdHash: new Uint8Array([2]),
      prfInput: new Uint8Array([3]),
      rpId: 'example.test',
    }
    const prfOutput = new Uint8Array([99])
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([access])
    vi.mocked(fakes.passkeys!.getPrfAssertionForCredentials).mockResolvedValueOnce({
      credentialId: access.credentialId!,
      credentialIdHash: access.credentialIdHash!,
      prfInput: access.prfInput!,
      prfOutput,
      rpId: 'example.test',
    })
    vi.mocked(fakes.vault!.unlockWithPrf).mockResolvedValueOnce(
      makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: 'wif-existing' }),
    )

    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    const result = await controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-extra')
    expect(result.identityId).toBe(IDENTITY_ID)
    expect(fakes.vault!.unlockWithPrf).toHaveBeenCalledWith(IDENTITY_ID, access, prfOutput)
  })

  it('throws when an existing vault requires a passkey unlock but no passkey adapter is configured', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: false,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    fakes.vault!.vaults.set(IDENTITY_ID, {
      version: 1,
      identityId: IDENTITY_ID,
      network: 'testnet',
      secretKind: 'auth-key',
      source: 'direct-key',
      updatedAt: 0,
    })
    fakes.vault!.status.set(IDENTITY_ID, {
      configured: true,
      hasVault: true,
      hasPasswordAccess: false,
      passkeyCount: 1,
      hasEncryptionKey: false,
      hasTransferKey: false,
    })

    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(
      controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-extra'),
    ).rejects.toThrow(/Passkeys are required to unlock this auth vault/)
  })

  it('throws when a passkey assertion succeeds but does not match any registered vault access', async () => {
    const fakes = setupVaultLoggedIn()
    fakes.vault!.vaults.set(IDENTITY_ID, {
      version: 1,
      identityId: IDENTITY_ID,
      network: 'testnet',
      secretKind: 'auth-key',
      source: 'direct-key',
      updatedAt: 0,
    })
    fakes.vault!.status.set(IDENTITY_ID, {
      configured: true,
      hasVault: true,
      hasPasswordAccess: false,
      passkeyCount: 1,
      hasEncryptionKey: false,
      hasTransferKey: false,
    })
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([
      {
        $id: 'a-1',
        $ownerId: IDENTITY_ID,
        label: 'Device',
        credentialId: new Uint8Array([1]),
        credentialIdHash: new Uint8Array([2]),
        prfInput: new Uint8Array([3]),
        rpId: 'example.test',
      },
    ])
    vi.mocked(fakes.passkeys!.getPrfAssertionForCredentials).mockResolvedValueOnce({
      credentialId: new Uint8Array([1]),
      credentialIdHash: new Uint8Array([9]),
      prfInput: new Uint8Array([3]),
      prfOutput: new Uint8Array([99]),
      rpId: 'example.test',
    })

    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(
      controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-extra'),
    ).rejects.toThrow(/selected passkey is not registered for this account on this site/i)
  })

  it('throws when an existing vault has passkey accesses but none are registered for the current rpId', async () => {
    const fakes = setupVaultLoggedIn()
    fakes.vault!.vaults.set(IDENTITY_ID, {
      version: 1,
      identityId: IDENTITY_ID,
      network: 'testnet',
      secretKind: 'auth-key',
      source: 'direct-key',
      updatedAt: 0,
    })
    fakes.vault!.status.set(IDENTITY_ID, {
      configured: true,
      hasVault: true,
      hasPasswordAccess: false,
      passkeyCount: 1,
      hasEncryptionKey: false,
      hasTransferKey: false,
    })
    vi.mocked(fakes.vault!.getPasskeyAccesses).mockResolvedValueOnce([
      {
        $id: 'a-1',
        $ownerId: IDENTITY_ID,
        label: 'Device',
        credentialId: new Uint8Array([1]),
        credentialIdHash: new Uint8Array([2]),
        prfInput: new Uint8Array([3]),
        rpId: 'other.test',
      },
    ])

    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(
      controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-extra'),
    ).rejects.toThrow(/none are registered for this site/)
  })

  it('throws when an existing vault has no DEK and no recoverable unlock methods', async () => {
    const fakes = setupVaultLoggedIn()
    fakes.vault!.vaults.set(IDENTITY_ID, {
      version: 1,
      identityId: IDENTITY_ID,
      network: 'testnet',
      secretKind: 'auth-key',
      source: 'direct-key',
      updatedAt: 0,
    })
    fakes.vault!.status.set(IDENTITY_ID, {
      configured: true,
      hasVault: true,
      hasPasswordAccess: false,
      passkeyCount: 0,
      hasEncryptionKey: false,
      hasTransferKey: false,
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(
      controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-extra'),
    ).rejects.toThrow(/already exists but is not unlocked/)
  })

  it('loginWithPassword derives keys from a login-key vault bundle', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const loginKey = new Uint8Array(32).fill(5)
    const loginKeyBundle = makeVaultUnlockResult(IDENTITY_ID, { loginKey })
    loginKeyBundle.bundle.secretKind = 'login-key'
    loginKeyBundle.bundle.authKeyWif = undefined
    vi.mocked(fakes.vault!.unlockWithPassword).mockResolvedValueOnce(loginKeyBundle)
    const expectedIdBytes = new TextEncoder().encode(`decoded:${IDENTITY_ID}`)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithPassword('alice', 'pw')

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.crypto!.deriveAuthKeyFromLogin).toHaveBeenCalledWith(loginKey, expectedIdBytes)
    expect(fakes.crypto!.deriveEncryptionKeyFromLogin).toHaveBeenCalledWith(loginKey, expectedIdBytes)
    expect(fakes.secretStore.state.loginKeys.get(IDENTITY_ID)).toEqual(loginKey)
  })

  it('loginWithPassword throws when a login-key vault bundle is missing its loginKey secret', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const unlocked = makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: undefined })
    unlocked.bundle.secretKind = 'login-key'
    unlocked.bundle.loginKey = undefined
    vi.mocked(fakes.vault!.unlockWithPassword).mockResolvedValueOnce(unlocked)

    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.loginWithPassword('alice', 'pw')).rejects.toThrow(
      /Auth vault is missing the wallet login secret/,
    )
  })

  it('loginWithPassword throws when an auth-key vault bundle is missing authKeyWif', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const unlocked = makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: 'wif-vault-auth' })
    unlocked.bundle.secretKind = 'auth-key'
    unlocked.bundle.authKeyWif = undefined
    vi.mocked(fakes.vault!.unlockWithPassword).mockResolvedValueOnce(unlocked)

    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.loginWithPassword('alice', 'pw')).rejects.toThrow(
      /Auth vault is missing the authentication key/,
    )
  })

  it('loginWithPassword persists transfer keys from an unlocked vault bundle', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const unlocked = makeVaultUnlockResult(IDENTITY_ID, { authKeyWif: 'wif-vault-auth' })
    unlocked.bundle.transferKeyWif = 'wif-transfer'
    vi.mocked(fakes.vault!.unlockWithPassword).mockResolvedValueOnce(unlocked)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithPassword('alice', 'pw')

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.secretStore.state.transferKeys.get(IDENTITY_ID)).toBe('wif-transfer')
  })
})

describe('PlatformAuthController.loginWithLoginKey', () => {
  it('throws when keyExchangeLogin is disabled', async () => {
    const fakes = createFakeDependencies({ features: { keyExchangeLogin: false } })
    const controller = new PlatformAuthController(fakes.deps)
    await expect(
      controller.loginWithLoginKey(IDENTITY_ID, new Uint8Array(32), 0),
    ).rejects.toThrow(/Login-key login is disabled/)
  })

  it('throws when crypto port is missing', async () => {
    const fakes = createFakeDependencies({ withCrypto: false })
    const controller = new PlatformAuthController(fakes.deps)
    await expect(
      controller.loginWithLoginKey(IDENTITY_ID, new Uint8Array(32), 0),
    ).rejects.toThrow(/Login-key login requires crypto adapters/)
  })

  it('derives auth/encryption WIFs and persists them on success', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    const loginKey = new Uint8Array(32).fill(7)
    const expectedIdBytes = new TextEncoder().encode(`decoded:${IDENTITY_ID}`)

    const result = await controller.loginWithLoginKey(IDENTITY_ID, loginKey, 5)

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.crypto!.deriveAuthKeyFromLogin).toHaveBeenCalledWith(loginKey, expectedIdBytes)
    expect(fakes.crypto!.deriveEncryptionKeyFromLogin).toHaveBeenCalledWith(loginKey, expectedIdBytes)
    expect(fakes.secretStore.state.loginKeys.get(IDENTITY_ID)).toEqual(loginKey)
    expect(fakes.secretStore.state.privateKeys.has(IDENTITY_ID)).toBe(true)
    expect(fakes.secretStore.state.encryptionKeys.has(IDENTITY_ID)).toBe(true)
    expect(fakes.secretStore.state.encryptionKeyTypes.get(IDENTITY_ID)).toBe('derived')
  })

  it('logs a warning but still resolves when the post-login vault merge fails', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const vaultError = new Error('vault offline')
    vi.mocked(fakes.vault!.mergeSecrets).mockRejectedValue(vaultError)
    vi.mocked(fakes.vault!.createOrUpdateVaultBundle).mockRejectedValue(vaultError)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithLoginKey(IDENTITY_ID, new Uint8Array(32).fill(7), 0)

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(vi.mocked(fakes.logger.warn)).toHaveBeenCalledWith(
      expect.stringContaining('failed to'),
      vaultError,
    )
  })

  it('logs the merge-secrets warning but still resolves when only the merge step fails', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const mergeError = new Error('merge offline')
    vi.mocked(fakes.vault!.mergeSecrets).mockRejectedValueOnce(mergeError)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.loginWithLoginKey(IDENTITY_ID, new Uint8Array(32).fill(7), 0)

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(vi.mocked(fakes.logger.warn)).toHaveBeenCalledWith(
      'platform-auth: failed to merge login-key secrets into vault',
      mergeError,
    )
  })

  it('clears all secrets when the underlying loginWithAuthKey throws', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map(),
    })
    const controller = new PlatformAuthController(fakes.deps)
    const loginKey = new Uint8Array(32).fill(7)

    await expect(controller.loginWithLoginKey(IDENTITY_ID, loginKey, 0)).rejects.toThrow(
      /Identity not found/,
    )
    expect(fakes.secretStore.state.privateKeys.has(IDENTITY_ID)).toBe(false)
    expect(fakes.secretStore.state.loginKeys.has(IDENTITY_ID)).toBe(false)
    expect(fakes.secretStore.state.encryptionKeys.has(IDENTITY_ID)).toBe(false)
  })
})

describe('PlatformAuthController vault management', () => {
  function setupLoggedIn() {
    const fakes = createFakeDependencies({
      withVault: true,
      withPasskeys: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      profiles: new Set([IDENTITY_ID]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    return { fakes, controller }
  }

  it('createOrUpdateVaultFromAuthKey writes a new vault bundle and stores its DEK', async () => {
    const { fakes, controller } = setupLoggedIn()
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    const result = await controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-new')

    expect(fakes.vault!.createOrUpdateVaultBundle).toHaveBeenCalledTimes(1)
    expect(fakes.vault!.createOrUpdateVaultBundle).toHaveBeenCalledWith(
      IDENTITY_ID,
      expect.objectContaining({
        identityId: IDENTITY_ID,
        secretKind: 'auth-key',
        authKeyWif: 'wif-new',
        source: 'direct-key',
        network: 'testnet',
      }),
      undefined,
    )
    expect(fakes.secretStore.state.vaultDeks.get(IDENTITY_ID)).toEqual(result.dek)
  })

  it('createOrUpdateVaultFromLoginKey persists the loginKey in the secret store', async () => {
    const { fakes, controller } = setupLoggedIn()
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)
    const loginKey = new Uint8Array(32).fill(3)

    await controller.createOrUpdateVaultFromLoginKey(IDENTITY_ID, loginKey)

    expect(fakes.secretStore.state.loginKeys.get(IDENTITY_ID)).toEqual(loginKey)
  })

  it('mergeSecretsIntoVault returns null when no DEK is available', async () => {
    const { controller } = setupLoggedIn()

    const result = await controller.mergeSecretsIntoVault(IDENTITY_ID, { authKeyWif: 'wif' })
    expect(result).toBeNull()
  })

  it('mergeSecretsIntoVault returns null when the vault has no record to merge into', async () => {
    const { fakes, controller } = setupLoggedIn()
    fakes.secretStore.state.vaultDeks.set(IDENTITY_ID, new Uint8Array([1, 2, 3, 4]))

    const result = await controller.mergeSecretsIntoVault(IDENTITY_ID, { authKeyWif: 'wif' })
    expect(result).toBeNull()
  })

  it('mergeSecretsIntoVault writes a fresh loginKey to the secret store when supplied', async () => {
    const { fakes, controller } = setupLoggedIn()
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)
    await controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-existing')

    const newLoginKey = new Uint8Array(32).fill(0xab)
    await controller.mergeSecretsIntoVault(IDENTITY_ID, { loginKey: newLoginKey })

    expect(fakes.secretStore.state.loginKeys.get(IDENTITY_ID)).toEqual(newLoginKey)
  })

  it('addPasswordAccess throws when the vault is not configured', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(controller.addPasswordAccess('pw', 100_000)).rejects.toThrow(
      /Auth vault is not configured/,
    )
  })

  it('addPasskeyAccess throws when passkeys are not configured', async () => {
    const fakes = createFakeDependencies({
      withVault: true,
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await expect(controller.addPasskeyAccess()).rejects.toThrow(/Passkeys are not configured/)
  })

  it('mergeSecretsIntoVault writes the merged DEK back to the secret store', async () => {
    const { fakes, controller } = setupLoggedIn()
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)
    await controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, 'wif-existing')

    const newDek = new Uint8Array([7, 7, 7, 7])
    fakes.secretStore.state.vaultDeks.set(IDENTITY_ID, newDek)

    const merged = await controller.mergeSecretsIntoVault(IDENTITY_ID, {
      encryptionKeyWif: 'wif-encryption',
    })

    expect(merged).not.toBeNull()
    expect(fakes.vault!.mergeSecrets).toHaveBeenCalledWith(
      IDENTITY_ID,
      newDek,
      expect.objectContaining({ encryptionKeyWif: 'wif-encryption' }),
    )
  })

  it('throws when no active login secret is available for auth vault enrollment', async () => {
    const fakes = createFakeDependencies({ withVault: true })
    const controller = new PlatformAuthController(fakes.deps)

    await expect(controller.createOrUpdateVaultFromAuthKey(IDENTITY_ID, '')).rejects.toThrow(
      /No active login secret is available for auth vault enrollment/,
    )
  })

  it('addPasswordAccess throws when the user is not logged in', async () => {
    const { controller } = setupLoggedIn()
    await expect(controller.addPasswordAccess('pw', 100_000)).rejects.toThrow(
      /must be logged in/,
    )
  })

  it('addPasswordAccess forwards to vault.addPasswordAccess after vault enrollment', async () => {
    const { fakes, controller } = setupLoggedIn()
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await controller.addPasswordAccess('pw', 100_000, 'My password')

    expect(fakes.vault!.addPasswordAccess).toHaveBeenCalledWith(
      IDENTITY_ID,
      expect.objectContaining({ password: 'pw', iterations: 100_000, label: 'My password' }),
    )
  })

  it('addPasskeyAccess forwards to vault.addPasskeyAccess after creating a passkey', async () => {
    const { fakes, controller } = setupLoggedIn()
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    const passkey = {
      credentialId: new Uint8Array([1]),
      credentialIdHash: new Uint8Array([2]),
      prfInput: new Uint8Array([3]),
      prfOutput: new Uint8Array([4]),
      rpId: 'example.test',
      label: 'My device',
    }
    vi.mocked(fakes.passkeys!.createPasskeyWithPrf).mockResolvedValueOnce(passkey)

    await controller.addPasskeyAccess('My device')

    expect(fakes.passkeys!.createPasskeyWithPrf).toHaveBeenCalledWith(
      expect.objectContaining({ identityId: IDENTITY_ID, label: 'My device' }),
    )
    expect(fakes.vault!.addPasskeyAccess).toHaveBeenCalledWith(
      IDENTITY_ID,
      expect.objectContaining({ passkey }),
    )
  })
})

describe('PlatformAuthController.logout', () => {
  it('clears all secret stores, calls runLogoutCleanup, and emits a logout event', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)
    fakes.secretStore.state.encryptionKeys.set(IDENTITY_ID, 'enc')
    fakes.secretStore.state.transferKeys.set(IDENTITY_ID, 'transfer')
    fakes.secretStore.state.loginKeys.set(IDENTITY_ID, new Uint8Array(32))
    fakes.secretStore.state.vaultDeks.set(IDENTITY_ID, new Uint8Array(32))

    const result = await controller.logout()

    expect(result.intent).toEqual({ kind: 'logged-out' })
    expect(controller.getState().user).toBeNull()
    expect(fakes.sessionStore.state.snapshot).toBeNull()
    expect(fakes.secretStore.state.privateKeys.has(IDENTITY_ID)).toBe(false)
    expect(fakes.secretStore.state.encryptionKeys.has(IDENTITY_ID)).toBe(false)
    expect(fakes.secretStore.state.transferKeys.has(IDENTITY_ID)).toBe(false)
    expect(fakes.secretStore.state.loginKeys.has(IDENTITY_ID)).toBe(false)
    expect(fakes.secretStore.state.vaultDeks.has(IDENTITY_ID)).toBe(false)
    expect(fakes.sideEffects?.runLogoutCleanup).toHaveBeenCalledWith(IDENTITY_ID)
    const logoutEvent = fakes.events.find((e) => e.type === 'logout')
    expect(logoutEvent).toEqual({ type: 'logout', identityId: IDENTITY_ID })
  })

  it('emits a logout event with no identityId when no session is active', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)

    await controller.logout()

    const event = fakes.events.find((e) => e.type === 'logout')
    expect(event).toEqual({ type: 'logout', identityId: undefined })
  })
})

const YAPPR_CONTRACT_ID_BASE58 = '4n5sZSE3qC8gZSEcgM3vAjNbpwbmpajaUtAUsoyMVjaR'

describe('PlatformAuthController Yappr key exchange wiring', () => {
  function setupYappr() {
    return createFakeDependencies({
      withYapprKeyExchange: true,
      yapprKeyExchangeConfig: {
        appContractId: YAPPR_CONTRACT_ID_BASE58,
        keyExchangeContractId: YAPPR_CONTRACT_ID_BASE58,
        network: 'testnet',
      },
    })
  }

  it('getYapprKeyExchangeConfig throws when no contract ids are configured', () => {
    const fakes = createFakeDependencies({ withYapprKeyExchange: true })
    const controller = new PlatformAuthController(fakes.deps)

    expect(() => controller.getYapprKeyExchangeConfig()).toThrow(/Yappr key exchange is not configured/)
  })

  it('getYapprKeyExchangeConfig returns merged defaults + overrides', () => {
    const fakes = setupYappr()
    const controller = new PlatformAuthController(fakes.deps)

    const config = controller.getYapprKeyExchangeConfig({ label: 'Custom', timeoutMs: 5000 })
    expect(config.label).toBe('Custom')
    expect(config.timeoutMs).toBe(5000)
    expect(config.network).toBe('testnet')
  })

  it('checkYapprKeysRegistered forwards the exact identity id and key bytes to the port', async () => {
    const fakes = setupYappr()
    vi.mocked(fakes.yapprKeyExchange!.checkKeysRegistered).mockResolvedValueOnce(true)
    const controller = new PlatformAuthController(fakes.deps)
    const authPublicKey = new Uint8Array([1, 2, 3])
    const encryptionPublicKey = new Uint8Array([4, 5, 6])

    const result = await controller.checkYapprKeysRegistered(
      IDENTITY_ID,
      authPublicKey,
      encryptionPublicKey,
    )

    expect(result).toBe(true)
    expect(fakes.yapprKeyExchange!.checkKeysRegistered).toHaveBeenCalledTimes(1)
    expect(fakes.yapprKeyExchange!.checkKeysRegistered).toHaveBeenCalledWith(
      IDENTITY_ID,
      authPublicKey,
      encryptionPublicKey,
    )
  })

  it('buildYapprUnsignedKeyRegistrationTransition forwards the request to the port and returns its result', async () => {
    const fakes = setupYappr()
    const transition = {
      transitionBytes: new Uint8Array([1, 2, 3]),
      authKeyId: 7,
      encryptionKeyId: 8,
      identityRevision: 9n,
    }
    vi.mocked(fakes.yapprKeyExchange!.buildUnsignedKeyRegistrationTransition).mockResolvedValueOnce(
      transition,
    )
    const controller = new PlatformAuthController(fakes.deps)
    const request = {
      identityId: IDENTITY_ID,
      authPrivateKey: new Uint8Array([1]),
      authPublicKey: new Uint8Array([2]),
      encryptionPrivateKey: new Uint8Array([3]),
      encryptionPublicKey: new Uint8Array([4]),
    }

    const result = await controller.buildYapprUnsignedKeyRegistrationTransition(request)

    expect(result).toEqual(transition)
    expect(fakes.yapprKeyExchange!.buildUnsignedKeyRegistrationTransition).toHaveBeenCalledTimes(1)
    expect(fakes.yapprKeyExchange!.buildUnsignedKeyRegistrationTransition).toHaveBeenCalledWith(request)
  })

  it('pollYapprKeyExchangeResponse decrypts a real ECDH/AES-GCM response and returns the wallet login key', async () => {
    const fakes = setupYappr()

    const sharedSecret = deriveYapprSharedSecret(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY)
    const encryptedPayload = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)
    const appEphemeralPubKeyHash = hash160(APP_PUBLIC_KEY)

    const response = {
      $id: 'doc',
      $ownerId: IDENTITY_ID_BASE58,
      $revision: 1,
      contractId: CONTRACT_ID_BYTES,
      appEphemeralPubKeyHash,
      walletEphemeralPubKey: WALLET_PUBLIC_KEY,
      encryptedPayload,
      keyIndex: 4,
    }
    vi.mocked(fakes.yapprKeyExchange!.getResponse).mockResolvedValueOnce(response)

    const controller = new PlatformAuthController(fakes.deps)
    const result = await controller.pollYapprKeyExchangeResponse(
      appEphemeralPubKeyHash,
      APP_PRIVATE_KEY,
      { pollIntervalMs: 5, timeoutMs: 1000 },
    )

    expect(result.loginKey).toEqual(LOGIN_KEY)
    expect(result.keyIndex).toBe(4)
    expect(result.identityId).toBe(IDENTITY_ID_BASE58)
    expect(result.walletEphemeralPubKey).toEqual(WALLET_PUBLIC_KEY)

    const callArgs = vi.mocked(fakes.yapprKeyExchange!.getResponse).mock.calls[0]
    expect(callArgs?.[0]).toEqual(decodeYapprContractId(YAPPR_CONTRACT_ID_BASE58))
    expect(callArgs?.[1]).toEqual(appEphemeralPubKeyHash)
  })

  it('pollYapprKeyExchangeResponse times out when the wallet never responds', async () => {
    vi.useFakeTimers()
    try {
      const fakes = setupYappr()
      vi.mocked(fakes.yapprKeyExchange!.getResponse).mockResolvedValue(null)

      const controller = new PlatformAuthController(fakes.deps)
      const promise = controller.pollYapprKeyExchangeResponse(
        new Uint8Array(20).fill(1),
        APP_PRIVATE_KEY,
        { pollIntervalMs: 100, timeoutMs: 500 },
      )
      const settled = expect(promise).rejects.toThrow(/Timeout/)

      await vi.runAllTimersAsync()
      await settled

      const callCount = vi.mocked(fakes.yapprKeyExchange!.getResponse).mock.calls.length
      expect(callCount).toBeGreaterThanOrEqual(4)
      expect(callCount).toBeLessThanOrEqual(6)
    } finally {
      vi.useRealTimers()
    }
  })

  it('completeYapprKeyExchangeLogin runs the login-key path with the supplied loginKey', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    const loginKey = new Uint8Array(32).fill(1)
    const expectedIdBytes = new TextEncoder().encode(`decoded:${IDENTITY_ID}`)

    const result = await controller.completeYapprKeyExchangeLogin({
      identityId: IDENTITY_ID,
      loginKey,
      keyIndex: 0,
    })

    expect(result.intent).toEqual({ kind: 'ready', identityId: IDENTITY_ID })
    expect(fakes.crypto!.deriveAuthKeyFromLogin).toHaveBeenCalledWith(loginKey, expectedIdBytes)
    expect(fakes.crypto!.deriveEncryptionKeyFromLogin).toHaveBeenCalledWith(loginKey, expectedIdBytes)
    expect(fakes.secretStore.state.loginKeys.get(IDENTITY_ID)).toEqual(loginKey)
  })

  it('throws when key exchange is disabled', async () => {
    const fakes = createFakeDependencies({
      withYapprKeyExchange: true,
      features: { keyExchangeLogin: false },
    })
    const controller = new PlatformAuthController(fakes.deps)

    await expect(
      controller.checkYapprKeysRegistered(IDENTITY_ID, new Uint8Array(), new Uint8Array()),
    ).rejects.toThrow(/Yappr key exchange login is disabled/)
  })
})

describe('PlatformAuthController state refresh helpers', () => {
  it('refreshUsername updates the user when the resolver returns a new username', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY, { skipUsernameCheck: true })

    fakes.usernames!.usernames.set(IDENTITY_ID, 'alice-renamed')
    await controller.refreshUsername()

    expect(controller.getState().user?.username).toBe('alice-renamed')
    expect(fakes.usernames!.clearCache).toHaveBeenCalledWith(undefined, IDENTITY_ID)
  })

  it('refreshUsername no-ops when the resolver returns null', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)
    fakes.usernames!.usernames.delete(IDENTITY_ID)

    await controller.refreshUsername()

    expect(controller.getState().user?.username).toBe('alice')
  })

  it('setUsername writes through the session store', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)

    await controller.setUsername('bob')

    expect(controller.getState().user?.username).toBe('bob')
    expect(fakes.sessionStore.state.snapshot?.user.username).toBe('bob')
  })

  it('setUsername no-ops when the controller has no current user', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)

    await controller.setUsername('bob')
    expect(controller.getState().user).toBeNull()
  })

  it('refreshUsername no-ops when no user is logged in', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID)]]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.refreshUsername()
    expect(fakes.usernames!.resolveUsername).not.toHaveBeenCalled()
  })

  it('refreshBalance no-ops when no user is logged in', async () => {
    const fakes = createFakeDependencies()
    const controller = new PlatformAuthController(fakes.deps)
    await controller.refreshBalance()
    expect(fakes.identity.getBalance).not.toHaveBeenCalled()
  })

  it('emits a background-error event when the username backfill resolver throws', async () => {
    const fakes = createFakeDependencies({
      usernameMap: new Map(),
    })
    fakes.usernames!.resolveUsername = vi.fn(async () => {
      throw new Error('resolver crashed')
    })
    fakes.sessionStore.state.snapshot = makeSnapshot({ user: makeUser({ username: undefined }) })
    fakes.secretStore.state.privateKeys.set(IDENTITY_ID, PRIVATE_KEY)

    const controller = new PlatformAuthController(fakes.deps)
    await controller.restoreSession()

    await vi.waitFor(() => {
      const evt = fakes.events.find((e) => e.type === 'background-error')
      expect(evt).toBeDefined()
      expect(evt).toMatchObject({ operation: 'backfill-username' })
    })
  })

  it('refreshBalance updates the user balance from the identity port', async () => {
    const fakes = createFakeDependencies({
      identityRecords: new Map([[IDENTITY_ID, makeIdentityRecord(IDENTITY_ID, { balance: 100 })]]),
      usernameMap: new Map([[IDENTITY_ID, 'alice']]),
      profiles: new Set([IDENTITY_ID]),
    })
    const controller = new PlatformAuthController(fakes.deps)
    await controller.loginWithAuthKey(IDENTITY_ID, PRIVATE_KEY)
    fakes.identity.records.get(IDENTITY_ID)!.balance = 999

    await controller.refreshBalance()

    expect(controller.getState().user?.balance).toBe(999)
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
