import { vi } from 'vitest'
import type {
  AuthPublicKey,
  AuthSessionSnapshot,
  AuthVaultBundle,
  AuthVaultStatus,
  AuthVaultUnlockResult,
  ClientIdentityPort,
  EncryptionKeyType,
  IdentityPort,
  IdentityRecord,
  LegacyPasswordLoginPort,
  PasskeyPort,
  PlatformAuthCryptoPort,
  PlatformAuthDependencies,
  PlatformAuthEvent,
  PlatformAuthFeatures,
  PlatformAuthLogger,
  ProfilePort,
  SecretStore,
  SessionStore,
  SideEffectsPort,
  UnifiedVaultPort,
  UsernamePort,
  YapprKeyExchangePort,
} from '../types'

export interface FakeSessionStoreState {
  snapshot: AuthSessionSnapshot | null
}

export function createFakeSessionStore(initial: AuthSessionSnapshot | null = null): SessionStore & {
  state: FakeSessionStoreState
} {
  const state: FakeSessionStoreState = { snapshot: initial }
  return {
    state,
    getSession: vi.fn(async () => state.snapshot),
    setSession: vi.fn(async (snapshot) => {
      state.snapshot = snapshot
    }),
    clearSession: vi.fn(async () => {
      state.snapshot = null
    }),
  }
}

export interface FakeSecretStoreState {
  privateKeys: Map<string, string>
  encryptionKeys: Map<string, string>
  encryptionKeyTypes: Map<string, EncryptionKeyType>
  transferKeys: Map<string, string>
  loginKeys: Map<string, Uint8Array>
  vaultDeks: Map<string, Uint8Array>
}

export function createFakeSecretStore(): SecretStore & { state: FakeSecretStoreState } {
  const state: FakeSecretStoreState = {
    privateKeys: new Map(),
    encryptionKeys: new Map(),
    encryptionKeyTypes: new Map(),
    transferKeys: new Map(),
    loginKeys: new Map(),
    vaultDeks: new Map(),
  }
  return {
    state,
    storePrivateKey: vi.fn(async (id, key) => {
      state.privateKeys.set(id, key)
    }),
    getPrivateKey: vi.fn(async (id) => state.privateKeys.get(id) ?? null),
    hasPrivateKey: vi.fn(async (id) => state.privateKeys.has(id)),
    clearPrivateKey: vi.fn(async (id) => {
      state.privateKeys.delete(id)
    }),
    storeEncryptionKey: vi.fn(async (id, key) => {
      state.encryptionKeys.set(id, key)
    }),
    getEncryptionKey: vi.fn(async (id) => state.encryptionKeys.get(id) ?? null),
    hasEncryptionKey: vi.fn(async (id) => state.encryptionKeys.has(id)),
    clearEncryptionKey: vi.fn(async (id) => {
      state.encryptionKeys.delete(id)
    }),
    storeEncryptionKeyType: vi.fn(async (id, type) => {
      state.encryptionKeyTypes.set(id, type)
    }),
    clearEncryptionKeyType: vi.fn(async (id) => {
      state.encryptionKeyTypes.delete(id)
    }),
    storeTransferKey: vi.fn(async (id, key) => {
      state.transferKeys.set(id, key)
    }),
    getTransferKey: vi.fn(async (id) => state.transferKeys.get(id) ?? null),
    clearTransferKey: vi.fn(async (id) => {
      state.transferKeys.delete(id)
    }),
    storeLoginKey: vi.fn(async (id, key) => {
      state.loginKeys.set(id, key)
    }),
    getLoginKey: vi.fn(async (id) => state.loginKeys.get(id) ?? null),
    clearLoginKey: vi.fn(async (id) => {
      state.loginKeys.delete(id)
    }),
    storeAuthVaultDek: vi.fn(async (id, dek) => {
      state.vaultDeks.set(id, dek)
    }),
    getAuthVaultDek: vi.fn(async (id) => state.vaultDeks.get(id) ?? null),
    clearAuthVaultDek: vi.fn(async (id) => {
      state.vaultDeks.delete(id)
    }),
  }
}

export function createFakeIdentityPort(records: Map<string, IdentityRecord> = new Map()): IdentityPort & {
  records: Map<string, IdentityRecord>
} {
  return {
    records,
    getIdentity: vi.fn(async (id) => records.get(id) ?? null),
    getBalance: vi.fn(async (id) => records.get(id)?.balance ?? 0),
    clearCache: vi.fn(),
  }
}

export function createFakeUsernamePort(map: Map<string, string> = new Map()): UsernamePort & {
  usernames: Map<string, string>
} {
  return {
    usernames: map,
    resolveUsername: vi.fn(async (id) => map.get(id) ?? null),
    resolveIdentity: vi.fn(async (input) => {
      for (const [id, name] of map) {
        if (id === input || name === input) return id
      }
      return null
    }),
    clearCache: vi.fn(),
  }
}

export function createFakeProfilePort(profiles: Set<string> = new Set()): ProfilePort & {
  profiles: Set<string>
} {
  return {
    profiles,
    hasProfile: vi.fn(async (id) => profiles.has(id)),
  }
}

export function createFakeClientIdentityPort(): ClientIdentityPort & {
  current: { identityId: string }
} {
  const current = { identityId: '' }
  return {
    current,
    setIdentity: vi.fn(async (id) => {
      current.identityId = id
    }),
  }
}

export function createFakeSideEffectsPort(): SideEffectsPort {
  return {
    runPostLogin: vi.fn(async () => undefined),
    runLogoutCleanup: vi.fn(async () => undefined),
  }
}

export function createFakeLegacyPasswordLogin(
  records: Record<string, { identityId: string; privateKey: string }> = {},
  options: { isConfigured?: boolean; kind?: string } = {},
): LegacyPasswordLoginPort {
  return {
    kind: options.kind ?? 'fake-legacy',
    isConfigured: vi.fn(() => options.isConfigured ?? true),
    loginWithPassword: vi.fn(async (input, password) => {
      const record = records[`${input}:${password}`]
      if (!record) {
        throw new Error('Invalid password')
      }
      return record
    }),
  }
}

export function createFakeCryptoPort(): PlatformAuthCryptoPort {
  return {
    parsePrivateKey: vi.fn((wif) => ({
      privateKey: new TextEncoder().encode(`parsed:${wif}`),
    })),
    privateKeyToWif: vi.fn((priv, network, compressed) =>
      `wif:${network}:${compressed ? 'c' : 'u'}:${Array.from(priv.slice(0, 4)).join(',')}`,
    ),
    deriveEncryptionKey: vi.fn((priv) => priv.slice().reverse()),
    validateDerivedKeyMatchesIdentity: vi.fn(async () => true),
    identityHasEncryptionKey: vi.fn(() => false),
    decodeIdentityId: vi.fn((id) => new TextEncoder().encode(`decoded:${id}`)),
    deriveAuthKeyFromLogin: vi.fn((loginKey: Uint8Array) =>
      Uint8Array.from(loginKey, (b: number) => (b + 1) & 0xff),
    ),
    deriveEncryptionKeyFromLogin: vi.fn((loginKey: Uint8Array) =>
      Uint8Array.from(loginKey, (b: number) => (b + 2) & 0xff),
    ),
  }
}

export function createFakePasskeyPort(): PasskeyPort {
  return {
    getDefaultRpId: vi.fn(() => 'example.test'),
    createPasskeyWithPrf: vi.fn(),
    getPrfAssertionForCredentials: vi.fn(),
    selectDiscoverablePasskey: vi.fn(),
  }
}

export function createFakeVaultPort(options: { configured?: boolean } = {}): UnifiedVaultPort & {
  vaults: Map<string, AuthVaultBundle>
  status: Map<string, AuthVaultStatus>
} {
  const vaults = new Map<string, AuthVaultBundle>()
  const status = new Map<string, AuthVaultStatus>()
  return {
    vaults,
    status,
    isConfigured: vi.fn(() => options.configured ?? true),
    getStatus: vi.fn(async (id) => status.get(id) ?? {
      configured: true,
      hasVault: vaults.has(id),
      hasPasswordAccess: false,
      passkeyCount: 0,
      hasEncryptionKey: false,
      hasTransferKey: false,
    }),
    hasVault: vi.fn(async (id) => vaults.has(id)),
    resolveIdentityId: vi.fn(async (input) => input),
    createOrUpdateVaultBundle: vi.fn(async (id, bundle, dek) => {
      vaults.set(id, bundle)
      const newDek = dek ?? new Uint8Array([1, 2, 3, 4])
      return { identityId: id, vault: { $id: `vault:${id}` }, bundle, dek: newDek }
    }),
    mergeSecrets: vi.fn(async (id, dek, partial) => {
      const existing = vaults.get(id)
      if (!existing) return null
      const merged: AuthVaultBundle = {
        ...existing,
        loginKey: partial.loginKey ?? existing.loginKey,
        authKeyWif: partial.authKeyWif ?? existing.authKeyWif,
        encryptionKeyWif: partial.encryptionKeyWif ?? existing.encryptionKeyWif,
        transferKeyWif: partial.transferKeyWif ?? existing.transferKeyWif,
        source: partial.source ?? existing.source,
      }
      vaults.set(id, merged)
      return { identityId: id, vault: { $id: `vault:${id}` }, bundle: merged, dek }
    }),
    unlockWithPassword: vi.fn(),
    unlockWithPrf: vi.fn(),
    getPasskeyAccesses: vi.fn(async () => []),
    addPasswordAccess: vi.fn(async () => undefined),
    addPasskeyAccess: vi.fn(async () => undefined),
  }
}

export function createFakeYapprKeyExchangePort(): YapprKeyExchangePort {
  return {
    getResponse: vi.fn(async () => null),
    buildUnsignedKeyRegistrationTransition: vi.fn(),
    checkKeysRegistered: vi.fn(async () => false),
  }
}

export function createNoopLogger(): PlatformAuthLogger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }
}

export interface FakeDependenciesOverrides {
  network?: PlatformAuthDependencies['network']
  features?: Partial<PlatformAuthFeatures>
  /**
   * When true (the default), background features that interfere with the controller's
   * synchronous test surface — `balanceRefresh`, `postLoginTasks`, and
   * `autoDeriveEncryptionKey` — are forced off. Tests that need to exercise the
   * production-default behavior must set this to false. The `features` overrides
   * still take precedence over both modes.
   */
  quietBackground?: boolean
  identityRecords?: Map<string, IdentityRecord>
  usernameMap?: Map<string, string>
  profiles?: Set<string>
  withVault?: boolean
  withPasskeys?: boolean
  withCrypto?: boolean
  withUsernames?: boolean
  withProfiles?: boolean
  withSideEffects?: boolean
  withClientIdentity?: boolean
  withYapprKeyExchange?: boolean
  legacyPasswordRecords?: Record<string, { identityId: string; privateKey: string }>
  yapprKeyExchangeConfig?: PlatformAuthDependencies['yapprKeyExchangeConfig']
  balanceRefreshMs?: number
  now?: () => number
  onEvent?: (event: PlatformAuthEvent) => void | Promise<void>
}

export interface FakeDependencies {
  deps: PlatformAuthDependencies
  sessionStore: ReturnType<typeof createFakeSessionStore>
  secretStore: ReturnType<typeof createFakeSecretStore>
  identity: ReturnType<typeof createFakeIdentityPort>
  usernames?: ReturnType<typeof createFakeUsernamePort>
  profiles?: ReturnType<typeof createFakeProfilePort>
  clientIdentity?: ReturnType<typeof createFakeClientIdentityPort>
  sideEffects?: SideEffectsPort
  vault?: ReturnType<typeof createFakeVaultPort>
  passkeys?: PasskeyPort
  crypto?: PlatformAuthCryptoPort
  yapprKeyExchange?: YapprKeyExchangePort
  legacyPasswordLogins?: LegacyPasswordLoginPort[]
  logger: PlatformAuthLogger
  events: PlatformAuthEvent[]
}

export function createFakeDependencies(overrides: FakeDependenciesOverrides = {}): FakeDependencies {
  const sessionStore = createFakeSessionStore()
  const secretStore = createFakeSecretStore()
  const identity = createFakeIdentityPort(overrides.identityRecords)
  const usernames = overrides.withUsernames !== false
    ? createFakeUsernamePort(overrides.usernameMap)
    : undefined
  const profiles = overrides.withProfiles !== false
    ? createFakeProfilePort(overrides.profiles)
    : undefined
  const clientIdentity = overrides.withClientIdentity !== false
    ? createFakeClientIdentityPort()
    : undefined
  const sideEffects = overrides.withSideEffects !== false
    ? createFakeSideEffectsPort()
    : undefined
  const vault = overrides.withVault ? createFakeVaultPort() : undefined
  const passkeys = overrides.withPasskeys ? createFakePasskeyPort() : undefined
  const crypto = overrides.withCrypto !== false ? createFakeCryptoPort() : undefined
  const yapprKeyExchange = overrides.withYapprKeyExchange ? createFakeYapprKeyExchangePort() : undefined
  const legacyPasswordLogins = overrides.legacyPasswordRecords
    ? [createFakeLegacyPasswordLogin(overrides.legacyPasswordRecords)]
    : undefined
  const logger = createNoopLogger()
  const events: PlatformAuthEvent[] = []

  const quietBackground = overrides.quietBackground ?? true
  const baseFeatures: Partial<PlatformAuthFeatures> = {
    ...(quietBackground
      ? { balanceRefresh: false, postLoginTasks: false, autoDeriveEncryptionKey: false }
      : {}),
    ...overrides.features,
  }

  const deps: PlatformAuthDependencies = {
    network: overrides.network ?? 'testnet',
    sessionStore,
    secretStore,
    identity,
    ...(usernames ? { usernames } : {}),
    ...(profiles ? { profiles } : {}),
    ...(clientIdentity ? { clientIdentity } : {}),
    ...(sideEffects ? { sideEffects } : {}),
    ...(vault ? { vault } : {}),
    ...(passkeys ? { passkeys } : {}),
    ...(crypto ? { crypto } : {}),
    ...(yapprKeyExchange ? { yapprKeyExchange } : {}),
    ...(legacyPasswordLogins ? { legacyPasswordLogins } : {}),
    ...(overrides.yapprKeyExchangeConfig ? { yapprKeyExchangeConfig: overrides.yapprKeyExchangeConfig } : {}),
    features: baseFeatures,
    ...(overrides.balanceRefreshMs !== undefined ? { balanceRefreshMs: overrides.balanceRefreshMs } : {}),
    now: overrides.now,
    logger,
    onEvent: async (event) => {
      events.push(event)
      await overrides.onEvent?.(event)
    },
  }

  return {
    deps,
    sessionStore,
    secretStore,
    identity,
    usernames,
    profiles,
    clientIdentity,
    sideEffects,
    vault,
    passkeys,
    crypto,
    yapprKeyExchange,
    legacyPasswordLogins,
    logger,
    events,
  }
}

export function makeIdentityRecord(id: string, options: Partial<IdentityRecord> = {}): IdentityRecord {
  const publicKeys: AuthPublicKey[] = options.publicKeys ?? []
  return {
    id,
    balance: options.balance ?? 100,
    publicKeys,
  }
}

export function makeVaultUnlockResult(
  identityId: string,
  bundle: Partial<AuthVaultBundle> = {},
): AuthVaultUnlockResult {
  return {
    identityId,
    vault: { $id: `vault:${identityId}` },
    bundle: {
      version: 1,
      identityId,
      network: 'testnet',
      secretKind: 'auth-key',
      authKeyWif: bundle.authKeyWif ?? 'wif-auth',
      encryptionKeyWif: bundle.encryptionKeyWif,
      transferKeyWif: bundle.transferKeyWif,
      loginKey: bundle.loginKey,
      source: bundle.source ?? 'direct-key',
      updatedAt: bundle.updatedAt ?? 0,
    },
    dek: new Uint8Array([9, 9, 9, 9]),
  }
}
