import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createBrowserSecretStore,
  generatePrfInput,
  type BrowserSecretStoreCrypto,
} from './secret-store'

const IDENTITY_ID = 'IdentityFixture111111111111111111111111111111'

function createFakeCrypto(): BrowserSecretStoreCrypto {
  return {
    parsePrivateKey: vi.fn((wif: string) => ({
      privateKey: new TextEncoder().encode(`bytes:${wif}`),
    })),
    privateKeyToWif: vi.fn((priv: Uint8Array, network: string, compressed: boolean) =>
      `wif:${network}:${compressed ? 'c' : 'u'}:${new TextDecoder().decode(priv)}`,
    ),
    isLikelyWif: vi.fn((value: string) => value.startsWith('wif:')),
  }
}

function makeStore(overrides: Partial<Parameters<typeof createBrowserSecretStore>[0]> = {}) {
  return createBrowserSecretStore({
    network: 'testnet',
    crypto: createFakeCrypto(),
    ...overrides,
  })
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('createBrowserSecretStore — private keys', () => {
  it('round-trips a private key via localStorage', () => {
    const store = makeStore()
    store.storePrivateKey(IDENTITY_ID, 'wif-priv')

    expect(store.hasPrivateKey(IDENTITY_ID)).toBe(true)
    expect(store.getPrivateKey(IDENTITY_ID)).toBe('wif-priv')
    expect(localStorage.getItem(`platform_auth_secure_pk_${IDENTITY_ID}`)).toBe('"wif-priv"')
  })

  it('clearPrivateKey removes the stored entry and returns true the first time', () => {
    const store = makeStore()
    store.storePrivateKey(IDENTITY_ID, 'wif-priv')

    expect(store.clearPrivateKey(IDENTITY_ID)).toBe(true)
    expect(store.hasPrivateKey(IDENTITY_ID)).toBe(false)
    expect(store.clearPrivateKey(IDENTITY_ID)).toBe(false)
  })

  it('clearAllPrivateKeys deletes only pk_ entries, leaving other namespaces intact', () => {
    const store = makeStore()
    store.storePrivateKey(`${IDENTITY_ID}-A`, 'wif-A')
    store.storePrivateKey(`${IDENTITY_ID}-B`, 'wif-B')
    store.storeLoginKey(IDENTITY_ID, new Uint8Array([1, 2, 3]))

    store.clearAllPrivateKeys()

    expect(store.hasPrivateKey(`${IDENTITY_ID}-A`)).toBe(false)
    expect(store.hasPrivateKey(`${IDENTITY_ID}-B`)).toBe(false)
    expect(store.hasLoginKey(IDENTITY_ID)).toBe(true)
  })

  it('honors a custom prefix and never reads through it', () => {
    const a = makeStore({ prefix: 'a_' })
    const b = makeStore({ prefix: 'b_' })

    a.storePrivateKey(IDENTITY_ID, 'wif-A')
    b.storePrivateKey(IDENTITY_ID, 'wif-B')

    expect(a.getPrivateKey(IDENTITY_ID)).toBe('wif-A')
    expect(b.getPrivateKey(IDENTITY_ID)).toBe('wif-B')
    expect(localStorage.getItem(`a_pk_${IDENTITY_ID}`)).toBe('"wif-A"')
    expect(localStorage.getItem(`b_pk_${IDENTITY_ID}`)).toBe('"wif-B"')
  })
})

describe('createBrowserSecretStore — Uint8Array round-trip via base64', () => {
  it('login keys serialize to base64 in storage and deserialize back to bytes', () => {
    const store = makeStore()
    const loginKey = new Uint8Array(32).map((_, i) => (i * 11 + 5) & 0xff)
    store.storeLoginKey(IDENTITY_ID, loginKey)

    const raw = JSON.parse(localStorage.getItem(`platform_auth_secure_lk_${IDENTITY_ID}`) ?? 'null')
    expect(raw).toBe(Buffer.from(loginKey).toString('base64'))
    expect(store.getLoginKeyBytes(IDENTITY_ID)).toEqual(loginKey)
    expect(store.hasLoginKey(IDENTITY_ID)).toBe(true)
  })

  it('vault DEKs serialize to base64 in storage and deserialize back to bytes', () => {
    const store = makeStore()
    const dek = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3])
    store.storeAuthVaultDek(IDENTITY_ID, dek)

    const raw = JSON.parse(localStorage.getItem(`platform_auth_secure_avd_${IDENTITY_ID}`) ?? 'null')
    expect(raw).toBe(Buffer.from(dek).toString('base64'))
    expect(store.getAuthVaultDekBytes(IDENTITY_ID)).toEqual(dek)
    expect(store.hasAuthVaultDek(IDENTITY_ID)).toBe(true)
  })

  it('returns null bytes when the stored base64 is malformed', () => {
    const store = makeStore()
    localStorage.setItem(
      `platform_auth_secure_lk_${IDENTITY_ID}`,
      JSON.stringify('!!! not base64 !!!'),
    )

    expect(store.getLoginKeyBytes(IDENTITY_ID)).toBeNull()
  })

  it('returns null bytes when no value is stored', () => {
    const store = makeStore()
    expect(store.getLoginKeyBytes(IDENTITY_ID)).toBeNull()
    expect(store.getAuthVaultDekBytes(IDENTITY_ID)).toBeNull()
  })
})

describe('createBrowserSecretStore — encryption / transfer key WIF normalization', () => {
  it('stores already-WIF inputs verbatim without calling parsePrivateKey', () => {
    const fakeCrypto = createFakeCrypto()
    const store = makeStore({ crypto: fakeCrypto })

    store.storeEncryptionKey(IDENTITY_ID, 'wif:testnet:c:abc')

    expect(fakeCrypto.parsePrivateKey).not.toHaveBeenCalled()
    expect(fakeCrypto.privateKeyToWif).not.toHaveBeenCalled()
    expect(store.getEncryptionKey(IDENTITY_ID)).toBe('wif:testnet:c:abc')
  })

  it('normalizes raw private keys to WIF on store via the injected crypto', () => {
    const fakeCrypto = createFakeCrypto()
    const store = makeStore({ crypto: fakeCrypto, network: 'testnet' })

    store.storeEncryptionKey(IDENTITY_ID, 'raw-private')

    expect(fakeCrypto.parsePrivateKey).toHaveBeenCalledWith('raw-private')
    expect(fakeCrypto.privateKeyToWif).toHaveBeenCalledWith(expect.any(Uint8Array), 'testnet', true)
    expect(store.getEncryptionKey(IDENTITY_ID)).toBe('wif:testnet:c:bytes:raw-private')
  })

  it('getEncryptionKeyBytes parses the stored WIF through the injected crypto', () => {
    const fakeCrypto = createFakeCrypto()
    const store = makeStore({ crypto: fakeCrypto })
    store.storeEncryptionKey(IDENTITY_ID, 'wif:testnet:c:abc')

    expect(store.getEncryptionKeyBytes(IDENTITY_ID)).toEqual(
      new TextEncoder().encode('bytes:wif:testnet:c:abc'),
    )
  })

  it('getEncryptionKeyBytes returns null when parsePrivateKey throws', () => {
    const fakeCrypto = createFakeCrypto()
    fakeCrypto.parsePrivateKey = vi.fn(() => {
      throw new Error('bad WIF')
    })
    const store = makeStore({ crypto: fakeCrypto })
    store.storeEncryptionKey(IDENTITY_ID, 'wif:testnet:c:bad')

    expect(store.getEncryptionKeyBytes(IDENTITY_ID)).toBeNull()
  })

  it('storeTransferKey applies the same normalization as storeEncryptionKey', () => {
    const fakeCrypto = createFakeCrypto()
    const store = makeStore({ crypto: fakeCrypto })

    store.storeTransferKey(IDENTITY_ID, 'raw-transfer')

    expect(fakeCrypto.privateKeyToWif).toHaveBeenCalledTimes(1)
    expect(store.getTransferKey(IDENTITY_ID)).toBe('wif:testnet:c:bytes:raw-transfer')
    expect(store.hasTransferKey(IDENTITY_ID)).toBe(true)
  })
})

describe('createBrowserSecretStore — encryption key type', () => {
  it('round-trips "derived" and "external" types', () => {
    const store = makeStore()
    store.storeEncryptionKeyType(IDENTITY_ID, 'derived')
    expect(store.getEncryptionKeyType(IDENTITY_ID)).toBe('derived')

    store.storeEncryptionKeyType(IDENTITY_ID, 'external')
    expect(store.getEncryptionKeyType(IDENTITY_ID)).toBe('external')
  })

  it('returns null for unrecognized stored values', () => {
    const store = makeStore()
    localStorage.setItem(
      `platform_auth_secure_ek_type_${IDENTITY_ID}`,
      JSON.stringify('garbage'),
    )
    expect(store.getEncryptionKeyType(IDENTITY_ID)).toBeNull()
  })

  it('clearEncryptionKeyType removes the entry', () => {
    const store = makeStore()
    store.storeEncryptionKeyType(IDENTITY_ID, 'derived')
    expect(store.clearEncryptionKeyType(IDENTITY_ID)).toBe(true)
    expect(store.getEncryptionKeyType(IDENTITY_ID)).toBeNull()
  })
})

describe('createBrowserSecretStore — sessionStorage legacy migration', () => {
  it('reads a value that was previously written to sessionStorage and migrates it to localStorage', () => {
    const store = makeStore()
    sessionStorage.setItem(
      `platform_auth_secure_pk_${IDENTITY_ID}`,
      JSON.stringify('legacy-wif'),
    )

    expect(store.getPrivateKey(IDENTITY_ID)).toBe('legacy-wif')
    expect(localStorage.getItem(`platform_auth_secure_pk_${IDENTITY_ID}`)).toBe('"legacy-wif"')
    expect(sessionStorage.getItem(`platform_auth_secure_pk_${IDENTITY_ID}`)).toBeNull()
  })

  it('storing a value clears any matching sessionStorage entry', () => {
    const store = makeStore()
    sessionStorage.setItem(
      `platform_auth_secure_pk_${IDENTITY_ID}`,
      JSON.stringify('legacy-wif'),
    )

    store.storePrivateKey(IDENTITY_ID, 'new-wif')

    expect(sessionStorage.getItem(`platform_auth_secure_pk_${IDENTITY_ID}`)).toBeNull()
    expect(localStorage.getItem(`platform_auth_secure_pk_${IDENTITY_ID}`)).toBe('"new-wif"')
  })

  it('has() reports true if the value lives only in sessionStorage', () => {
    const store = makeStore()
    sessionStorage.setItem(
      `platform_auth_secure_pk_${IDENTITY_ID}`,
      JSON.stringify('legacy-wif'),
    )
    expect(store.hasPrivateKey(IDENTITY_ID)).toBe(true)
  })
})

describe('createBrowserSecretStore — failure modes', () => {
  it('treats storage as unavailable and skips writes when localStorage.setItem throws', () => {
    const realLocalStorage = globalThis.localStorage
    const throwingStorage: Storage = {
      length: 0,
      clear: () => undefined,
      getItem: () => null,
      key: () => null,
      removeItem: () => undefined,
      setItem: () => {
        throw new Error('quota exceeded')
      },
    }
    vi.stubGlobal('localStorage', throwingStorage)
    try {
      const store = makeStore()
      store.storePrivateKey(IDENTITY_ID, 'wif')

      expect(store.getPrivateKey(IDENTITY_ID)).toBeNull()
      expect(store.hasPrivateKey(IDENTITY_ID)).toBe(false)
    } finally {
      vi.stubGlobal('localStorage', realLocalStorage)
    }
  })
})

describe('generatePrfInput', () => {
  it('returns a 32-byte Uint8Array sourced from crypto.getRandomValues', () => {
    const out = generatePrfInput()
    expect(out).toBeInstanceOf(Uint8Array)
    expect(out).toHaveLength(32)
  })

  it('produces different bytes across calls', () => {
    const a = generatePrfInput()
    const b = generatePrfInput()
    expect(a).not.toEqual(b)
  })
})
