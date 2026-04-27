import bs58 from 'bs58'
import { describe, expect, it, vi } from 'vitest'
import type { YapprKeyExchangePort, YapprKeyExchangeResponse } from '../core/types'
import {
  APP_PRIVATE_KEY,
  APP_PUBLIC_KEY,
  AUTH_KEY_FROM_LOGIN_HEX,
  CONTRACT_ID_BASE58,
  CONTRACT_ID_BYTES,
  ENCRYPTION_KEY_FROM_LOGIN_HEX,
  FIXED_NONCE,
  HASH160_OF_010203_HEX,
  IDENTITY_ID_BASE58,
  IDENTITY_ID_BYTES,
  LOGIN_KEY,
  SAMPLE_LABEL,
  SERIALIZED_REQUEST_HEX,
  WALLET_PRIVATE_KEY,
  WALLET_PUBLIC_KEY,
  encryptLoginKeyForFixture,
  hexToBytes,
} from '../__fixtures__/yappr-vectors'
import {
  DEFAULT_YAPPR_KEY_EXCHANGE_CONFIG,
  YAPPR_KEY_EXCHANGE_VERSION,
  YAPPR_NETWORK_IDS,
  YAPPR_STATE_TRANSITION_VERSION,
  buildYapprKeyExchangeUri,
  buildYapprStateTransitionUri,
  clearSensitiveBytes,
  decodeYapprContractId,
  decodeYapprIdentityId,
  decryptYapprKeyExchangeResponse,
  decryptYapprLoginKey,
  deriveYapprAuthKeyFromLogin,
  deriveYapprEncryptionKeyFromLogin,
  deriveYapprSharedSecret,
  generateYapprEphemeralKeyPair,
  getYapprPublicKey,
  hash160,
  parseYapprKeyExchangeUri,
  parseYapprStateTransitionUri,
  pollForYapprKeyExchangeResponse,
  serializeYapprKeyExchangeRequest,
} from './yappr-protocol'

describe('hash160', () => {
  it('produces a 20-byte ripemd160(sha256(x))', () => {
    const out = hash160(new Uint8Array([1, 2, 3]))
    expect(out).toBeInstanceOf(Uint8Array)
    expect(out).toHaveLength(20)
  })

  it('is deterministic for the same input', () => {
    const a = hash160(APP_PUBLIC_KEY)
    const b = hash160(APP_PUBLIC_KEY)
    expect(a).toEqual(b)
  })

  it('matches the known vector for [0x01, 0x02, 0x03]', () => {
    expect(hash160(new Uint8Array([1, 2, 3]))).toEqual(hexToBytes(HASH160_OF_010203_HEX))
  })
})

describe('generateYapprEphemeralKeyPair', () => {
  it('returns a 32-byte private and 33-byte compressed public key', () => {
    const pair = generateYapprEphemeralKeyPair()
    expect(pair.privateKey).toHaveLength(32)
    expect(pair.publicKey).toHaveLength(33)
  })

  it('generates fresh keys each call', () => {
    const a = generateYapprEphemeralKeyPair()
    const b = generateYapprEphemeralKeyPair()
    expect(a.privateKey).not.toEqual(b.privateKey)
  })
})

describe('deriveYapprSharedSecret', () => {
  it('is symmetric: ECDH(privA, pubB) === ECDH(privB, pubA)', () => {
    const fromApp = deriveYapprSharedSecret(APP_PRIVATE_KEY, WALLET_PUBLIC_KEY)
    const fromWallet = deriveYapprSharedSecret(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY)
    expect(fromApp).toEqual(fromWallet)
    expect(fromApp).toHaveLength(32)
  })
})

describe('AES-GCM round-trip via decryptYapprLoginKey', () => {
  it('decrypts a payload produced by the matching encrypt fixture', async () => {
    const sharedSecret = deriveYapprSharedSecret(APP_PRIVATE_KEY, WALLET_PUBLIC_KEY)
    const encrypted = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)
    const decrypted = await decryptYapprLoginKey(encrypted, sharedSecret)
    expect(decrypted).toEqual(LOGIN_KEY)
  })

  it('rejects payloads shorter than 60 bytes', async () => {
    const sharedSecret = new Uint8Array(32)
    await expect(decryptYapprLoginKey(new Uint8Array(10), sharedSecret)).rejects.toThrow(
      /Encrypted payload too short/,
    )
  })

  it('rejects when decrypted key is not 32 bytes', async () => {
    const sharedSecret = deriveYapprSharedSecret(APP_PRIVATE_KEY, WALLET_PUBLIC_KEY)
    const wrongSizeKey = new Uint8Array(48).fill(7)
    const encrypted = await encryptLoginKeyForFixture(wrongSizeKey, sharedSecret, FIXED_NONCE)
    expect(encrypted.length).toBeGreaterThanOrEqual(60)
    await expect(decryptYapprLoginKey(encrypted, sharedSecret)).rejects.toThrow(
      /Invalid decrypted login key length/,
    )
  })

  it('throws on tampered ciphertext (AES-GCM auth failure)', async () => {
    const sharedSecret = deriveYapprSharedSecret(APP_PRIVATE_KEY, WALLET_PUBLIC_KEY)
    const encrypted = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)
    encrypted[encrypted.length - 1] ^= 0xff
    await expect(decryptYapprLoginKey(encrypted, sharedSecret)).rejects.toBeDefined()
  })
})

describe('deriveYapprAuthKeyFromLogin / deriveYapprEncryptionKeyFromLogin', () => {
  it('produce 32-byte keys, deterministic and distinct from each other', () => {
    const auth = deriveYapprAuthKeyFromLogin(LOGIN_KEY, IDENTITY_ID_BYTES)
    const enc = deriveYapprEncryptionKeyFromLogin(LOGIN_KEY, IDENTITY_ID_BYTES)
    expect(auth).toHaveLength(32)
    expect(enc).toHaveLength(32)
    expect(auth).not.toEqual(enc)
    expect(deriveYapprAuthKeyFromLogin(LOGIN_KEY, IDENTITY_ID_BYTES)).toEqual(auth)
    expect(deriveYapprEncryptionKeyFromLogin(LOGIN_KEY, IDENTITY_ID_BYTES)).toEqual(enc)
  })

  it('match committed vectors (locks HKDF salt strings)', () => {
    expect(deriveYapprAuthKeyFromLogin(LOGIN_KEY, IDENTITY_ID_BYTES)).toEqual(
      hexToBytes(AUTH_KEY_FROM_LOGIN_HEX),
    )
    expect(deriveYapprEncryptionKeyFromLogin(LOGIN_KEY, IDENTITY_ID_BYTES)).toEqual(
      hexToBytes(ENCRYPTION_KEY_FROM_LOGIN_HEX),
    )
  })

  it('rejects wrong-length login keys', () => {
    expect(() => deriveYapprAuthKeyFromLogin(new Uint8Array(16), IDENTITY_ID_BYTES)).toThrow(
      /Invalid login key length/,
    )
    expect(() => deriveYapprEncryptionKeyFromLogin(new Uint8Array(16), IDENTITY_ID_BYTES)).toThrow(
      /Invalid login key length/,
    )
  })

  it('rejects wrong-length identity IDs', () => {
    expect(() => deriveYapprAuthKeyFromLogin(LOGIN_KEY, new Uint8Array(16))).toThrow(
      /Invalid identity ID length/,
    )
    expect(() => deriveYapprEncryptionKeyFromLogin(LOGIN_KEY, new Uint8Array(16))).toThrow(
      /Invalid identity ID length/,
    )
  })
})

describe('getYapprPublicKey', () => {
  it('matches secp256k1.getPublicKey(priv, true)', () => {
    const pub = getYapprPublicKey(APP_PRIVATE_KEY)
    expect(pub).toEqual(APP_PUBLIC_KEY)
    expect(pub).toHaveLength(33)
  })
})

describe('clearSensitiveBytes', () => {
  it('zeroes the buffer in place', () => {
    const buf = new Uint8Array([1, 2, 3, 4])
    clearSensitiveBytes(buf)
    expect(Array.from(buf)).toEqual([0, 0, 0, 0])
  })
})

describe('decodeYapprIdentityId / decodeYapprContractId', () => {
  it('round-trip through bs58', () => {
    expect(decodeYapprIdentityId(IDENTITY_ID_BASE58)).toEqual(IDENTITY_ID_BYTES)
    expect(decodeYapprContractId(CONTRACT_ID_BASE58)).toEqual(CONTRACT_ID_BYTES)
  })

  it('rejects identity IDs that are not 32 bytes', () => {
    const short = bs58.encode(new Uint8Array(16).fill(1))
    expect(() => decodeYapprIdentityId(short)).toThrow(/Invalid identity ID length/)
  })

  it('rejects contract IDs that are not 32 bytes', () => {
    const short = bs58.encode(new Uint8Array(16).fill(1))
    expect(() => decodeYapprContractId(short)).toThrow(/Invalid contract ID length/)
  })

  it('throws on invalid base58 input', () => {
    expect(() => decodeYapprIdentityId('!!!not-base58!!!')).toThrow()
  })
})

describe('serializeYapprKeyExchangeRequest', () => {
  it('encodes [version|pubkey|contractId|labelLen|label]', () => {
    const out = serializeYapprKeyExchangeRequest({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
      label: SAMPLE_LABEL,
    })
    expect(out[0]).toBe(YAPPR_KEY_EXCHANGE_VERSION)
    expect(out.slice(1, 34)).toEqual(APP_PUBLIC_KEY)
    expect(out.slice(34, 66)).toEqual(CONTRACT_ID_BYTES)
    expect(out[66]).toBe(SAMPLE_LABEL.length)
    expect(new TextDecoder().decode(out.slice(67))).toBe(SAMPLE_LABEL)
  })

  it('matches the committed wire-format vector (locks byte layout)', () => {
    const out = serializeYapprKeyExchangeRequest({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
      label: SAMPLE_LABEL,
    })
    expect(out).toEqual(hexToBytes(SERIALIZED_REQUEST_HEX))
  })

  it('measures label length in UTF-8 bytes, not JS string units', () => {
    const fox = '🦊'
    expect(fox.length).toBe(2)
    const utf8 = new TextEncoder().encode(fox)
    expect(utf8.length).toBe(4)

    const out = serializeYapprKeyExchangeRequest({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
      label: fox,
    })
    expect(out[66]).toBe(4)
    expect(out.slice(67, 71)).toEqual(utf8)
    expect(new TextDecoder().decode(out.slice(67))).toBe(fox)
  })

  it('rejects labels whose UTF-8 byte length exceeds 64 even when string length does not', () => {
    const label = `${'x'.repeat(63)}🦊`
    expect(label.length).toBe(65)
    expect(new TextEncoder().encode(label).length).toBe(67)
    expect(() =>
      serializeYapprKeyExchangeRequest({
        appEphemeralPubKey: APP_PUBLIC_KEY,
        contractId: CONTRACT_ID_BYTES,
        label,
      }),
    ).toThrow(/Label too long/)
  })

  it('accepts ASCII labels at the 64-byte boundary', () => {
    const out = serializeYapprKeyExchangeRequest({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
      label: 'x'.repeat(64),
    })
    expect(out[66]).toBe(64)
  })

  it('handles missing label as zero-length', () => {
    const out = serializeYapprKeyExchangeRequest({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
    })
    expect(out).toHaveLength(67)
    expect(out[66]).toBe(0)
  })

  it('rejects wrong-length pubkey', () => {
    expect(() =>
      serializeYapprKeyExchangeRequest({
        appEphemeralPubKey: new Uint8Array(32),
        contractId: CONTRACT_ID_BYTES,
      }),
    ).toThrow(/ephemeral public key length/)
  })

  it('rejects wrong-length contract id', () => {
    expect(() =>
      serializeYapprKeyExchangeRequest({
        appEphemeralPubKey: APP_PUBLIC_KEY,
        contractId: new Uint8Array(16),
      }),
    ).toThrow(/contract ID length/)
  })

  it('rejects labels longer than 64 bytes', () => {
    expect(() =>
      serializeYapprKeyExchangeRequest({
        appEphemeralPubKey: APP_PUBLIC_KEY,
        contractId: CONTRACT_ID_BYTES,
        label: 'x'.repeat(65),
      }),
    ).toThrow(/Label too long/)
  })
})

describe('buildYapprKeyExchangeUri / parseYapprKeyExchangeUri', () => {
  const baseRequest = {
    appEphemeralPubKey: APP_PUBLIC_KEY,
    contractId: CONTRACT_ID_BYTES,
    label: SAMPLE_LABEL,
  }

  it('round-trips on testnet (default)', () => {
    const uri = buildYapprKeyExchangeUri(baseRequest)
    expect(uri.startsWith('dash-key:')).toBe(true)
    expect(uri).toContain(`n=${YAPPR_NETWORK_IDS.testnet}`)
    expect(uri).toContain(`v=${YAPPR_KEY_EXCHANGE_VERSION}`)

    const parsed = parseYapprKeyExchangeUri(uri)
    expect(parsed).not.toBeNull()
    expect(parsed!.network).toBe('testnet')
    expect(parsed!.version).toBe(YAPPR_KEY_EXCHANGE_VERSION)
    expect(parsed!.request.appEphemeralPubKey).toEqual(APP_PUBLIC_KEY)
    expect(parsed!.request.contractId).toEqual(CONTRACT_ID_BYTES)
    expect(parsed!.request.label).toBe(SAMPLE_LABEL)
  })

  it.each(['mainnet', 'devnet'] as const)('round-trips on %s', (network) => {
    const uri = buildYapprKeyExchangeUri(baseRequest, network)
    const parsed = parseYapprKeyExchangeUri(uri)
    expect(parsed?.network).toBe(network)
  })

  it('handles missing label cleanly', () => {
    const uri = buildYapprKeyExchangeUri({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
    })
    const parsed = parseYapprKeyExchangeUri(uri)
    expect(parsed?.request.label).toBeUndefined()
  })

  it('round-trips a multibyte UTF-8 label end-to-end', () => {
    const label = 'café 🦊'
    const uri = buildYapprKeyExchangeUri({
      appEphemeralPubKey: APP_PUBLIC_KEY,
      contractId: CONTRACT_ID_BYTES,
      label,
    })
    const parsed = parseYapprKeyExchangeUri(uri)
    expect(parsed?.request.label).toBe(label)
  })

  describe('returns null for malformed input', () => {
    it('wrong scheme', () => {
      expect(parseYapprKeyExchangeUri('http://foo')).toBeNull()
    })

    it('missing query string', () => {
      expect(parseYapprKeyExchangeUri('dash-key:abc')).toBeNull()
    })

    it('missing required params', () => {
      expect(parseYapprKeyExchangeUri('dash-key:abc?n=t')).toBeNull()
      expect(parseYapprKeyExchangeUri('dash-key:abc?v=1')).toBeNull()
    })

    it('unsupported version', () => {
      const uri = buildYapprKeyExchangeUri(baseRequest).replace(
        `v=${YAPPR_KEY_EXCHANGE_VERSION}`,
        'v=999',
      )
      expect(parseYapprKeyExchangeUri(uri)).toBeNull()
    })

    it('unknown network id', () => {
      const uri = buildYapprKeyExchangeUri(baseRequest).replace('n=t', 'n=z')
      expect(parseYapprKeyExchangeUri(uri)).toBeNull()
    })

    it('payload too short', () => {
      const tooShort = bs58.encode(new Uint8Array(10))
      expect(parseYapprKeyExchangeUri(`dash-key:${tooShort}?n=t&v=1`)).toBeNull()
    })

    it('byte-version mismatch inside payload', () => {
      const payload = new Uint8Array(67)
      payload[0] = 99
      const uri = `dash-key:${bs58.encode(payload)}?n=t&v=1`
      expect(parseYapprKeyExchangeUri(uri)).toBeNull()
    })

    it('label length exceeds 64', () => {
      const payload = new Uint8Array(67)
      payload[0] = YAPPR_KEY_EXCHANGE_VERSION
      payload[66] = 65
      const uri = `dash-key:${bs58.encode(payload)}?n=t&v=1`
      expect(parseYapprKeyExchangeUri(uri)).toBeNull()
    })

    it('label length runs past payload end', () => {
      const payload = new Uint8Array(67)
      payload[0] = YAPPR_KEY_EXCHANGE_VERSION
      payload[66] = 10
      const uri = `dash-key:${bs58.encode(payload)}?n=t&v=1`
      expect(parseYapprKeyExchangeUri(uri)).toBeNull()
    })

    it('non-base58 payload', () => {
      expect(parseYapprKeyExchangeUri('dash-key:!!!?n=t&v=1')).toBeNull()
    })
  })
})

describe('buildYapprStateTransitionUri / parseYapprStateTransitionUri', () => {
  const transitionBytes = new Uint8Array([10, 20, 30, 40, 50])

  it('round-trips on testnet (default)', () => {
    const uri = buildYapprStateTransitionUri(transitionBytes)
    expect(uri.startsWith('dash-st:')).toBe(true)
    const parsed = parseYapprStateTransitionUri(uri)
    expect(parsed?.transitionBytes).toEqual(transitionBytes)
    expect(parsed?.network).toBe('testnet')
    expect(parsed?.version).toBe(YAPPR_STATE_TRANSITION_VERSION)
  })

  it.each(['mainnet', 'devnet'] as const)('round-trips on %s', (network) => {
    const parsed = parseYapprStateTransitionUri(buildYapprStateTransitionUri(transitionBytes, network))
    expect(parsed?.network).toBe(network)
  })

  it('returns null on wrong scheme', () => {
    expect(parseYapprStateTransitionUri('dash-key:abc?n=t&v=1')).toBeNull()
  })

  it('returns null on missing query', () => {
    expect(parseYapprStateTransitionUri('dash-st:abc')).toBeNull()
  })

  it('returns null on missing params', () => {
    expect(parseYapprStateTransitionUri('dash-st:abc?n=t')).toBeNull()
    expect(parseYapprStateTransitionUri('dash-st:abc?v=1')).toBeNull()
  })

  it('returns null on bad version', () => {
    const uri = buildYapprStateTransitionUri(transitionBytes).replace(
      `v=${YAPPR_STATE_TRANSITION_VERSION}`,
      'v=999',
    )
    expect(parseYapprStateTransitionUri(uri)).toBeNull()
  })

  it('returns null on unknown network', () => {
    const uri = buildYapprStateTransitionUri(transitionBytes).replace('n=t', 'n=z')
    expect(parseYapprStateTransitionUri(uri)).toBeNull()
  })

  it('returns null on non-base58 payload', () => {
    expect(parseYapprStateTransitionUri('dash-st:!!!?n=t&v=1')).toBeNull()
  })
})

describe('decryptYapprKeyExchangeResponse', () => {
  it('decrypts a wallet response and returns the login key + identity', async () => {
    const sharedSecret = deriveYapprSharedSecret(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY)
    const encryptedPayload = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)

    const response: YapprKeyExchangeResponse = {
      $id: 'doc-id',
      $ownerId: IDENTITY_ID_BASE58,
      $revision: 1,
      contractId: CONTRACT_ID_BYTES,
      appEphemeralPubKeyHash: hash160(APP_PUBLIC_KEY),
      walletEphemeralPubKey: WALLET_PUBLIC_KEY,
      encryptedPayload,
      keyIndex: 5,
    }

    const result = await decryptYapprKeyExchangeResponse(response, APP_PRIVATE_KEY)
    expect(result.loginKey).toEqual(LOGIN_KEY)
    expect(result.keyIndex).toBe(5)
    expect(result.identityId).toBe(IDENTITY_ID_BASE58)
    expect(result.walletEphemeralPubKey).toEqual(WALLET_PUBLIC_KEY)
  })
})

describe('pollForYapprKeyExchangeResponse', () => {
  function makeResponse(encryptedPayload: Uint8Array): YapprKeyExchangeResponse {
    return {
      $id: 'doc-id',
      $ownerId: IDENTITY_ID_BASE58,
      $revision: 1,
      contractId: CONTRACT_ID_BYTES,
      appEphemeralPubKeyHash: hash160(APP_PUBLIC_KEY),
      walletEphemeralPubKey: WALLET_PUBLIC_KEY,
      encryptedPayload,
      keyIndex: 1,
    }
  }

  function fakePort(getResponse: YapprKeyExchangePort['getResponse']): YapprKeyExchangePort {
    return {
      getResponse,
      buildUnsignedKeyRegistrationTransition: vi.fn(),
      checkKeysRegistered: vi.fn(),
    }
  }

  it('resolves on the first non-null response', async () => {
    vi.useFakeTimers()
    try {
      const sharedSecret = deriveYapprSharedSecret(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY)
      const payload = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)

      const getResponse = vi.fn().mockResolvedValue(makeResponse(payload))
      const onPoll = vi.fn()
      const port = fakePort(getResponse)

      const promise = pollForYapprKeyExchangeResponse(
        port,
        CONTRACT_ID_BYTES,
        hash160(APP_PUBLIC_KEY),
        APP_PRIVATE_KEY,
        { onPoll, pollIntervalMs: 100, timeoutMs: 5000 },
      )

      await vi.runAllTimersAsync()
      const result = await promise

      expect(result.loginKey).toEqual(LOGIN_KEY)
      expect(getResponse).toHaveBeenCalledTimes(1)
      expect(onPoll).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('keeps polling until a response appears, advancing one pollIntervalMs at a time', async () => {
    vi.useFakeTimers()
    try {
      const sharedSecret = deriveYapprSharedSecret(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY)
      const payload = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)

      const getResponse = vi
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(makeResponse(payload))

      const onPoll = vi.fn()
      const port = fakePort(getResponse)
      const pollIntervalMs = 100

      const promise = pollForYapprKeyExchangeResponse(
        port,
        CONTRACT_ID_BYTES,
        hash160(APP_PUBLIC_KEY),
        APP_PRIVATE_KEY,
        { onPoll, pollIntervalMs, timeoutMs: 5000 },
      )

      await vi.advanceTimersByTimeAsync(0)
      expect(getResponse).toHaveBeenCalledTimes(1)
      expect(onPoll).toHaveBeenCalledTimes(1)

      await vi.advanceTimersByTimeAsync(pollIntervalMs / 2)
      expect(getResponse).toHaveBeenCalledTimes(1)

      await vi.advanceTimersByTimeAsync(pollIntervalMs / 2)
      expect(getResponse).toHaveBeenCalledTimes(2)
      expect(onPoll).toHaveBeenCalledTimes(2)

      await vi.advanceTimersByTimeAsync(pollIntervalMs)
      expect(getResponse).toHaveBeenCalledTimes(3)
      expect(onPoll).toHaveBeenCalledTimes(3)

      const result = await promise
      expect(result.loginKey).toEqual(LOGIN_KEY)
    } finally {
      vi.useRealTimers()
    }
  })

  it('logs and continues when getResponse rejects', async () => {
    vi.useFakeTimers()
    try {
      const sharedSecret = deriveYapprSharedSecret(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY)
      const payload = await encryptLoginKeyForFixture(LOGIN_KEY, sharedSecret, FIXED_NONCE)

      const getResponse = vi
        .fn()
        .mockRejectedValueOnce(new Error('network blip'))
        .mockResolvedValueOnce(makeResponse(payload))

      const port = fakePort(getResponse)
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() }

      const promise = pollForYapprKeyExchangeResponse(
        port,
        CONTRACT_ID_BYTES,
        hash160(APP_PUBLIC_KEY),
        APP_PRIVATE_KEY,
        { pollIntervalMs: 100, timeoutMs: 5000, logger },
      )

      await vi.runAllTimersAsync()
      const result = await promise

      expect(result.loginKey).toEqual(LOGIN_KEY)
      expect(logger.warn).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('throws on timeout when no response ever arrives', async () => {
    vi.useFakeTimers()
    try {
      const getResponse = vi.fn().mockResolvedValue(null)
      const port = fakePort(getResponse)

      const promise = pollForYapprKeyExchangeResponse(
        port,
        CONTRACT_ID_BYTES,
        hash160(APP_PUBLIC_KEY),
        APP_PRIVATE_KEY,
        { pollIntervalMs: 100, timeoutMs: 500 },
      )
      const settled = expect(promise).rejects.toThrow(/Timeout/)

      await vi.runAllTimersAsync()
      await settled
    } finally {
      vi.useRealTimers()
    }
  })

  it('throws Cancelled when signal is already aborted', async () => {
    const port = fakePort(vi.fn().mockResolvedValue(null))
    const controller = new AbortController()
    controller.abort()

    await expect(
      pollForYapprKeyExchangeResponse(
        port,
        CONTRACT_ID_BYTES,
        hash160(APP_PUBLIC_KEY),
        APP_PRIVATE_KEY,
        { pollIntervalMs: 100, timeoutMs: 5000, signal: controller.signal },
      ),
    ).rejects.toThrow(/Cancelled/)
  })

  it('throws Cancelled when signal aborts mid-sleep', async () => {
    vi.useFakeTimers()
    try {
      const getResponse = vi.fn().mockResolvedValue(null)
      const port = fakePort(getResponse)
      const controller = new AbortController()

      const promise = pollForYapprKeyExchangeResponse(
        port,
        CONTRACT_ID_BYTES,
        hash160(APP_PUBLIC_KEY),
        APP_PRIVATE_KEY,
        { pollIntervalMs: 1000, timeoutMs: 60000, signal: controller.signal },
      )
      const settled = expect(promise).rejects.toThrow(/Cancelled/)

      await vi.advanceTimersByTimeAsync(10)
      controller.abort()
      await vi.runAllTimersAsync()
      await settled
    } finally {
      vi.useRealTimers()
    }
  })

  it('uses default pollIntervalMs / timeoutMs when not supplied', () => {
    expect(DEFAULT_YAPPR_KEY_EXCHANGE_CONFIG.pollIntervalMs).toBe(3000)
    expect(DEFAULT_YAPPR_KEY_EXCHANGE_CONFIG.timeoutMs).toBe(120000)
  })
})
