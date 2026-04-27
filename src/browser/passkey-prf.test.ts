import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  FakePublicKeyCredential,
  bytesToArrayBuffer,
  makeAssertionCredential,
  makeCreateCredential,
} from '../__fixtures__/webauthn'
import {
  createPasskeyWithPrf,
  getDefaultRpId,
  getPasskeyAllowCredentialIds,
  getPrfAssertionForCredentials,
  selectDiscoverablePasskey,
} from './passkey-prf'

const RP_ID = 'localhost'
const CREDENTIAL_ID = new Uint8Array([1, 2, 3, 4, 5])

let create: ReturnType<typeof vi.fn>
let get: ReturnType<typeof vi.fn>
let originalIsSecureContext: PropertyDescriptor | undefined

function installFakeWebAuthn(): void {
  create = vi.fn()
  get = vi.fn()

  vi.stubGlobal('PublicKeyCredential', FakePublicKeyCredential)
  ;(window as unknown as { PublicKeyCredential: typeof FakePublicKeyCredential }).PublicKeyCredential =
    FakePublicKeyCredential

  // Capture the original descriptor so afterEach can restore it; happy-dom
  // installs isSecureContext as a real property, and vi.unstubAllGlobals does
  // not undo Object.defineProperty writes.
  if (originalIsSecureContext === undefined) {
    originalIsSecureContext = Object.getOwnPropertyDescriptor(window, 'isSecureContext')
  }
  Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true })

  vi.stubGlobal('navigator', {
    credentials: { create, get },
    userAgent: 'test',
    platform: 'test',
  })
}

beforeEach(() => {
  installFakeWebAuthn()
})

afterEach(() => {
  vi.unstubAllGlobals()
  if (originalIsSecureContext) {
    Object.defineProperty(window, 'isSecureContext', originalIsSecureContext)
  } else {
    delete (window as unknown as Record<string, unknown>).isSecureContext
  }
  originalIsSecureContext = undefined
})

describe('getDefaultRpId', () => {
  it('returns window.location.hostname', () => {
    expect(getDefaultRpId()).toBe(window.location.hostname)
  })

  it('throws when running outside a browser environment', () => {
    const originalWindow = globalThis.window
    vi.stubGlobal('window', undefined)
    try {
      expect(() => getDefaultRpId()).toThrow(/browser environment/)
    } finally {
      vi.stubGlobal('window', originalWindow)
    }
  })
})

describe('getPrfAssertionForCredentials', () => {
  it('throws when no credentials are supplied', async () => {
    await expect(getPrfAssertionForCredentials([])).rejects.toThrow(/No passkey credentials available/)
  })

  it('returns the PRF output, credential id, and SHA-256 hash on success', async () => {
    const prfFirst = new Uint8Array(32).fill(0x42)
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID, prfFirst }))

    const result = await getPrfAssertionForCredentials([
      { credentialId: CREDENTIAL_ID, prfInput: new Uint8Array([9, 9, 9]), rpId: RP_ID },
    ])

    expect(result.credentialId).toEqual(CREDENTIAL_ID)
    expect(result.prfOutput).toEqual(prfFirst)
    expect(result.rpId).toBe(RP_ID)
    expect(result.credentialIdHash).toHaveLength(32)
    expect(result.prfInput).toEqual(new Uint8Array([9, 9, 9]))
  })

  it('forwards the rpId, challenge, allowCredentials, and PRF eval map to navigator.credentials.get', async () => {
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID }))
    const prfInput = new Uint8Array([9, 9, 9])

    await getPrfAssertionForCredentials([
      { credentialId: CREDENTIAL_ID, prfInput, rpId: RP_ID },
    ])

    expect(get).toHaveBeenCalledTimes(1)
    const call = get.mock.calls[0][0]
    expect(call.publicKey.rpId).toBe(RP_ID)
    expect(call.publicKey.challenge).toBeInstanceOf(Uint8Array)
    expect(call.publicKey.challenge).toHaveLength(32)
    expect(call.publicKey.allowCredentials).toHaveLength(1)
    expect(call.publicKey.allowCredentials[0].type).toBe('public-key')
    expect(new Uint8Array(call.publicKey.allowCredentials[0].id)).toEqual(CREDENTIAL_ID)
    expect(call.publicKey.userVerification).toBe('required')
    expect(call.publicKey.extensions.prf.evalByCredential).toBeDefined()
    const evalMap = call.publicKey.extensions.prf.evalByCredential as Record<string, { first: Uint8Array }>
    const onlyKey = Object.keys(evalMap)[0]
    expect(evalMap[onlyKey].first).toEqual(prfInput)
  })

  it('throws when navigator.credentials.get returns null', async () => {
    get.mockResolvedValueOnce(null)

    await expect(
      getPrfAssertionForCredentials([
        { credentialId: CREDENTIAL_ID, prfInput: new Uint8Array([9]), rpId: RP_ID },
      ]),
    ).rejects.toThrow(/Passkey assertion failed/)
  })

  it('throws when navigator.credentials.get returns a non-PublicKeyCredential value', async () => {
    get.mockResolvedValueOnce({ id: 'not-a-credential', type: 'public-key' })

    await expect(
      getPrfAssertionForCredentials([
        { credentialId: CREDENTIAL_ID, prfInput: new Uint8Array([9]), rpId: RP_ID },
      ]),
    ).rejects.toThrow(/Passkey assertion failed/)
  })

  it('throws when the credential carries no PRF output', async () => {
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID, prfFirst: null }))

    await expect(
      getPrfAssertionForCredentials([
        { credentialId: CREDENTIAL_ID, prfInput: new Uint8Array([9]), rpId: RP_ID },
      ]),
    ).rejects.toThrow(/did not return PRF output/)
  })

  it('throws when the returned credential id is not in the input descriptor list', async () => {
    get.mockResolvedValueOnce(
      makeAssertionCredential({
        credentialId: new Uint8Array([99, 99, 99]),
        prfFirst: new Uint8Array(32),
      }),
    )

    await expect(
      getPrfAssertionForCredentials([
        { credentialId: CREDENTIAL_ID, prfInput: new Uint8Array([9]), rpId: RP_ID },
      ]),
    ).rejects.toThrow(/not registered for this identity/)
  })

  it('refuses to run outside a secure browser context', async () => {
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true })

    await expect(
      getPrfAssertionForCredentials([
        { credentialId: CREDENTIAL_ID, prfInput: new Uint8Array([9]), rpId: RP_ID },
      ]),
    ).rejects.toThrow(/secure browser/)
  })
})

describe('createPasskeyWithPrf', () => {
  const enrollOptions = {
    identityId: 'IdentityFixture111111111111111111111111111111',
    username: 'alice',
    displayName: 'Alice',
    label: 'My device',
    rpId: RP_ID,
  }

  it('creates a passkey with PRF enabled and returns the assertion plus the supplied label', async () => {
    const prfFirst = new Uint8Array(32).fill(0x77)
    create.mockResolvedValueOnce(makeCreateCredential({ credentialId: CREDENTIAL_ID }))
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID, prfFirst }))

    const result = await createPasskeyWithPrf(enrollOptions)

    expect(result.label).toBe('My device')
    expect(result.credentialId).toEqual(CREDENTIAL_ID)
    expect(result.prfOutput).toEqual(prfFirst)
    expect(result.rpId).toBe(RP_ID)
  })

  it('forwards rpId, identityId-derived user.id, alg list, and prf extension to navigator.credentials.create', async () => {
    create.mockResolvedValueOnce(makeCreateCredential({ credentialId: CREDENTIAL_ID }))
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID }))

    await createPasskeyWithPrf(enrollOptions)

    const call = create.mock.calls[0][0]
    expect(call.publicKey.rp.id).toBe(RP_ID)
    expect(call.publicKey.rp.name).toBe('Platform Auth')
    expect(call.publicKey.user.name).toBe('alice')
    expect(call.publicKey.user.displayName).toBe('Alice')
    expect(call.publicKey.user.id).toBeInstanceOf(Uint8Array)
    expect(call.publicKey.user.id).toEqual(new TextEncoder().encode(enrollOptions.identityId).slice(0, 64))
    expect(call.publicKey.pubKeyCredParams.map((p: { alg: number }) => p.alg)).toEqual([-7, -8, -257])
    expect(call.publicKey.authenticatorSelection.residentKey).toBe('required')
    expect(call.publicKey.authenticatorSelection.userVerification).toBe('required')
    expect(call.publicKey.extensions.prf).toEqual({})
  })

  it('feeds the newly-created credentialId and a fresh 32-byte PRF input into the follow-up assertion', async () => {
    create.mockResolvedValueOnce(makeCreateCredential({ credentialId: CREDENTIAL_ID }))
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID }))

    // Deterministically capture every Uint8Array that getRandomValues fills,
    // so we can assert the exact bytes wired through rather than relying on
    // randomness being non-zero.
    const filled: Uint8Array[] = []
    const spy = vi
      .spyOn(globalThis.crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(arr: T): T => {
        if (arr instanceof Uint8Array) {
          const seed = (filled.length + 1) & 0xff
          for (let i = 0; i < arr.length; i += 1) arr[i] = (seed + i) & 0xff
          filled.push(new Uint8Array(arr))
        }
        return arr
      })

    try {
      await createPasskeyWithPrf(enrollOptions)
    } finally {
      spy.mockRestore()
    }

    expect(get).toHaveBeenCalledTimes(1)
    const assertCall = get.mock.calls[0][0]
    expect(assertCall.publicKey.allowCredentials).toHaveLength(1)
    expect(new Uint8Array(assertCall.publicKey.allowCredentials[0].id)).toEqual(CREDENTIAL_ID)

    const evalMap = assertCall.publicKey.extensions.prf.evalByCredential as Record<
      string,
      { first: Uint8Array }
    >
    const evalKeys = Object.keys(evalMap)
    expect(evalKeys).toHaveLength(1)
    const prfInputUsed = evalMap[evalKeys[0]].first
    expect(prfInputUsed).toHaveLength(32)
    // Three 32-byte fills happen during createPasskeyWithPrf:
    // create-challenge, generatePrfInput, get-challenge.
    // The PRF input is the second fill, and must differ from both challenges
    // so they cannot be accidentally reused.
    expect(filled).toHaveLength(3)
    expect(prfInputUsed).toEqual(filled[1])
    expect(prfInputUsed).not.toEqual(filled[0])
    expect(prfInputUsed).not.toEqual(filled[2])
  })

  it('throws when the create call resolves to a non-PublicKeyCredential value', async () => {
    create.mockResolvedValueOnce({ not: 'a-credential' })

    await expect(createPasskeyWithPrf(enrollOptions)).rejects.toThrow(/Failed to create passkey credential/)
  })

  it('throws when the credential reports prf.enabled === false', async () => {
    create.mockResolvedValueOnce(
      makeCreateCredential({ credentialId: CREDENTIAL_ID, prfEnabled: false }),
    )

    await expect(createPasskeyWithPrf(enrollOptions)).rejects.toThrow(/did not enable PRF/)
  })

  it('uses window.location.hostname as the rpId when none is supplied', async () => {
    create.mockResolvedValueOnce(makeCreateCredential({ credentialId: CREDENTIAL_ID }))
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID }))

    const result = await createPasskeyWithPrf({ ...enrollOptions, rpId: undefined })

    expect(result.rpId).toBe(window.location.hostname)
    expect(create.mock.calls[0][0].publicKey.rp.id).toBe(window.location.hostname)
  })

  it('honors a custom rpName override', async () => {
    create.mockResolvedValueOnce(makeCreateCredential({ credentialId: CREDENTIAL_ID }))
    get.mockResolvedValueOnce(makeAssertionCredential({ credentialId: CREDENTIAL_ID }))

    await createPasskeyWithPrf({ ...enrollOptions, rpName: 'Custom App' })

    expect(create.mock.calls[0][0].publicKey.rp.name).toBe('Custom App')
  })
})

describe('selectDiscoverablePasskey', () => {
  it('returns the credential id, hash, decoded userHandle, and rpId', async () => {
    get.mockResolvedValueOnce(
      makeAssertionCredential({ credentialId: CREDENTIAL_ID, userHandle: 'user-handle-string' }),
    )

    const result = await selectDiscoverablePasskey(RP_ID)

    expect(result.credentialId).toEqual(CREDENTIAL_ID)
    expect(result.userHandle).toBe('user-handle-string')
    expect(result.rpId).toBe(RP_ID)
    expect(result.credentialIdHash).toHaveLength(32)
  })

  it('returns userHandle=undefined when the assertion does not carry one', async () => {
    get.mockResolvedValueOnce(
      makeAssertionCredential({ credentialId: CREDENTIAL_ID, userHandle: null }),
    )

    const result = await selectDiscoverablePasskey(RP_ID)
    expect(result.userHandle).toBeUndefined()
  })

  it('returns userHandle=undefined when the value is empty after decoding', async () => {
    get.mockResolvedValueOnce(
      makeAssertionCredential({ credentialId: CREDENTIAL_ID, userHandle: '' }),
    )

    const result = await selectDiscoverablePasskey(RP_ID)
    expect(result.userHandle).toBeUndefined()
  })

  it('throws when navigator.credentials.get returns null', async () => {
    get.mockResolvedValueOnce(null)
    await expect(selectDiscoverablePasskey(RP_ID)).rejects.toThrow(/Passkey assertion failed/)
  })

  it('throws when navigator.credentials.get returns a non-PublicKeyCredential value', async () => {
    get.mockResolvedValueOnce({ id: 'not-a-credential', type: 'public-key' })
    await expect(selectDiscoverablePasskey(RP_ID)).rejects.toThrow(/Passkey assertion failed/)
  })

  it('falls back to window.location.hostname when no rpId is supplied', async () => {
    get.mockResolvedValueOnce(
      makeAssertionCredential({ credentialId: CREDENTIAL_ID, userHandle: 'u' }),
    )

    const result = await selectDiscoverablePasskey()
    expect(result.rpId).toBe(window.location.hostname)
  })
})

describe('getPasskeyAllowCredentialIds', () => {
  it('returns a fresh Uint8Array per descriptor (value-equal but identity-distinct)', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6])

    const out = getPasskeyAllowCredentialIds([
      { credentialId: a, prfInput: new Uint8Array([0]), rpId: RP_ID },
      { credentialId: b, prfInput: new Uint8Array([0]), rpId: RP_ID },
    ])

    expect(out).toHaveLength(2)
    expect(out[0]).toEqual(a)
    expect(out[1]).toEqual(b)
    expect(out[0]).not.toBe(a)
    expect(out[1]).not.toBe(b)
    // Identity-distinct is necessary but not sufficient — two views can share
    // a buffer. The mutation-isolation test below is the real proof.
  })

  it('isolates the returned bytes from later mutations of the input', () => {
    const a = new Uint8Array([1, 2, 3])

    const out = getPasskeyAllowCredentialIds([
      { credentialId: a, prfInput: new Uint8Array([0]), rpId: RP_ID },
    ])

    a[0] = 99
    expect(out[0][0]).toBe(1)
  })
})

describe('FakePublicKeyCredential sanity', () => {
  it('passes the instanceof PublicKeyCredential check used by the production code', () => {
    const cred = new FakePublicKeyCredential({
      rawId: bytesToArrayBuffer(new Uint8Array([1])),
      response: {
        clientDataJSON: bytesToArrayBuffer(new Uint8Array([0])),
      } as AuthenticatorResponse,
    })
    // Asserting against the resolved global, not the local class binding —
    // this is the check production code performs.
    expect(cred instanceof (globalThis as unknown as { PublicKeyCredential: Function }).PublicKeyCredential).toBe(true)
  })
})
