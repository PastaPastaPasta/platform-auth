/**
 * Hand-rolled WebAuthn fixtures for passkey-prf tests under happy-dom.
 *
 * happy-dom does not provide a real `PublicKeyCredential` class, but the source
 * uses `instanceof PublicKeyCredential` to validate `navigator.credentials.{create,get}`
 * results. Tests install `FakePublicKeyCredential` on `globalThis.PublicKeyCredential`
 * (and `window.PublicKeyCredential`) so the production code's instanceof check
 * succeeds on instances we construct here.
 */

export class FakePublicKeyCredential {
  public readonly id: string
  public readonly type = 'public-key'
  public readonly rawId: ArrayBuffer
  public readonly response: AuthenticatorResponse
  public readonly authenticatorAttachment: string | null = 'platform'

  constructor(init: {
    rawId: ArrayBuffer
    response: AuthenticatorResponse
    extensions?: AuthenticationExtensionsClientOutputs & {
      prf?: { enabled?: boolean; results?: { first?: ArrayBuffer; second?: ArrayBuffer } }
    }
  }) {
    this.rawId = init.rawId
    this.response = init.response
    this.id = bytesToBase64Url(new Uint8Array(init.rawId))
    this.#extensions = init.extensions ?? {}
  }

  #extensions: AuthenticationExtensionsClientOutputs & {
    prf?: { enabled?: boolean; results?: { first?: ArrayBuffer; second?: ArrayBuffer } }
  }

  getClientExtensionResults(): AuthenticationExtensionsClientOutputs & {
    prf?: { enabled?: boolean; results?: { first?: ArrayBuffer; second?: ArrayBuffer } }
  } {
    return this.#extensions
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

export interface MakeCreateCredentialOptions {
  credentialId?: Uint8Array
  prfEnabled?: boolean
  prfFirst?: Uint8Array | null
}

/**
 * Build a fake credential as returned by `navigator.credentials.create()`.
 * The PRF extension on registration commonly carries `enabled: true` (or the
 * absence of the field — also enabled) and may not include results yet.
 */
export function makeCreateCredential(
  options: MakeCreateCredentialOptions = {},
): FakePublicKeyCredential {
  const credentialId = options.credentialId ?? new Uint8Array([1, 2, 3, 4])
  const attestationResponse: AuthenticatorAttestationResponse = {
    clientDataJSON: bytesToArrayBuffer(new Uint8Array([0x7b, 0x7d])),
    attestationObject: bytesToArrayBuffer(new Uint8Array([0xa0])),
    getAuthenticatorData: () => new ArrayBuffer(0),
    getPublicKey: () => null,
    getPublicKeyAlgorithm: () => 0,
    getTransports: () => [],
  }
  return new FakePublicKeyCredential({
    rawId: bytesToArrayBuffer(credentialId),
    response: attestationResponse,
    extensions: {
      prf:
        options.prfEnabled === false
          ? { enabled: false }
          : {
              enabled: options.prfEnabled,
              ...(options.prfFirst !== undefined && options.prfFirst !== null
                ? { results: { first: bytesToArrayBuffer(options.prfFirst) } }
                : {}),
            },
    },
  })
}

export interface MakeAssertionCredentialOptions {
  credentialId?: Uint8Array
  prfFirst?: Uint8Array | null
  userHandle?: string | null
}

export function makeAssertionCredential(
  options: MakeAssertionCredentialOptions = {},
): FakePublicKeyCredential {
  const credentialId = options.credentialId ?? new Uint8Array([1, 2, 3, 4])
  const userHandleBytes =
    options.userHandle === null
      ? null
      : bytesToArrayBuffer(new TextEncoder().encode(options.userHandle ?? ''))
  const assertionResponse: AuthenticatorAssertionResponse = {
    clientDataJSON: bytesToArrayBuffer(new Uint8Array([0x7b, 0x7d])),
    authenticatorData: bytesToArrayBuffer(new Uint8Array([0])),
    signature: bytesToArrayBuffer(new Uint8Array([0])),
    userHandle: userHandleBytes,
  }
  return new FakePublicKeyCredential({
    rawId: bytesToArrayBuffer(credentialId),
    response: assertionResponse,
    extensions: {
      prf:
        options.prfFirst === null
          ? {}
          : options.prfFirst !== undefined
            ? { results: { first: bytesToArrayBuffer(options.prfFirst) } }
            : { results: { first: bytesToArrayBuffer(new Uint8Array(32).fill(0xaa)) } },
    },
  })
}
