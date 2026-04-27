import { afterEach, describe, expect, it, vi } from 'vitest'
import { getPasskeyPrfSupport } from './passkey-support'

interface PublicKeyCredentialStatics {
  isConditionalMediationAvailable?: () => Promise<boolean>
  isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>
}

function setUserAgent(userAgent: string, platform = 'MacIntel'): void {
  vi.stubGlobal('navigator', {
    userAgent,
    platform,
  })
}

function setSecureContext(value: boolean): void {
  Object.defineProperty(window, 'isSecureContext', {
    value,
    configurable: true,
  })
}

function installPublicKeyCredential(statics: PublicKeyCredentialStatics): void {
  vi.stubGlobal('PublicKeyCredential', statics as unknown as typeof PublicKeyCredential)
  ;(window as unknown as { PublicKeyCredential: PublicKeyCredentialStatics }).PublicKeyCredential = statics
}

function removePublicKeyCredential(): void {
  vi.stubGlobal('PublicKeyCredential', undefined)
  ;(window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential = undefined
}

afterEach(() => {
  vi.unstubAllGlobals()
  setSecureContext(true)
})

describe('getPasskeyPrfSupport — environment guards', () => {
  it('blocks when not running in a browser context (window undefined)', async () => {
    vi.stubGlobal('window', undefined)

    const result = await getPasskeyPrfSupport()

    expect(result).toEqual({
      webauthnAvailable: false,
      conditionalUiAvailable: false,
      likelyPrfCapable: false,
      platformHint: 'unknown',
      blockedReason: 'Passkeys are only available in a browser context.',
    })
  })

  it('blocks when the document is not in a secure context', async () => {
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X)', 'MacIntel')
    setSecureContext(false)
    installPublicKeyCredential({})

    const result = await getPasskeyPrfSupport()

    expect(result.webauthnAvailable).toBe(false)
    expect(result.likelyPrfCapable).toBe(false)
    expect(result.platformHint).toBe('apple')
    expect(result.blockedReason).toMatch(/secure browser context/)
  })

  it('blocks when window.PublicKeyCredential is missing', async () => {
    setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64)', 'Win32')
    setSecureContext(true)
    removePublicKeyCredential()

    const result = await getPasskeyPrfSupport()

    expect(result.webauthnAvailable).toBe(false)
    expect(result.platformHint).toBe('windows')
    expect(result.blockedReason).toMatch(/does not support WebAuthn/)
  })
})

describe('getPasskeyPrfSupport — capability matrix', () => {
  it('reports likelyPrfCapable=true when the platform authenticator is available', async () => {
    setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)', 'iPhone')
    setSecureContext(true)
    installPublicKeyCredential({
      isConditionalMediationAvailable: vi.fn(async () => false),
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
    })

    const result = await getPasskeyPrfSupport()

    expect(result).toEqual({
      webauthnAvailable: true,
      conditionalUiAvailable: false,
      likelyPrfCapable: true,
      platformHint: 'apple',
      blockedReason: undefined,
    })
  })

  it('reports likelyPrfCapable=true when only conditional UI is available', async () => {
    setUserAgent('Mozilla/5.0 (Linux; Android 14)', 'Linux armv8l')
    setSecureContext(true)
    installPublicKeyCredential({
      isConditionalMediationAvailable: vi.fn(async () => true),
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
    })

    const result = await getPasskeyPrfSupport()

    expect(result.webauthnAvailable).toBe(true)
    expect(result.conditionalUiAvailable).toBe(true)
    expect(result.likelyPrfCapable).toBe(true)
    expect(result.platformHint).toBe('android')
    expect(result.blockedReason).toBeUndefined()
  })

  it('reports likelyPrfCapable=false but still webauthnAvailable when both static probes are absent', async () => {
    setUserAgent('Mozilla/5.0 (X11; Linux x86_64)', 'Linux x86_64')
    setSecureContext(true)
    installPublicKeyCredential({})

    const result = await getPasskeyPrfSupport()

    expect(result.webauthnAvailable).toBe(true)
    expect(result.conditionalUiAvailable).toBe(false)
    expect(result.likelyPrfCapable).toBe(false)
    expect(result.platformHint).toBe('desktop-other')
    expect(result.blockedReason).toMatch(/PRF capability still needs to be confirmed/)
  })

  it('treats a rejected isConditionalMediationAvailable() as false', async () => {
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X)', 'MacIntel')
    setSecureContext(true)
    installPublicKeyCredential({
      isConditionalMediationAvailable: vi.fn(async () => {
        throw new Error('not implemented')
      }),
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
    })

    const result = await getPasskeyPrfSupport()

    expect(result.conditionalUiAvailable).toBe(false)
    expect(result.likelyPrfCapable).toBe(false)
  })

  it('treats a rejected isUserVerifyingPlatformAuthenticatorAvailable() as false', async () => {
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X)', 'MacIntel')
    setSecureContext(true)
    installPublicKeyCredential({
      isConditionalMediationAvailable: vi.fn(async () => false),
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => {
        throw new Error('not implemented')
      }),
    })

    const result = await getPasskeyPrfSupport()

    expect(result.likelyPrfCapable).toBe(false)
  })
})

describe('getPasskeyPrfSupport — platform hint detection', () => {
  it.each([
    ['Mozilla/5.0 (iPhone)', 'iPhone', 'apple'],
    ['Mozilla/5.0 (iPad)', 'iPad', 'apple'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X)', 'MacIntel', 'apple'],
    ['Mozilla/5.0 (Linux; Android 14)', 'Linux armv8l', 'android'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64)', 'Win32', 'windows'],
    ['Mozilla/5.0 (X11; Linux x86_64)', 'Linux x86_64', 'desktop-other'],
  ] as const)('returns %s for userAgent=%s', async (userAgent, platform, expected) => {
    setUserAgent(userAgent, platform)
    setSecureContext(true)
    installPublicKeyCredential({})

    const result = await getPasskeyPrfSupport()
    expect(result.platformHint).toBe(expected)
  })

  it('falls through to "unknown" when the userAgent is empty', async () => {
    setUserAgent('', '')
    setSecureContext(true)
    installPublicKeyCredential({})

    const result = await getPasskeyPrfSupport()
    expect(result.platformHint).toBe('unknown')
  })

  it('detects "windows" via navigator.platform when userAgent does not match', async () => {
    setUserAgent('SomeBrowser/1.0', 'Win32')
    setSecureContext(true)
    installPublicKeyCredential({})

    const result = await getPasskeyPrfSupport()
    expect(result.platformHint).toBe('windows')
  })

  it('detects "apple" via navigator.platform when userAgent does not match', async () => {
    setUserAgent('SomeBrowser/1.0', 'iPhone')
    setSecureContext(true)
    installPublicKeyCredential({})

    const result = await getPasskeyPrfSupport()
    expect(result.platformHint).toBe('apple')
  })
})
