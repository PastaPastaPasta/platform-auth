import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useYapprKeyExchangeLogin, useYapprKeyRegistration } from './yappr-hooks'
import {
  decodeYapprIdentityId,
  deriveYapprAuthKeyFromLogin,
  deriveYapprEncryptionKeyFromLogin,
  getYapprPublicKey,
  hash160,
} from './yappr-protocol'
import { IDENTITY_ID_BASE58, CONTRACT_ID_BASE58, LOGIN_KEY } from '../__fixtures__/yappr-vectors'
import type { PlatformAuthController } from '../core/controller'
import type {
  YapprDecryptedKeyExchangeResult,
  YapprKeyExchangeConfig,
  YapprKeyRegistrationRequest,
  YapprUnsignedKeyRegistrationResult,
} from '../core/types'

const RESOLVED_CONFIG: YapprKeyExchangeConfig = {
  appContractId: CONTRACT_ID_BASE58,
  keyExchangeContractId: CONTRACT_ID_BASE58,
  network: 'testnet',
  label: 'Test App',
  pollIntervalMs: 1000,
  timeoutMs: 60_000,
}

interface FakeKeyExchangeController {
  controller: PlatformAuthController
  getYapprKeyExchangeConfig: ReturnType<typeof vi.fn>
  pollYapprKeyExchangeResponse: ReturnType<typeof vi.fn>
  checkYapprKeysRegistered: ReturnType<typeof vi.fn>
  buildYapprUnsignedKeyRegistrationTransition: ReturnType<typeof vi.fn>
  resolvePoll: (value: YapprDecryptedKeyExchangeResult) => void
  rejectPoll: (reason: Error) => void
}

function createFakeKeyExchangeController(): FakeKeyExchangeController {
  let resolvePoll: (value: YapprDecryptedKeyExchangeResult) => void = () => undefined
  let rejectPoll: (reason: Error) => void = () => undefined

  const pollYapprKeyExchangeResponse = vi.fn(
    (
      _hash: Uint8Array,
      _priv: Uint8Array,
      _overrides?: Partial<YapprKeyExchangeConfig>,
      options: { signal?: AbortSignal } = {},
    ) =>
      new Promise<YapprDecryptedKeyExchangeResult>((resolve, reject) => {
        resolvePoll = resolve
        rejectPoll = reject
        options.signal?.addEventListener('abort', () => {
          reject(new Error('Cancelled'))
        })
      }),
  )

  const checkYapprKeysRegistered = vi.fn(async () => false)
  const buildYapprUnsignedKeyRegistrationTransition = vi.fn(
    async (_req: YapprKeyRegistrationRequest): Promise<YapprUnsignedKeyRegistrationResult> => ({
      transitionBytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
      authKeyId: 4,
      encryptionKeyId: 5,
      identityRevision: 1n,
    }),
  )

  const getYapprKeyExchangeConfig = vi.fn(
    (overrides: Partial<YapprKeyExchangeConfig> = {}): YapprKeyExchangeConfig => ({
      ...RESOLVED_CONFIG,
      ...overrides,
    }),
  )

  const controller = {
    getYapprKeyExchangeConfig,
    pollYapprKeyExchangeResponse,
    checkYapprKeysRegistered,
    buildYapprUnsignedKeyRegistrationTransition,
  } as unknown as PlatformAuthController

  return {
    controller,
    getYapprKeyExchangeConfig,
    pollYapprKeyExchangeResponse,
    checkYapprKeysRegistered,
    buildYapprUnsignedKeyRegistrationTransition,
    resolvePoll: (value) => resolvePoll(value),
    rejectPoll: (reason) => rejectPoll(reason),
  }
}

async function flushMicrotasks(times = 5): Promise<void> {
  for (let i = 0; i < times; i += 1) {
    await Promise.resolve()
  }
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('useYapprKeyExchangeLogin — initial state', () => {
  it('starts in idle with no uri, error, or result', () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    expect(result.current.state).toBe('idle')
    expect(result.current.uri).toBeNull()
    expect(result.current.error).toBeNull()
    expect(result.current.result).toBeNull()
    expect(result.current.remainingTime).toBeNull()
    expect(result.current.keyIndex).toBe(0)
    expect(result.current.needsKeyRegistration).toBe(false)
  })
})

describe('useYapprKeyExchangeLogin — happy path through to complete', () => {
  it('drives idle → waiting → checking → complete with all keys derived correctly (decrypting collapses into checking via React batching)', async () => {
    const fake = createFakeKeyExchangeController()
    let releaseCheck: (value: boolean) => void = () => undefined
    fake.checkYapprKeysRegistered.mockImplementation(
      () => new Promise<boolean>((resolve) => {
        releaseCheck = resolve
      }),
    )

    const seenStates: string[] = []
    const { result } = renderHook(() => {
      const r = useYapprKeyExchangeLogin(fake.controller)
      seenStates.push(r.state)
      return r
    })

    await act(async () => {
      result.current.start({ label: 'Custom Label' })
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('waiting')
    expect(result.current.uri).toMatch(/^dash-key:/)
    expect(fake.getYapprKeyExchangeConfig).toHaveBeenCalledWith({ label: 'Custom Label' })

    const expectedAuthKey = deriveYapprAuthKeyFromLogin(LOGIN_KEY, decodeYapprIdentityId(IDENTITY_ID_BASE58))
    const expectedEncKey = deriveYapprEncryptionKeyFromLogin(LOGIN_KEY, decodeYapprIdentityId(IDENTITY_ID_BASE58))

    await act(async () => {
      fake.resolvePoll({
        loginKey: LOGIN_KEY,
        keyIndex: 3,
        walletEphemeralPubKey: new Uint8Array(33).fill(0x02),
        identityId: IDENTITY_ID_BASE58,
      })
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('checking')
    expect(seenStates).toContain('waiting')

    await act(async () => {
      releaseCheck(true)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('complete')
    expect(seenStates).toContain('checking')
    expect(result.current.result?.identityId).toBe(IDENTITY_ID_BASE58)
    expect(result.current.result?.keyIndex).toBe(3)
    expect(result.current.result?.needsKeyRegistration).toBe(false)
    expect(result.current.result?.authKey).toEqual(expectedAuthKey)
    expect(result.current.result?.encryptionKey).toEqual(expectedEncKey)
    expect(result.current.keyIndex).toBe(3)
    expect(result.current.needsKeyRegistration).toBe(false)

    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledWith(
      IDENTITY_ID_BASE58,
      getYapprPublicKey(expectedAuthKey),
      getYapprPublicKey(expectedEncKey),
      undefined,
    )
  })

  it('transitions to "registering" instead of "complete" when keys are not yet registered', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValue(false)
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    await act(async () => {
      fake.resolvePoll({
        loginKey: LOGIN_KEY,
        keyIndex: 1,
        walletEphemeralPubKey: new Uint8Array(33).fill(0x02),
        identityId: IDENTITY_ID_BASE58,
      })
      await flushMicrotasks()
    })

    const expectedAuthKey = deriveYapprAuthKeyFromLogin(LOGIN_KEY, decodeYapprIdentityId(IDENTITY_ID_BASE58))
    const expectedEncKey = deriveYapprEncryptionKeyFromLogin(LOGIN_KEY, decodeYapprIdentityId(IDENTITY_ID_BASE58))

    expect(result.current.state).toBe('registering')
    expect(result.current.needsKeyRegistration).toBe(true)
    expect(result.current.result?.identityId).toBe(IDENTITY_ID_BASE58)
    expect(result.current.result?.keyIndex).toBe(1)
    expect(result.current.result?.needsKeyRegistration).toBe(true)
    expect(result.current.result?.authKey).toEqual(expectedAuthKey)
    expect(result.current.result?.encryptionKey).toEqual(expectedEncKey)
  })

  it('forwards the correct ephemeral pubkey hash and contract id bytes to the controller', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    expect(fake.pollYapprKeyExchangeResponse).toHaveBeenCalledTimes(1)
    const [hashArg, privArg, overridesArg, opts] = fake.pollYapprKeyExchangeResponse.mock.calls[0]
    expect(hashArg).toBeInstanceOf(Uint8Array)
    expect(hashArg).toHaveLength(20)
    expect(privArg).toBeInstanceOf(Uint8Array)
    expect(privArg).toHaveLength(32)
    expect(overridesArg).toBeUndefined()
    expect(opts.signal).toBeInstanceOf(AbortSignal)

    expect(hash160(getYapprPublicKey(privArg))).toEqual(hashArg)
    expect(result.current.uri).toMatch(/^dash-key:/)
    expect(result.current.uri).toMatch(/n=t/)
  })
})

describe('useYapprKeyExchangeLogin — countdown timer', () => {
  it('updates remainingTime once per second after start and stops at 0', async () => {
    const fake = createFakeKeyExchangeController()
    fake.getYapprKeyExchangeConfig.mockImplementation((overrides = {}) => ({
      ...RESOLVED_CONFIG,
      timeoutMs: 3000,
      ...overrides,
    }))
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    expect(result.current.remainingTime).toBeNull()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
    })
    expect(result.current.remainingTime).toBe(2)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
    })
    expect(result.current.remainingTime).toBe(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
    })
    expect(result.current.remainingTime).toBe(0)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(result.current.remainingTime).toBe(0)
  })
})

describe('useYapprKeyExchangeLogin — error and timeout paths', () => {
  it('maps a Timeout error into the "timeout" state with a friendly message', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    await act(async () => {
      fake.rejectPoll(new Error('Timeout: wallet did not respond'))
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('timeout')
    expect(result.current.error).toBe('Timed out waiting for wallet response')
  })

  it('maps a Cancelled error into the "idle" state with no error string', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    await act(async () => {
      fake.rejectPoll(new Error('Cancelled'))
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('idle')
    expect(result.current.error).toBeNull()
  })

  it('captures generic Error.message into "error" state', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    await act(async () => {
      fake.rejectPoll(new Error('Network unreachable'))
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('error')
    expect(result.current.error).toBe('Network unreachable')
  })

  it('uses a generic message for non-Error rejections', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    await act(async () => {
      fake.rejectPoll('weird-string-rejection' as unknown as Error)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('error')
    expect(result.current.error).toBe('An unexpected error occurred')
  })

  it('throws and surfaces an error when getYapprKeyExchangeConfig itself fails', async () => {
    const fake = createFakeKeyExchangeController()
    fake.getYapprKeyExchangeConfig.mockImplementation(() => {
      throw new Error('Yappr key exchange is not configured')
    })
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('error')
    expect(result.current.error).toBe('Yappr key exchange is not configured')
  })
})

describe('useYapprKeyExchangeLogin — cancel and retry', () => {
  it('cancel() aborts the in-flight poll and resets state to idle', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })
    expect(result.current.state).toBe('waiting')

    await act(async () => {
      result.current.cancel()
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('idle')
    expect(result.current.uri).toBeNull()
    expect(result.current.error).toBeNull()
    expect(result.current.remainingTime).toBeNull()

    const signal = fake.pollYapprKeyExchangeResponse.mock.calls[0][3].signal as AbortSignal
    expect(signal.aborted).toBe(true)

    await act(async () => {
      fake.resolvePoll({
        loginKey: LOGIN_KEY,
        keyIndex: 7,
        walletEphemeralPubKey: new Uint8Array(33).fill(0x02),
        identityId: IDENTITY_ID_BASE58,
      })
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('idle')
    expect(result.current.result).toBeNull()
  })

  it('retry() re-invokes start with the most recent options', async () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start({ label: 'first-label' })
      await flushMicrotasks()
    })

    await act(async () => {
      result.current.retry()
      await flushMicrotasks()
    })

    expect(fake.getYapprKeyExchangeConfig).toHaveBeenCalledTimes(2)
    expect(fake.getYapprKeyExchangeConfig).toHaveBeenLastCalledWith({ label: 'first-label' })
    expect(fake.pollYapprKeyExchangeResponse).toHaveBeenCalledTimes(2)
    const firstSignal = fake.pollYapprKeyExchangeResponse.mock.calls[0][3].signal as AbortSignal
    const secondSignal = fake.pollYapprKeyExchangeResponse.mock.calls[1][3].signal as AbortSignal
    expect(firstSignal.aborted).toBe(true)
    expect(secondSignal.aborted).toBe(false)
  })
})

describe('useYapprKeyExchangeLogin — unmount cleanup', () => {
  it('aborts the in-flight poll when the hook unmounts', async () => {
    const fake = createFakeKeyExchangeController()
    const { result, unmount } = renderHook(() => useYapprKeyExchangeLogin(fake.controller))

    await act(async () => {
      result.current.start()
      await flushMicrotasks()
    })

    const signal = fake.pollYapprKeyExchangeResponse.mock.calls[0][3].signal as AbortSignal
    expect(signal.aborted).toBe(false)

    unmount()
    expect(signal.aborted).toBe(true)
  })
})

describe('useYapprKeyRegistration — initial state and happy path', () => {
  const AUTH_KEY = new Uint8Array(32).fill(0x77)
  const ENC_KEY = new Uint8Array(32).fill(0x88)

  it('starts in idle', () => {
    const fake = createFakeKeyExchangeController()
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller))

    expect(result.current.state).toBe('idle')
    expect(result.current.uri).toBeNull()
    expect(result.current.error).toBeNull()
    expect(result.current.result).toBeNull()
    expect(result.current.remainingTime).toBeNull()
  })

  it('drives building → verifying → complete and invokes onComplete once (waiting collapses into verifying via React batching when keys are immediately found)', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValue(true)
    let releaseBuild: (value: YapprUnsignedKeyRegistrationResult) => void = () => undefined
    fake.buildYapprUnsignedKeyRegistrationTransition.mockImplementation(
      () => new Promise<YapprUnsignedKeyRegistrationResult>((resolve) => {
        releaseBuild = resolve
      }),
    )
    const onComplete = vi.fn()
    const seenStates: string[] = []
    const { result } = renderHook(() => {
      const r = useYapprKeyRegistration(fake.controller, onComplete)
      seenStates.push(r.state)
      return r
    })

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('building')
    expect(seenStates).toContain('building')

    await act(async () => {
      releaseBuild({
        transitionBytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
        authKeyId: 4,
        encryptionKeyId: 5,
        identityRevision: 1n,
      })
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('verifying')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('complete')
    expect(result.current.result).toEqual({ authKeyId: 4, encryptionKeyId: 5 })
    expect(onComplete).toHaveBeenCalledTimes(1)
    expect(result.current.uri).toMatch(/^dash-st:/)

    expect(fake.buildYapprUnsignedKeyRegistrationTransition).toHaveBeenCalledTimes(1)
    const [requestArg] = fake.buildYapprUnsignedKeyRegistrationTransition.mock.calls[0]
    expect(requestArg.identityId).toBe(IDENTITY_ID_BASE58)
    expect(requestArg.authPrivateKey).toEqual(AUTH_KEY)
    expect(requestArg.encryptionPrivateKey).toEqual(ENC_KEY)
    expect(requestArg.authPublicKey).toEqual(getYapprPublicKey(AUTH_KEY))
    expect(requestArg.encryptionPublicKey).toEqual(getYapprPublicKey(ENC_KEY))
  })

  it('keeps polling at 5s intervals until keys appear, then transitions to complete', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValueOnce(false)
    fake.checkYapprKeysRegistered.mockResolvedValueOnce(false)
    fake.checkYapprKeysRegistered.mockResolvedValue(true)
    const onComplete = vi.fn()
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller, onComplete))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('waiting')
    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000)
      await flushMicrotasks()
    })
    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
      await flushMicrotasks()
    })
    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(2)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000)
      await flushMicrotasks()
    })
    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(2)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
      await flushMicrotasks()
    })
    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(3)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500)
      await flushMicrotasks()
    })
    expect(result.current.state).toBe('complete')
    expect(onComplete).toHaveBeenCalledTimes(1)
  })

  it('keeps polling instead of failing when checkYapprKeysRegistered throws', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockRejectedValueOnce(new Error('transient'))
    fake.checkYapprKeysRegistered.mockResolvedValue(true)
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('waiting')
    expect(result.current.error).toBeNull()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
      await flushMicrotasks()
    })
    expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(2)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('complete')
  })
})

describe('useYapprKeyRegistration — error, cancel, retry', () => {
  const AUTH_KEY = new Uint8Array(32).fill(0x77)
  const ENC_KEY = new Uint8Array(32).fill(0x88)

  it('puts the hook in error state when buildYapprUnsignedKeyRegistrationTransition throws', async () => {
    const fake = createFakeKeyExchangeController()
    fake.buildYapprUnsignedKeyRegistrationTransition.mockRejectedValue(new Error('Identity not found'))
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('error')
    expect(result.current.error).toBe('Identity not found')
  })

  it('returns to idle without error on a Cancelled rejection', async () => {
    const fake = createFakeKeyExchangeController()
    fake.buildYapprUnsignedKeyRegistrationTransition.mockRejectedValue(new Error('Cancelled'))
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('idle')
    expect(result.current.error).toBeNull()
  })

  it('cancel() during the 500ms post-verify wait resets state and prevents the transition to complete', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValue(true)
    const onComplete = vi.fn()
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller, onComplete))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('verifying')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(200)
      await flushMicrotasks()
    })
    expect(result.current.state).toBe('verifying')

    await act(async () => {
      result.current.cancel()
    })

    expect(result.current.state).toBe('idle')
    expect(result.current.uri).toBeNull()
    expect(result.current.result).toBeNull()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500)
      await flushMicrotasks()
    })
    expect(onComplete).not.toHaveBeenCalled()
    expect(result.current.state).toBe('idle')
  })

  it('retry() re-invokes start with the last identity/keys', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValue(false)
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })
    expect(result.current.state).toBe('waiting')

    await act(async () => {
      result.current.retry()
      await flushMicrotasks()
    })

    expect(fake.buildYapprUnsignedKeyRegistrationTransition).toHaveBeenCalledTimes(2)
    const [firstCallReq] = fake.buildYapprUnsignedKeyRegistrationTransition.mock.calls[0]
    const [secondCallReq] = fake.buildYapprUnsignedKeyRegistrationTransition.mock.calls[1]
    expect(secondCallReq.identityId).toBe(IDENTITY_ID_BASE58)
    expect(secondCallReq.authPrivateKey).toEqual(AUTH_KEY)
    expect(secondCallReq.encryptionPrivateKey).toEqual(ENC_KEY)
    expect(secondCallReq.authPrivateKey).not.toBe(firstCallReq.authPrivateKey)
    expect(secondCallReq.encryptionPrivateKey).not.toBe(firstCallReq.encryptionPrivateKey)
    expect(result.current.state).toBe('waiting')
  })

  it('drops to error and stops polling after the 5-minute registration timeout', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValue(false)
    const { result } = renderHook(() => useYapprKeyRegistration(fake.controller))

    await act(async () => {
      result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
      await flushMicrotasks()
    })
    expect(result.current.state).toBe('waiting')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(300_000)
      await flushMicrotasks()
    })

    expect(result.current.state).toBe('error')
    expect(result.current.error).toBe('Request timed out. Please try again.')
  })
})

describe('useYapprKeyRegistration — unmount cleanup', () => {
  const AUTH_KEY = new Uint8Array(32).fill(0x77)
  const ENC_KEY = new Uint8Array(32).fill(0x88)

  it('clears polling and timer intervals on unmount without state-update warnings', async () => {
    const fake = createFakeKeyExchangeController()
    fake.checkYapprKeysRegistered.mockResolvedValue(false)
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    try {
      const { result, unmount } = renderHook(() => useYapprKeyRegistration(fake.controller))

      await act(async () => {
        result.current.start(IDENTITY_ID_BASE58, AUTH_KEY, ENC_KEY)
        await flushMicrotasks()
      })
      expect(result.current.state).toBe('waiting')
      expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(1)

      unmount()

      await vi.advanceTimersByTimeAsync(15_000)
      await flushMicrotasks()

      expect(fake.checkYapprKeysRegistered).toHaveBeenCalledTimes(1)
      const unmountedWarnings = errorSpy.mock.calls.filter((args) =>
        args.some((a) => typeof a === 'string' && a.includes('unmounted')),
      )
      expect(unmountedWarnings).toHaveLength(0)
    } finally {
      errorSpy.mockRestore()
    }
  })
})
