import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js'
import { decodeBase58 } from './primitives'
import { APP_CONNECT_MAX_REQUEST_AGE_MS } from './request'

/**
 * Candidate discovery for App Connect. Responses live in the App Connect system
 * contract (`H8F9…`, `loginKeyResponse`), keyed by `appEphemeralPubKeyHash`
 * then `$ownerId`. Anyone can answer a request, so the app pages through every
 * candidate and verifies each one; nothing here decides who logged in.
 */

/** One `loginKeyResponse` entry. */
export interface AppConnectCandidate {
  ownerId: string
  walletEphemeralPubKey: Uint8Array
  encryptedPayload: Uint8Array
}

export interface AppConnectResponsePort {
  /**
   * Up to `limit` responses with `appEphemeralPubKeyHash == requestHash`,
   * ordered by `$ownerId` ascending, after `startAfter` when given, and only
   * `$ownerId == hint` when a hint is given.
   */
  listCandidates(
    requestHash: Uint8Array,
    hint: string | undefined,
    startAfter: string | undefined,
    limit: number,
  ): Promise<AppConnectCandidate[]>
}

export const APP_CONNECT_PAGE_SIZE = 10
/** Platform returns at most this many documents per query. */
export const APP_CONNECT_MAX_PAGE_SIZE = 100
/** Past this many candidates the app stops and asks the user to start again. */
export const APP_CONNECT_MAX_CANDIDATES = 20
export const APP_CONNECT_FAST_POLL_MS = 2_000
export const APP_CONNECT_SLOW_POLL_MS = 4_000
export const APP_CONNECT_FAST_POLL_WINDOW_MS = 60_000

/** The response port broke its contract, so the candidate list may be incomplete. A bug in the port, not in the request. */
export class AppConnectPortError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = 'AppConnectPortError'
  }
}

export interface ListAppConnectCandidatesOptions {
  hint?: string
  pageSize?: number
  maxCandidates?: number
}

/**
 * Pages through every candidate for a request. `truncated` means more than
 * `maxCandidates` exist (spam): the caller should abandon the request. Throws
 * {@link AppConnectPortError} when the port ignores the cursor or returns
 * owners out of order, because the list may be missing candidates; report it
 * rather than retrying, since a broken port fails the same way every time.
 */
export async function listAppConnectCandidates(
  port: AppConnectResponsePort,
  requestHash: Uint8Array,
  options: ListAppConnectCandidatesOptions = {},
): Promise<{ candidates: AppConnectCandidate[]; truncated: boolean }> {
  const { hint, pageSize = APP_CONNECT_PAGE_SIZE, maxCandidates = APP_CONNECT_MAX_CANDIDATES } = options
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > APP_CONNECT_MAX_PAGE_SIZE) {
    throw new RangeError(`pageSize must be an integer from 1 to ${APP_CONNECT_MAX_PAGE_SIZE}, got ${pageSize}`)
  }
  if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 0) {
    throw new RangeError(`maxCandidates must be a non-negative integer, got ${maxCandidates}`)
  }
  const candidates: AppConnectCandidate[] = []
  let startAfter: string | undefined

  for (;;) {
    const page = await port.listCandidates(requestHash, hint, startAfter, pageSize)
    for (const candidate of page) {
      // Defend against a port that ignores the cursor or the hint: anything not
      // strictly after the cursor would loop or hide a candidate, anything else
      // is not ours to see.
      if (startAfter !== undefined && !idAfter(candidate.ownerId, startAfter)) {
        throw new AppConnectPortError(`response port returned ${candidate.ownerId} after ${startAfter}; candidates must be ordered by $ownerId and follow the cursor`)
      }
      startAfter = candidate.ownerId
      if (hint !== undefined && candidate.ownerId !== hint) continue
      if (candidates.length === maxCandidates) return { candidates, truncated: true }
      candidates.push(candidate)
    }
    if (page.length < pageSize) return { candidates, truncated: false }
  }
}

/** Whether base58 id `a` sorts strictly after `b` in byte order, as Platform orders `$ownerId`. */
function idAfter(a: string, b: string): boolean {
  let left: Uint8Array
  let right: Uint8Array
  try {
    left = decodeBase58(a)
    right = decodeBase58(b)
  } catch {
    return false
  }
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const l = left[i] ?? 0
    const r = right[i] ?? 0
    if (l !== r) return l > r
  }
  return left.length > right.length
}

/**
 * Delay before the next poll: every 2 s for the first minute, then every 4 s,
 * and null once the request has expired (10 minutes). Polls on focus or on the
 * wallet's callback happen immediately, outside this cadence.
 */
export function appConnectPollDelayMs(elapsedMs: number): number | null {
  if (elapsedMs >= APP_CONNECT_MAX_REQUEST_AGE_MS) return null
  return elapsedMs < APP_CONNECT_FAST_POLL_WINDOW_MS ? APP_CONNECT_FAST_POLL_MS : APP_CONNECT_SLOW_POLL_MS
}

/**
 * Identifies a candidate's exact contents, so a poll loop verifies each
 * response once and notices when an identity republishes a different one.
 */
export function appConnectCandidateKey(candidate: AppConnectCandidate): string {
  const contents = concatBytes(candidate.walletEphemeralPubKey, candidate.encryptedPayload)
  return `${candidate.ownerId}:${bytesToHex(sha256(contents))}`
}
