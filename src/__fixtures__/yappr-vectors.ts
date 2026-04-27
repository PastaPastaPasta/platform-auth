import bs58 from 'bs58'
import * as secp256k1 from '@noble/secp256k1'

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) {
    throw new Error(`hex must be even length: ${hex}`)
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export const APP_PRIVATE_KEY = hexToBytes(
  '0101010101010101010101010101010101010101010101010101010101010101',
)
export const WALLET_PRIVATE_KEY = hexToBytes(
  '0202020202020202020202020202020202020202020202020202020202020202',
)

export const APP_PUBLIC_KEY = secp256k1.getPublicKey(APP_PRIVATE_KEY, true)
export const WALLET_PUBLIC_KEY = secp256k1.getPublicKey(WALLET_PRIVATE_KEY, true)

export const IDENTITY_ID_BYTES = new Uint8Array(32).fill(0xab)
export const CONTRACT_ID_BYTES = new Uint8Array(32).fill(0xcd)
export const IDENTITY_ID_BASE58 = bs58.encode(IDENTITY_ID_BYTES)
export const CONTRACT_ID_BASE58 = bs58.encode(CONTRACT_ID_BYTES)

export const LOGIN_KEY = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff)

export const SAMPLE_LABEL = 'Login to Yappr'

export async function encryptLoginKeyForFixture(
  loginKey: Uint8Array,
  sharedSecret: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  if (nonce.length !== 12) {
    throw new Error('nonce must be 12 bytes')
  }
  const key = await crypto.subtle.importKey(
    'raw',
    sharedSecret.slice().buffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce.slice().buffer },
    key,
    loginKey.slice().buffer,
  )
  const out = new Uint8Array(12 + ciphertext.byteLength)
  out.set(nonce, 0)
  out.set(new Uint8Array(ciphertext), 12)
  return out
}

export const FIXED_NONCE = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
])

export const HASH160_OF_010203_HEX = '9bc4860bb936abf262d7a51f74b4304833fee3b2'

export const AUTH_KEY_FROM_LOGIN_HEX =
  'e06ee7ae45f257741dab7379793c854829b67171af111238c664d9fd90603706'

export const ENCRYPTION_KEY_FROM_LOGIN_HEX =
  '6879c11819d1a60026adae34c296e83d13d06559ad63da41d03c44b203a90f80'

export const SERIALIZED_REQUEST_HEX =
  '01031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f' +
  'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
  '0e4c6f67696e20746f205961707072'
