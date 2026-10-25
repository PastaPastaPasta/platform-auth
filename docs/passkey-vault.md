# Passkey vault core (`@pastapastapasta/platform-auth/passkey-vault`)

A passkey keeps a session's signing keys on Dash Platform. A signed-in device seals the keys into a public `vaultEntry` document that only one passkey can open. On another device, signing in with that passkey brings the session back. The module is generic: each app supplies a **profile** (labels and bundle formats), a **port** (Platform reads and writes), an **adapter** (WebAuthn), and a **chain check**. It has no SDK and no React. Its only external dependencies are `@noble/ciphers`, `@noble/curves` and `@noble/hashes`. Imports inside it are relative, so an app can vendor `src/passkey-vault/` as it is.

The format is the one Yappr (`docs/PASSKEY_VAULT.md` §3) and govhub (`packages/auth/src/vault/bundle.ts`) already use. Their profiles below reproduce their bytes exactly, and the test vectors check this.

## 1. Format

| Item | Value |
|---|---|
| HPKE | RFC 9180 base mode, single shot: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003` (Appendix A.2's suite) |
| PRF input | `UTF8(prfLabel) ‖ contractId`: one input per deployment, so a discoverable sign-in evaluates the PRF in the same ceremony that picks the passkey |
| Recipient | `(skR, pkR) = DeriveKeyPair(prfOutput)`; `pkR` is the entry's `recipientKey` |
| info | `UTF8(infoLabel) ‖ 0x00 ‖ contractId ‖ ownerId` |
| AAD | `UTF8(aadDocType) ‖ 0x00 ‖ u8 version ‖ u8 len(credentialId) ‖ credentialId ‖ recipientKey ‖ u32be authKeyId` |
| Entry version | 1 |
| Credential id | 16 to 255 bytes |
| User handle | `identityId ‖ contractId`, 64 bytes, binary |
| Sealed | `len(bundle) + 16` (Poly1305 tag); `enc` is 32 bytes |

All ids are raw 32-byte identifiers.

### Bundles

Every bundle starts with a format byte and is padded with zeros to its codec's fixed length. Decoding rejects any padding byte that is not zero.

- **slotKeys** (Yappr formats 1 and 2; govhub KEY with one slot; Forge):
  `format u8 ‖ n u8 ‖ n × (purpose u8 ‖ securityLevel u8 ‖ keyType u8 ‖ keyId u32be ‖ privateKey[32]) ‖ zeros`
  - Slot 0 must be the entry's `authKeyId`.
  - A key id may not appear twice.
  - Every private key must be a valid secp256k1 scalar.
  - Every slot must pass the profile's `allow(key, slotIndex, format)`, and the whole bundle its optional `check(keys)`.
- **seed** (govhub SEED): `format ‖ len u8 (16|32) ‖ identityIndex u32be (< 2^31) ‖ entropy ‖ zeros`.
- **votingKeys** (govhub VOTING_KEYS): `format ‖ n u8 ‖ n × privateKey[32] ‖ zeros`. The keys must be distinct and valid.

### Opening order

`openEntry` performs these checks in order and stops at the first failure:

1. The version is the profile's.
2. `enc` is 32 bytes.
3. The ciphertext length is one of the formats' lengths + 16. A strict profile has only one such length.
4. The recipient key derived from the PRF output equals the entry's `recipientKey` (`wrong-passkey`). This check runs before any decryption.
5. The AEAD tag verifies (`decrypt`).
6. The format byte selects a codec of that length.
7. The codec's rules pass (`bundle`).

`openEntry` wipes the derived secret key and the plaintext. The PRF output belongs to the caller, so `openEntry` does not wipe it.

## 2. Profiles

| | Yappr | govhub | Forge (new) |
|---|---|---|---|
| prfLabel | `yappr/passkey-vault/v1/prf` | `govhub/vault/v1/prf` | `dash-forge/passkey-vault/v1/prf` |
| infoLabel | `yappr/passkey-vault/v1` | `govhub/vault/v1` | `dash-forge/passkey-vault/v1` |
| aadDocType | `vaultEntry` | `vault` | `vaultEntry` |
| formats | slotKeys{id 1, 80 B, ≤2}, slotKeys{id 2, 160 B, ≤4} | seed{1, 240 B}, slotKeys{2, 240 B, 1}, votingKeys{3, 240 B, ≤7} | slotKeys{1, 240 B, ≤6} |
| sealed | 96 / 176 B | 256 B | 256 B |
| strictSealedLength | false | true | true |

The slot rules are each app's own. They change no bytes:

- **Yappr:** AUTHENTICATION at HIGH or CRITICAL (secp256k1 or hash160) in any slot, and always in slot 0. ENCRYPTION at MEDIUM (secp256k1) in slots 1 and up; the key ring (format 2) also allows DECRYPTION. A raw bundle (format 1) holds exactly one sign-in key.
- **govhub:** one AUTHENTICATION key at HIGH or CRITICAL.
- **Forge:** slot 0 is AUTHENTICATION at HIGH (secp256k1 or hash160). Slots 1 and up hold further HIGH authentication keys (per-contract wallet grants) and at most one ENCRYPTION key at MEDIUM. Never MASTER, CRITICAL or TRANSFER. With 2 + 6 × 39 = 236 bytes, the 240-byte format holds the main key, four grants and the encryption key. Every Forge entry is 256 bytes sealed, whatever it holds.

`src/passkey-vault/__fixtures__/profiles.ts` defines the three profiles as the vectors pin them. An app copies its own profile into its code. If any id, length, maxKeys or label changes, every stored entry is orphaned.

## 3. Test vectors (`src/passkey-vault/__vectors__/`)

| File | Source | Checked |
|---|---|---|
| (in `hpke.test.ts`) | RFC 9180 A.2.1 | key pairs, ciphertext, and refusals |
| `yappr.json` | Copied from Yappr `lib/crypto/passkey-vault.test.ts` (RAW from Yappr's independent prototype, RING from the prototype's HPKE) | PRF input, recipient, info, AAD, bundle, `enc`, and sealed bytes, byte for byte |
| `govhub.json` | govhub `test/vault.test.ts` and its snapshot (`enc`, first 16 sealed bytes, tag) | the snapshot, plus the full bytes written by the generator and checked against that snapshot |
| `forge.json` | Written by `generate.py` | every field of three vectors: main key only; full (6 keys); and hash160 main key, 255-byte credential id and key id above 2^31 |

`generate.py` is an independent implementation in Python. Its HKDF is built on `hmac`, and its X25519 and ChaCha20-Poly1305 come from `cryptography`. It shares no code with the TypeScript module. It checks RFC 9180 A.2, reproduces Yappr's two vectors and govhub's snapshot, then writes `forge.json`. `python3 generate.py --check` (also run by `entry.test.ts` when `cryptography` is installed) fails if the JSON is stale.

## 4. API outline

- `defineProfile`, `slotKeysCodec`, `seedCodec`, `votingKeysCodec`: build a profile.
- `prfInput`, `recipientFromPrf`, `hpkeInfo`, `entryAad`, `sealEntry`, `openEntry`: the pure crypto.
- `userHandleFor(identity, contract)` and `parseUserHandle(handle, contract)`:
  - `parseUserHandle` throws `PasskeyError` with code `not-vault` when the handle is absent or is not 64 bytes, for example a local-only passkey with a random 32-byte id;
  - it throws `other-vault` when the handle names another vault contract.
- `PasskeyAdapter`, `browserPasskeyAdapter({ timeoutMs, mapError })` and `prfSupport()`: WebAuthn.
  - The adapter creates resident, user-verified passkeys with the PRF evaluated.
  - A backstop aborts any ceremony that outlives its timeout by 5 s, so the prompt closes.
  - `signalUnknown` calls `PublicKeyCredential.signalUnknownCredential` where it exists.
- `VaultPort` and `OnChainKey`: Platform as the app binds it. The port reads with proofs, binds the contract and the signer, and serialises writes per identity.
- `matchKey(sk, key)` and `checkSlots(keys, onChain, { now, expiryMarginMs, accept })`: the shared parts of the chain check. A slot is dropped when its key is missing, has the wrong shape, is disabled, has expired, has a budget known to be spent, does not match, or fails the app's rule.
- `PasskeyVault<S, B, R>`: the service.
  - `enroll(session, { userName })`: the create ceremony. Returns a `PendingEnrolment`.
  - `confirm(target)`: a get ceremony limited to one credential.
    - The handle must name this identity and this vault.
    - The get-time PRF output must equal the create-time one, when there was one.
    - For an existing entry, the passkey must give that entry's `recipientKey`.
    - Returns a `ConfirmedPasskey`.
  - `store(session, confirmed)`: seals the session and writes the entry. Only a `ConfirmedPasskey` minted by this instance is accepted. If an entry already exists for this credential but is sealed to another recipient key, this passkey can never open it. `store` seals the new entry first, then deletes the old one and creates the new one, so nothing is written when sealing or the passkey cap refuses.
  - `trustMarker({ ownerId, credentialId, recipientKey })`: mints a `TrustedRecipient` from the app's own local record of a passkey this device made. It is accepted by `reseal` only, never by `store`.
  - `waitForEntry(ownerId, credentialId, recipientKey, { reads, intervalMs })`: a failed read is retried, except the last one, whose error propagates.
  - `open({ allow?, keepPrfOutput? })`: a discoverable get, the entry lookup, `openEntry`, then the app's `verify(bundle, keys, ctx)`. The bundle is wiped as soon as `verify` returns, so `verify` must return copies.
  - `reseal(entry, session, { trustedRecipient })`: `trustedRecipient` is a `TrustedRecipient` minted by this instance for that identity and credential, from `confirm` or `trustMarker`. Raw bytes are not accepted. The entry, re-read with proofs, must still carry that key.
  - Options: `codecFor(session)` picks another of the profile's formats per session (govhub seals a seed or a single key). `authKeyIdOf(session)` supplies the entry key id for a codec that has none. `now` and `sleep` are for tests.
  - `list`, `remove(entry, { thisDevice })`, `abandon(pending)`.

Errors:

- `VaultCryptoError` codes: `input`, `version`, `format`, `wrong-passkey`, `decrypt`, `bundle`.
- `PasskeyError` codes: `unsupported`, `no-prf`, `cancelled`, `timeout`, `exists` (an `excludeCredentials` hit), `failed`, `not-vault`, `other-vault`.
- `VaultError` codes: `too-many`, `no-entry`, `other-identity`, `unknown-identity`, `untrusted-recipient`, `mismatch`, `not-visible`, `refused`. The vault never throws `refused` itself: the code is for the app's `verify` to throw, and whatever `verify` throws propagates unchanged.

The messages are for logs. Apps write their own copy.

## 5. Threat notes

- **No sender authentication.** Anyone can seal to a public recipient key, and anyone who once held a live key of the owner can write or overwrite an entry. An opened bundle proves nothing on its own. The app's `verify` must check every key against the identity read fresh with proofs (`checkSlots` plus the app's bounds, group and budget rules). A dropped slot 0 must refuse the sign-in.
- **Planted entries and re-sealing.** Sealing new keys to an attacker's recipient key would hand them over. So the vault seals only to:
  - a recipient key derived in this tab from a passkey's PRF output (`confirm`), or
  - one the app vouches for from its own local record (`trustMarker`, for `reseal` only).

  A recipient key read from the chain is never trusted. If an entry for the user's credential is sealed to another key, this passkey can never open it, so `store` deletes it and creates a new one.
- **The user handle is checked against the identity.** All of one vault's passkeys share the PRF input, so the handle is what ties a passkey to an identity. A confirmation whose handle names another identity or another vault is refused, and so is a confirmation without a handle.
- **Old ciphertexts stay public.** Every sealed entry remains readable in state-transition history forever. Removing an entry does not lock out someone who holds the passkey. To lock them out, rotate the keys that were inside, including any encryption key.
- **Metadata on chain.** The chain shows:
  - the owner, the number of passkeys and `$createdAt`/`$updatedAt`;
  - `authKeyId`;
  - the credential id's length, which can hint at the provider.

  Fixed padding (strict profiles) hides which keys an entry holds and how many.
- **Wiping is best effort.** The module overwrites PRF outputs, derived secret keys, plaintexts and bundles once they have served their purpose. Copies made by libraries and the engine are out of reach.
- **XSS** can seal keys to an attacker without a prompt. An injected script could already read the unlocked keys, so this adds no new exposure. The defence is the CSP, plus `frame-ancestors`: a framing page can grant `publickey-credentials-get`.
- **RP ID.** Use the app's own host, never a parent domain shared by other apps. Every subdomain of a shared parent could ask for the same PRF output.
