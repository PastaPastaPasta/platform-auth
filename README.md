# @pastapastapasta/platform-auth

`@pastapastapasta/platform-auth` is a reusable authentication toolkit for Dash Platform applications.

The project is intended for app developers who want a consistent, configurable auth stack for Platform-based web apps without hard-coding auth flow logic into each individual product.

## Scope

`@pastapastapasta/platform-auth` focuses on orchestration, session state, and integration boundaries.

It is designed to help applications compose and reuse:

- identity-based sign-in
- password-unlock flows
- passkey-unlock flows
- wallet or login-key based sign-in flows
- Yappr-compatible wallet key exchange with QR-based login and first-login key registration
- auth-vault enrollment and secret merging
- session restore and logout behavior
- username and balance refresh
- application-specific post-login hooks

## Design

The project is headless-first.

That means the core package owns auth state and flow coordination, while each application keeps control over:

- branding and UI
- routing
- storage implementation details
- Dash service adapters
- optional product-specific side effects

This keeps the auth engine reusable across multiple apps with different onboarding, navigation, and feature sets.

## Package Structure

- `PlatformAuthController`: the core auth orchestration engine
- `PlatformAuthProvider` and `usePlatformAuth`: React bindings for consuming controller state
- typed adapter interfaces: contracts for storage, identity lookup, usernames, vaults, passkeys, and side effects
- Yappr-compatible key-exchange module: protocol helpers, transport polling, registration helpers, and React hooks
- App Connect v2 module (`src/app-connect/`, also importable as `@pastapastapasta/platform-auth/app-connect`): headless wallet-login protocol core (request encoding, response encryption, candidate polling, verification, session records)
- `tools/vendor.mjs`: copies modules into an app's repo with a `VENDORED.json` manifest; see [docs/vendoring.md](docs/vendoring.md)
- `@pastapastapasta/platform-auth/passkey-vault`: an on-chain passkey vault core (HPKE + WebAuthn PRF, no SDK, no React); see [`docs/passkey-vault.md`](./docs/passkey-vault.md)

## Integration Model

Applications integrate `@pastapastapasta/platform-auth` by providing adapters for their own environment.

Typical adapters include:

- session persistence
- secret storage
- identity and DPNS lookups
- profile existence checks
- passkey operations
- auth-vault reads and writes
- key-exchange response queries and key-registration transition building
- app-specific post-login tasks

The package returns state, methods, and high-level intents. The host app decides how those intents map to routes, dialogs, or other UI.

## Yappr-Compatible Key Exchange

`@pastapastapasta/platform-auth` now ships a first-class, headless Yappr-compatible key-exchange module.

That module includes:

- `dash-key:` URI helpers
- ECDH + AES-GCM login-key decryption helpers
- polling utilities for `loginKeyResponse` documents
- `dash-st:` URI helpers for first-login key registration
- React hooks:
  - `useYapprKeyExchangeLogin(controller, options?)`
  - `useYapprKeyRegistration(controller, onComplete?, options?)`

The hooks are headless. Apps render their own QR code, timers, errors, and success states while the package keeps the protocol, timers, and state transitions consistent.

## App Connect v2

`src/app-connect/` is a headless implementation of the App Connect v2 wallet-login protocol, specified in [docs/APP_CONNECT_PROFILE.md](docs/APP_CONNECT_PROFILE.md). It depends only on `@noble/hashes` and `@noble/secp256k1`, ships its own test vectors (`vectors.json`), and is meant to be consumed either as a package import or vendored into an app with `tools/vendor.mjs`. The app supplies the transport (identity and document queries) through the port interfaces in `types.ts`; the module encodes requests, opens and verifies wallet responses, and builds session records.

## Minimum Integration

To enable the shared Yappr-compatible flow in an app:

1. Create a `PlatformAuthController` with the normal auth adapters.
2. Provide `yapprKeyExchangeConfig` with:
   - `appContractId`
   - `keyExchangeContractId`
   - `network`
   - optional label and timeout overrides
3. Provide a `yapprKeyExchange` adapter that can:
   - query a wallet response by `(contractId, appEphemeralPubKeyHash)`
   - build an unsigned key-registration transition
   - verify whether the derived keys already exist on the identity
4. Use `useYapprKeyExchangeLogin(...)` and `useYapprKeyRegistration(...)` in app-owned UI.
5. Complete login with `controller.completeYapprKeyExchangeLogin(...)` or the lower-level `controller.loginWithLoginKey(...)`.

This keeps the package reusable across apps while allowing each app to keep its own styling, routing, and SDK/service wiring.

## Goals

- make Platform auth reusable across applications
- preserve app behavior while removing auth orchestration from app code
- keep flows individually configurable and disableable
- support multiple storage and contract strategies
- avoid coupling the package to a single app’s UI

## Non-Goals

- shipping a single branded login modal for all apps
- forcing one routing model or onboarding sequence
- bundling app-specific product logic into the core controller

## Current Status

The project currently provides the reusable controller, React bindings, adapter contracts, and a Yappr-compatible key-exchange module for QR-based wallet login flows.

## Installation

```bash
npm install @pastapastapasta/platform-auth
```

The package ships ESM and CommonJS builds with type declarations for both. Under Node.js it needs 20.19+ or 22.12+, because its `@noble/*` dependencies are ESM-only and the CommonJS build relies on `require()` of ES modules; bundlers have no such limit. The root entry point includes the React bindings and needs `react` 18 or 19. The `./app-connect` and `./passkey-vault` subpaths need neither React nor a DOM, so `react` is an optional peer dependency.

## Security Notes

Read these before you ship the package in a production app.

- **Secrets in browser storage.** `createBrowserSecretStore` keeps the auth, encryption and transfer private keys (WIFs), the login key and the auth-vault key in `localStorage` as plain text, under the `platform_auth_secure_` prefix by default. "Secure" in that prefix does not mean encrypted. Any script that runs on your origin can read them, including an XSS bug, a compromised dependency or a browser extension with page access. Serve the app with a strict Content Security Policy, and keep third-party scripts off origins that hold keys.
- **Yappr-compatible key exchange (v1).** The wallet's response is not tied to the user who scanned the code. Anyone who sees the QR code or the `dash-key:` URI (a shared screen, a stream, someone looking over a shoulder, another app registered for `dash-key:`) can answer it with their own identity. If the port returns that response, the hooks complete the login as that identity. Before you call `completeYapprKeyExchangeLogin`, show the user the identity (username or avatar) and ask them to confirm it. Prefer App Connect v2 for new integrations.
- **App Connect v2.** Anyone who sees the request can answer it too. `verifyAppConnectCandidate` proves that an answer is a valid grant, not that it came from the user. Follow the identity-confirmation rules in [docs/APP_CONNECT_PROFILE.md](docs/APP_CONNECT_PROFILE.md): with an identity hint, accept only that identity; without one, always ask the user to confirm the identity, and when several candidates verify, let the user choose. Never pick one silently.

Implementation notes from the initial extraction work are kept in [`docs/`](./docs), including app-specific migration material and an integration guide for the reusable key-exchange module.

## Releasing

Pushing a `vX.Y.Z` tag that matches `package.json` runs `.github/workflows/publish-package.yml`, which lints, tests, smoke-tests the packed tarball and publishes to npm through [trusted publishing](https://docs.npmjs.com/trusted-publishers) (no npm token in the repo; npm adds provenance). A version with a prerelease suffix (`-rc.1`) is published under the `next` dist-tag. The job runs in the `npm` environment, so publishing can be limited to approved people in the repository settings.

npm can only trust a workflow for a package that it knows about. If `npm trust github` refuses the package before it exists, publish the first version by hand from a clean checkout of the tag (`npm ci && npm publish`), then register the workflow:

```bash
npm trust github <package-name> --file publish-package.yml --repository <owner>/platform-auth --environment npm
```

## Development

```bash
npm install
npm run lint
npm run build
```
