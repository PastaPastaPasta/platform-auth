# platform-auth

`platform-auth` is a reusable authentication toolkit for Dash Platform applications.

The project is intended for app developers who want a consistent, configurable auth stack for Platform-based web apps without hard-coding auth flow logic into each individual product.

## Scope

`platform-auth` focuses on orchestration, session state, and integration boundaries.

It is designed to help applications compose and reuse:

- identity-based sign-in
- password-unlock flows
- passkey-unlock flows
- wallet or login-key based sign-in flows
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

## Integration Model

Applications integrate `platform-auth` by providing adapters for their own environment.

Typical adapters include:

- session persistence
- secret storage
- identity and DPNS lookups
- profile existence checks
- passkey operations
- auth-vault reads and writes
- app-specific post-login tasks

The package returns state, methods, and high-level intents. The host app decides how those intents map to routes, dialogs, or other UI.

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

The project currently provides the reusable controller, React bindings, and adapter contracts needed to move application auth flows behind a shared package boundary.

Implementation notes from the initial extraction work are kept in [`docs/`](./docs), including app-specific migration and review material.

## Development

```bash
npm install
npm run lint
npm run build
```
