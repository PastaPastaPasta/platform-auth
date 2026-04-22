# platform-auth

`platform-auth` is a headless, reusable authentication engine for Dash Platform applications.

It is designed around the auth flow already implemented in Yappr, but split into portable modules so another app can keep the same behavior while swapping UI, routes, storage, contracts, or optional features.

## What the package includes

- A headless `PlatformAuthController` that orchestrates:
  - session restore
  - direct auth-key login
  - password login with fallback chains
  - passkey login
  - login-key / wallet key-exchange login
  - unified auth-vault enrollment and merging
  - logout
  - username and balance refresh
- A React provider and hook for consuming controller state in application code
- Typed adapter contracts so each app can plug in its own Dash services, storage, routing, and optional side effects
- Review and migration docs based on Yappr’s current auth flow

## What the package intentionally does not include

This package does not ship a fully branded login modal.

Yappr’s current auth UI is tightly coupled to app copy, route choices, modal stores, backup prompts, and post-login product decisions. A prebuilt UI here would either be too rigid to reuse or so configurable that it would hide the real orchestration boundary.

Instead, this package provides:

- a headless controller
- React bindings
- intent and event objects for app-specific UI and routing

## Design goals

- Preserve observed behavior while moving orchestration out of app code
- Keep all major auth capabilities individually configurable or disableable
- Support multiple storage and contract strategies
- Keep app-specific UI and navigation outside the core package

## Main exports

- `PlatformAuthController`
- `PlatformAuthProvider`
- `usePlatformAuth`
- all core types and adapter interfaces

## Development

```bash
npm install
npm run lint
npm run build
```
