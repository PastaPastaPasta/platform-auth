# Vendoring platform-auth modules

Some apps cannot take `@pastapastapasta/platform-auth` as a dependency (static builds, a registry they cannot reach, a module they want to review in-tree). For those, `tools/vendor.mjs` copies one or more `src/<module>/` directories into the app's repo and records exactly what it copied. The copy belongs to the app and may be edited. Upstream stays canonical, and the tool tells you how far the two have drifted.

Node only, no dependencies. Run it from a platform-auth checkout.

## Vendor a module

```
node tools/vendor.mjs <targetDir> --modules app-connect[,other] [--from <ref>|WORKTREE] [--keep-local|--force] [--dry-run]
```

- Files land in `<targetDir>/<module>/...`, mirroring `src/<module>/...`. Tests, `vectors.json` and `test-helpers.ts` come along, so the app runs upstream's tests.
- `--from` is a git ref (default `HEAD`); the files are read from that commit with `git ls-tree` and `git show`. `WORKTREE` copies the files on disk instead and records `"dirty": true`; use it only for trying out unmerged changes.
- Imports are checked, never rewritten. A relative import must stay inside the module or point at another module in the same `--modules` list. Anything else fails the sync and nothing is written. Bare imports are recorded as `externals`, and the tool warns if one is missing from the nearest `package.json` above `<targetDir>`. Imports in `*.test.*` files (for example `vitest`) are not counted as externals.
- `<targetDir>/VENDORED.json` records, per module, the upstream commit, the ref, whether it was dirty, the externals and a `sha256-<hex>` for every file. It has sorted keys, no timestamps and a trailing newline, so syncing the same commit again changes nothing. Commit it with the vendored files.
- Modules sync independently, so one app can hold `app-connect` at one commit and another module at a later one.

Typical setup in an app's `package.json`:

```json
"vendor:status": "node ${PLATFORM_AUTH_DIR:-../platform-auth}/tools/vendor.mjs status lib/vendor/platform-auth"
```

## Check for drift

```
node tools/vendor.mjs status <targetDir> [--against <ref>] [--json]
```

For each module, every file is compared three ways: on disk, in the manifest, and upstream at `--against` (default `HEAD`).

| Local state | Meaning |
|---|---|
| `clean` | matches the manifest |
| `modified` | edited since the sync |
| `deleted` | in the manifest, missing on disk |
| `added` | on disk, not in the manifest |

| Upstream state | Meaning |
|---|---|
| `unchanged` | same as the manifest |
| `upstream-changed` | upstream has newer content |
| `upstream-added` | new upstream file |
| `upstream-removed` | upstream deleted it |

A file that is both `modified` and `upstream-changed` is flagged `both-changed`; those are the ones to merge by hand. The report also says how many upstream commits touched the module since the recorded one (`git rev-list --count <commit>..<ref> -- src/<module>`). If the recorded commit is not in the checkout it says to fetch upstream.

`status` exits 0 whatever it finds. It exits non-zero only for a malformed manifest or a git failure.

## Pull in upstream changes

Run the sync again with a newer `--from`.

- If any file differs from the manifest, a plain sync refuses, lists the files and writes nothing.
- `--keep-local` updates every clean file, leaves edited files alone and records the new upstream hashes, so your edits keep showing as `modified` against the new commit.
- `--force` overwrites local edits.
- A file deleted upstream is removed if clean, and kept and reported if edited.
- `--dry-run` prints the plan and writes nothing.

## Divergence policy

Divergence is allowed. If an app needs a local fix or a different shape, it edits its copy and carries on. The expectations are:

- Say why in the commit that makes the edit, and prefer sending the change upstream when it is generally useful.
- Before relying on a protocol detail, run `status` and look at the `modified` and `both-changed` files; a copy with local edits no longer guarantees upstream's test vectors still hold.
- Never hand-edit `VENDORED.json`. Let the tool write it.
- Nothing fails a build because of drift. Wire `status` into a script or a periodic reminder if you want to be told.
