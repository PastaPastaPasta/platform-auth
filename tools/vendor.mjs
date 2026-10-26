#!/usr/bin/env node
// Copies platform-auth modules (src/<module>/) into an app's repo and keeps a
// VENDORED.json manifest next to them, so the app can later see how far its
// copy has drifted from upstream. Node only, no dependencies.
//
//   node tools/vendor.mjs <targetDir> --modules app-connect[,other] [--from <ref>|WORKTREE]
//                         [--keep-local | --force] [--dry-run]
//   node tools/vendor.mjs status <targetDir> [--against <ref>|WORKTREE] [--json]
//
// The app owns its copy and may edit it; divergence is reported, never an error.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { builtinModules } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const MANIFEST_NAME = 'VENDORED.json'
const MANIFEST_NOTE = 'Owned by this repo, free to diverge. Run platform-auth tools/vendor.mjs status <dir>.'
const WORKTREE = 'WORKTREE'
const MODULE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const SOURCE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/
const TEST_FILE = /\.(?:test|spec)\.[^/]+$/
const BUILTINS = new Set(builtinModules)

const USAGE = `Usage:
  node tools/vendor.mjs <targetDir> --modules <a[,b]> [--from <ref>|WORKTREE] [--keep-local|--force] [--dry-run]
  node tools/vendor.mjs status <targetDir> [--against <ref>|WORKTREE] [--json]

  --modules     comma-separated module names under src/ (required when syncing)
  --from        git ref to copy from (default HEAD); WORKTREE copies the files on disk and records dirty: true
  --keep-local  update clean files, leave locally edited files alone, still record the new upstream hashes
  --force       overwrite locally edited files
  --dry-run     print what would change and write nothing
  --against     ref to compare with when running status (default HEAD)
  --json        status as JSON
  --repo <dir>  platform-auth checkout to read (default: the checkout this script lives in)
`

class UserError extends Error {
  constructor(message, exitCode = 1) {
    super(message)
    this.exitCode = exitCode
  }
}

// ---------------------------------------------------------------- arguments

function parseArgs(argv) {
  const valueFlags = new Set(['modules', 'from', 'against', 'repo'])
  const boolFlags = new Set(['keep-local', 'force', 'dry-run', 'json', 'help'])
  const positional = []
  const flags = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (!arg.startsWith('--')) {
      positional.push(arg)
      continue
    }
    const eq = arg.indexOf('=')
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq)
    if (boolFlags.has(name) && eq === -1) {
      flags[name] = true
    } else if (valueFlags.has(name)) {
      const value = eq === -1 ? argv[++i] : arg.slice(eq + 1)
      if (value === undefined || value === '') throw new UserError(`--${name} needs a value`, 2)
      flags[name] = value
    } else {
      throw new UserError(`unknown option ${arg}\n\n${USAGE}`, 2)
    }
  }
  return { positional, flags }
}

function rejectFlags(flags, names, mode) {
  for (const name of names) {
    if (flags[name] !== undefined) throw new UserError(`--${name} does not apply to ${mode}`, 2)
  }
}

// --------------------------------------------------------------------- git

function git(repo, args, { buffer = false, optional = false } = {}) {
  try {
    return execFileSync('git', ['-C', repo, ...args], {
      encoding: buffer ? 'buffer' : 'utf8',
      maxBuffer: 512 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch (error) {
    if (optional) return null
    const detail = String(error.stderr ?? error.message).trim()
    throw new UserError(`git ${args.join(' ')} failed: ${detail}`)
  }
}

/** A readable source: a commit in the checkout, or the files on disk. */
function resolveSource(repo, ref) {
  const worktree = ref === WORKTREE
  const commit = git(repo, ['rev-parse', '--verify', `${worktree ? 'HEAD' : ref}^{commit}`]).trim()
  return { kind: worktree ? 'worktree' : 'git', ref, commit }
}

/** Files of src/<module>/ as Map(relative posix path -> Buffer). */
function readUpstreamFiles(repo, source, moduleName) {
  const prefix = `src/${moduleName}/`
  const files = new Map()
  if (source.kind === 'worktree') {
    for (const rel of walkFiles(path.join(repo, 'src', moduleName))) {
      files.set(rel, fs.readFileSync(path.join(repo, 'src', moduleName, ...rel.split('/'))))
    }
    return files
  }
  const listing = git(repo, ['ls-tree', '-r', '-z', '--name-only', source.commit, '--', prefix])
  for (const entry of listing.split('\0')) {
    if (!entry.startsWith(prefix)) continue
    files.set(entry.slice(prefix.length), git(repo, ['show', `${source.commit}:${entry}`], { buffer: true }))
  }
  return new Map([...files].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
}

// ------------------------------------------------------------- filesystem

function walkFiles(root) {
  const out = []
  const visit = (dir, prefix) => {
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch (error) {
      if (error.code === 'ENOENT') return
      throw error
    }
    for (const entry of entries) {
      if (entry.name === '.DS_Store') continue
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.isDirectory()) visit(path.join(dir, entry.name), rel)
      else if (entry.isFile()) out.push(rel)
    }
  }
  visit(root, '')
  return out.sort()
}

function sha256(buffer) {
  return `sha256-${createHash('sha256').update(buffer).digest('hex')}`
}

function hashFiles(files) {
  return new Map([...files].map(([rel, content]) => [rel, sha256(content)]))
}

/** Hashes of the files currently under <target>/<module>/. */
function readDiskHashes(targetDir, moduleName) {
  const root = path.join(targetDir, moduleName)
  const hashes = new Map()
  for (const rel of walkFiles(root)) hashes.set(rel, sha256(fs.readFileSync(path.join(root, ...rel.split('/')))))
  return hashes
}

/**
 * Where `rel` lives under <target>/<module>/. Refuses a path that leaves the
 * module, and one that goes through a symlink (a write would land elsewhere).
 */
function moduleFilePath(targetDir, moduleName, rel) {
  const root = path.resolve(targetDir, moduleName)
  const full = path.resolve(root, ...rel.split('/'))
  if (full !== root && !full.startsWith(root + path.sep)) throw new UserError(`refusing to write outside ${root}: ${rel}`)
  let current = root
  for (const part of path.relative(root, full).split(path.sep)) {
    current = path.join(current, part)
    let stat
    try {
      stat = fs.lstatSync(current)
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') break
      throw error
    }
    if (stat.isSymbolicLink()) throw new UserError(`refusing to touch ${current}: it is a symlink`)
  }
  return full
}

function removeEmptyParents(root, file) {
  let dir = path.dirname(file)
  while (dir !== root && dir.startsWith(root + path.sep)) {
    try {
      fs.rmdirSync(dir)
    } catch {
      return
    }
    dir = path.dirname(dir)
  }
}

// ---------------------------------------------------------------- manifest

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeys(value[key])]))
  }
  return value
}

function toJson(value) {
  return `${JSON.stringify(sortKeys(value), null, 2)}\n`
}

function readManifest(targetDir) {
  const file = path.join(targetDir, MANIFEST_NAME)
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
  const bad = (why) => new UserError(`${file} is malformed: ${why}`)
  let manifest
  try {
    manifest = JSON.parse(text)
  } catch (error) {
    throw bad(error.message)
  }
  if (!isRecord(manifest)) throw bad('not an object')
  if (manifest.schema !== 1) throw bad(`unsupported schema ${JSON.stringify(manifest.schema)}`)
  if (!isRecord(manifest.modules)) throw bad('"modules" is missing')
  // Null-prototype maps, so a file or module named like an Object.prototype member cannot alias it.
  manifest.modules = Object.assign(Object.create(null), manifest.modules)
  for (const [name, entry] of Object.entries(manifest.modules)) {
    if (!isRecord(entry) || !/^[0-9a-f]{40,64}$/.test(entry.commit)) throw bad(`module ${name} has no valid commit`)
    if (!isRecord(entry.files)) throw bad(`module ${name} has no files`)
    for (const [rel, hash] of Object.entries(entry.files)) {
      if (typeof hash !== 'string' || !/^sha256-[0-9a-f]{64}$/.test(hash)) throw bad(`module ${name}: bad hash for ${rel}`)
    }
    entry.files = Object.assign(Object.create(null), entry.files)
  }
  return manifest
}

function normalizeRepoUrl(url) {
  let out = url.trim().replace(/^git\+/, '')
  const scp = out.match(/^git@([^:]+):(.+)$/)
  if (scp) out = `https://${scp[1]}/${scp[2]}`
  out = out.replace(/^(?:ssh:\/\/git@|git:\/\/)/, 'https://')
  return out.replace(/\/$/, '').replace(/\.git$/, '')
}

function upstreamInfo(repo) {
  let pkg
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'))
  } catch (error) {
    throw new UserError(`cannot read ${path.join(repo, 'package.json')}: ${error.message}`)
  }
  const url = typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url
  if (!url) throw new UserError('package.json has no repository.url')
  return { repo: normalizeRepoUrl(url), package: pkg.name }
}

// ----------------------------------------------------------- import check

/**
 * Removes comments but keeps string and template literals intact (they hold the
 * specifiers), skipping over them so a `//` or `/*` inside a string is not
 * mistaken for a comment. A regex literal containing a quote can derail this
 * for the rest of its line; that is accepted.
 */
function stripComments(source) {
  let out = ''
  let i = 0
  while (i < source.length) {
    const ch = source[i]
    const next = source[i + 1]
    if (ch === '/' && next === '/') {
      while (i < source.length && source[i] !== '\n') i++
    } else if (ch === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2)
      i = end === -1 ? source.length : end + 2
      out += ' '
    } else if (ch === "'" || ch === '"' || ch === '`') {
      let j = i + 1
      while (j < source.length && source[j] !== ch && !(ch !== '`' && source[j] === '\n')) j += source[j] === '\\' ? 2 : 1
      out += source.slice(i, j + 1)
      i = j + 1
    } else {
      out += ch
      i++
    }
  }
  return out
}

const IMPORT_PATTERNS = [
  /(?:^|[\n;])\s*(?:import|export)\s[^'"`;]*?\bfrom\s*['"]([^'"\n]+)['"]/g,
  /(?:^|[\n;])\s*import\s*['"]([^'"\n]+)['"]/g,
  /\bimport\s*\(\s*['"`]([^'"`\n$]+)['"`]\s*\)/g,
  /\brequire\s*\(\s*['"]([^'"\n]+)['"]\s*\)/g,
  // Test-runner module mocks name modules too.
  /\b(?:vi|jest)\.(?:mock|doMock|importActual|importMock)\s*\(\s*['"]([^'"\n]+)['"]/g,
]

function importSpecifiers(source) {
  const text = stripComments(source)
  const found = new Set()
  for (const pattern of IMPORT_PATTERNS) {
    for (const match of text.matchAll(pattern)) found.add(match[1])
  }
  return [...found]
}

/** `node:` and bare builtins, URL-like specifiers, and `#` subpath imports are not packages to install. */
function isBuiltinOrUrl(specifier) {
  return BUILTINS.has(specifier) || /^[a-z][a-z0-9+.-]*:/i.test(specifier) || specifier.startsWith('#')
}

function packageName(specifier) {
  const parts = specifier.split('/')
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
}

/**
 * Checks every import in the module's files. Relative imports must stay inside
 * the vendored module set. Bare imports are collected (test files excluded, they
 * only ever need the test runner).
 */
function checkImports(moduleName, files, moduleSet) {
  const errors = []
  const externals = new Set()
  const testExternals = new Set()
  for (const [rel, content] of files) {
    if (!SOURCE_FILE.test(rel)) continue
    const from = `src/${moduleName}/${rel}`
    for (const specifier of importSpecifiers(content.toString('utf8'))) {
      if (specifier.startsWith('.')) {
        const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier))
        const parts = resolved.split('/')
        if (parts[0] === 'src' && moduleSet.has(parts[1])) continue
        errors.push(
          `${from}: import '${specifier}' resolves to ${resolved}, outside the vendored modules (${[...moduleSet].join(', ')})`,
        )
      } else if (!isBuiltinOrUrl(specifier)) {
        (TEST_FILE.test(rel) ? testExternals : externals).add(packageName(specifier))
      }
    }
  }
  for (const name of externals) testExternals.delete(name)
  return { errors, externals: [...externals].sort(), testExternals: [...testExternals].sort() }
}

function nearestPackageJson(startDir) {
  let dir = path.resolve(startDir)
  for (;;) {
    const candidate = path.join(dir, 'package.json')
    if (fs.existsSync(candidate)) return candidate
    const parent = path.dirname(dir)
    if (parent === dir) return null
    dir = parent
  }
}

function missingDependencies(targetDir, names) {
  if (names.length === 0) return { file: null, missing: [] }
  const file = nearestPackageJson(targetDir)
  if (!file) return { file: null, missing: names }
  let pkg
  try {
    pkg = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (error) {
    throw new UserError(`cannot read ${file}: ${error.message}`)
  }
  const declared = new Set(
    ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'].flatMap((key) => Object.keys(pkg[key] ?? {})),
  )
  return { file, missing: names.filter((name) => !declared.has(name)) }
}

// -------------------------------------------------------------------- sync

/** Decides, per file, what a sync does. Pure: no writes. */
function planModule({ upstreamHashes, manifestFiles, diskHashes, mode }) {
  const write = []
  const remove = []
  const unchanged = []
  const conflicts = []
  const rels = new Set([...upstreamHashes.keys(), ...Object.keys(manifestFiles)])
  for (const rel of [...rels].sort()) {
    const wanted = upstreamHashes.get(rel)
    const recorded = manifestFiles[rel]
    const onDisk = diskHashes.get(rel)
    if (wanted !== undefined) {
      if (onDisk === undefined) {
        if (recorded !== undefined) conflicts.push({ rel, why: 'deleted locally' })
        else write.push(rel)
      } else if (onDisk === wanted) {
        unchanged.push(rel)
      } else if (recorded !== undefined && onDisk === recorded) {
        write.push(rel)
      } else {
        conflicts.push({ rel, why: recorded !== undefined ? 'edited locally' : 'exists locally with different content' })
      }
    } else if (onDisk !== undefined) {
      if (onDisk === recorded) remove.push(rel)
      else conflicts.push({ rel, why: 'edited locally and removed upstream' })
    }
  }
  const kept = []
  if (mode === 'force') {
    for (const { rel } of conflicts) (upstreamHashes.has(rel) ? write : remove).push(rel)
  } else if (mode === 'keep-local') {
    for (const { rel } of conflicts) kept.push(rel)
  }
  return { write: write.sort(), remove: remove.sort(), unchanged, conflicts, kept }
}

function runSync(positional, flags, repo) {
  rejectFlags(flags, ['against', 'json'], 'a sync')
  if (positional.length !== 1) throw new UserError(`expected one target directory\n\n${USAGE}`, 2)
  if (!flags.modules) throw new UserError('--modules is required', 2)
  if (flags['keep-local'] && flags.force) throw new UserError('--keep-local and --force are mutually exclusive', 2)

  const targetDir = path.resolve(positional[0])
  const names = [...new Set(flags.modules.split(',').map((name) => name.trim()).filter(Boolean))].sort()
  if (names.length === 0) throw new UserError('--modules is empty', 2)
  for (const name of names) {
    if (!MODULE_NAME.test(name)) throw new UserError(`invalid module name "${name}"`, 2)
  }
  const moduleSet = new Set(names)
  const mode = flags.force ? 'force' : flags['keep-local'] ? 'keep-local' : 'plain'
  const dryRun = Boolean(flags['dry-run'])
  const source = resolveSource(repo, flags.from ?? 'HEAD')
  const manifest = readManifest(targetDir)
  const info = upstreamInfo(repo)

  const errors = []
  const modules = []
  for (const name of names) {
    const upstream = readUpstreamFiles(repo, source, name)
    if (upstream.size === 0) {
      errors.push(`module "${name}" has no files under src/${name}/ at ${source.ref}`)
      continue
    }
    const checked = checkImports(name, upstream, moduleSet)
    errors.push(...checked.errors)
    const upstreamHashes = hashFiles(upstream)
    const manifestFiles = manifest?.modules[name]?.files ?? Object.create(null)
    const plan = planModule({ upstreamHashes, manifestFiles, diskHashes: readDiskHashes(targetDir, name), mode })
    modules.push({ name, upstream, upstreamHashes, checked, plan })
  }
  if (errors.length > 0) throw new UserError(`import check failed, nothing was written:\n  ${errors.join('\n  ')}`)

  const refused = modules.flatMap((m) => m.plan.conflicts.map((c) => `${m.name}/${c.rel} (${c.why})`))
  if (mode === 'plain' && refused.length > 0) {
    throw new UserError(
      `refusing to overwrite local changes, nothing was written:\n  ${refused.join('\n  ')}\n`
      + 'Re-run with --keep-local to keep these edits and still advance the recorded commit, or --force to overwrite them.',
    )
  }

  // Everything that can fail is checked before the first write, so a failed sync leaves the target alone.
  const warnings = []
  const lines = []
  const tag = dryRun ? '[dry-run] ' : ''
  if (source.kind === 'worktree') warnings.push('syncing from WORKTREE: the manifest will record dirty: true and a commit that does not contain these files')
  for (const { name, plan } of modules) {
    for (const rel of [...plan.remove, ...plan.write]) moduleFilePath(targetDir, name, rel)
  }

  for (const { name, checked, plan } of modules) {
    const { file, missing } = missingDependencies(targetDir, checked.externals)
    if (file === null && missing.length > 0) {
      warnings.push(`${name}: no package.json above ${targetDir}; cannot confirm ${missing.join(', ')} is installed`)
    } else if (missing.length > 0) {
      warnings.push(`${name}: ${missing.join(', ')} not listed in ${file}`)
    }
    lines.push(
      `${tag}${name} @ ${source.commit.slice(0, 12)} (${source.ref}${source.kind === 'worktree' ? ', dirty' : ''}): `
      + `${plan.write.length} written, ${plan.unchanged.length} unchanged, ${plan.remove.length} removed, ${plan.kept.length} kept local`,
      `  externals: ${checked.externals.join(', ') || '(none)'}`,
    )
    if (checked.testExternals.length > 0) lines.push(`  test-only imports (not in externals): ${checked.testExternals.join(', ')}`)
    for (const rel of plan.kept) lines.push(`  kept local edit: ${name}/${rel}`)
    if (mode === 'force') {
      for (const { rel, why } of plan.conflicts) lines.push(`  overwrote (${why}): ${name}/${rel}`)
    }
  }

  if (!dryRun) {
    // Removals first: a case-only rename (Foo.ts to foo.ts) is the same file on a case-insensitive disk,
    // and a file turning into a directory (or back) needs the old entry gone before the new one is written.
    for (const { name, plan } of modules) {
      const root = path.resolve(targetDir, name)
      for (const rel of plan.remove) {
        const full = moduleFilePath(targetDir, name, rel)
        fs.rmSync(full, { force: true })
        removeEmptyParents(root, full)
      }
    }
    for (const { name, upstream, plan } of modules) {
      for (const rel of plan.write) {
        const full = moduleFilePath(targetDir, name, rel)
        fs.mkdirSync(path.dirname(full), { recursive: true })
        fs.writeFileSync(full, upstream.get(rel))
      }
    }
    const next = {
      schema: 1,
      upstream: info,
      note: MANIFEST_NOTE,
      modules: { ...(manifest?.modules ?? {}) },
    }
    for (const { name, upstreamHashes, checked } of modules) {
      next.modules[name] = {
        commit: source.commit,
        ref: source.ref,
        dirty: source.kind === 'worktree',
        externals: checked.externals,
        files: Object.fromEntries(upstreamHashes),
      }
    }
    fs.mkdirSync(targetDir, { recursive: true })
    fs.writeFileSync(path.join(targetDir, MANIFEST_NAME), toJson(next))
  }
  for (const warning of warnings) process.stderr.write(`warning: ${warning}\n`)
  process.stdout.write(`${lines.join('\n')}\n`)
}

// ------------------------------------------------------------------ status

function statusForModule({ repo, targetDir, name, entry, against }) {
  const upstream = readUpstreamFiles(repo, against, name)
  const upstreamHashes = hashFiles(upstream)
  const diskHashes = readDiskHashes(targetDir, name)
  const recorded = entry.files

  const files = {}
  const counts = { clean: 0, modified: 0, deleted: 0, added: 0, unchanged: 0, 'upstream-changed': 0, 'upstream-added': 0, 'upstream-removed': 0, 'both-changed': 0 }
  const rels = new Set([...Object.keys(recorded), ...diskHashes.keys(), ...upstreamHashes.keys()])
  for (const rel of [...rels].sort()) {
    const isRecorded = rel in recorded
    const onDisk = diskHashes.get(rel)
    const local = !isRecorded ? (onDisk === undefined ? null : 'added') : onDisk === undefined ? 'deleted' : onDisk === recorded[rel] ? 'clean' : 'modified'
    const wanted = upstreamHashes.get(rel)
    const remote = isRecorded
      ? wanted === undefined ? 'upstream-removed' : wanted === recorded[rel] ? 'unchanged' : 'upstream-changed'
      : wanted === undefined ? null : 'upstream-added'
    if (local === null && remote === null) continue
    const bothChanged = local === 'modified' && remote === 'upstream-changed'
    files[rel] = { local: local ?? 'absent', upstream: remote ?? 'unchanged', bothChanged }
    if (local) counts[local]++
    if (remote) counts[remote]++
    if (bothChanged) counts['both-changed']++
  }

  const commitKnown = git(repo, ['cat-file', '-e', `${entry.commit}^{commit}`], { optional: true }) !== null
  let ahead = null
  if (commitKnown) {
    ahead = Number(git(repo, ['rev-list', '--count', `${entry.commit}..${against.commit}`, '--', `src/${name}`]).trim())
  }
  return {
    commit: entry.commit,
    ref: entry.ref ?? null,
    dirty: entry.dirty === true,
    externals: entry.externals ?? [],
    commitKnown,
    ahead,
    counts,
    files,
  }
}

function runStatus(positional, flags, repo) {
  rejectFlags(flags, ['modules', 'from', 'keep-local', 'force', 'dry-run'], 'status')
  if (positional.length !== 1) throw new UserError(`expected one target directory\n\n${USAGE}`, 2)
  const targetDir = path.resolve(positional[0])
  const manifest = readManifest(targetDir)
  if (!manifest) throw new UserError(`${path.join(targetDir, MANIFEST_NAME)} not found; nothing has been vendored here`)

  const against = resolveSource(repo, flags.against ?? 'HEAD')
  const report = {
    target: targetDir,
    upstream: manifest.upstream ?? null,
    against: { ref: against.ref, commit: against.commit },
    modules: {},
  }
  for (const name of Object.keys(manifest.modules).sort()) {
    report.modules[name] = statusForModule({ repo, targetDir, name, entry: manifest.modules[name], against })
  }

  if (flags.json) {
    process.stdout.write(toJson(report))
    return
  }
  const out = [targetDir, `against ${against.ref} (${against.commit.slice(0, 12)})`]
  for (const [name, mod] of Object.entries(report.modules)) {
    out.push('', `${name}: vendored at ${mod.commit.slice(0, 12)}${mod.ref ? ` (${mod.ref})` : ''}${mod.dirty ? ', from a dirty worktree' : ''}`)
    if (!mod.commitKnown) out.push(`  commit ${mod.commit.slice(0, 12)} is not in this checkout (fetch upstream to count commits)`)
    else out.push(`  ${mod.ahead} upstream ${mod.ahead === 1 ? 'commit' : 'commits'} ahead`)
    const c = mod.counts
    out.push(
      `  local: ${c.clean} clean, ${c.modified} modified, ${c.deleted} deleted, ${c.added} added`,
      `  upstream: ${c.unchanged} unchanged, ${c['upstream-changed']} changed, ${c['upstream-added']} added, ${c['upstream-removed']} removed`,
    )
    if (c['both-changed'] > 0) out.push(`  ${c['both-changed']} changed on both sides (both-changed)`)
    for (const [rel, file] of Object.entries(mod.files)) {
      if (file.local === 'clean' && file.upstream === 'unchanged') continue
      out.push(`  ${file.local.padEnd(9)} ${file.upstream.padEnd(16)} ${name}/${rel}${file.bothChanged ? '  both-changed' : ''}`)
    }
  }
  process.stdout.write(`${out.join('\n')}\n`)
}

// -------------------------------------------------------------------- main

function main(argv) {
  const { positional, flags } = parseArgs(argv)
  if (flags.help) {
    process.stdout.write(USAGE)
    return
  }
  const repo = path.resolve(flags.repo ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..'))
  if (positional[0] === 'status') runStatus(positional.slice(1), flags, repo)
  else runSync(positional, flags, repo)
}

try {
  main(process.argv.slice(2))
} catch (error) {
  if (error instanceof UserError) {
    process.stderr.write(`error: ${error.message}\n`)
    process.exit(error.exitCode)
  }
  throw error
}
