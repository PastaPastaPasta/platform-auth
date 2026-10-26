import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { after, describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'

const TOOL = path.join(path.dirname(fileURLToPath(import.meta.url)), 'vendor.mjs')
const roots = []

after(() => {
  for (const root of roots) fs.rmSync(root, { recursive: true, force: true })
})

// Throwaway fixture repos must not pick up the developer's git config (signing, hooks, injected GIT_CONFIG_*).
function cleanEnv() {
  const env = { ...process.env }
  for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key]
  return { ...env, GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_NOSYSTEM: '1' }
}

function git(cwd, ...args) {
  const result = spawnSync('git', ['-c', 'user.name=Test', '-c', 'user.email=test@example.com', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    env: cleanEnv(),
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, `git ${args.join(' ')}: ${result.stderr}`)
  return result.stdout.trim()
}

function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, text)
}

function sha(text) {
  return `sha256-${createHash('sha256').update(text).digest('hex')}`
}

/** An upstream repo with modules a and b (b imports a), plus an app directory to vendor into. */
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vendor-test-'))
  roots.push(root)
  const repo = path.join(root, 'upstream')
  const app = path.join(root, 'app')
  const target = path.join(app, 'vendor')
  git(root, 'init', '-q', '-b', 'main', repo)
  write(path.join(repo, 'package.json'), JSON.stringify({ name: '@x/pkg', repository: { url: 'git+https://github.com/o/pkg.git' } }))
  write(path.join(repo, 'src/a/x.ts'), 'export const x = 1\n')
  write(path.join(repo, 'src/b/y.ts'), "import { x } from '../a/x'\nimport { sha256 } from '@noble/hashes/sha2.js'\nimport { readFileSync } from 'node:fs'\nexport const y = [x, sha256, readFileSync]\n")
  write(path.join(repo, 'src/b/y.test.ts'), "import { it } from 'vitest'\nimport { y } from './y'\nit('y', () => y)\n")
  git(repo, 'add', '.')
  git(repo, 'commit', '-q', '-m', 'initial')
  write(path.join(app, 'package.json'), JSON.stringify({ dependencies: { '@noble/hashes': '^2.0.0' } }))

  const run = (...args) => {
    const result = spawnSync(process.execPath, [TOOL, ...args], { cwd: root, encoding: 'utf8' })
    return { status: result.status, out: result.stdout, err: result.stderr }
  }
  const sync = (...args) => run(target, '--repo', repo, ...args)
  const status = (...args) => run('status', target, '--repo', repo, ...args)
  const manifest = () => JSON.parse(fs.readFileSync(path.join(target, 'VENDORED.json'), 'utf8'))
  const manifestText = () => fs.readFileSync(path.join(target, 'VENDORED.json'), 'utf8')
  const commitUpstream = (file, text, message = 'change') => {
    write(path.join(repo, file), text)
    git(repo, 'add', file)
    git(repo, 'commit', '-q', '-m', message)
    return git(repo, 'rev-parse', 'HEAD')
  }
  return { root, repo, app, target, run, sync, status, manifest, manifestText, commitUpstream, head: () => git(repo, 'rev-parse', 'HEAD') }
}

describe('tools/vendor.mjs', () => {
  it('syncs files, per-file sha256 hashes and the manifest', () => {
    const f = fixture()
    const result = f.sync('--modules', 'a')
    assert.equal(result.status, 0, result.err)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/x.ts'), 'utf8'), 'export const x = 1\n')
    const manifest = f.manifest()
    assert.equal(manifest.schema, 1)
    assert.deepEqual(manifest.upstream, { repo: 'https://github.com/o/pkg', package: '@x/pkg' })
    assert.equal(manifest.modules.a.commit, f.head())
    assert.equal(manifest.modules.a.ref, 'HEAD')
    assert.equal(manifest.modules.a.dirty, false)
    assert.deepEqual(manifest.modules.a.externals, [])
    assert.deepEqual(manifest.modules.a.files, { 'x.ts': sha('export const x = 1\n') })
    const text = f.manifestText()
    assert.ok(text.endsWith('}\n'))
    assert.equal(text, `${JSON.stringify(JSON.parse(text), null, 2)}\n`)
    assert.deepEqual(Object.keys(manifest), [...Object.keys(manifest)].sort())
    assert.doesNotMatch(text, /20\d\d-\d\d-\d\d/, 'no timestamps')
  })

  it('fails on an import that escapes the module, passes with the whole set, and records externals', () => {
    const f = fixture()
    const alone = f.sync('--modules', 'b')
    assert.notEqual(alone.status, 0)
    assert.match(alone.err, /src\/b\/y\.ts: import '\.\.\/a\/x'/)
    assert.equal(fs.existsSync(f.target), false, 'a failed check writes nothing')

    const both = f.sync('--modules', 'a,b')
    assert.equal(both.status, 0, both.err)
    // node: builtins and imports from test files are not externals.
    assert.deepEqual(f.manifest().modules.b.externals, ['@noble/hashes'])
    assert.deepEqual(Object.keys(f.manifest().modules.b.files), ['y.test.ts', 'y.ts'])
    assert.doesNotMatch(both.err, /not listed/, '@noble/hashes is in the app package.json')
  })

  it('warns when an external is missing from the nearest package.json', () => {
    const f = fixture()
    write(path.join(f.app, 'package.json'), JSON.stringify({ dependencies: {} }))
    const result = f.sync('--modules', 'a,b')
    assert.equal(result.status, 0, result.err)
    assert.match(result.err, /warning: b: @noble\/hashes not listed in .*package\.json/)
  })

  it('status reports a local edit as modified and exits 0', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    write(path.join(f.target, 'a/x.ts'), 'export const x = 2\n')
    write(path.join(f.target, 'a/extra.ts'), 'export {}\n')
    const result = f.status()
    assert.equal(result.status, 0, result.err)
    assert.match(result.out, /modified\s+unchanged\s+a\/x\.ts/)
    assert.match(result.out, /added\s+unchanged\s+a\/extra\.ts/)
    const json = JSON.parse(f.status('--json').out)
    assert.equal(json.modules.a.files['x.ts'].local, 'modified')
    assert.equal(json.modules.a.ahead, 0)
    fs.rmSync(path.join(f.target, 'a/x.ts'))
    assert.equal(JSON.parse(f.status('--json').out).modules.a.files['x.ts'].local, 'deleted')
  })

  it('status reports upstream changes and how many commits ahead', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    f.commitUpstream('src/a/x.ts', 'export const x = 3\n')
    f.commitUpstream('src/b/y.ts', '// not module a\n')
    f.commitUpstream('src/a/new.ts', 'export {}\n')
    const result = f.status()
    assert.equal(result.status, 0, result.err)
    assert.match(result.out, /2 upstream commits ahead/)
    assert.match(result.out, /clean\s+upstream-changed\s+a\/x\.ts/)
    assert.match(result.out, /absent\s+upstream-added\s+a\/new\.ts/)

    const single = fixture()
    single.sync('--modules', 'a')
    single.commitUpstream('src/a/x.ts', 'export const x = 3\n')
    assert.match(single.status().out, /1 upstream commit ahead/)
  })

  it('flags a file changed on both sides', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    write(path.join(f.target, 'a/x.ts'), 'export const x = 2\n')
    f.commitUpstream('src/a/x.ts', 'export const x = 3\n')
    const result = f.status()
    assert.match(result.out, /modified\s+upstream-changed\s+a\/x\.ts\s+both-changed/)
    assert.equal(JSON.parse(f.status('--json').out).modules.a.files['x.ts'].bothChanged, true)
  })

  it('says to fetch when the manifest commit is not in the checkout, still exiting 0', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    const manifest = f.manifest()
    manifest.modules.a.commit = 'deadbeef'.repeat(5)
    fs.writeFileSync(path.join(f.target, 'VENDORED.json'), `${JSON.stringify(manifest, null, 2)}\n`)
    const result = f.status()
    assert.equal(result.status, 0, result.err)
    assert.match(result.out, /not in this checkout \(fetch upstream/)
  })

  it('exits non-zero for a malformed manifest or a missing ref', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    assert.notEqual(f.status('--against', 'no-such-ref').status, 0)
    fs.writeFileSync(path.join(f.target, 'VENDORED.json'), '{ not json')
    const result = f.status()
    assert.notEqual(result.status, 0)
    assert.match(result.err, /malformed/)
    assert.notEqual(f.run('status', path.join(f.root, 'empty'), '--repo', f.repo).status, 0)
  })

  it('refuses to overwrite local edits; --keep-local keeps them and advances the commit; --force overwrites', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    const first = f.head()
    write(path.join(f.target, 'a/x.ts'), 'export const x = 2\n')
    const second = f.commitUpstream('src/a/x.ts', 'export const x = 3\n')

    const refused = f.sync('--modules', 'a')
    assert.notEqual(refused.status, 0)
    assert.match(refused.err, /a\/x\.ts \(edited locally\)/)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/x.ts'), 'utf8'), 'export const x = 2\n')
    assert.equal(f.manifest().modules.a.commit, first)

    const dry = f.sync('--modules', 'a', '--keep-local', '--dry-run')
    assert.equal(dry.status, 0, dry.err)
    assert.equal(f.manifest().modules.a.commit, first, 'dry run writes nothing')

    const kept = f.sync('--modules', 'a', '--keep-local')
    assert.equal(kept.status, 0, kept.err)
    assert.match(kept.out, /kept local edit: a\/x\.ts/)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/x.ts'), 'utf8'), 'export const x = 2\n')
    assert.equal(f.manifest().modules.a.commit, second)
    assert.equal(f.manifest().modules.a.files['x.ts'], sha('export const x = 3\n'))
    const after = JSON.parse(f.status('--json').out).modules.a
    assert.equal(after.files['x.ts'].local, 'modified', 'the edit still shows against upstream')
    assert.equal(after.files['x.ts'].upstream, 'unchanged')

    const forced = f.sync('--modules', 'a', '--force')
    assert.equal(forced.status, 0, forced.err)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/x.ts'), 'utf8'), 'export const x = 3\n')
    assert.deepEqual(JSON.parse(f.status('--json').out).modules.a.files['x.ts'], { local: 'clean', upstream: 'unchanged', bothChanged: false })
  })

  it('removes files deleted upstream when clean, keeps and reports them when edited', () => {
    const f = fixture()
    f.commitUpstream('src/a/gone.ts', 'export {}\n')
    f.commitUpstream('src/a/gone-edited.ts', 'export {}\n')
    f.sync('--modules', 'a')
    write(path.join(f.target, 'a/gone-edited.ts'), '// mine\n')
    git(f.repo, 'rm', '-q', 'src/a/gone.ts', 'src/a/gone-edited.ts')
    git(f.repo, 'commit', '-q', '-m', 'remove')

    const refused = f.sync('--modules', 'a')
    assert.notEqual(refused.status, 0)
    assert.match(refused.err, /a\/gone-edited\.ts \(edited locally and removed upstream\)/)

    const kept = f.sync('--modules', 'a', '--keep-local')
    assert.equal(kept.status, 0, kept.err)
    assert.equal(fs.existsSync(path.join(f.target, 'a/gone.ts')), false)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/gone-edited.ts'), 'utf8'), '// mine\n')
    assert.deepEqual(Object.keys(f.manifest().modules.a.files), ['x.ts'])
    assert.match(f.status().out, /added\s+unchanged\s+a\/gone-edited\.ts/)
  })

  it('leaves a byte-identical manifest when the same commit is synced again', () => {
    const f = fixture()
    f.sync('--modules', 'a,b')
    const before = f.manifestText()
    assert.equal(f.sync('--modules', 'b,a').status, 0)
    assert.equal(f.manifestText(), before)
  })

  it('keeps other modules in the manifest when syncing one', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    const aCommit = f.manifest().modules.a.commit
    f.commitUpstream('src/a/x.ts', 'export const x = 9\n')
    f.sync('--modules', 'b,a', '--from', 'HEAD~1')
    f.sync('--modules', 'a', '--force')
    assert.equal(f.manifest().modules.b.commit, aCommit)
    assert.equal(f.manifest().modules.a.commit, f.head())
  })

  it('--from WORKTREE reads files on disk and records dirty: true', () => {
    const f = fixture()
    write(path.join(f.repo, 'src/a/x.ts'), 'export const x = 42 // uncommitted\n')
    const result = f.sync('--modules', 'a', '--from', 'WORKTREE')
    assert.equal(result.status, 0, result.err)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/x.ts'), 'utf8'), 'export const x = 42 // uncommitted\n')
    const entry = f.manifest().modules.a
    assert.equal(entry.dirty, true)
    assert.equal(entry.ref, 'WORKTREE')
    assert.equal(entry.commit, f.head())
    assert.equal(entry.files['x.ts'], sha('export const x = 42 // uncommitted\n'))
    assert.match(f.status('--against', 'WORKTREE').out, /from a dirty worktree/)
  })

  it('finds imports behind trailing comments, strings that look like comments, and test mocks', () => {
    const f = fixture()
    write(path.join(f.repo, 'src/c/tricky.ts'), [
      "const glob = 'src/*'",
      'import {',
      "  one, // don't use two; or three",
      "} from '../a/x'",
      '/** doc */',
      "vi.mock('../outside/mocked', () => ({}))",
      '// import { nope } from "../not/an/import"',
      "export const note = 'see // import x from \"../in/a/string\"'",
      '',
    ].join('\n'))
    git(f.repo, 'add', 'src/c/tricky.ts')
    git(f.repo, 'commit', '-q', '-m', 'tricky')
    const result = f.sync('--modules', 'a,c')
    assert.notEqual(result.status, 0)
    assert.match(result.err, /src\/c\/tricky\.ts: import '\.\.\/outside\/mocked'/)
    assert.doesNotMatch(result.err, /not\/an\/import|in\/a\/string/)
    assert.doesNotMatch(result.err, /'\.\.\/a\/x'/, 'the multi-line import into module a is allowed')
  })

  it('never writes through a symlink, even with --force', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    const outside = path.join(f.root, 'outside.txt')
    fs.writeFileSync(outside, 'precious')
    fs.rmSync(path.join(f.target, 'a/x.ts'))
    fs.symlinkSync(outside, path.join(f.target, 'a/x.ts'))
    const result = f.sync('--modules', 'a', '--force')
    assert.notEqual(result.status, 0)
    assert.match(result.err, /symlink/)
    assert.equal(fs.readFileSync(outside, 'utf8'), 'precious')
  })

  it('handles a file turning into a directory upstream', () => {
    const f = fixture()
    f.commitUpstream('src/a/thing', 'a file\n')
    f.sync('--modules', 'a')
    git(f.repo, 'rm', '-q', 'src/a/thing')
    write(path.join(f.repo, 'src/a/thing/inner.ts'), 'export {}\n')
    git(f.repo, 'add', 'src/a/thing/inner.ts')
    git(f.repo, 'commit', '-q', '-m', 'file to dir')
    const result = f.sync('--modules', 'a')
    assert.equal(result.status, 0, result.err)
    assert.equal(fs.readFileSync(path.join(f.target, 'a/thing/inner.ts'), 'utf8'), 'export {}\n')
    assert.deepEqual(Object.keys(f.manifest().modules.a.files), ['thing/inner.ts', 'x.ts'])
  })

  it('rejects a manifest with an invalid commit or hash', () => {
    const f = fixture()
    f.sync('--modules', 'a')
    const good = f.manifest()
    for (const mutate of [
      (m) => { m.modules.a.commit = 'main' },
      (m) => { m.modules.a.files['x.ts'] = 'sha256-nope' },
      (m) => { m.schema = 2 },
    ]) {
      const bad = structuredClone(good)
      mutate(bad)
      fs.writeFileSync(path.join(f.target, 'VENDORED.json'), JSON.stringify(bad))
      const result = f.status()
      assert.notEqual(result.status, 0)
      assert.match(result.err, /malformed/)
    }
  })

  it('rejects bad usage with exit 2', () => {
    const f = fixture()
    assert.equal(f.sync().status, 2)
    assert.equal(f.sync('--modules', 'a', '--force', '--keep-local').status, 2)
    assert.equal(f.sync('--modules', '../a').status, 2)
    assert.equal(f.status('--force').status, 2)
    assert.notEqual(f.sync('--modules', 'missing').status, 0)
  })
})
