#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { name, version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const entries = {
  '': 'PlatformAuthController',
  '/app-connect': 'verifyAppConnectCandidate',
  '/passkey-vault': 'PasskeyVault',
}

const work = mkdtempSync(join(tmpdir(), 'platform-auth-pack-'))
try {
  execFileSync('npm', ['pack', '--pack-destination', work], { cwd: root, stdio: 'inherit' })
  const filename = `${name.replace(/^@/, '').replace('/', '-')}-${version}.tgz`
  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'pack-smoke', private: true }))
  execFileSync('npm', ['install', '--no-audit', '--no-fund', join(work, filename), 'react@18', 'react-dom@18'], {
    cwd: work,
    stdio: 'inherit',
  })

  const checks = Object.entries(entries).flatMap(([subpath, symbol]) => {
    const specifier = JSON.stringify(name + subpath)
    const expect = `if (typeof m.${symbol} !== 'function') throw new Error(${JSON.stringify(`${name}${subpath} is missing ${symbol}`)})`
    return [
      ['--input-type=module', '-e', `const m = await import(${specifier}); ${expect}`],
      ['--input-type=commonjs', '-e', `const m = require(${specifier}); ${expect}`],
    ]
  })
  for (const args of checks) execFileSync(process.execPath, args, { cwd: work, stdio: 'inherit' })
  console.log(`${filename}: ${checks.length} import checks passed on Node ${process.version}`)
} finally {
  rmSync(work, { recursive: true, force: true })
}
