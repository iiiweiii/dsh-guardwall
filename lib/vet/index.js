// dsh-guardwall · 体检流水线（统一入口）
// vet(spec) → { manifest, files, permissions, staticScan, score, verdict }
// verdict.gate = 'allow' | 'warn' | 'deny'（按信任等级与门禁阈值）

import { resolveSpec, vetLocalDir, findInstalledPackage } from './manifest.js'
import { buildPermissionInventory, humanizePermissions } from './permissions.js'
import { fullStaticScan } from './static.js'
import { scorePackage } from './score.js'
import { readSource } from './manifest.js'
import { runNpm } from './npm.js'
import { promises as fs } from 'node:fs'
import { execFile } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'

const HOME = os.homedir()
const SEARCH_ROOTS = [path.join(HOME, '.dsh', 'profiles', 'web'), path.join(HOME, '.dsh', 'profiles', 'headless')]

function runFile(command, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, {
      timeout: opts.timeout ?? 120000,
      windowsHide: true,
      maxBuffer: 5 * 1024 * 1024,
      cwd: opts.cwd,
    }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`${command} failed: ${(stderr || err.message).trim()}`))
      resolve(stdout)
    })
  })
}

function npmPackageName(spec) {
  const value = String(spec)
  if (value.startsWith('@')) {
    const slash = value.indexOf('/')
    const versionAt = value.indexOf('@', slash)
    return versionAt === -1 ? value : value.slice(0, versionAt)
  }
  const versionAt = value.indexOf('@')
  return versionAt === -1 ? value : value.slice(0, versionAt)
}

function isBareNpmName(spec) {
  return npmPackageName(spec) === spec
}

async function materializeNpm(spec) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'guardwall-npm-'))
  try {
    await runNpm([
      'install', '--ignore-scripts', '--no-audit', '--no-fund',
      '--package-lock=true', '--prefix', root, '--', spec,
    ])
    const name = npmPackageName(spec)
    const dir = path.join(root, 'node_modules', ...(name.startsWith('@') ? name.split('/') : [name]))
    const stat = await fs.stat(dir)
    if (!stat.isDirectory()) throw new Error(`npm package not materialized: ${name}`)
    return { root, dir, auditDir: root }
  } catch (e) {
    await fs.rm(root, { recursive: true, force: true })
    throw e
  }
}

async function materializeGithub(loc) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(loc.value)) throw new Error('invalid GitHub repository')
  if (loc.ref !== 'HEAD' && (!/^[\w./-]+$/.test(loc.ref) || loc.ref.includes('..'))) {
    throw new Error('invalid GitHub ref')
  }
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'guardwall-git-'))
  try {
    const git = 'git'
    const noHooks = process.platform === 'win32' ? 'NUL' : '/dev/null'
    const common = ['-c', `core.hooksPath=${noHooks}`, '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.required=false']
    await runFile(git, [...common, 'clone', '--depth', '1', '--no-checkout', `https://github.com/${loc.value}.git`, root])
    if (loc.ref !== 'HEAD') {
      await runFile(git, [...common, '-C', root, 'fetch', '--depth', '1', 'origin', loc.ref])
      await runFile(git, [...common, '-C', root, 'checkout', '--detach', 'FETCH_HEAD'])
    } else {
      await runFile(git, [...common, '-C', root, 'checkout', '--detach', 'HEAD'])
    }
    return { root, dir: root }
  } catch (e) {
    await fs.rm(root, { recursive: true, force: true })
    throw e
  }
}

/**
 * 对包做安装前体检。
 * @param {string} spec 本地路径 / npm 包名 / github:owner/repo
 * @param {object} opts { denyGrade: 'D', includeSources: true, timeout }
 */
export async function vet(spec, opts = {}) {
  const { denyGrade = 'D', repoHint } = opts
  const loc = resolveSpec(spec)

  let dir = null
  let manifest = null
  let files = []
  let patch = null
  let localResult = null
  let cleanupRoot = null
  let auditDir = null

  try {
  if (loc.kind === 'local') {
    dir = loc.value
    localResult = await vetLocalDir(dir)
    manifest = localResult.manifest
    files = localResult.files
    patch = localResult.patch
  } else if (loc.kind === 'npm') {
    const packageName = npmPackageName(loc.value)
    dir = isBareNpmName(loc.value) ? await findInstalledPackage(packageName, SEARCH_ROOTS) : null
    if (dir) {
      localResult = await vetLocalDir(dir)
      manifest = localResult.manifest
      files = localResult.files
      patch = localResult.patch
    } else {
      // Download the exact install artifact without running lifecycle scripts.
      const materialized = await materializeNpm(loc.value)
      cleanupRoot = materialized.root
      auditDir = materialized.auditDir
      dir = materialized.dir
      localResult = await vetLocalDir(dir)
      manifest = localResult.manifest
      files = localResult.files
      patch = localResult.patch
    }
  } else if (loc.kind === 'github') {
    // Scan the exact checked-out repository rather than trusting metadata.
    const materialized = await materializeGithub(loc)
    cleanupRoot = materialized.root
    dir = materialized.dir
    localResult = await vetLocalDir(dir)
    manifest = localResult.manifest
    manifest.repository ||= `github.com/${loc.value}`
    files = localResult.files
    patch = localResult.patch
  }

  // 读源码
  let sources = []
  if (dir) {
    if (localResult?.skill) {
      // skill 类插件：SKILL.md 本身就是"可执行提示词"，作为源码扫描
      sources = [{ rel: localResult.skill.path, source: localResult.skill.content }]
    } else {
      for (const rel of localResult?.sourceFiles || files) {
        if (!/\.(js|cjs|mjs|ts|mts|cts)$/.test(rel)) continue
        const source = await readSource(dir, rel)
        if (source) sources.push({ rel, source })
      }
    }
  }

  const permissions = buildPermissionInventory(sources)
  const staticScan = await fullStaticScan({ manifest, files, sources, auditDir })
  const score = await scorePackage({ manifest, files, permissions, staticScan, dir, repoHint: repoHint || (loc.kind === 'github' ? loc.value : undefined) })

  // 门禁判定
  const gradeOrder = ['A', 'B', 'C', 'D']
  const denyIdx = gradeOrder.indexOf(denyGrade) // D → 3
  const gradeIdx = gradeOrder.indexOf(score.grade)
  const gate = gradeIdx >= denyIdx ? 'deny' : score.grade === 'C' ? 'warn' : 'allow'

  return {
    spec,
    location: loc,
    manifest: {
      name: manifest.name, version: manifest.version, license: manifest.license,
      depCount: manifest.depCount, installScripts: manifest.installScripts,
      dsh: manifest.dsh, author: manifest.author, repository: manifest.repository,
    },
    sourceFiles: sources.length,
    patch,
    permissions: {
      ...permissions,
      human: humanizePermissions(permissions),
    },
    staticScan: {
      findings: staticScan.findings.slice(0, 30),
      findingCount: staticScan.findings.length,
      maxSeverity: staticScan.maxSeverity,
      audit: staticScan.audit,
    },
    score,
    gate,
  }
  } finally {
    if (cleanupRoot) await fs.rm(cleanupRoot, { recursive: true, force: true }).catch(() => {})
  }
}

/** 门禁建议文案 */
export function gateMessage(v) {
  const g = v.score.grade
  if (v.gate === 'deny') {
    return `信任等级 ${g}（${v.score.score}/100）低于门禁阈值，建议拒绝安装。` +
      `如需强制安装请用户显式确认（--force）。\n高风险点：` +
      (v.permissions.maxSeverity >= 8 ? '权限诉求过大；' : '') +
      (v.staticScan.maxSeverity >= 8 ? '静态扫描发现高危模式；' : '') +
      (v.staticScan.audit?.critical ? `npm audit ${v.staticScan.audit.critical} 个 critical 漏洞。` : '')
  }
  if (v.gate === 'warn') {
    return `信任等级 ${g}（${v.score.score}/100），可安装但建议人工复核权限清单。`
  }
  return `信任等级 ${g}（${v.score.score}/100），可以安装。`
}
