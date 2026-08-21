// dsh-guardwall · 体检流水线（统一入口）
// vet(spec) → { manifest, files, permissions, staticScan, score, verdict }
// verdict.gate = 'allow' | 'warn' | 'deny'（按信任等级与门禁阈值）

import { resolveSpec, vetLocalDir, findInstalledPackage } from './manifest.js'
import { buildPermissionInventory, humanizePermissions } from './permissions.js'
import { fullStaticScan } from './static.js'
import { scorePackage } from './score.js'
import { readSource } from './manifest.js'
import os from 'node:os'
import path from 'node:path'

const HOME = os.homedir()
const SEARCH_ROOTS = [path.join(HOME, '.dsh', 'profiles', 'web'), path.join(HOME, '.dsh', 'profiles', 'headless')]

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

  if (loc.kind === 'local') {
    dir = loc.value
    localResult = await vetLocalDir(dir)
    manifest = localResult.manifest
    files = localResult.files
    patch = localResult.patch
  } else if (loc.kind === 'npm') {
    dir = await findInstalledPackage(loc.value, SEARCH_ROOTS)
    if (dir) {
      localResult = await vetLocalDir(dir)
      manifest = localResult.manifest
      files = localResult.files
      patch = localResult.patch
    } else {
      // npm 远程元数据（不下载源码，权限扫描降级为仅 manifest）
      const { execFile } = await import('node:child_process')
      const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
      const stdout = await new Promise((resolve, reject) => {
        execFile(npm, ['view', loc.value, '--json'], { timeout: 30000, windowsHide: true }, (err, out) => (err ? reject(err) : resolve(out)))
      })
      const pkg = JSON.parse(stdout)
      manifest = { name: pkg.name, version: pkg.version, description: pkg.description, license: pkg.license, repository: pkg.repository?.url, dsh: pkg.dsh || null, dependencies: pkg.dependencies || {}, installScripts: { preinstall: pkg.scripts?.preinstall, install: pkg.scripts?.install, postinstall: pkg.scripts?.postinstall }, depCount: Object.keys(pkg.dependencies || {}).length }
      dir = null
      files = []
    }
  } else if (loc.kind === 'github') {
    // github 引用：尝试 clone 太重，MVP 走 gh api 元数据
    const { execFile } = await import('node:child_process')
    const gh = process.platform === 'win32' ? 'gh.exe' : 'gh'
    const stdout = await new Promise((resolve, reject) => {
      execFile(gh, ['api', `repos/${loc.value}`, '--jq', '{name:.name,description:.description,stars:.stargazers_count,license:.license.spdx_id,default_branch:.default_branch,homepage:.homepage}'], { timeout: 20000, windowsHide: true }, (err, out) => (err ? reject(err) : resolve(out)))
    })
    const meta = JSON.parse(stdout)
    manifest = { name: meta.name, version: 'github', description: meta.description, license: meta.license, repository: `github.com/${loc.value}`, dsh: null, dependencies: {}, installScripts: {}, depCount: 0 }
    files = []
  }

  // 读源码
  let sources = []
  if (dir) {
    if (localResult?.skill) {
      // skill 类插件：SKILL.md 本身就是"可执行提示词"，作为源码扫描
      sources = [{ rel: localResult.skill.path, source: localResult.skill.content }]
    } else {
      for (const rel of files) {
        if (!/\.(js|cjs|mjs|ts|mts|cts)$/.test(rel)) continue
        const source = await readSource(dir, rel)
        if (source) sources.push({ rel, source })
      }
    }
  }

  const permissions = buildPermissionInventory(sources)
  const staticScan = await fullStaticScan({ manifest, files, sources })
  const score = await scorePackage({ manifest, files, permissions, staticScan, dir, repoHint })

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
    sourceFiles: files.length,
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
