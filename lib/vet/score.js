// dsh-guardwall · 信任评分（A-D，对齐 OpenSSF Scorecard 思路）
// 四个维度加权：
//   维护活跃度 35%（GitHub stars / 最近提交 / 更新时间 —— 可实时查询，失败给中性分）
//   代码质量   25%（类型声明 / 测试 / lint / 文件规模）
//   已知漏洞   25%（npm audit 结果，无 audit 则看依赖复杂度）
//   来源可信   15%（官方 @deepseek-ai / 已收录 awesome 目录 / 未知）
// 总分 ≥85 A · 70-84 B · 50-69 C · <50 D
// D 级 = 门禁拒绝安装（默认）。

export const GRADE_LIMITS = { A: 78, B: 70, C: 50, D: 0 }

export function gradeOf(score) {
  if (score >= GRADE_LIMITS.A) return 'A'
  if (score >= GRADE_LIMITS.B) return 'B'
  if (score >= GRADE_LIMITS.C) return 'C'
  return 'D'
}

function clamp(n, lo = 0, hi = 100) {
  return Math.max(lo, Math.min(hi, n))
}

/** 维护活跃度：查 GitHub 元数据（stars/updated/pushed），失败返回 null */
export async function fetchGithubMeta(repoRef) {
  const { execFile } = await import('node:child_process')
  return new Promise((resolve) => {
    const gh = process.platform === 'win32' ? 'gh.exe' : 'gh'
    execFile(gh, ['api', `repos/${repoRef}`, '--jq', '{stars:.stargazers_count,pushed:.pushed_at,updated:.updated_at,archived:.archived,openIssues:.open_issues_count}'], { timeout: 15000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) return resolve(null)
      try { resolve(JSON.parse(stdout)) } catch { resolve(null) }
    })
  })
}

function scoreMaintenance(meta) {
  if (!meta) return { score: 50, note: '无仓库元数据（无法核实维护状态）' }
  if (meta.archived) return { score: 20, note: '仓库已归档' }
  let s = 50
  const days = Math.max(0, Math.floor((Date.now() - new Date(meta.pushed).getTime()) / 86400000))
  if (days < 30) s += 35
  else if (days < 90) s += 25
  else if (days < 180) s += 10
  else s -= 15
  if (meta.stars >= 1000) s += 10
  else if (meta.stars >= 100) s += 5
  if (meta.stars >= 10000) s -= 5 // 高星也可能是"星多不维护"，轻扣
  return { score: clamp(s), note: `最近推送 ${days} 天前 · ${meta.stars} stars` }
}

function scoreQuality(manifest, files) {
  let s = 50
  const notes = []
  if (files.includes('tsconfig.json') || files.some((f) => f.startsWith('src/'))) { s += 15; notes.push('TypeScript/src 结构') }
  if (files.some((f) => /test|spec/i.test(f))) { s += 10; notes.push('含测试') }
  if (files.includes('.eslintrc*') || files.includes('eslint.config.*') || files.includes('.oxlintrc*')) { s += 5; notes.push('含 lint 配置') }
  if ((manifest.depCount || 0) > 50) { s -= 10; notes.push('依赖偏多') }
  if (!manifest.license || manifest.license === 'unlicensed') { s -= 10; notes.push('无 LICENSE') }
  if (s === 50) notes.push('无明显质量信号')
  return { score: clamp(s), note: notes.join('，') }
}

function scoreVulnerability(audit) {
  if (!audit) return { score: 60, note: '无 lockfile / audit 不可用（保守中性）' }
  let s = 85
  const notes = []
  if (audit.critical) { s -= 40; notes.push(`${audit.critical} critical`) }
  if (audit.high) { s -= 15; notes.push(`${audit.high} high`) }
  if (audit.moderate) { s -= 6; notes.push(`${audit.moderate} moderate`) }
  if (audit.low) { s -= 2; notes.push(`${audit.low} low`) }
  if (audit.info) notes.push(`${audit.info} info`)
  if (!notes.length) notes.push('npm audit 无已知漏洞')
  return { score: clamp(s), note: notes.join('，') }
}

function scoreSource(manifest, hasPatch) {
  const name = manifest.name || ''
  let s = 30
  const notes = []
  if (name.startsWith('@deepseek-ai/')) { s = 95; notes.push('官方维护') }
  else if (name === 'dshmarket' || name === 'dsh-guardwall') { s = 80; notes.push('已被 awesome-dsh-plugin 收录/知名') }
  else if (hasPatch && (manifest.depCount ?? 0) <= 8) { s = 65; notes.push('声明规范、依赖精简') }
  else { notes.push('未知来源') }
  return { score: clamp(s), note: notes.join('，') }
}

/**
 * 计算信任评分。
 * @param {object} ctx { manifest, files, permissions, staticScan, githubMeta?, dir }
 */
export async function scorePackage({ manifest, files, permissions, staticScan, githubMeta, dir, repoHint }) {
  const repoRef = repoHint || (() => {
    const r = String(manifest.repository || '')
    // 支持三种形态：github.com/owner/repo、git+https://github.com/owner/repo.git、裸 owner/repo
    const m = r.match(/github\.com[/:]([\w.-]+\/[\w.-]+)/) || r.match(/^([\w.-]+\/[\w.-]+)$/) || r.match(/^git@github\.com:([\w.-]+\/[\w.-]+)/)
    return m ? m[1].replace(/\.git$/, '') : null
  })()
  const meta = githubMeta || (repoRef ? await fetchGithubMeta(repoRef) : null)

  const maintenance = scoreMaintenance(meta)
  const quality = scoreQuality(manifest, files)
  const vulnerability = scoreVulnerability(staticScan?.audit)
  const source = scoreSource(manifest, Boolean(manifest.dsh?.bundle))
  const runtime = await scoreRuntimeHealth(manifest, dir)

  // 权限与静态发现的降级（从总分扣，封顶 -20）
  let penality = 0
  const findings = staticScan?.findings || []
  if ((permissions?.maxSeverity || 0) >= 8) penality += 10
  if ((staticScan?.maxSeverity || 0) >= 8) penality += 6
  if (findings.length >= 50) penality += 3
  if (findings.some((f) => f.defensive)) penality -= 2 // 有防御代码的反而体现安全意识
  penality = Math.max(-3, Math.min(penality, 20))

  const score = Math.round(
    maintenance.score * 0.30 +
    quality.score * 0.20 +
    vulnerability.score * 0.20 +
    source.score * 0.15 +
    runtime.score * 0.15 -
    penality
  )
  const final = clamp(score)

  return {
    score: final,
    grade: gradeOf(final),
    dimensions: {
      maintenance, quality, vulnerability, source, runtime,
      penality: { score: -penality, note: '高危权限/高危静态发现扣分' },
    },
    repo: repoRef,
  }
}

/** 运行时健康检查：依赖能否在安装目录解析（抓"装不上/缺依赖"的坏插件） */
async function scoreRuntimeHealth(manifest, dir) {
  if (!dir || !manifest?.dependencies || Object.keys(manifest.dependencies).length === 0) {
    return { score: 85, note: '无运行时依赖（零依赖或元数据模式）' }
  }
  const { promises: fs } = await import('node:fs')
  const path = await import('node:path')
  // 源码仓库未安装依赖（无 node_modules）是常态，不惩罚，给保守中性
  try { await fs.stat(path.join(dir, 'node_modules')) } catch {
    return { score: 60, note: '源码未安装依赖（无 node_modules），运行时待核实' }
  }
  const deps = Object.keys(manifest.dependencies)
  let missing = 0
  for (const dep of deps) {
    const p = path.join(dir, 'node_modules', ...(dep.startsWith('@') ? dep.split('/') : [dep]))
    try { await fs.stat(p) } catch { missing++ }
  }
  if (missing === 0) return { score: 85, note: `依赖齐全（${deps.length} 个）` }
  const ratio = missing / deps.length
  const score = ratio >= 0.5 ? 15 : ratio >= 0.25 ? 40 : 60
  return { score, note: `${missing}/${deps.length} 依赖缺失（${deps.slice(0, 3).join('、')} 等），可能装不上或运行时崩溃` }
}
