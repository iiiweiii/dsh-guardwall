// dsh-guardwall · 插件包解析（manifest + 源码清单）
// 支持三种包来源：
//   - 本地路径   （目录，读 package.json + 源码）
//   - npm 包名   （优先用已安装的 node_modules 副本；否则 npm view 元数据）
//   - github: 引用（可选，仅元数据）
// 产出：manifest 摘要（dependencies / dsh.bundle / scripts / 源码文件清单）

import { promises as fs } from 'node:fs'
import path from 'node:path'

const SRC_EXT = /\.(js|cjs|mjs|ts|tsx|mts|cts)$/

/** 从 package.json 提取权限相关摘要 */
export function summarizeManifest(pkg, root) {
  const scripts = pkg.scripts || {}
  const deps = {
    ...(pkg.dependencies || {}),
    ...(pkg.optionalDependencies || {}),
  }
  return {
    name: pkg.name,
    version: pkg.version || 'unknown',
    description: (pkg.description || '').slice(0, 200),
    type: pkg.type || 'commonjs',
    main: pkg.main || 'index.js',
    license: pkg.license || 'unlicensed',
    author: typeof pkg.author === 'string' ? pkg.author : pkg.author?.name || null,
    repository: typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url || null,
    engines: pkg.engines || {},
    dsh: pkg.dsh || null,                 // bundle.patch / client 声明
    installScripts: {
      preinstall: scripts.preinstall || null,
      install: scripts.install || null,
      postinstall: scripts.postinstall || null,
    },
    dependencies: deps,
    depCount: Object.keys(deps).length,
    root,
  }
}

/** 递归收集源码文件（最多 200 个，忽略 node_modules/.git/dist） */
export async function collectSourceFiles(root) {
  const out = []
  const seen = new Set()
  async function walk(dir, depth = 0) {
    if (depth > 8 || out.length >= 200) return
    let entries
    try { entries = await fs.readdir(dir, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      // 排除依赖/构建/测试/示例目录：测试构造样例会污染权限清单
      if (e.name === 'node_modules' || e.name === '.git' || e.name === 'dist' || e.name === '.pnpm') continue
      if (e.isDirectory() && /^(test|tests|__tests__|spec|example|examples|fixtures|benchmark)$/.test(e.name)) continue
      const full = path.join(dir, e.name)
      if (e.isDirectory()) {
        await walk(full, depth + 1)
      } else if (SRC_EXT.test(e.name) && !e.name.endsWith('.d.ts')) {
        const rel = path.relative(root, full).replace(/\\/g, '/')
        if (!seen.has(rel)) {
          seen.add(rel)
          out.push(rel)
        }
      }
    }
  }
  await walk(root)
  return out
}

/** 读取源码文件内容（单文件 ≤ 512KB，防止内存爆炸） */
export async function readSource(root, rel) {
  try {
    const full = path.join(root, rel)
    const st = await fs.stat(full)
    if (st.size > 512 * 1024) return null
    return await fs.readFile(full, 'utf8')
  } catch {
    return null
  }
}

/** 解析 cordis.patch.yml（看插件 insert 了哪些行） */
export function summarizePatch(patchYaml) {
  if (!patchYaml || typeof patchYaml !== 'string') return null
  // 极简 YAML 扫描（只提取 insert 块的 id/name/config 键，不引入 YAML 依赖）
  const rows = []
  const idRe = /^\s*-?\s*id:\s*(\S+)/gm
  const nameRe = /^\s*name:\s*(\S+)/gm
  const ids = [...patchYaml.matchAll(idRe)].map((m) => m[1])
  const names = [...patchYaml.matchAll(nameRe)].map((m) => m[1])
  const count = Math.max(ids.length, names.length)
  for (let i = 0; i < count; i++) {
    rows.push({ id: ids[i] || null, name: names[i] || null })
  }
  return { insertedRows: rows, hasConfig: /^\s*config:/m.test(patchYaml) }
}

/** 读取本地目录里的 package.json + cordis.patch.yml + 源码 */
export async function vetLocalDir(dir) {
  const pkgPath = path.join(dir, 'package.json')
  let pkg
  try {
    pkg = JSON.parse(await fs.readFile(pkgPath, 'utf8'))
  } catch {
    // 无 package.json → skill 类插件（SKILL.md 形态）降级处理
    const skill = await findSkillFile(dir)
    if (skill) {
      return {
        manifest: {
          name: path.basename(dir),
          version: 'skill',
          description: 'Skill 类插件（SKILL.md，无 npm 包结构）',
          type: 'skill',
          main: null,
          license: null,
          author: null,
          repository: null,
          engines: {},
          dsh: null,
          installScripts: {},
          dependencies: {},
          depCount: 0,
          root: dir,
        },
        files: ['SKILL.md'],
        patch: null,
        skill: { path: skill.rel, content: skill.content },
      }
    }
    throw new Error(`不是有效插件目录（缺 package.json 且无 SKILL.md）: ${dir}`)
  }
  const manifest = summarizeManifest(pkg, dir)
  const files = await collectSourceFiles(dir)
  let patch = null
  try {
    const p = pkg.dsh?.bundle?.patch
    if (p) patch = await fs.readFile(path.join(dir, p), 'utf8')
  } catch { /* 无 patch 也允许 */ }
  return { manifest, files, patch: summarizePatch(patch) }
}

/** 在目录树里找 SKILL.md（根、docs/、skills/ 等常见位置，最多 2 层） */
export async function findSkillFile(dir) {
  const candidates = []
  const walk = async (d, dep = 0) => {
    if (dep > 2) return
    let entries
    try { entries = await fs.readdir(d, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      if (e.name === '.git' || e.name === 'node_modules') continue
      const full = path.join(d, e.name)
      if (e.isDirectory()) await walk(full, dep + 1)
      else if (/^SKILL\.md$/i.test(e.name)) candidates.push(full)
    }
  }
  await walk(dir)
  if (!candidates.length) return null
  // 优先根目录的 SKILL.md
  candidates.sort((a, b) => a.split(path.sep).length - b.split(path.sep).length)
  const target = candidates[0]
  const content = await fs.readFile(target, 'utf8').catch(() => null)
  if (!content) return null
  return { rel: path.relative(dir, target).replace(/\\/g, '/'), content }
}

/** 解析用户给的 spec（本地路径 / npm 包名 / github 引用），返回定位信息 */
export function resolveSpec(spec) {
  const s = String(spec || '').trim()
  if (!s) throw new Error('缺少包参数')
  // 本地路径：存在即视为路径
  if (s.startsWith('.') || s.startsWith('/') || /^[A-Za-z]:[\\/]/.test(s) || s === '~') {
    return { kind: 'local', value: s.startsWith('~') ? path.join(process.env.HOME || '', s.slice(1)) : s }
  }
  // github:owner/repo#ref
  if (/^github:[\w.-]+\/[\w.-]+/.test(s)) {
    const m = s.match(/^github:([\w.-]+\/[\w.-]+)(?:#(.+))?$/)
    return { kind: 'github', value: m[1], ref: m[2] || 'HEAD' }
  }
  // npm 包名（含 scope）
  return { kind: 'npm', value: s }
}

/** 尝试在已安装的 profile node_modules 里定位包（本地快速路径） */
export async function findInstalledPackage(name, searchRoots = []) {
  for (const root of searchRoots) {
    const p = path.join(root, 'node_modules', ...(name.startsWith('@') ? name.split('/') : [name]))
    try {
      const st = await fs.stat(p)
      if (st.isDirectory()) return p
    } catch { /* 继续 */ }
  }
  return null
}
