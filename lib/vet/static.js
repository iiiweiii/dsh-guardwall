// dsh-guardwall · 静态风险扫描
// 两层：
//   1. 源码危险模式（eval、动态导入、密钥读取、SSRF、无约束写、混淆）
//   2. 依赖树（直接依赖 + 安装脚本 + 已知高危包名表）
// npm audit 为可选增强（见 runNpmAudit），失败不阻塞。

const DANGEROUS_PATTERNS = [
  { id: 'DYN-001', sev: 9, re: /\beval\s*\(|new\s+Function\s*\(|Function\s*\(\s*['"`]/, title: '动态代码执行 eval/new Function' },
  { id: 'DYN-002', sev: 8, re: /require\s*\(\s*['"`][^'"`]*['"`]\s*\)\s*\.exec|import\s*\(\s*['"`](?!node:)/, title: '动态 require/import（依赖运行时可变量）' },
  { id: 'SECRET-001', sev: 8, re: /process\.env\.[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z_]*/, title: '读取环境变量密钥' },
  // SSRF：仅当行内有访问动词才算高危；纯字符串数据引用（备份/配置列表）降为提示
  { id: 'SSRF-001', sev: 9, re: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.tencentyun\.com/, title: 'SSRF：云元数据端点', requireVerb: /fetch\s*\(|axios|\.get\s*\(|\.post\s*\(|http\.request|https\.request|request\s*\(|WebSocket|net\.connect|tls\.connect|new\s+URL\s*\(|XMLHttpRequest/i, defensive: /block|deny|reject|forbid|prevent|guard|protect|exclude|allowlist|disallow|isSsrf|ssrf|sanitize|filter|vet/i },
  // 递归删除：仅当路径无明确落点（根/家目录/变量）时高危；明确路径（tmp/目录名）为常规清理
  { id: 'FS-001', sev: 9, re: /rm(?:Sync)?\s*\(|rmdir\s*\(/, title: '递归删除', requirePath: /recursive\s*:\s*true|rmdir/i, dangerousPath: /['"`]\s*[\/~\\]?\s*['"`]\s*[,)]|process\.cwd|os\.homedir|__dirname\s*[+)]|path\.join\s*\(\s*['"`]\/['"`]|['"`]\s*\/\s*['"`]\s*(?:,|\))|['"`]\s*~\s*['"`]/, defensive: /(?:tmp|temp|cache|build|dist|\.git|old|backup|stale)[\\/]?['"`]\s*[,)]/i },
  { id: 'FS-002', sev: 7, re: /writeFile(?:Sync)?\s*\(\s*['"`](?![~\/A-Za-z]:\\)/, title: '写入相对/未知路径' },
  { id: 'EXEC-001', sev: 7, re: /exec(?:Sync)?\s*\(\s*(?!['"`])|spawn(?:Sync)?\s*\(\s*(?!['"`])/, title: '非字面量命令执行（参数动态拼接）' },
  { id: 'NET-001', sev: 7, re: /fetch\s*\(\s*(?!['"`])|axios\.(?:get|post)\s*\(\s*(?!['`])/, title: '动态网络请求（URL 运行时拼接）' },
  { id: 'OBF-001', sev: 8, re: /(?:atob|Buffer\.from|String\.fromCharCode)\s*\([\s\S]{0,200}(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){8,}/i, title: '疑似混淆/编码载荷' },
  { id: 'NET-002', sev: 4, re: /https?:\/\/[^\s'"]*\/\s*(?:telemetry|track|analytics|beacon|report|collect)/i, title: '遥测/数据上报端点' },
  { id: 'PRIV-001', sev: 5, re: /chmod\s+777|chown\s+-R|sudo\s+su/, title: '高危权限变更' },
]

/** 已知风险依赖名（常见供应链风险包，持续扩充） */
const RISKY_DEP_PATTERNS = [
  { re: /^event-stream$/, note: '历史上发生过供应链投毒（flatmap-stream 事件）' },
  { re: /^ua-parser-js$/, note: '历史投毒事件' },
  { re: /^coa$|^rc$/, note: '历史投毒事件' },
]

/** 提示注入检测（SKILL.md / 提示词类内容专用，社区调研指出的审计盲区） */
export const PROMPT_INJECTION_PATTERNS = [
  { id: 'INJ-001', sev: 8, re: /忽略(?:以上|之前|前面)?(?:所有|全部)?(?:指令|指示|规则|设定|约束)/i, title: '提示注入：要求忽略既有指令' },
  { id: 'INJ-002', sev: 9, re: /你是系统|system\s*:?\s*(?:prompt|message)|你的真实身份|绕过(?:安全|限制|审查)/i, title: '提示注入：伪装系统/绕过限制' },
  { id: 'INJ-003', sev: 8, re: /输出(?:上面|之前)?所有(?:的)?(?:提示词|指令|system prompt)|泄露(?:提示词|指令|配置)/i, title: '提示注入：诱导泄露提示词' },
  { id: 'INJ-004', sev: 7, re: /不要(?:告诉|告知)(?:用户|人类)|隐瞒(?:行为|操作|真相)/i, title: '提示注入：要求隐瞒行为' },
  { id: 'INJ-005', sev: 6, re: /无条件(?:执行|服从)|任何情况下都|always obey|ignore all previous/i, title: '提示注入：绝对服从指令' },
]

/** 扫描 skill 内容（提示词）的注入风险 */
export function scanPromptInjection(content) {
  const hits = []
  if (!content) return hits
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const p of PROMPT_INJECTION_PATTERNS) {
      if (p.re.test(line)) {
        hits.push({ id: p.id, severity: p.sev, title: p.title, file: 'SKILL.md', line: i + 1, sample: line.trim().slice(0, 100) })
      }
    }
  }
  return hits
}

/** 扫描源码内容，返回命中列表（按规则聚合，最多保留 3 个文件样本） */
export function scanSource(source, rel) {
  const raw = []
  if (!source) return raw
  const lines = source.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const p of DANGEROUS_PATTERNS) {
      if (p.re.test(line)) {
        // requireVerb：行内必须有访问动词才是高危；否则按数据引用降级
        if (p.requireVerb && !p.requireVerb.test(line)) continue
        // requirePath+dangerousPath：递归删除需命中无约束路径才高危；明确路径（tmp 等）降级
        if (p.requirePath && p.dangerousPath && !p.dangerousPath.test(line)) {
          if (p.defensive && p.defensive.test(line)) continue
          // 有明确路径的递归删除：常规清理，低危
          raw.push({
            id: p.id, severity: 3, title: p.title + '（明确路径，常规清理）',
            file: rel, line: i + 1, sample: line.trim().slice(0, 100), defensive: true,
          })
          continue
        }
        // 防御上下文降级：命中防御代码（block/deny/guard 等）时降为低危提示
        const isDefensive = p.defensive && p.defensive.test(line)
        raw.push({
          id: p.id, severity: isDefensive ? 2 : p.sev,
          title: p.title, file: rel, line: i + 1,
          sample: line.trim().slice(0, 100),
          defensive: isDefensive,
        })
      }
    }
  }
  // 按 (id + file) 聚合，只保留前 3 个文件位置，记录总命中数
  const byKey = new Map()
  for (const h of raw) {
    const key = `${h.id}::${h.file}`
    const prev = byKey.get(key)
    if (!prev) {
      byKey.set(key, { ...h, count: 1 })
    } else {
      prev.count++
    }
  }
  const out = []
  const fileCount = new Map()
  for (const h of [...byKey.values()].sort((a, b) => b.severity - a.severity || b.count - a.count)) {
    const n = fileCount.get(h.id) || 0
    if (n >= 3) continue
    fileCount.set(h.id, n + 1)
    out.push(h)
  }
  return out
}

/** 依赖树风险（直接依赖 + 安装脚本） */
export function scanDependencies(manifest) {
  const findings = []
  for (const [name, ver] of Object.entries(manifest.dependencies || {})) {
    for (const p of RISKY_DEP_PATTERNS) {
      if (p.re.test(name)) findings.push({ id: 'DEP-001', severity: 8, title: `风险依赖 ${name}@${ver}`, file: 'package.json', sample: p.note })
    }
  }
  for (const [key, script] of Object.entries(manifest.installScripts || {})) {
    if (script) {
      findings.push({ id: 'INST-001', severity: 6, title: `安装脚本 ${key} 存在（安装时执行任意代码）`, file: 'package.json', sample: script.slice(0, 120) })
    }
  }
  if ((manifest.depCount || 0) > 50) {
    findings.push({ id: 'DEP-002', severity: 3, title: `依赖过多（${manifest.depCount} 个直接依赖），供应链面偏大`, file: 'package.json' })
  }
  return findings
}

/** 可选：跑 npm audit（对本地目录），失败静默 */
export async function runNpmAudit(dir, { npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm' } = {}) {
  const { execFile } = await import('node:child_process')
  return new Promise((resolve) => {
    execFile(npmCmd, ['audit', '--json', '--omit=dev'], { cwd: dir, timeout: 30000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) return resolve(null)
      try {
        const data = JSON.parse(stdout)
        const meta = data.metadata?.vulnerabilities
        resolve({
          info: meta?.info || 0, low: meta?.low || 0, moderate: meta?.moderate || 0,
          high: meta?.high || 0, critical: meta?.critical || 0,
        })
      } catch { resolve(null) }
    })
  })
}

/** 汇总全部静态发现 */
export async function fullStaticScan({ manifest, files, sources }) {
  const findings = []
  for (const s of sources) {
    // skill 类：SKILL.md 同时跑提示注入检测
    if (s.rel.endsWith('.md')) {
      findings.push(...scanPromptInjection(s.source))
    }
    findings.push(...scanSource(s.source, s.rel))
  }
  findings.push(...scanDependencies(manifest))
  // 有 lockfile 才跑 audit
  const hasLock = files.includes('package-lock.json') || files.includes('pnpm-lock.yaml') || files.includes('yarn.lock')
  let audit = null
  if (hasLock && manifest.root) {
    try { audit = await runNpmAudit(manifest.root) } catch { /* 忽略 */ }
  }
  return {
    findings: findings.sort((a, b) => b.severity - a.severity),
    audit,
    maxSeverity: Math.max(0, ...findings.map((f) => f.severity), audit?.critical ? 10 : 0),
  }
}
