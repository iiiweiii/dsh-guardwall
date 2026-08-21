// dsh-guardwall · 权限清单提取
// 静态分析插件源码，回答用户最关心的问题：
//   "装这个插件 = 给了它哪些权限？"
//   - 文件访问：读/写哪些路径（~/.ssh、.env、凭据、临时目录、项目内）
//   - 命令执行：exec/spawn 跑什么命令
//   - 网络访问：fetch/http 连哪些域名
// 说明：静态字符串提取，无法覆盖动态拼接（这是运行时 guard 的职责）。

const FS_OPS = [
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile',
  'appendFileSync', 'readdir', 'readdirSync', 'unlink', 'unlinkSync', 'rm',
  'rmSync', 'mkdir', 'mkdirSync', 'copyFile', 'copyFileSync', 'stat', 'existsSync',
]
const SHELL_OPS = ['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync', 'run_shell', 'run_code']
const NET_OPS = ['fetch(', 'axios', 'got(', 'http.get', 'http.request', 'https.get', 'https.request', 'WebSocket(', 'net.connect', 'tls.connect', 'request(']

// 敏感路径分类
const SENSITIVE_PATHS = [
  { re: /\.ssh[\\/]|id_rsa|id_ed25519|\.gnupg/, kind: 'ssh', sev: 9, label: 'SSH 私钥目录' },
  { re: /\.aws[\\/]|credentials\.(?:json|ini|yaml)|\.kube[\\/]/, kind: 'cloud', sev: 9, label: '云平台凭据' },
  { re: /\.env(?:\b|$)|\.npmrc|\.netrc|keyring|wallet/, kind: 'secret', sev: 8, label: '密钥/令牌文件' },
  { re: /(?:DEEPSEEK|OPENAI|ANTHROPIC|GITHUB|SLACK|TELEGRAM)[_A-Z]*(?:KEY|TOKEN|SECRET)/, kind: 'env', sev: 8, label: '环境变量密钥读取' },
  { re: /etc[\\/]passwd|etc[\\/]shadow|boot[\\/]/, kind: 'system', sev: 9, label: '系统关键文件' },
  { re: /(?:tmp|temp)[\\/]/, kind: 'tmp', sev: 1, label: '临时目录' },
]

/** 从一行源码提取字符串字面量（'' "" ``） */
function literals(line) {
  const out = []
  const re = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g
  let m
  while ((m = re.exec(line)) !== null) out.push(m[2])
  return out
}

/** 提取文件访问条目 */
export function extractFileAccess(source, rel) {
  const hits = []
  const lines = source.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const op = FS_OPS.find((o) => line.includes(o + '(') || line.includes(o + 'Sync('))
    if (!op) continue
    const lits = literals(line)
    if (!lits.length) continue
    const match = lits.find((l) => /[\\/.]/.test(l) && l.length > 3)
    if (!match) continue
    const sens = SENSITIVE_PATHS.find((s) => s.re.test(match))
    hits.push({
      op, path: match.slice(0, 120),
      kind: sens?.kind || 'generic',
      severity: sens?.sev || 2,
      label: sens?.label || '常规路径',
      file: rel, line: i + 1,
    })
  }
  return hits
}

/** 提取命令执行条目 */
export function extractCommands(source, rel) {
  const hits = []
  const lines = source.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const op = SHELL_OPS.find((o) => line.includes(o + '('))
    if (!op) continue
    const lits = literals(line)
    const cmd = lits.find((l) => /[a-z]/.test(l) && l.length > 2)
    if (!cmd) continue
    let severity = 3
    let label = '命令执行'
    if (/rm|del|format|mkfs|dd\b|shutdown/i.test(cmd)) { severity = 8; label = '破坏性命令' }
    else if (/curl|wget|nc\b|ncat|ssh|scp|\/dev\/tcp/i.test(cmd)) { severity = 6; label = '网络命令' }
    else if (/chmod|chown|sudo|su\b|useradd/i.test(cmd)) { severity = 6; label = '权限操作' }
    hits.push({ op, command: cmd.slice(0, 120), label, severity, file: rel, line: i + 1 })
  }
  return hits
}

/** 提取网络访问条目 */
export function extractNetwork(source, rel) {
  const hits = []
  const lines = source.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const op = NET_OPS.find((o) => line.includes(o))
    if (!op) continue
    const lits = literals(line)
    const url = lits.find((l) => /^https?:\/\//i.test(l) || /^wss?:\/\//i.test(l) || /\.(com|io|org|net|dev|cn|ai)\b/.test(l))
    if (!url) continue
    let host = url
    try { host = new URL(url.startsWith('http') ? url : 'http://' + url).host } catch { /* 保留原文 */ }
    let severity = 3
    let label = '网络请求'
    if (/169\.254\.169\.254|metadata\.|169\.254|100\.100\.100|10\.0\.0\.1/.test(url)) { severity = 9; label = 'SSRF 目标/元数据' }
    else if (/telemetry|track|analytics|report|beacon/i.test(url)) { severity = 4; label = '遥测上报' }
    hits.push({ op: op.replace('(', ''), host: host.slice(0, 120), label, severity, file: rel, line: i + 1 })
  }
  return hits
}

/**
 * 汇总权限清单。
 * @param {Array<{rel:string, source:string|null}>} sources
 */
export function buildPermissionInventory(sources) {
  const files = []
  const commands = []
  const network = []
  for (const s of sources) {
    if (!s.source) continue
    files.push(...extractFileAccess(s.source, s.rel))
    commands.push(...extractCommands(s.source, s.rel))
    network.push(...extractNetwork(s.source, s.rel))
  }
  // 去重（同路径/命令/域名只留最高严重度）
  const dedupe = (arr, key) => {
    const m = new Map()
    for (const x of arr) {
      const k = key(x)
      const prev = m.get(k)
      if (!prev || x.severity > prev.severity) m.set(k, x)
    }
    return [...m.values()].sort((a, b) => b.severity - a.severity)
  }
  return {
    files: dedupe(files, (x) => x.kind + '|' + x.path),
    commands: dedupe(commands, (x) => x.command),
    network: dedupe(network, (x) => x.host),
    maxSeverity: Math.max(0, ...[...files, ...commands, ...network].map((x) => x.severity)),
  }
}

/** 人类可读的权限摘要（面向用户的"装它 = 给了什么"） */
export function humanizePermissions(inv) {
  const lines = []
  if (inv.files.length) {
    lines.push('文件访问：' + [...new Set(inv.files.map((f) => f.label))].join('、'))
    const crit = inv.files.filter((f) => f.severity >= 8)
    if (crit.length) lines.push(`  高危路径：${[...new Set(crit.map((f) => f.path))].slice(0, 5).join('、')}`)
  }
  if (inv.commands.length) {
    lines.push('命令执行：' + [...new Set(inv.commands.map((c) => c.label))].join('、'))
    const crit = inv.commands.filter((c) => c.severity >= 6)
    if (crit.length) lines.push(`  示例：${[...new Set(crit.map((c) => c.command))].slice(0, 3).join('；')}`)
  }
  if (inv.network.length) {
    lines.push('网络访问：' + inv.network.slice(0, 5).map((n) => n.host).join('、') + (inv.network.length > 5 ? ` 等 ${inv.network.length} 个` : ''))
    const crit = inv.network.filter((n) => n.severity >= 8)
    if (crit.length) lines.push(`  高危目标：${crit.map((n) => n.host).join('、')}`)
  }
  if (!lines.length) lines.push('未发现明显权限诉求（可能为纯 UI/工具型插件）')
  return lines.join('\n')
}
