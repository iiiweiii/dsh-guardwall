// dsh-guardwall · 规则引擎
// 双向扫描规则：
//   SEC-*  输入侧（工具调用参数）：注入、危险命令、凭据、SSRF、反向 shell
//   OUT-*  输出侧（工具返回内容）：密钥泄露、内部地址、数据库串、env dump
// 每条规则：id / 方向 / 风险分(1-10) / 正则（命中即触发）/ 说明
// 零依赖，正则全部为可读字面量。

/** 正则工具：大小写不敏感匹配，返回命中文本 */
function find(re, text) {
  if (typeof text !== 'string') return null
  const m = text.match(re)
  return m ? m[0] : null
}

/** 输入侧规则（参数注入 / 危险操作） */
export const INPUT_RULES = [
  {
    id: 'SEC-001', risk: 10, direction: 'input',
    re: /(?:rm|rmdir|del|rd)\s+(?:-rf|-r|-f)?\s*(\/|\/\/|~|C:\\|D:\\)|format\s+[a-z]:|mkfs\.\w+|dd\s+if=.*of=\/dev\/|diskpart/i,
    summary: '破坏性删除/格式化/磁盘写入',
    advice: '禁止对根目录/家目录/系统盘执行删除或格式化；如确需清理，改用回收站或限定路径后二次确认',
  },
  {
    id: 'SEC-002', risk: 9, direction: 'input',
    re: /(?:~\/|%USERPROFILE%\\|C:\\Users\\)(?:\.ssh|\.aws|\.kube|\.gnupg|\.config\/gcloud)\/|(?:id_rsa|id_ed25519|credentials\.(?:yaml|json|ini)|\.env|\.npmrc|keyring|wallet|\.netrc)/i,
    summary: '访问凭据/密钥文件',
    advice: '正在读取 SSH 私钥/AWS/云凭据/环境变量文件；确认这是用户显式授权，否则终止',
  },
  {
    id: 'SEC-003', risk: 9, direction: 'input',
    re: /(?:password|passwd|api[_-]?key|secret|token|access[_-]?key|private[_-]?key)\s*[=:]\s*\S{6,}|(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})/i,
    summary: '参数中出现疑似明文凭据',
    advice: '正在把疑似密钥/口令写入工具参数；改用环境变量或凭据服务引用，禁止明文落盘',
  },
  {
    id: 'SEC-004', risk: 9, direction: 'input',
    re: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.tencentyun\.com|metadata\.(?:compute|azure)\./i,
    summary: 'SSRF：访问云元数据端点',
    advice: '正在访问云厂商元数据服务（可窃取 IAM 临时凭据）；禁止，除非用户显式授权的特定场景',
  },
  {
    id: 'SEC-005', risk: 10, direction: 'input',
    re: /bash\s+-i|nc\s+(-e|-lvp|-l\s+-p)|ncat\s+.*-e|\/dev\/tcp\/|powershell.*(?:-enc|encod)|Invoke-(?:WebRequest|Expression)|curl\s+.*\|\s*(?:sh|bash)|wget\s+.*\|\s*(?:sh|bash)|base64\s+.*-d\s*\|/i,
    summary: '反向 shell / 远程代码执行管道',
    advice: '检测到反向 shell 或下载执行管道，高风险，已拦截',
  },
  {
    id: 'SEC-006', risk: 8, direction: 'input',
    re: /;\s*(?:rm|del|format|shutdown|reboot)|&&\s*(?:rm|del|format|shutdown|reboot)|\|\s*(?:sh|bash|cmd)|`[^`]+`|\(\s*\)\s*\{[^}]*\};\s*[a-z]/i,
    summary: '命令链注入（拼接危险命令）',
    advice: '检测到命令拼接链；请拆分为独立步骤并由用户逐项确认',
  },
  {
    id: 'SEC-007', risk: 8, direction: 'input',
    re: /sudo\s+(?:su|-\s*i|-i\b)|chmod\s+777\s+\/|chown\s+-R\s+0:0|passwd\s+root|useradd\s+.*-o\s+0/i,
    summary: '提权 / 权限变更',
    advice: '正在执行提权或高危权限变更；需用户显式确认',
  },
  {
    id: 'SEC-008', risk: 9, direction: 'input',
    re: /\/etc\/(?:passwd|shadow|sudoers)\b|\/boot\b|C:\\Windows\\System32\\(?:config|drivers)|\/dev\/(?:sda|sdb|nvme)/i,
    summary: '写入系统关键文件/设备',
    advice: '正在访问系统关键文件或块设备；高风险，确认意图后谨慎执行',
  },
  {
    id: 'SEC-009', risk: 5, direction: 'input',
    re: /git\s+push|npm\s+publish|gh\s+release|docker\s+push/i,
    summary: '对外发布操作（推送/发布）',
    advice: '将执行对外发布类操作（push/publish）；默认放行但记录审计，请确认目标仓库正确',
  },
]

/** 输出侧规则（结果泄露检测） */
export const OUTPUT_RULES = [
  {
    id: 'OUT-001', risk: 10, direction: 'output',
    re: /(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|Bearer\s+[A-Za-z0-9._-]{20,})|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/i,
    summary: '输出泄露密钥/私钥',
    advice: '工具结果疑似包含密钥或私钥块；请立即更换泄露凭据并避免在输出中回显',
  },
  {
    id: 'OUT-002', risk: 6, direction: 'output',
    re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/i,
    summary: '输出内网 IP 地址',
    advice: '工具结果包含内网 IP；若属敏感拓扑信息请打码后再展示',
  },
  {
    id: 'OUT-003', risk: 8, direction: 'output',
    re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s/]+:[^\s@]+@/i,
    summary: '输出含凭据的数据库连接串',
    advice: '数据库连接串带明文口令，属高敏信息；禁止在对话中完整展示',
  },
  {
    id: 'OUT-004', risk: 8, direction: 'output',
    re: /\b(?:AWS_SECRET_ACCESS_KEY|DB_PASSWORD|SECRET_KEY|API_KEY|PRIVATE_KEY)\s*[=:]/i,
    summary: '输出环境变量密钥 dump',
    advice: '疑似环境变量密钥批量输出；属于高敏泄露，请立即止损',
  },
  {
    id: 'OUT-005', risk: 7, direction: 'output',
    re: /ssh-rsa AAAA[0-9A-Za-z+/]{40,}|-----BEGIN (?:CERTIFICATE|PGP PRIVATE KEY)-----/i,
    summary: '输出公钥/证书/私密材料',
    advice: '工具结果包含密钥材料；确认是否为授权展示',
  },
]

/** 单文本扫描：返回命中规则数组（按风险降序） */
export function scan(text, rules) {
  const hits = []
  for (const rule of rules) {
    const hit = find(rule.re, text)
    if (hit !== null) {
      hits.push({ id: rule.id, risk: rule.risk, summary: rule.summary, advice: rule.advice, sample: hit.slice(0, 120) })
    }
  }
  return hits.sort((a, b) => b.risk - a.risk)
}

/**
 * 解析一条自定义规则（来自 rules.d/*.json）。
 * @param {object} raw { id, direction: 'input'|'output', risk, re, summary, advice }
 * @returns 编译后的规则对象（re → RegExp）
 */
export function parseCustomRule(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('规则必须是对象')
  const { id, direction, risk, re, summary, advice } = raw
  if (!id || typeof id !== 'string') throw new Error('规则缺少 id')
  if (direction !== 'input' && direction !== 'output') throw new Error(`规则 ${id} direction 必须是 input/output`)
  if (typeof risk !== 'number' || risk < 1 || risk > 10) throw new Error(`规则 ${id} risk 必须是 1-10`)
  if (typeof re !== 'string') throw new Error(`规则 ${id} 缺少正则 re`)
  let compiled
  try {
    compiled = new RegExp(re, 'i')
  } catch (e) {
    throw new Error(`规则 ${id} 正则非法: ${e.message}`)
  }
  return {
    id: String(id), risk: Number(risk), direction,
    re: compiled,
    summary: summary || `自定义规则 ${id}`,
    advice: advice || '',
    custom: true,
  }
}

/** 构建完整规则集：内置 + 自定义合并 */
export function buildRuleSet(customInput = [], customOutput = []) {
  return {
    input: [...INPUT_RULES, ...customInput],
    output: [...OUTPUT_RULES, ...customOutput],
  }
}

/** 输入参数扫描：递归序列化 arguments（防嵌套对象里的字符串漏检） */
export function scanArguments(args, rules = INPUT_RULES) {
  const texts = []
  const walk = (v, depth = 0) => {
    if (depth > 6 || v == null) return
    if (typeof v === 'string') texts.push(v)
    else if (typeof v === 'object') {
      for (const k of Object.keys(v)) {
        texts.push(k)
        walk(v[k], depth + 1)
      }
    }
  }
  walk(args)
  // 也扫 JSON 序列化整体，捕获拼接形态
  try { texts.push(JSON.stringify(args)) } catch { /* ignore */ }
  const hits = []
  for (const t of texts) hits.push(...scan(t, rules))
  // 去重（同规则多文本命中只记一条）
  const seen = new Set()
  return hits.filter((h) => {
    const k = h.id + '|' + h.sample
    if (seen.has(k)) return false
    seen.add(k)
    return true
  }).sort((a, b) => b.risk - a.risk)
}

/** 输出内容扫描：提取 content blocks 里的文本 */
export function scanOutput(result, rules = OUTPUT_RULES) {
  const texts = []
  const content = result?.content
  if (Array.isArray(content)) {
    for (const block of content) {
      if (block?.type === 'text' && typeof block.text === 'string') texts.push(block.text)
    }
  } else if (typeof result?.text === 'string') {
    texts.push(result.text)
  }
  if (typeof result?.error?.message === 'string') texts.push(result.error.message)
  const hits = []
  for (const t of texts) hits.push(...scan(t, rules))
  const seen = new Set()
  return hits.filter((h) => {
    const k = h.id + '|' + h.sample
    if (seen.has(k)) return false
    seen.add(k)
    return true
  }).sort((a, b) => b.risk - a.risk)
}
